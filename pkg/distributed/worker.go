package distributed

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/f2u0a0d3/GoRecon/pkg/config"
	"github.com/f2u0a0d3/GoRecon/pkg/core"
	"github.com/f2u0a0d3/GoRecon/pkg/models"
	"github.com/gorilla/websocket"
	"github.com/rs/zerolog/log"
)

type WorkerNode struct {
	config        *config.Config
	id            string
	capabilities  []string
	maxJobs       int
	currentJobs   int
	pluginManager *core.PluginManager
	coordinator   *CoordinatorClient
	jobExecutor   *JobExecutor
	stats         WorkerNodeStats
	mutex         sync.RWMutex
	ctx           context.Context
	cancel        context.CancelFunc
}

type WorkerNodeStats struct {
	StartTime     time.Time     `json:"start_time"`
	TotalJobs     int           `json:"total_jobs"`
	CompletedJobs int           `json:"completed_jobs"`
	FailedJobs    int           `json:"failed_jobs"`
	AverageTime   time.Duration `json:"average_time"`
	LastJobTime   time.Time     `json:"last_job_time"`
	Uptime        time.Duration `json:"uptime"`
}

type CoordinatorClient struct {
	address    string
	conn       *websocket.Conn
	connected  bool
	mutex      sync.RWMutex
	heartbeat  chan struct{}
	messages   chan map[string]interface{}
	reconnect  chan struct{}
	maxRetries int
	retryDelay time.Duration
}

type JobExecutor struct {
	worker        *WorkerNode
	activeJobs    map[string]*ActiveJob
	jobQueue      chan *Job
	results       chan *JobResult
	mutex         sync.RWMutex
	maxConcurrent int
}

type ActiveJob struct {
	Job       *Job           `json:"job"`
	StartTime time.Time      `json:"start_time"`
	Context   context.Context
	Cancel    context.CancelFunc
	Plugin    core.Plugin    `json:"-"`
	SharedCtx *core.SharedContext `json:"-"`
}

func NewWorkerNode(cfg *config.Config, manager *core.PluginManager) *WorkerNode {
	ctx, cancel := context.WithCancel(context.Background())
	
	worker := &WorkerNode{
		config:        cfg,
		id:            generateWorkerID(),
		capabilities:  extractCapabilities(manager),
		maxJobs:       cfg.Distributed.Worker.MaxJobs,
		pluginManager: manager,
		stats: WorkerNodeStats{
			StartTime: time.Now(),
		},
		ctx:    ctx,
		cancel: cancel,
	}

	// Initialize coordinator client
	coordinatorAddr := cfg.Distributed.Coordinator.Address
	if coordinatorAddr == "" {
		coordinatorAddr = "localhost:8090"
	}
	
	worker.coordinator = &CoordinatorClient{
		address:    coordinatorAddr,
		heartbeat:  make(chan struct{}, 1),
		messages:   make(chan map[string]interface{}, 100),
		reconnect:  make(chan struct{}, 1),
		maxRetries: 10,
		retryDelay: 5 * time.Second,
	}

	// Initialize job executor
	worker.jobExecutor = &JobExecutor{
		worker:        worker,
		activeJobs:    make(map[string]*ActiveJob),
		jobQueue:      make(chan *Job, 50),
		results:       make(chan *JobResult, 100),
		maxConcurrent: worker.maxJobs,
	}

	return worker
}

func (w *WorkerNode) Start(ctx context.Context) error {
	log.Info().
		Str("worker_id", w.id).
		Str("coordinator", w.coordinator.address).
		Int("max_jobs", w.maxJobs).
		Msg("Starting distributed worker")

	// Start background services
	go w.heartbeatLoop(ctx)
	go w.messageHandler(ctx)
	go w.jobExecutor.start(ctx)
	go w.resultProcessor(ctx)
	go w.coordinatorReconnector(ctx)

	// Register with coordinator
	if err := w.registerWithCoordinator(); err != nil {
		log.Error().Err(err).Msg("Failed to register with coordinator")
		return err
	}

	// Connect to coordinator via WebSocket
	if err := w.connectToCoordinator(); err != nil {
		log.Error().Err(err).Msg("Failed to connect to coordinator")
		return err
	}

	// Wait for shutdown signal
	<-ctx.Done()
	return w.Stop()
}

func (w *WorkerNode) Stop() error {
	log.Info().Str("worker_id", w.id).Msg("Shutting down worker")

	// Cancel all active jobs
	w.jobExecutor.mutex.Lock()
	for _, activeJob := range w.jobExecutor.activeJobs {
		activeJob.Cancel()
	}
	w.jobExecutor.mutex.Unlock()

	// Close connections
	w.coordinator.mutex.Lock()
	if w.coordinator.conn != nil {
		w.coordinator.conn.Close()
	}
	w.coordinator.mutex.Unlock()

	// Cancel context
	w.cancel()

	return nil
}

func (w *WorkerNode) registerWithCoordinator() error {
	registrationURL := fmt.Sprintf("http://%s/api/v1/workers/register", w.coordinator.address)
	
	payload := map[string]interface{}{
		"worker_id":     w.id,
		"address":       w.getWorkerAddress(),
		"capabilities":  w.capabilities,
		"max_jobs":      w.maxJobs,
		"metadata": map[string]string{
			"version":    "1.0.0",
			"start_time": w.stats.StartTime.Format(time.RFC3339),
		},
	}

	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal registration payload: %w", err)
	}

	resp, err := http.Post(registrationURL, "application/json", strings.NewReader(string(payloadBytes)))
	if err != nil {
		return fmt.Errorf("failed to register with coordinator: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("coordinator rejected registration: %s", resp.Status)
	}

	log.Info().Str("worker_id", w.id).Msg("Successfully registered with coordinator")
	return nil
}

func (w *WorkerNode) connectToCoordinator() error {
	wsURL := url.URL{
		Scheme: "ws",
		Host:   w.coordinator.address,
		Path:   fmt.Sprintf("/api/v1/ws/worker/%s", w.id),
	}

	conn, _, err := websocket.DefaultDialer.Dial(wsURL.String(), nil)
	if err != nil {
		return fmt.Errorf("failed to connect to coordinator WebSocket: %w", err)
	}

	w.coordinator.mutex.Lock()
	w.coordinator.conn = conn
	w.coordinator.connected = true
	w.coordinator.mutex.Unlock()

	log.Info().Str("worker_id", w.id).Msg("Connected to coordinator via WebSocket")

	// Start message reader
	go w.messageReader()

	return nil
}

func (w *WorkerNode) messageReader() {
	defer func() {
		w.coordinator.mutex.Lock()
		w.coordinator.connected = false
		if w.coordinator.conn != nil {
			w.coordinator.conn.Close()
			w.coordinator.conn = nil
		}
		w.coordinator.mutex.Unlock()

		// Signal for reconnection
		select {
		case w.coordinator.reconnect <- struct{}{}:
		default:
		}
	}()

	for {
		var message map[string]interface{}
		if err := w.coordinator.conn.ReadJSON(&message); err != nil {
			log.Debug().Err(err).Msg("WebSocket connection closed")
			return
		}

		select {
		case w.coordinator.messages <- message:
		case <-w.ctx.Done():
			return
		default:
			log.Warn().Msg("Message queue full, dropping message")
		}
	}
}

func (w *WorkerNode) messageHandler(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case message := <-w.coordinator.messages:
			w.handleCoordinatorMessage(message)
		}
	}
}

func (w *WorkerNode) handleCoordinatorMessage(message map[string]interface{}) {
	msgType, ok := message["type"].(string)
	if !ok {
		log.Warn().Interface("message", message).Msg("Invalid message format from coordinator")
		return
	}

	switch msgType {
	case "job_assignment":
		w.handleJobAssignment(message)
	case "job_cancellation":
		w.handleJobCancellation(message)
	case "health_check":
		w.handleHealthCheck(message)
	case "shutdown":
		w.handleShutdownRequest(message)
	default:
		log.Warn().Str("type", msgType).Msg("Unknown message type from coordinator")
	}
}

func (w *WorkerNode) handleJobAssignment(message map[string]interface{}) {
	jobData, ok := message["job"]
	if !ok {
		log.Warn().Msg("Job assignment missing job data")
		return
	}

	// Parse job
	jobBytes, err := json.Marshal(jobData)
	if err != nil {
		log.Error().Err(err).Msg("Failed to marshal job data")
		return
	}

	var job Job
	if err := json.Unmarshal(jobBytes, &job); err != nil {
		log.Error().Err(err).Msg("Failed to unmarshal job")
		return
	}

	// Queue job for execution
	select {
	case w.jobExecutor.jobQueue <- &job:
		log.Info().
			Str("job_id", job.ID).
			Str("plugin", job.PluginID).
			Msg("Received job assignment")
	default:
		log.Warn().Str("job_id", job.ID).Msg("Job queue full, rejecting job")
		
		// Send rejection back to coordinator
		result := &JobResult{
			JobID:    job.ID,
			ScanID:   job.ScanID,
			Status:   JobStatusFailed,
			Error:    "Worker job queue full",
			EndTime:  time.Now(),
		}
		w.sendJobResult(result)
	}
}

func (w *WorkerNode) handleJobCancellation(message map[string]interface{}) {
	jobID, ok := message["job_id"].(string)
	if !ok {
		log.Warn().Msg("Job cancellation missing job_id")
		return
	}

	w.jobExecutor.mutex.Lock()
	if activeJob, exists := w.jobExecutor.activeJobs[jobID]; exists {
		activeJob.Cancel()
		delete(w.jobExecutor.activeJobs, jobID)
		log.Info().Str("job_id", jobID).Msg("Cancelled job")
	}
	w.jobExecutor.mutex.Unlock()
}

func (w *WorkerNode) handleHealthCheck(message map[string]interface{}) {
	// Respond with current status
	response := map[string]interface{}{
		"type":         "health_response",
		"worker_id":    w.id,
		"status":       "healthy",
		"current_jobs": w.currentJobs,
		"max_jobs":     w.maxJobs,
		"stats":        w.getStats(),
		"timestamp":    time.Now(),
	}

	w.sendMessage(response)
}

func (w *WorkerNode) handleShutdownRequest(message map[string]interface{}) {
	log.Info().Msg("Received shutdown request from coordinator")
	w.cancel()
}

func (w *WorkerNode) heartbeatLoop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.sendHeartbeat()
		case <-w.coordinator.heartbeat:
			w.sendHeartbeat()
		}
	}
}

func (w *WorkerNode) sendHeartbeat() {
	message := map[string]interface{}{
		"type":         "heartbeat",
		"worker_id":    w.id,
		"timestamp":    time.Now(),
		"current_jobs": w.currentJobs,
		"stats":        w.getStats(),
	}

	w.sendMessage(message)
}

func (w *WorkerNode) sendMessage(message map[string]interface{}) {
	w.coordinator.mutex.RLock()
	conn := w.coordinator.conn
	connected := w.coordinator.connected
	w.coordinator.mutex.RUnlock()

	if !connected || conn == nil {
		log.Debug().Msg("Not connected to coordinator, cannot send message")
		return
	}

	if err := conn.WriteJSON(message); err != nil {
		log.Error().Err(err).Msg("Failed to send message to coordinator")
		
		// Signal for reconnection
		select {
		case w.coordinator.reconnect <- struct{}{}:
		default:
		}
	}
}

func (w *WorkerNode) coordinatorReconnector(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-w.coordinator.reconnect:
			w.attemptReconnection(ctx)
		}
	}
}

func (w *WorkerNode) attemptReconnection(ctx context.Context) {
	retries := 0
	for retries < w.coordinator.maxRetries {
		select {
		case <-ctx.Done():
			return
		default:
		}

		log.Info().
			Int("attempt", retries+1).
			Int("max_retries", w.coordinator.maxRetries).
			Msg("Attempting to reconnect to coordinator")

		if err := w.connectToCoordinator(); err != nil {
			log.Warn().
				Err(err).
				Int("retry", retries+1).
				Msg("Failed to reconnect to coordinator")
			
			retries++
			time.Sleep(w.coordinator.retryDelay)
			continue
		}

		log.Info().Msg("Successfully reconnected to coordinator")
		return
	}

	log.Error().Msg("Max reconnection attempts exceeded, shutting down worker")
	w.cancel()
}

// Job Executor Implementation

func (je *JobExecutor) start(ctx context.Context) {
	log.Info().
		Int("max_concurrent", je.maxConcurrent).
		Msg("Starting job executor")

	// Start worker goroutines
	for i := 0; i < je.maxConcurrent; i++ {
		go je.jobWorker(ctx, i)
	}
}

func (je *JobExecutor) jobWorker(ctx context.Context, workerID int) {
	log.Debug().Int("worker_id", workerID).Msg("Job worker started")

	for {
		select {
		case <-ctx.Done():
			return
		case job := <-je.jobQueue:
			if job != nil {
				je.executeJob(ctx, job)
			}
		}
	}
}

func (je *JobExecutor) executeJob(ctx context.Context, job *Job) {
	log.Info().
		Str("job_id", job.ID).
		Str("plugin", job.PluginID).
		Str("target", job.Target.String()).
		Msg("Executing job")

	startTime := time.Now()
	
	// Create job context with timeout
	jobCtx, cancel := context.WithTimeout(ctx, job.Timeout)
	defer cancel()

	// Create active job record
	activeJob := &ActiveJob{
		Job:       job,
		StartTime: startTime,
		Context:   jobCtx,
		Cancel:    cancel,
		SharedCtx: core.NewSharedContext(),
	}

	// Track active job
	je.mutex.Lock()
	je.activeJobs[job.ID] = activeJob
	je.worker.currentJobs++
	je.mutex.Unlock()

	// Get plugin
	plugin := je.worker.pluginManager.GetPlugin(job.PluginID)
	if plugin == nil {
		result := &JobResult{
			JobID:     job.ID,
			ScanID:    job.ScanID,
			Status:    JobStatusFailed,
			Error:     fmt.Sprintf("Plugin %s not found", job.PluginID),
			StartTime: startTime,
			EndTime:   time.Now(),
			Duration:  time.Since(startTime),
		}
		je.sendResult(result)
		return
	}

	activeJob.Plugin = plugin

	// Send status update
	je.worker.sendJobStatusUpdate(job.ID, JobStatusRunning, "")

	// Execute plugin
	pluginResult, err := plugin.Execute(jobCtx, job.Target, activeJob.SharedCtx)
	endTime := time.Now()
	duration := endTime.Sub(startTime)

	// Create result
	result := &JobResult{
		JobID:     job.ID,
		ScanID:    job.ScanID,
		StartTime: startTime,
		EndTime:   endTime,
		Duration:  duration,
		Metadata: map[string]interface{}{
			"plugin":      job.PluginID,
			"target":      job.Target.String(),
			"worker_id":   je.worker.id,
			"job_timeout": job.Timeout.String(),
		},
	}

	if err != nil {
		result.Status = JobStatusFailed
		result.Error = err.Error()
		log.Error().
			Err(err).
			Str("job_id", job.ID).
			Str("plugin", job.PluginID).
			Msg("Job execution failed")
	} else {
		result.Status = JobStatusCompleted
		result.Result = pluginResult
		log.Info().
			Str("job_id", job.ID).
			Str("plugin", job.PluginID).
			Dur("duration", duration).
			Msg("Job completed successfully")
	}

	// Update stats
	je.worker.mutex.Lock()
	je.worker.stats.TotalJobs++
	if result.Status == JobStatusCompleted {
		je.worker.stats.CompletedJobs++
	} else {
		je.worker.stats.FailedJobs++
	}
	je.worker.stats.LastJobTime = endTime
	
	// Update average time
	if je.worker.stats.CompletedJobs > 0 {
		totalTime := time.Duration(je.worker.stats.CompletedJobs) * je.worker.stats.AverageTime
		totalTime += duration
		je.worker.stats.AverageTime = totalTime / time.Duration(je.worker.stats.CompletedJobs)
	} else {
		je.worker.stats.AverageTime = duration
	}
	je.worker.mutex.Unlock()

	// Clean up active job
	je.mutex.Lock()
	delete(je.activeJobs, job.ID)
	je.worker.currentJobs--
	je.mutex.Unlock()

	// Send result
	je.sendResult(result)
}

func (je *JobExecutor) sendResult(result *JobResult) {
	select {
	case je.results <- result:
	default:
		log.Warn().Str("job_id", result.JobID).Msg("Result queue full, dropping result")
	}
}

func (w *WorkerNode) resultProcessor(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case result := <-w.jobExecutor.results:
			if result != nil {
				w.sendJobResult(result)
			}
		}
	}
}

func (w *WorkerNode) sendJobResult(result *JobResult) {
	message := map[string]interface{}{
		"type":   "job_result",
		"result": result,
	}

	w.sendMessage(message)
}

func (w *WorkerNode) sendJobStatusUpdate(jobID string, status JobStatus, message string) {
	update := map[string]interface{}{
		"type":    "status_update",
		"job_id":  jobID,
		"status":  status,
		"message": message,
		"timestamp": time.Now(),
	}

	w.sendMessage(update)
}

func (w *WorkerNode) getStats() WorkerNodeStats {
	w.mutex.RLock()
	defer w.mutex.RUnlock()

	stats := w.stats
	stats.Uptime = time.Since(w.stats.StartTime)
	return stats
}

func (w *WorkerNode) getWorkerAddress() string {
	// Return the worker's address for coordinator communication
	return fmt.Sprintf("worker-%s", w.id)
}

// Utility functions

func generateWorkerID() string {
	return fmt.Sprintf("worker-%d", time.Now().UnixNano())
}

func extractCapabilities(manager *core.PluginManager) []string {
	var capabilities []string
	
	plugins := manager.ListPlugins()
	for _, plugin := range plugins {
		capabilities = append(capabilities, plugin.ID())
	}

	return capabilities
}
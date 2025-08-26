package distributed

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/f2u0a0d3/GoRecon/pkg/config"
	"github.com/f2u0a0d3/GoRecon/pkg/core"
	"github.com/f2u0a0d3/GoRecon/pkg/models"
	"github.com/gorilla/websocket"
	"github.com/rs/zerolog/log"
)

type Coordinator struct {
	config      *config.Config
	workers     map[string]*Worker
	jobQueue    chan *Job
	results     chan *JobResult
	httpServer  *http.Server
	upgrader    websocket.Upgrader
	mutex       sync.RWMutex
	scanManager *ScanManager
}

type Worker struct {
	ID           string              `json:"id"`
	Address      string              `json:"address"`
	Capabilities []string            `json:"capabilities"`
	Status       WorkerStatus        `json:"status"`
	MaxJobs      int                 `json:"max_jobs"`
	CurrentJobs  int                 `json:"current_jobs"`
	LastSeen     time.Time           `json:"last_seen"`
	Stats        WorkerStats         `json:"stats"`
	Connection   *websocket.Conn     `json:"-"`
	JobHistory   []CompletedJob      `json:"job_history"`
	Metadata     map[string]string   `json:"metadata"`
}

type WorkerStatus string

const (
	WorkerStatusOnline   WorkerStatus = "online"
	WorkerStatusOffline  WorkerStatus = "offline"
	WorkerStatusBusy     WorkerStatus = "busy"
	WorkerStatusError    WorkerStatus = "error"
)

type WorkerStats struct {
	TotalJobs     int           `json:"total_jobs"`
	CompletedJobs int           `json:"completed_jobs"`
	FailedJobs    int           `json:"failed_jobs"`
	AverageTime   time.Duration `json:"average_time"`
	Uptime        time.Duration `json:"uptime"`
	LastJobTime   time.Time     `json:"last_job_time"`
}

type Job struct {
	ID          string                 `json:"id"`
	ScanID      string                 `json:"scan_id"`
	PluginID    string                 `json:"plugin_id"`
	Target      models.Target          `json:"target"`
	Parameters  map[string]interface{} `json:"parameters"`
	Priority    int                    `json:"priority"`
	RequiredCaps []string              `json:"required_capabilities"`
	CreatedAt   time.Time              `json:"created_at"`
	AssignedTo  string                 `json:"assigned_to"`
	Status      JobStatus              `json:"status"`
	Retries     int                    `json:"retries"`
	MaxRetries  int                    `json:"max_retries"`
	Timeout     time.Duration          `json:"timeout"`
	Metadata    map[string]string      `json:"metadata"`
}

type JobStatus string

const (
	JobStatusPending    JobStatus = "pending"
	JobStatusAssigned   JobStatus = "assigned"
	JobStatusRunning    JobStatus = "running"
	JobStatusCompleted  JobStatus = "completed"
	JobStatusFailed     JobStatus = "failed"
	JobStatusCancelled  JobStatus = "cancelled"
)

type JobResult struct {
	JobID     string                 `json:"job_id"`
	ScanID    string                 `json:"scan_id"`
	WorkerID  string                 `json:"worker_id"`
	Result    *models.PluginResult   `json:"result"`
	Error     string                 `json:"error,omitempty"`
	Status    JobStatus              `json:"status"`
	StartTime time.Time              `json:"start_time"`
	EndTime   time.Time              `json:"end_time"`
	Duration  time.Duration          `json:"duration"`
	Metadata  map[string]interface{} `json:"metadata"`
}

type CompletedJob struct {
	JobID     string        `json:"job_id"`
	PluginID  string        `json:"plugin_id"`
	Status    JobStatus     `json:"status"`
	Duration  time.Duration `json:"duration"`
	Timestamp time.Time     `json:"timestamp"`
}

type ScanManager struct {
	activeScans map[string]*DistributedScan
	mutex       sync.RWMutex
}

type DistributedScan struct {
	ID          string                   `json:"id"`
	Target      models.Target            `json:"target"`
	Plugins     []string                 `json:"plugins"`
	Jobs        map[string]*Job          `json:"jobs"`
	Results     []*models.PluginResult   `json:"results"`
	Status      ScanStatus               `json:"status"`
	CreatedAt   time.Time                `json:"created_at"`
	StartedAt   time.Time                `json:"started_at"`
	CompletedAt time.Time                `json:"completed_at"`
	Progress    ScanProgress             `json:"progress"`
	Metadata    map[string]interface{}   `json:"metadata"`
}

type ScanStatus string

const (
	ScanStatusPending    ScanStatus = "pending"
	ScanStatusRunning    ScanStatus = "running"
	ScanStatusCompleted  ScanStatus = "completed"
	ScanStatusFailed     ScanStatus = "failed"
	ScanStatusCancelled  ScanStatus = "cancelled"
)

type ScanProgress struct {
	TotalJobs     int     `json:"total_jobs"`
	CompletedJobs int     `json:"completed_jobs"`
	FailedJobs    int     `json:"failed_jobs"`
	Percentage    float64 `json:"percentage"`
	ETA           string  `json:"eta"`
}

func NewCoordinator(cfg *config.Config) *Coordinator {
	return &Coordinator{
		config:   cfg,
		workers:  make(map[string]*Worker),
		jobQueue: make(chan *Job, 1000),
		results:  make(chan *JobResult, 1000),
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				return true // Allow all origins in development
			},
		},
		scanManager: &ScanManager{
			activeScans: make(map[string]*DistributedScan),
		},
	}
}

func (c *Coordinator) Start(ctx context.Context) error {
	// Start background goroutines
	go c.jobDispatcher(ctx)
	go c.resultProcessor(ctx)
	go c.workerHealthChecker(ctx)

	// Setup HTTP server
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(gin.Recovery())

	c.setupRoutes(router)

	port := ":8090" // Default coordinator port
	if c.config.Distributed.Coordinator.Port != "" {
		port = ":" + c.config.Distributed.Coordinator.Port
	}

	c.httpServer = &http.Server{
		Addr:    port,
		Handler: router,
	}

	log.Info().
		Str("port", port).
		Msg("Starting distributed coordinator")

	go func() {
		<-ctx.Done()
		c.Stop()
	}()

	if err := c.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}

	return nil
}

func (c *Coordinator) Stop() error {
	log.Info().Msg("Shutting down coordinator")
	
	// Close job channels
	close(c.jobQueue)
	close(c.results)

	// Disconnect all workers
	c.mutex.Lock()
	for _, worker := range c.workers {
		if worker.Connection != nil {
			worker.Connection.Close()
		}
	}
	c.mutex.Unlock()

	// Shutdown HTTP server
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	return c.httpServer.Shutdown(ctx)
}

func (c *Coordinator) setupRoutes(router *gin.Engine) {
	api := router.Group("/api/v1")

	// Worker management
	api.POST("/workers/register", c.registerWorker)
	api.GET("/workers", c.listWorkers)
	api.GET("/workers/:id", c.getWorker)
	api.DELETE("/workers/:id", c.removeWorker)
	api.GET("/workers/:id/stats", c.getWorkerStats)

	// Job management
	api.POST("/jobs", c.createJob)
	api.GET("/jobs", c.listJobs)
	api.GET("/jobs/:id", c.getJob)
	api.DELETE("/jobs/:id", c.cancelJob)

	// Scan management
	api.POST("/scans", c.createDistributedScan)
	api.GET("/scans", c.listDistributedScans)
	api.GET("/scans/:id", c.getDistributedScan)
	api.DELETE("/scans/:id", c.cancelDistributedScan)
	api.GET("/scans/:id/results", c.getScanResults)

	// Real-time communication
	api.GET("/ws/worker/:id", c.handleWorkerWebSocket)
	api.GET("/ws/scan/:id", c.handleScanWebSocket)

	// Health and status
	api.GET("/health", c.healthCheck)
	api.GET("/status", c.getClusterStatus)
	api.GET("/metrics", c.getMetrics)
}

func (c *Coordinator) registerWorker(ctx *gin.Context) {
	var req struct {
		WorkerID     string            `json:"worker_id" binding:"required"`
		Address      string            `json:"address" binding:"required"`
		Capabilities []string          `json:"capabilities"`
		MaxJobs      int               `json:"max_jobs"`
		Metadata     map[string]string `json:"metadata"`
	}

	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.mutex.Lock()
	defer c.mutex.Unlock()

	worker := &Worker{
		ID:           req.WorkerID,
		Address:      req.Address,
		Capabilities: req.Capabilities,
		Status:       WorkerStatusOnline,
		MaxJobs:      req.MaxJobs,
		CurrentJobs:  0,
		LastSeen:     time.Now(),
		Stats:        WorkerStats{},
		JobHistory:   make([]CompletedJob, 0),
		Metadata:     req.Metadata,
	}

	c.workers[req.WorkerID] = worker

	log.Info().
		Str("worker_id", req.WorkerID).
		Str("address", req.Address).
		Strs("capabilities", req.Capabilities).
		Msg("Worker registered")

	ctx.JSON(http.StatusOK, gin.H{
		"message":   "Worker registered successfully",
		"worker_id": req.WorkerID,
		"status":    "online",
	})
}

func (c *Coordinator) listWorkers(ctx *gin.Context) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	workers := make([]*Worker, 0, len(c.workers))
	for _, worker := range c.workers {
		workers = append(workers, worker)
	}

	ctx.JSON(http.StatusOK, gin.H{
		"workers": workers,
		"total":   len(workers),
	})
}

func (c *Coordinator) createDistributedScan(ctx *gin.Context) {
	var req struct {
		Target   models.Target          `json:"target" binding:"required"`
		Plugins  []string               `json:"plugins"`
		Priority int                    `json:"priority"`
		Metadata map[string]interface{} `json:"metadata"`
	}

	if err := ctx.ShouldBindJSON(&req); err != nil {
		ctx.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	scanID := generateScanID()
	scan := &DistributedScan{
		ID:        scanID,
		Target:    req.Target,
		Plugins:   req.Plugins,
		Jobs:      make(map[string]*Job),
		Results:   make([]*models.PluginResult, 0),
		Status:    ScanStatusPending,
		CreatedAt: time.Now(),
		Metadata:  req.Metadata,
	}

	// Create jobs for each plugin
	for _, pluginID := range req.Plugins {
		job := &Job{
			ID:          generateJobID(),
			ScanID:      scanID,
			PluginID:    pluginID,
			Target:      req.Target,
			Priority:    req.Priority,
			CreatedAt:   time.Now(),
			Status:      JobStatusPending,
			MaxRetries:  3,
			Timeout:     15 * time.Minute,
		}

		scan.Jobs[job.ID] = job
	}

	scan.Progress.TotalJobs = len(scan.Jobs)

	c.scanManager.mutex.Lock()
	c.scanManager.activeScans[scanID] = scan
	c.scanManager.mutex.Unlock()

	// Queue all jobs
	for _, job := range scan.Jobs {
		select {
		case c.jobQueue <- job:
		default:
			log.Warn().Str("job_id", job.ID).Msg("Job queue full, dropping job")
		}
	}

	scan.Status = ScanStatusRunning
	scan.StartedAt = time.Now()

	log.Info().
		Str("scan_id", scanID).
		Str("target", req.Target.String()).
		Int("plugins", len(req.Plugins)).
		Msg("Created distributed scan")

	ctx.JSON(http.StatusCreated, gin.H{
		"scan_id": scanID,
		"status":  scan.Status,
		"jobs":    len(scan.Jobs),
	})
}

func (c *Coordinator) jobDispatcher(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case job := <-c.jobQueue:
			if job != nil {
				c.assignJob(job)
			}
		}
	}
}

func (c *Coordinator) assignJob(job *Job) {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	var bestWorker *Worker
	bestScore := -1

	// Find the best worker for this job
	for _, worker := range c.workers {
		if worker.Status != WorkerStatusOnline {
			continue
		}

		if worker.CurrentJobs >= worker.MaxJobs {
			continue
		}

		// Check if worker has required capabilities
		if !c.hasRequiredCapabilities(worker, job.RequiredCaps) {
			continue
		}

		// Calculate worker score (lower current jobs = higher score)
		score := worker.MaxJobs - worker.CurrentJobs
		if score > bestScore {
			bestScore = score
			bestWorker = worker
		}
	}

	if bestWorker == nil {
		// No available worker, put job back in queue
		select {
		case c.jobQueue <- job:
		default:
			log.Warn().Str("job_id", job.ID).Msg("Failed to reassign job")
		}
		return
	}

	// Assign job to worker
	job.AssignedTo = bestWorker.ID
	job.Status = JobStatusAssigned

	c.sendJobToWorker(bestWorker, job)

	bestWorker.CurrentJobs++
	bestWorker.Stats.TotalJobs++

	log.Info().
		Str("job_id", job.ID).
		Str("worker_id", bestWorker.ID).
		Str("plugin", job.PluginID).
		Msg("Job assigned to worker")
}

func (c *Coordinator) sendJobToWorker(worker *Worker, job *Job) {
	if worker.Connection == nil {
		log.Warn().Str("worker_id", worker.ID).Msg("Worker has no WebSocket connection")
		return
	}

	message := map[string]interface{}{
		"type": "job_assignment",
		"job":  job,
	}

	if err := worker.Connection.WriteJSON(message); err != nil {
		log.Error().Err(err).Str("worker_id", worker.ID).Msg("Failed to send job to worker")
		worker.Status = WorkerStatusError
	}
}

func (c *Coordinator) resultProcessor(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case result := <-c.results:
			if result != nil {
				c.processJobResult(result)
			}
		}
	}
}

func (c *Coordinator) processJobResult(result *JobResult) {
	log.Info().
		Str("job_id", result.JobID).
		Str("scan_id", result.ScanID).
		Str("worker_id", result.WorkerID).
		Str("status", string(result.Status)).
		Msg("Processing job result")

	// Update worker stats
	c.mutex.Lock()
	if worker, exists := c.workers[result.WorkerID]; exists {
		worker.CurrentJobs--
		if result.Status == JobStatusCompleted {
			worker.Stats.CompletedJobs++
		} else {
			worker.Stats.FailedJobs++
		}
		worker.Stats.LastJobTime = time.Now()

		// Add to job history
		completedJob := CompletedJob{
			JobID:     result.JobID,
			PluginID:  "unknown", // Would need to track this
			Status:    result.Status,
			Duration:  result.Duration,
			Timestamp: result.EndTime,
		}
		worker.JobHistory = append(worker.JobHistory, completedJob)

		// Limit history size
		if len(worker.JobHistory) > 100 {
			worker.JobHistory = worker.JobHistory[len(worker.JobHistory)-100:]
		}
	}
	c.mutex.Unlock()

	// Update scan progress
	c.scanManager.mutex.Lock()
	if scan, exists := c.scanManager.activeScans[result.ScanID]; exists {
		if result.Status == JobStatusCompleted {
			scan.Progress.CompletedJobs++
			if result.Result != nil {
				scan.Results = append(scan.Results, result.Result)
			}
		} else {
			scan.Progress.FailedJobs++
		}

		// Calculate progress percentage
		scan.Progress.Percentage = float64(scan.Progress.CompletedJobs+scan.Progress.FailedJobs) / float64(scan.Progress.TotalJobs) * 100

		// Check if scan is complete
		if scan.Progress.CompletedJobs+scan.Progress.FailedJobs >= scan.Progress.TotalJobs {
			scan.Status = ScanStatusCompleted
			scan.CompletedAt = time.Now()

			log.Info().
				Str("scan_id", result.ScanID).
				Int("results", len(scan.Results)).
				Msg("Distributed scan completed")
		}
	}
	c.scanManager.mutex.Unlock()
}

func (c *Coordinator) workerHealthChecker(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.checkWorkerHealth()
		}
	}
}

func (c *Coordinator) checkWorkerHealth() {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	now := time.Now()
	for workerID, worker := range c.workers {
		if now.Sub(worker.LastSeen) > 2*time.Minute {
			if worker.Status == WorkerStatusOnline {
				log.Warn().Str("worker_id", workerID).Msg("Worker appears to be offline")
				worker.Status = WorkerStatusOffline
			}
		}
	}
}

func (c *Coordinator) hasRequiredCapabilities(worker *Worker, required []string) bool {
	if len(required) == 0 {
		return true // No specific requirements
	}

	workerCaps := make(map[string]bool)
	for _, cap := range worker.Capabilities {
		workerCaps[cap] = true
	}

	for _, req := range required {
		if !workerCaps[req] {
			return false
		}
	}

	return true
}

func (c *Coordinator) handleWorkerWebSocket(ctx *gin.Context) {
	workerID := ctx.Param("id")

	conn, err := c.upgrader.Upgrade(ctx.Writer, ctx.Request, nil)
	if err != nil {
		log.Error().Err(err).Str("worker_id", workerID).Msg("Failed to upgrade WebSocket connection")
		return
	}
	defer conn.Close()

	c.mutex.Lock()
	if worker, exists := c.workers[workerID]; exists {
		worker.Connection = conn
		worker.Status = WorkerStatusOnline
		worker.LastSeen = time.Now()
	}
	c.mutex.Unlock()

	log.Info().Str("worker_id", workerID).Msg("Worker connected via WebSocket")

	// Handle incoming messages
	for {
		var message map[string]interface{}
		if err := conn.ReadJSON(&message); err != nil {
			log.Debug().Err(err).Str("worker_id", workerID).Msg("Worker disconnected")
			break
		}

		c.handleWorkerMessage(workerID, message)
	}

	// Clean up
	c.mutex.Lock()
	if worker, exists := c.workers[workerID]; exists {
		worker.Connection = nil
		worker.Status = WorkerStatusOffline
	}
	c.mutex.Unlock()
}

func (c *Coordinator) handleWorkerMessage(workerID string, message map[string]interface{}) {
	msgType, ok := message["type"].(string)
	if !ok {
		log.Warn().Str("worker_id", workerID).Msg("Invalid message format from worker")
		return
	}

	switch msgType {
	case "job_result":
		c.handleJobResultMessage(workerID, message)
	case "heartbeat":
		c.handleHeartbeat(workerID, message)
	case "status_update":
		c.handleStatusUpdate(workerID, message)
	default:
		log.Warn().Str("worker_id", workerID).Str("type", msgType).Msg("Unknown message type from worker")
	}
}

func (c *Coordinator) handleJobResultMessage(workerID string, message map[string]interface{}) {
	// Parse job result from message
	resultData, err := json.Marshal(message["result"])
	if err != nil {
		log.Error().Err(err).Str("worker_id", workerID).Msg("Failed to marshal job result")
		return
	}

	var result JobResult
	if err := json.Unmarshal(resultData, &result); err != nil {
		log.Error().Err(err).Str("worker_id", workerID).Msg("Failed to unmarshal job result")
		return
	}

	result.WorkerID = workerID

	// Send to result processor
	select {
	case c.results <- &result:
	default:
		log.Warn().Str("worker_id", workerID).Msg("Result queue full, dropping result")
	}
}

func (c *Coordinator) handleHeartbeat(workerID string, message map[string]interface{}) {
	c.mutex.Lock()
	if worker, exists := c.workers[workerID]; exists {
		worker.LastSeen = time.Now()
		if worker.Status == WorkerStatusOffline {
			worker.Status = WorkerStatusOnline
			log.Info().Str("worker_id", workerID).Msg("Worker back online")
		}
	}
	c.mutex.Unlock()
}

func (c *Coordinator) handleStatusUpdate(workerID string, message map[string]interface{}) {
	// Handle worker status updates
	log.Debug().Str("worker_id", workerID).Interface("message", message).Msg("Worker status update")
}

func (c *Coordinator) healthCheck(ctx *gin.Context) {
	c.mutex.RLock()
	onlineWorkers := 0
	totalWorkers := len(c.workers)
	for _, worker := range c.workers {
		if worker.Status == WorkerStatusOnline {
			onlineWorkers++
		}
	}
	c.mutex.RUnlock()

	c.scanManager.mutex.RLock()
	activeScans := len(c.scanManager.activeScans)
	c.scanManager.mutex.RUnlock()

	status := gin.H{
		"status":         "healthy",
		"timestamp":      time.Now(),
		"workers_online": onlineWorkers,
		"workers_total":  totalWorkers,
		"active_scans":   activeScans,
		"job_queue_size": len(c.jobQueue),
	}

	ctx.JSON(http.StatusOK, status)
}

// Utility functions
func generateScanID() string {
	return fmt.Sprintf("scan-%d", time.Now().UnixNano())
}

func generateJobID() string {
	return fmt.Sprintf("job-%d", time.Now().UnixNano())
}
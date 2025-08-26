package streaming

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/f2u0a0d3/GoRecon/pkg/config"
	"github.com/f2u0a0d3/GoRecon/pkg/models"
	"github.com/gorilla/websocket"
	"github.com/rs/zerolog/log"
)

type StreamManager interface {
	Subscribe(ctx context.Context, topics []string, clientID string) (<-chan StreamEvent, error)
	Publish(topic string, event StreamEvent) error
	Unsubscribe(clientID string, topics []string) error
	GetActiveSubscriptions() map[string][]string
	GetClientCount() int
	Close() error
}

type WebSocketStreamManager struct {
	config        *config.Config
	upgrader      websocket.Upgrader
	clients       map[string]*StreamClient
	topicClients  map[string]map[string]*StreamClient
	eventChannels map[string]chan StreamEvent
	mutex         sync.RWMutex
	ctx           context.Context
	cancel        context.CancelFunc
}

type StreamClient struct {
	ID          string                 `json:"id"`
	Connection  *websocket.Conn        `json:"-"`
	Topics      map[string]bool        `json:"topics"`
	LastSeen    time.Time              `json:"last_seen"`
	MessageCount int64                 `json:"message_count"`
	Connected   bool                   `json:"connected"`
	Metadata    map[string]interface{} `json:"metadata"`
	SendChan    chan StreamEvent       `json:"-"`
	mutex       sync.RWMutex
}

type StreamEvent struct {
	ID        string                 `json:"id"`
	Topic     string                 `json:"topic"`
	Type      StreamEventType        `json:"type"`
	Timestamp time.Time              `json:"timestamp"`
	Source    string                 `json:"source"`
	Data      interface{}            `json:"data"`
	Metadata  map[string]interface{} `json:"metadata"`
}

type StreamEventType string

const (
	EventTypeScanStart      StreamEventType = "scan_start"
	EventTypeScanComplete   StreamEventType = "scan_complete"
	EventTypeScanProgress   StreamEventType = "scan_progress"
	EventTypeFindingNew     StreamEventType = "finding_new"
	EventTypeFindingUpdate  StreamEventType = "finding_update"
	EventTypeCorrelation    StreamEventType = "correlation_new"
	EventTypeSystemHealth   StreamEventType = "system_health"
	EventTypePluginStatus   StreamEventType = "plugin_status"
	EventTypeRiskUpdate     StreamEventType = "risk_update"
	EventTypeAlert          StreamEventType = "alert"
	EventTypeError          StreamEventType = "error"
)

type ScanProgressEvent struct {
	ScanID           string        `json:"scan_id"`
	Status           string        `json:"status"`
	TotalPlugins     int           `json:"total_plugins"`
	CompletedPlugins int           `json:"completed_plugins"`
	CurrentPlugin    string        `json:"current_plugin"`
	Percentage       float64       `json:"percentage"`
	EstimatedTime    time.Duration `json:"estimated_time"`
	FindingsCount    int           `json:"findings_count"`
}

type FindingEvent struct {
	ScanID   string         `json:"scan_id"`
	Finding  models.Finding `json:"finding"`
	Previous *models.Finding `json:"previous,omitempty"`
}

type SystemHealthEvent struct {
	CPUUsage      float64           `json:"cpu_usage"`
	MemoryUsage   int64             `json:"memory_usage"`
	ActiveScans   int               `json:"active_scans"`
	QueueSizes    map[string]int    `json:"queue_sizes"`
	PluginStatus  map[string]string `json:"plugin_status"`
	Timestamp     time.Time         `json:"timestamp"`
}

func NewWebSocketStreamManager(cfg *config.Config) *WebSocketStreamManager {
	ctx, cancel := context.WithCancel(context.Background())
	
	return &WebSocketStreamManager{
		config: cfg,
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				return true // Configure properly for production
			},
			ReadBufferSize:  1024,
			WriteBufferSize: 1024,
		},
		clients:       make(map[string]*StreamClient),
		topicClients:  make(map[string]map[string]*StreamClient),
		eventChannels: make(map[string]chan StreamEvent),
		ctx:           ctx,
		cancel:        cancel,
	}
}

func (sm *WebSocketStreamManager) Start() error {
	// Start background services
	go sm.healthMonitor()
	go sm.clientHealthChecker()
	go sm.eventDistributor()

	log.Info().Msg("WebSocket stream manager started")
	return nil
}

func (sm *WebSocketStreamManager) HandleWebSocket(w http.ResponseWriter, r *http.Request, clientID string) {
	conn, err := sm.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Error().Err(err).Str("client_id", clientID).Msg("Failed to upgrade WebSocket connection")
		return
	}
	defer conn.Close()

	client := &StreamClient{
		ID:          clientID,
		Connection:  conn,
		Topics:      make(map[string]bool),
		LastSeen:    time.Now(),
		Connected:   true,
		Metadata:    make(map[string]interface{}),
		SendChan:    make(chan StreamEvent, 100),
	}

	sm.mutex.Lock()
	sm.clients[clientID] = client
	sm.mutex.Unlock()

	log.Info().Str("client_id", clientID).Msg("WebSocket client connected")

	// Start message handlers
	go sm.clientMessageSender(client)
	go sm.clientMessageReader(client)

	// Wait for connection to close
	<-r.Context().Done()
	
	// Cleanup
	sm.removeClient(clientID)
}

func (sm *WebSocketStreamManager) Subscribe(ctx context.Context, topics []string, clientID string) (<-chan StreamEvent, error) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	client, exists := sm.clients[clientID]
	if !exists {
		return nil, fmt.Errorf("client %s not found", clientID)
	}

	for _, topic := range topics {
		client.Topics[topic] = true
		
		if sm.topicClients[topic] == nil {
			sm.topicClients[topic] = make(map[string]*StreamClient)
		}
		sm.topicClients[topic][clientID] = client
		
		log.Debug().
			Str("client_id", clientID).
			Str("topic", topic).
			Msg("Client subscribed to topic")
	}

	return client.SendChan, nil
}

func (sm *WebSocketStreamManager) Publish(topic string, event StreamEvent) error {
	sm.mutex.RLock()
	clients := sm.topicClients[topic]
	sm.mutex.RUnlock()

	if len(clients) == 0 {
		log.Debug().Str("topic", topic).Msg("No clients subscribed to topic")
		return nil
	}

	event.Topic = topic
	if event.ID == "" {
		event.ID = generateEventID()
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}

	publishCount := 0
	for clientID, client := range clients {
		select {
		case client.SendChan <- event:
			publishCount++
		default:
			log.Warn().
				Str("client_id", clientID).
				Str("topic", topic).
				Msg("Client send channel full, dropping message")
		}
	}

	log.Debug().
		Str("topic", topic).
		Str("event_type", string(event.Type)).
		Int("clients", publishCount).
		Msg("Published event to clients")

	return nil
}

func (sm *WebSocketStreamManager) Unsubscribe(clientID string, topics []string) error {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	client, exists := sm.clients[clientID]
	if !exists {
		return fmt.Errorf("client %s not found", clientID)
	}

	for _, topic := range topics {
		delete(client.Topics, topic)
		
		if topicClients, exists := sm.topicClients[topic]; exists {
			delete(topicClients, clientID)
			
			// Clean up empty topic maps
			if len(topicClients) == 0 {
				delete(sm.topicClients, topic)
			}
		}
		
		log.Debug().
			Str("client_id", clientID).
			Str("topic", topic).
			Msg("Client unsubscribed from topic")
	}

	return nil
}

func (sm *WebSocketStreamManager) GetActiveSubscriptions() map[string][]string {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()

	subscriptions := make(map[string][]string)
	for clientID, client := range sm.clients {
		topics := make([]string, 0, len(client.Topics))
		for topic := range client.Topics {
			topics = append(topics, topic)
		}
		subscriptions[clientID] = topics
	}

	return subscriptions
}

func (sm *WebSocketStreamManager) GetClientCount() int {
	sm.mutex.RLock()
	defer sm.mutex.RUnlock()
	return len(sm.clients)
}

func (sm *WebSocketStreamManager) Close() error {
	sm.cancel()
	
	sm.mutex.Lock()
	defer sm.mutex.Unlock()
	
	// Close all client connections
	for clientID, client := range sm.clients {
		if client.Connection != nil {
			client.Connection.Close()
		}
		close(client.SendChan)
		log.Debug().Str("client_id", clientID).Msg("Closed client connection")
	}
	
	// Close event channels
	for topic, ch := range sm.eventChannels {
		close(ch)
		log.Debug().Str("topic", topic).Msg("Closed event channel")
	}

	log.Info().Msg("WebSocket stream manager closed")
	return nil
}

func (sm *WebSocketStreamManager) clientMessageReader(client *StreamClient) {
	defer func() {
		sm.removeClient(client.ID)
	}()

	for {
		var message map[string]interface{}
		if err := client.Connection.ReadJSON(&message); err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Error().Err(err).Str("client_id", client.ID).Msg("WebSocket read error")
			}
			break
		}

		client.mutex.Lock()
		client.LastSeen = time.Now()
		client.mutex.Unlock()

		sm.handleClientMessage(client, message)
	}
}

func (sm *WebSocketStreamManager) clientMessageSender(client *StreamClient) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case event, ok := <-client.SendChan:
			if !ok {
				return
			}

			if err := client.Connection.WriteJSON(event); err != nil {
				log.Error().Err(err).Str("client_id", client.ID).Msg("Failed to send message to client")
				return
			}

			client.mutex.Lock()
			client.MessageCount++
			client.mutex.Unlock()

		case <-ticker.C:
			// Send ping to keep connection alive
			if err := client.Connection.WriteMessage(websocket.PingMessage, []byte{}); err != nil {
				log.Debug().Err(err).Str("client_id", client.ID).Msg("Failed to send ping")
				return
			}
		}
	}
}

func (sm *WebSocketStreamManager) handleClientMessage(client *StreamClient, message map[string]interface{}) {
	msgType, ok := message["type"].(string)
	if !ok {
		log.Warn().Str("client_id", client.ID).Msg("Invalid message format from client")
		return
	}

	switch msgType {
	case "subscribe":
		sm.handleSubscribeMessage(client, message)
	case "unsubscribe":
		sm.handleUnsubscribeMessage(client, message)
	case "ping":
		sm.handlePingMessage(client, message)
	default:
		log.Warn().Str("client_id", client.ID).Str("type", msgType).Msg("Unknown message type from client")
	}
}

func (sm *WebSocketStreamManager) handleSubscribeMessage(client *StreamClient, message map[string]interface{}) {
	topics, ok := message["topics"].([]interface{})
	if !ok {
		log.Warn().Str("client_id", client.ID).Msg("Invalid subscribe message format")
		return
	}

	topicStrings := make([]string, 0, len(topics))
	for _, t := range topics {
		if topic, ok := t.(string); ok {
			topicStrings = append(topicStrings, topic)
		}
	}

	if len(topicStrings) > 0 {
		sm.Subscribe(context.Background(), topicStrings, client.ID)
		
		// Send confirmation
		response := StreamEvent{
			Type: "subscription_confirmed",
			Data: map[string]interface{}{
				"topics": topicStrings,
			},
		}
		
		select {
		case client.SendChan <- response:
		default:
		}
	}
}

func (sm *WebSocketStreamManager) handleUnsubscribeMessage(client *StreamClient, message map[string]interface{}) {
	topics, ok := message["topics"].([]interface{})
	if !ok {
		log.Warn().Str("client_id", client.ID).Msg("Invalid unsubscribe message format")
		return
	}

	topicStrings := make([]string, 0, len(topics))
	for _, t := range topics {
		if topic, ok := t.(string); ok {
			topicStrings = append(topicStrings, topic)
		}
	}

	if len(topicStrings) > 0 {
		sm.Unsubscribe(client.ID, topicStrings)
	}
}

func (sm *WebSocketStreamManager) handlePingMessage(client *StreamClient, message map[string]interface{}) {
	response := StreamEvent{
		Type: "pong",
		Data: map[string]interface{}{
			"timestamp": time.Now(),
		},
	}
	
	select {
	case client.SendChan <- response:
	default:
	}
}

func (sm *WebSocketStreamManager) removeClient(clientID string) {
	sm.mutex.Lock()
	defer sm.mutex.Unlock()

	client, exists := sm.clients[clientID]
	if !exists {
		return
	}

	// Remove from topic subscriptions
	for topic := range client.Topics {
		if topicClients, exists := sm.topicClients[topic]; exists {
			delete(topicClients, clientID)
			if len(topicClients) == 0 {
				delete(sm.topicClients, topic)
			}
		}
	}

	// Close client resources
	if client.Connection != nil {
		client.Connection.Close()
	}
	close(client.SendChan)

	delete(sm.clients, clientID)

	log.Info().
		Str("client_id", clientID).
		Int64("messages_sent", client.MessageCount).
		Msg("WebSocket client disconnected")
}

func (sm *WebSocketStreamManager) clientHealthChecker() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-sm.ctx.Done():
			return
		case <-ticker.C:
			sm.checkClientHealth()
		}
	}
}

func (sm *WebSocketStreamManager) checkClientHealth() {
	sm.mutex.RLock()
	clients := make([]*StreamClient, 0, len(sm.clients))
	for _, client := range sm.clients {
		clients = append(clients, client)
	}
	sm.mutex.RUnlock()

	for _, client := range clients {
		client.mutex.RLock()
		lastSeen := client.LastSeen
		client.mutex.RUnlock()

		if time.Since(lastSeen) > 5*time.Minute {
			log.Warn().
				Str("client_id", client.ID).
				Time("last_seen", lastSeen).
				Msg("Removing inactive client")
			
			sm.removeClient(client.ID)
		}
	}
}

func (sm *WebSocketStreamManager) healthMonitor() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-sm.ctx.Done():
			return
		case <-ticker.C:
			sm.publishHealthEvent()
		}
	}
}

func (sm *WebSocketStreamManager) publishHealthEvent() {
	health := SystemHealthEvent{
		CPUUsage:     getCPUUsage(),
		MemoryUsage:  getMemoryUsage(),
		ActiveScans:  getActiveScansCount(),
		QueueSizes:   getQueueSizes(),
		PluginStatus: getPluginStatuses(),
		Timestamp:    time.Now(),
	}

	event := StreamEvent{
		Type: EventTypeSystemHealth,
		Data: health,
	}

	sm.Publish("system.health", event)
}

func (sm *WebSocketStreamManager) eventDistributor() {
	// This would integrate with other system components
	// For now, it's a placeholder for event distribution logic
	for {
		select {
		case <-sm.ctx.Done():
			return
		case <-time.After(1 * time.Second):
			// Process any queued events
		}
	}
}

// Convenience methods for publishing specific event types

func (sm *WebSocketStreamManager) PublishScanProgress(scanID string, progress ScanProgressEvent) error {
	event := StreamEvent{
		Type: EventTypeScanProgress,
		Data: progress,
		Metadata: map[string]interface{}{
			"scan_id": scanID,
		},
	}
	return sm.Publish(fmt.Sprintf("scan.%s.progress", scanID), event)
}

func (sm *WebSocketStreamManager) PublishNewFinding(scanID string, finding models.Finding) error {
	event := StreamEvent{
		Type: EventTypeFindingNew,
		Data: FindingEvent{
			ScanID:  scanID,
			Finding: finding,
		},
		Metadata: map[string]interface{}{
			"scan_id":  scanID,
			"severity": finding.Severity,
			"plugin":   finding.Plugin,
		},
	}
	return sm.Publish(fmt.Sprintf("scan.%s.findings", scanID), event)
}

func (sm *WebSocketStreamManager) PublishAlert(alertType, message string, severity string) error {
	event := StreamEvent{
		Type: EventTypeAlert,
		Data: map[string]interface{}{
			"alert_type": alertType,
			"message":    message,
			"severity":   severity,
		},
	}
	return sm.Publish("system.alerts", event)
}

// Utility functions (placeholders for actual implementations)

func generateEventID() string {
	return fmt.Sprintf("event-%d", time.Now().UnixNano())
}

func getCPUUsage() float64 {
	// Implementation would collect actual CPU metrics
	return 0.0
}

func getMemoryUsage() int64 {
	// Implementation would collect actual memory metrics
	return 0
}

func getActiveScansCount() int {
	// Implementation would count active scans
	return 0
}

func getQueueSizes() map[string]int {
	// Implementation would collect queue metrics
	return map[string]int{
		"plugin_queue": 0,
		"result_queue": 0,
	}
}

func getPluginStatuses() map[string]string {
	// Implementation would collect plugin statuses
	return map[string]string{
		"gau":        "active",
		"cloud_enum": "active",
	}
}
package streaming

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/f2u0a0d3/GoRecon/pkg/config"
	"github.com/rs/zerolog/log"
)

type StreamingServer struct {
	config        *config.Config
	streamManager *WebSocketStreamManager
	httpServer    *http.Server
	router        *gin.Engine
}

func NewStreamingServer(cfg *config.Config, streamManager *WebSocketStreamManager) *StreamingServer {
	gin.SetMode(gin.ReleaseMode)
	router := gin.New()
	router.Use(gin.Recovery())
	
	return &StreamingServer{
		config:        cfg,
		streamManager: streamManager,
		router:        router,
	}
}

func (s *StreamingServer) Start(ctx context.Context) error {
	s.setupRoutes()
	
	port := ":8082" // Default streaming port
	if s.config.API.Streaming.Port != "" {
		port = ":" + s.config.API.Streaming.Port
	}
	
	s.httpServer = &http.Server{
		Addr:         port,
		Handler:      s.router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	
	log.Info().
		Str("port", port).
		Msg("Starting streaming server")
	
	// Start stream manager
	if err := s.streamManager.Start(); err != nil {
		return err
	}
	
	// Handle graceful shutdown
	go func() {
		<-ctx.Done()
		s.Stop()
	}()
	
	if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	
	return nil
}

func (s *StreamingServer) Stop() error {
	log.Info().Msg("Shutting down streaming server")
	
	// Close stream manager
	if err := s.streamManager.Close(); err != nil {
		log.Error().Err(err).Msg("Error closing stream manager")
	}
	
	// Shutdown HTTP server
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	return s.httpServer.Shutdown(ctx)
}

func (s *StreamingServer) setupRoutes() {
	// Health check
	s.router.GET("/health", s.healthCheck)
	
	// WebSocket endpoints
	s.router.GET("/ws", s.handleWebSocketConnection)
	s.router.GET("/ws/:client_id", s.handleWebSocketConnectionWithID)
	
	// REST endpoints for streaming management
	api := s.router.Group("/api/v1/streaming")
	{
		api.GET("/clients", s.getClients)
		api.GET("/subscriptions", s.getSubscriptions)
		api.POST("/publish", s.publishEvent)
		api.GET("/topics", s.getTopics)
		api.GET("/stats", s.getStreamingStats)
	}
	
	// Server-Sent Events endpoints
	sse := s.router.Group("/sse")
	{
		sse.GET("/events", s.handleSSE)
		sse.GET("/scan/:scan_id", s.handleScanSSE)
	}
}

func (s *StreamingServer) healthCheck(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"status":     "healthy",
		"timestamp":  time.Now(),
		"clients":    s.streamManager.GetClientCount(),
	})
}

func (s *StreamingServer) handleWebSocketConnection(c *gin.Context) {
	clientID := generateClientID()
	s.streamManager.HandleWebSocket(c.Writer, c.Request, clientID)
}

func (s *StreamingServer) handleWebSocketConnectionWithID(c *gin.Context) {
	clientID := c.Param("client_id")
	if clientID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "client_id required"})
		return
	}
	
	s.streamManager.HandleWebSocket(c.Writer, c.Request, clientID)
}

func (s *StreamingServer) getClients(c *gin.Context) {
	subscriptions := s.streamManager.GetActiveSubscriptions()
	
	clients := make([]map[string]interface{}, 0, len(subscriptions))
	for clientID, topics := range subscriptions {
		clients = append(clients, map[string]interface{}{
			"id":     clientID,
			"topics": topics,
		})
	}
	
	c.JSON(http.StatusOK, gin.H{
		"clients": clients,
		"total":   len(clients),
	})
}

func (s *StreamingServer) getSubscriptions(c *gin.Context) {
	subscriptions := s.streamManager.GetActiveSubscriptions()
	c.JSON(http.StatusOK, gin.H{
		"subscriptions": subscriptions,
		"total_clients": len(subscriptions),
	})
}

func (s *StreamingServer) publishEvent(c *gin.Context) {
	var req struct {
		Topic string      `json:"topic" binding:"required"`
		Type  string      `json:"type" binding:"required"`
		Data  interface{} `json:"data" binding:"required"`
	}
	
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	
	event := StreamEvent{
		Type: StreamEventType(req.Type),
		Data: req.Data,
	}
	
	if err := s.streamManager.Publish(req.Topic, event); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	
	c.JSON(http.StatusOK, gin.H{
		"message": "Event published successfully",
		"topic":   req.Topic,
		"type":    req.Type,
	})
}

func (s *StreamingServer) getTopics(c *gin.Context) {
	subscriptions := s.streamManager.GetActiveSubscriptions()
	
	topicCounts := make(map[string]int)
	for _, topics := range subscriptions {
		for _, topic := range topics {
			topicCounts[topic]++
		}
	}
	
	c.JSON(http.StatusOK, gin.H{
		"topics": topicCounts,
		"total":  len(topicCounts),
	})
}

func (s *StreamingServer) getStreamingStats(c *gin.Context) {
	subscriptions := s.streamManager.GetActiveSubscriptions()
	
	// Calculate statistics
	totalClients := len(subscriptions)
	totalSubscriptions := 0
	topicCounts := make(map[string]int)
	
	for _, topics := range subscriptions {
		totalSubscriptions += len(topics)
		for _, topic := range topics {
			topicCounts[topic]++
		}
	}
	
	stats := gin.H{
		"total_clients":       totalClients,
		"total_subscriptions": totalSubscriptions,
		"unique_topics":       len(topicCounts),
		"topic_distribution":  topicCounts,
		"timestamp":          time.Now(),
	}
	
	c.JSON(http.StatusOK, stats)
}

// Server-Sent Events handlers

func (s *StreamingServer) handleSSE(c *gin.Context) {
	clientID := generateClientID()
	
	// Set SSE headers
	c.Header("Content-Type", "text/event-stream")
	c.Header("Cache-Control", "no-cache")
	c.Header("Connection", "keep-alive")
	c.Header("Access-Control-Allow-Origin", "*")
	
	// Get topics from query parameters
	topics := c.QueryArray("topics")
	if len(topics) == 0 {
		topics = []string{"system.health", "system.alerts"}
	}
	
	// Subscribe to events
	eventChan, err := s.streamManager.Subscribe(c.Request.Context(), topics, clientID)
	if err != nil {
		c.String(http.StatusInternalServerError, "data: {\"error\": \"%s\"}\n\n", err.Error())
		return
	}
	
	// Send initial connection message
	c.String(http.StatusOK, "data: {\"type\": \"connected\", \"client_id\": \"%s\", \"topics\": %v}\n\n", clientID, topics)
	c.Writer.Flush()
	
	// Stream events
	for {
		select {
		case <-c.Request.Context().Done():
			s.streamManager.Unsubscribe(clientID, topics)
			return
		case event, ok := <-eventChan:
			if !ok {
				return
			}
			
			eventJSON, err := json.Marshal(event)
			if err != nil {
				continue
			}
			
			c.String(http.StatusOK, "data: %s\n\n", string(eventJSON))
			c.Writer.Flush()
		}
	}
}

func (s *StreamingServer) handleScanSSE(c *gin.Context) {
	scanID := c.Param("scan_id")
	if scanID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "scan_id required"})
		return
	}
	
	clientID := generateClientID()
	
	// Set SSE headers
	c.Header("Content-Type", "text/event-stream")
	c.Header("Cache-Control", "no-cache")
	c.Header("Connection", "keep-alive")
	c.Header("Access-Control-Allow-Origin", "*")
	
	// Subscribe to scan-specific topics
	topics := []string{
		fmt.Sprintf("scan.%s.progress", scanID),
		fmt.Sprintf("scan.%s.findings", scanID),
		fmt.Sprintf("scan.%s.status", scanID),
	}
	
	eventChan, err := s.streamManager.Subscribe(c.Request.Context(), topics, clientID)
	if err != nil {
		c.String(http.StatusInternalServerError, "data: {\"error\": \"%s\"}\n\n", err.Error())
		return
	}
	
	// Send initial connection message
	c.String(http.StatusOK, "data: {\"type\": \"connected\", \"scan_id\": \"%s\"}\n\n", scanID)
	c.Writer.Flush()
	
	// Stream scan events
	for {
		select {
		case <-c.Request.Context().Done():
			s.streamManager.Unsubscribe(clientID, topics)
			return
		case event, ok := <-eventChan:
			if !ok {
				return
			}
			
			eventJSON, err := json.Marshal(event)
			if err != nil {
				continue
			}
			
			c.String(http.StatusOK, "data: %s\n\n", string(eventJSON))
			c.Writer.Flush()
		}
	}
}

func generateClientID() string {
	return fmt.Sprintf("client-%d", time.Now().UnixNano())
}
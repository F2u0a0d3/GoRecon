package rest

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/f2u0a0d3/GoRecon/pkg/config"
	"github.com/f2u0a0d3/GoRecon/pkg/core"
	"github.com/f2u0a0d3/GoRecon/pkg/intelligence"
	"github.com/rs/zerolog/log"
)

type Server struct {
	config      *config.Config
	engine      *gin.Engine
	manager     *core.PluginManager
	correlator  *intelligence.IntelligenceCorrelator
	httpServer  *http.Server
}

type APIResponse struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Error   string      `json:"error,omitempty"`
	Meta    *Meta       `json:"meta,omitempty"`
}

type Meta struct {
	Page       int `json:"page,omitempty"`
	Limit      int `json:"limit,omitempty"`
	Total      int `json:"total,omitempty"`
	TotalPages int `json:"total_pages,omitempty"`
}

func NewServer(cfg *config.Config, manager *core.PluginManager, correlator *intelligence.IntelligenceCorrelator) *Server {
	gin.SetMode(gin.ReleaseMode)
	
	server := &Server{
		config:     cfg,
		engine:     gin.New(),
		manager:    manager,
		correlator: correlator,
	}

	server.setupMiddleware()
	server.setupRoutes()

	return server
}

func (s *Server) setupMiddleware() {
	// Recovery middleware
	s.engine.Use(gin.Recovery())
	
	// Custom logger middleware
	s.engine.Use(gin.LoggerWithFormatter(func(param gin.LogFormatterParams) string {
		log.Info().
			Str("method", param.Method).
			Str("path", param.Path).
			Int("status", param.StatusCode).
			Dur("latency", param.Latency).
			Str("ip", param.ClientIP).
			Str("user_agent", param.Request.UserAgent()).
			Msg("API request")
		return ""
	}))

	// CORS middleware
	s.engine.Use(func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Content-Type, Authorization")
		
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		
		c.Next()
	})

	// Rate limiting middleware (basic implementation)
	s.engine.Use(func(c *gin.Context) {
		// TODO: Implement proper rate limiting
		c.Next()
	})

	// Authentication middleware for protected routes
	s.engine.Use(func(c *gin.Context) {
		// Skip auth for health check and public endpoints
		if c.Request.URL.Path == "/api/v1/health" || 
		   c.Request.URL.Path == "/api/v1/version" {
			c.Next()
			return
		}
		
		// TODO: Implement JWT authentication
		c.Next()
	})
}

func (s *Server) setupRoutes() {
	v1 := s.engine.Group("/api/v1")
	
	// Health and status
	v1.GET("/health", s.healthCheck)
	v1.GET("/version", s.getVersion)
	v1.GET("/stats", s.getStats)

	// Scans
	scans := v1.Group("/scans")
	{
		scans.POST("", s.createScan)
		scans.GET("", s.listScans)
		scans.GET("/:id", s.getScan)
		scans.DELETE("/:id", s.deleteScan)
		scans.POST("/:id/stop", s.stopScan)
		scans.GET("/:id/status", s.getScanStatus)
		scans.GET("/:id/results", s.getScanResults)
	}

	// Plugins
	plugins := v1.Group("/plugins")
	{
		plugins.GET("", s.listPlugins)
		plugins.GET("/:id", s.getPlugin)
		plugins.POST("/:id/validate", s.validatePlugin)
		plugins.POST("/:id/execute", s.executePlugin)
	}

	// Intelligence
	intel := v1.Group("/intelligence")
	{
		intel.POST("/correlate", s.correlateFindings)
		intel.GET("/correlations/:id", s.getCorrelation)
		intel.POST("/analyze", s.analyzeResults)
		intel.GET("/attack-paths/:scan_id", s.getAttackPaths)
		intel.GET("/risk-assessment/:scan_id", s.getRiskAssessment)
	}

	// Reports
	reports := v1.Group("/reports")
	{
		reports.POST("/generate", s.generateReport)
		reports.GET("/:id", s.getReport)
		reports.GET("/:id/download", s.downloadReport)
		reports.GET("", s.listReports)
	}

	// Real-time endpoints
	realtime := v1.Group("/realtime")
	{
		realtime.GET("/stream/:scan_id", s.streamScanProgress)
		realtime.GET("/events", s.getEventStream)
	}
}

func (s *Server) Start(ctx context.Context) error {
	s.httpServer = &http.Server{
		Addr:         s.config.Server.Host + ":" + s.config.Server.Port,
		Handler:      s.engine,
		ReadTimeout:  s.config.Server.Timeout,
		WriteTimeout: s.config.Server.Timeout,
		IdleTimeout:  60 * time.Second,
	}

	log.Info().
		Str("host", s.config.Server.Host).
		Str("port", s.config.Server.Port).
		Msg("Starting REST API server")

	go func() {
		<-ctx.Done()
		s.Stop()
	}()

	if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}

	return nil
}

func (s *Server) Stop() error {
	log.Info().Msg("Shutting down REST API server")
	
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	return s.httpServer.Shutdown(ctx)
}

// Utility functions
func (s *Server) successResponse(data interface{}) APIResponse {
	return APIResponse{
		Success: true,
		Data:    data,
	}
}

func (s *Server) errorResponse(err string) APIResponse {
	return APIResponse{
		Success: false,
		Error:   err,
	}
}

func (s *Server) paginatedResponse(data interface{}, page, limit, total int) APIResponse {
	totalPages := (total + limit - 1) / limit
	
	return APIResponse{
		Success: true,
		Data:    data,
		Meta: &Meta{
			Page:       page,
			Limit:      limit,
			Total:      total,
			TotalPages: totalPages,
		},
	}
}
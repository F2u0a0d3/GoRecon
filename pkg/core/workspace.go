package core

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
	
	"github.com/f2u0a0d3/GoRecon/pkg/models"
)

// WorkspaceManager manages scan workspaces and file organization
type WorkspaceManager struct {
	basePath    string
	workspaces  map[string]*Workspace
	mutex       sync.RWMutex
}

// Workspace represents a scan workspace with organized file structure
type Workspace struct {
	ID          string                 `json:"id"`
	Target      string                 `json:"target"`
	BasePath    string                 `json:"base_path"`
	ScanID      string                 `json:"scan_id"`
	CreatedAt   time.Time              `json:"created_at"`
	Directories map[string]string      `json:"directories"`
	Files       map[string][]string    `json:"files"`
	Metadata    map[string]interface{} `json:"metadata"`
	mutex       sync.RWMutex
}

// Queue represents a thread-safe queue for sharing artifacts between plugins
type Queue struct {
	name     string
	items    []QueueItem
	maxSize  int
	mutex    sync.RWMutex
	notEmpty chan struct{}
	notFull  chan struct{}
}

// QueueItem represents an item in a queue
type QueueItem struct {
	ID        string                 `json:"id"`
	Type      string                 `json:"type"`
	Data      interface{}            `json:"data"`
	Source    string                 `json:"source"`
	Timestamp time.Time              `json:"timestamp"`
	Metadata  map[string]interface{} `json:"metadata"`
	Priority  int                    `json:"priority"`
}

// NewWorkspaceManager creates a new workspace manager
func NewWorkspaceManager(basePath string) *WorkspaceManager {
	return &WorkspaceManager{
		basePath:   basePath,
		workspaces: make(map[string]*Workspace),
	}
}

// CreateWorkspace creates a new workspace for a target
func (wm *WorkspaceManager) CreateWorkspace(target string, scanID string) (*Workspace, error) {
	wm.mutex.Lock()
	defer wm.mutex.Unlock()
	
	workspaceID := fmt.Sprintf("%s-%s", target, scanID)
	
	// Check if workspace already exists
	if ws, exists := wm.workspaces[workspaceID]; exists {
		return ws, nil
	}
	
	// Create workspace structure
	workspace := &Workspace{
		ID:          workspaceID,
		Target:      target,
		BasePath:    filepath.Join(wm.basePath, target, scanID),
		ScanID:      scanID,
		CreatedAt:   time.Now(),
		Directories: make(map[string]string),
		Files:       make(map[string][]string),
		Metadata:    make(map[string]interface{}),
	}
	
	// Define directory structure
	directories := map[string]string{
		"http_requests":   "http/requests",
		"http_responses":  "http/responses",
		"javascript":      "js",
		"urls":           "urls",
		"endpoints":      "endpoints",
		"vulnerabilities": "vulns",
		"secrets":        "secrets",
		"screenshots":    "screenshots",
		"reports":        "reports",
		"logs":          "logs",
		"checkpoints":   "checkpoints",
		"raw_output":    "raw",
		"processed":     "processed",
		"artifacts":     "artifacts",
		"tools":         "tools",
	}
	
	// Create directories
	for name, relPath := range directories {
		fullPath := filepath.Join(workspace.BasePath, relPath)
		workspace.Directories[name] = fullPath
		
		if err := os.MkdirAll(fullPath, 0755); err != nil {
			return nil, fmt.Errorf("failed to create directory %s: %w", fullPath, err)
		}
	}
	
	// Initialize file tracking
	for name := range directories {
		workspace.Files[name] = make([]string, 0)
	}
	
	// Store workspace
	wm.workspaces[workspaceID] = workspace
	
	return workspace, nil
}

// GetWorkspace returns an existing workspace
func (wm *WorkspaceManager) GetWorkspace(workspaceID string) (*Workspace, bool) {
	wm.mutex.RLock()
	defer wm.mutex.RUnlock()
	
	ws, exists := wm.workspaces[workspaceID]
	return ws, exists
}

// ListWorkspaces returns all workspaces
func (wm *WorkspaceManager) ListWorkspaces() []*Workspace {
	wm.mutex.RLock()
	defer wm.mutex.RUnlock()
	
	workspaces := make([]*Workspace, 0, len(wm.workspaces))
	for _, ws := range wm.workspaces {
		workspaces = append(workspaces, ws)
	}
	
	return workspaces
}

// Workspace methods

// GetDirectory returns the full path for a directory type
func (w *Workspace) GetDirectory(dirType string) (string, error) {
	w.mutex.RLock()
	defer w.mutex.RUnlock()
	
	dir, exists := w.Directories[dirType]
	if !exists {
		return "", fmt.Errorf("directory type %s not found", dirType)
	}
	
	return dir, nil
}

// SaveFile saves content to a file in the workspace
func (w *Workspace) SaveFile(dirType, filename string, content []byte) error {
	w.mutex.Lock()
	defer w.mutex.Unlock()
	
	dir, exists := w.Directories[dirType]
	if !exists {
		return fmt.Errorf("directory type %s not found", dirType)
	}
	
	filePath := filepath.Join(dir, filename)
	
	if err := os.WriteFile(filePath, content, 0644); err != nil {
		return fmt.Errorf("failed to write file %s: %w", filePath, err)
	}
	
	// Track the file
	w.Files[dirType] = append(w.Files[dirType], filename)
	
	return nil
}

// ReadFile reads content from a file in the workspace
func (w *Workspace) ReadFile(dirType, filename string) ([]byte, error) {
	dir, exists := w.Directories[dirType]
	if !exists {
		return nil, fmt.Errorf("directory type %s not found", dirType)
	}
	
	filePath := filepath.Join(dir, filename)
	
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %w", filePath, err)
	}
	
	return content, nil
}

// ListFiles returns all files in a directory type
func (w *Workspace) ListFiles(dirType string) ([]string, error) {
	w.mutex.RLock()
	defer w.mutex.RUnlock()
	
	files, exists := w.Files[dirType]
	if !exists {
		return nil, fmt.Errorf("directory type %s not found", dirType)
	}
	
	return files, nil
}

// SaveResult saves a plugin result to the workspace
func (w *Workspace) SaveResult(result models.PluginResult) error {
	// Determine file name based on result
	filename := fmt.Sprintf("%s-%s-%s.json", result.Plugin, result.Category, result.ID)
	
	// Marshal result to JSON
	content, err := marshalJSON(result)
	if err != nil {
		return fmt.Errorf("failed to marshal result: %w", err)
	}
	
	// Save to appropriate directory based on category
	dirType := "processed"
	if result.Category == "vuln" {
		dirType = "vulnerabilities"
	} else if result.Category == "js" {
		dirType = "javascript"
	}
	
	return w.SaveFile(dirType, filename, content)
}

// GetMetadata returns workspace metadata
func (w *Workspace) GetMetadata(key string) (interface{}, bool) {
	w.mutex.RLock()
	defer w.mutex.RUnlock()
	
	value, exists := w.Metadata[key]
	return value, exists
}

// SetMetadata sets workspace metadata
func (w *Workspace) SetMetadata(key string, value interface{}) {
	w.mutex.Lock()
	defer w.mutex.Unlock()
	
	w.Metadata[key] = value
}

// GetStats returns workspace statistics
func (w *Workspace) GetStats() WorkspaceStats {
	w.mutex.RLock()
	defer w.mutex.RUnlock()
	
	stats := WorkspaceStats{
		TotalFiles:    0,
		TotalSize:     0,
		DirectoryCount: len(w.Directories),
		CreatedAt:     w.CreatedAt,
		LastModified:  time.Now(),
	}
	
	// Calculate file counts and sizes
	for dirType, files := range w.Files {
		stats.TotalFiles += len(files)
		stats.FilesByType[dirType] = len(files)
		
		// Calculate directory size (simplified)
		if dir, exists := w.Directories[dirType]; exists {
			if info, err := os.Stat(dir); err == nil {
				stats.TotalSize += info.Size()
			}
		}
	}
	
	return stats
}

// WorkspaceStats represents workspace statistics
type WorkspaceStats struct {
	TotalFiles     int               `json:"total_files"`
	TotalSize      int64             `json:"total_size"`
	DirectoryCount int               `json:"directory_count"`
	FilesByType    map[string]int    `json:"files_by_type"`
	CreatedAt      time.Time         `json:"created_at"`
	LastModified   time.Time         `json:"last_modified"`
}

// Queue implementation

// NewQueue creates a new queue
func NewQueue(name string) *Queue {
	return &Queue{
		name:     name,
		items:    make([]QueueItem, 0),
		maxSize:  10000, // Default max size
		notEmpty: make(chan struct{}, 1),
		notFull:  make(chan struct{}, 1),
	}
}

// Push adds an item to the queue
func (q *Queue) Push(item QueueItem) error {
	q.mutex.Lock()
	defer q.mutex.Unlock()
	
	// Check if queue is full
	if len(q.items) >= q.maxSize {
		return fmt.Errorf("queue %s is full", q.name)
	}
	
	// Add timestamp if not set
	if item.Timestamp.IsZero() {
		item.Timestamp = time.Now()
	}
	
	// Insert based on priority (higher priority first)
	inserted := false
	for i, existing := range q.items {
		if item.Priority > existing.Priority {
			// Insert at position i
			q.items = append(q.items[:i], append([]QueueItem{item}, q.items[i:]...)...)
			inserted = true
			break
		}
	}
	
	if !inserted {
		q.items = append(q.items, item)
	}
	
	// Signal that queue is not empty
	select {
	case q.notEmpty <- struct{}{}:
	default:
	}
	
	return nil
}

// Pop removes and returns an item from the queue
func (q *Queue) Pop() (QueueItem, error) {
	q.mutex.Lock()
	defer q.mutex.Unlock()
	
	if len(q.items) == 0 {
		return QueueItem{}, fmt.Errorf("queue %s is empty", q.name)
	}
	
	// Get first item (highest priority)
	item := q.items[0]
	q.items = q.items[1:]
	
	// Signal that queue is not full
	select {
	case q.notFull <- struct{}{}:
	default:
	}
	
	return item, nil
}

// Peek returns the next item without removing it
func (q *Queue) Peek() (QueueItem, error) {
	q.mutex.RLock()
	defer q.mutex.RUnlock()
	
	if len(q.items) == 0 {
		return QueueItem{}, fmt.Errorf("queue %s is empty", q.name)
	}
	
	return q.items[0], nil
}

// Size returns the current queue size
func (q *Queue) Size() int {
	q.mutex.RLock()
	defer q.mutex.RUnlock()
	
	return len(q.items)
}

// IsEmpty returns true if the queue is empty
func (q *Queue) IsEmpty() bool {
	return q.Size() == 0
}

// IsFull returns true if the queue is full
func (q *Queue) IsFull() bool {
	q.mutex.RLock()
	defer q.mutex.RUnlock()
	
	return len(q.items) >= q.maxSize
}

// Clear removes all items from the queue
func (q *Queue) Clear() {
	q.mutex.Lock()
	defer q.mutex.Unlock()
	
	q.items = make([]QueueItem, 0)
}

// GetItems returns a copy of all items in the queue
func (q *Queue) GetItems() []QueueItem {
	q.mutex.RLock()
	defer q.mutex.RUnlock()
	
	items := make([]QueueItem, len(q.items))
	copy(items, q.items)
	
	return items
}

// FilterByType returns items of a specific type
func (q *Queue) FilterByType(itemType string) []QueueItem {
	q.mutex.RLock()
	defer q.mutex.RUnlock()
	
	var filtered []QueueItem
	for _, item := range q.items {
		if item.Type == itemType {
			filtered = append(filtered, item)
		}
	}
	
	return filtered
}

// QueueManager manages multiple queues
type QueueManager struct {
	queues map[string]*Queue
	mutex  sync.RWMutex
}

// NewQueueManager creates a new queue manager
func NewQueueManager() *QueueManager {
	return &QueueManager{
		queues: make(map[string]*Queue),
	}
}

// CreateQueue creates a new queue
func (qm *QueueManager) CreateQueue(name string) *Queue {
	qm.mutex.Lock()
	defer qm.mutex.Unlock()
	
	if queue, exists := qm.queues[name]; exists {
		return queue
	}
	
	queue := NewQueue(name)
	qm.queues[name] = queue
	
	return queue
}

// GetQueue returns an existing queue
func (qm *QueueManager) GetQueue(name string) (*Queue, bool) {
	qm.mutex.RLock()
	defer qm.mutex.RUnlock()
	
	queue, exists := qm.queues[name]
	return queue, exists
}

// GetOrCreateQueue returns an existing queue or creates a new one
func (qm *QueueManager) GetOrCreateQueue(name string) *Queue {
	if queue, exists := qm.GetQueue(name); exists {
		return queue
	}
	
	return qm.CreateQueue(name)
}

// ListQueues returns all queue names
func (qm *QueueManager) ListQueues() []string {
	qm.mutex.RLock()
	defer qm.mutex.RUnlock()
	
	names := make([]string, 0, len(qm.queues))
	for name := range qm.queues {
		names = append(names, name)
	}
	
	return names
}

// GetQueueStats returns statistics for all queues
func (qm *QueueManager) GetQueueStats() map[string]QueueStats {
	qm.mutex.RLock()
	defer qm.mutex.RUnlock()
	
	stats := make(map[string]QueueStats)
	for name, queue := range qm.queues {
		stats[name] = QueueStats{
			Name:     name,
			Size:     queue.Size(),
			IsFull:   queue.IsFull(),
			IsEmpty:  queue.IsEmpty(),
			MaxSize:  queue.maxSize,
		}
	}
	
	return stats
}

// QueueStats represents queue statistics
type QueueStats struct {
	Name     string `json:"name"`
	Size     int    `json:"size"`
	IsFull   bool   `json:"is_full"`
	IsEmpty  bool   `json:"is_empty"`
	MaxSize  int    `json:"max_size"`
}

// Helper functions

func marshalJSON(v interface{}) ([]byte, error) {
	// This would use json.Marshal in a real implementation
	// For now, return a placeholder
	return []byte("{}"), nil
}
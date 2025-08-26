package security

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"
)

// RBAC (Role-Based Access Control) system for GoRecon
type RBAC struct {
	users       map[string]*User
	roles       map[string]*Role
	permissions map[string]*Permission
	sessions    map[string]*Session
	config      RBACConfig
	mutex       sync.RWMutex
}

// RBACConfig configures the RBAC system
type RBACConfig struct {
	SessionTimeout    time.Duration `json:"session_timeout"`
	MaxSessions       int           `json:"max_sessions"`
	PasswordMinLength int           `json:"password_min_length"`
	RequireMFA        bool          `json:"require_mfa"`
	AuditLog          bool          `json:"audit_log"`
	DefaultRole       string        `json:"default_role"`
}

// User represents a system user
type User struct {
	ID           string            `json:"id"`
	Username     string            `json:"username"`
	Email        string            `json:"email"`
	PasswordHash string            `json:"password_hash"`
	Salt         string            `json:"salt"`
	Roles        []string          `json:"roles"`
	Metadata     map[string]string `json:"metadata"`
	CreatedAt    time.Time         `json:"created_at"`
	LastLogin    *time.Time        `json:"last_login,omitempty"`
	Disabled     bool              `json:"disabled"`
	MFAEnabled   bool              `json:"mfa_enabled"`
	MFASecret    string            `json:"mfa_secret,omitempty"`
}

// Role represents a collection of permissions
type Role struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Permissions []string `json:"permissions"`
	CreatedAt   time.Time `json:"created_at"`
}

// Permission represents a specific access right
type Permission struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description"`
	Resource    string `json:"resource"`
	Action      string `json:"action"`
}

// Session represents an active user session
type Session struct {
	ID        string    `json:"id"`
	UserID    string    `json:"user_id"`
	Username  string    `json:"username"`
	CreatedAt time.Time `json:"created_at"`
	LastSeen  time.Time `json:"last_seen"`
	IPAddress string    `json:"ip_address"`
	UserAgent string    `json:"user_agent"`
	Metadata  map[string]string `json:"metadata"`
}

// AuditEntry represents an audit log entry
type AuditEntry struct {
	ID        string                 `json:"id"`
	UserID    string                 `json:"user_id"`
	Username  string                 `json:"username"`
	Action    string                 `json:"action"`
	Resource  string                 `json:"resource"`
	Result    string                 `json:"result"` // success, failure, denied
	Details   map[string]interface{} `json:"details"`
	Timestamp time.Time              `json:"timestamp"`
	IPAddress string                 `json:"ip_address"`
}

// NewRBAC creates a new RBAC system
func NewRBAC(config RBACConfig) *RBAC {
	// Set defaults
	if config.SessionTimeout == 0 {
		config.SessionTimeout = 24 * time.Hour
	}
	if config.MaxSessions == 0 {
		config.MaxSessions = 10
	}
	if config.PasswordMinLength == 0 {
		config.PasswordMinLength = 8
	}
	if config.DefaultRole == "" {
		config.DefaultRole = "viewer"
	}

	rbac := &RBAC{
		users:       make(map[string]*User),
		roles:       make(map[string]*Role),
		permissions: make(map[string]*Permission),
		sessions:    make(map[string]*Session),
		config:      config,
	}

	// Initialize default permissions and roles
	rbac.initializeDefaults()

	// Start session cleanup goroutine
	go rbac.sessionCleanup()

	return rbac
}

// initializeDefaults sets up default permissions and roles
func (r *RBAC) initializeDefaults() {
	// Define default permissions
	defaultPermissions := []*Permission{
		{ID: "scan.create", Name: "Create Scans", Description: "Create new security scans", Resource: "scan", Action: "create"},
		{ID: "scan.read", Name: "View Scans", Description: "View scan results", Resource: "scan", Action: "read"},
		{ID: "scan.update", Name: "Update Scans", Description: "Modify scan configurations", Resource: "scan", Action: "update"},
		{ID: "scan.delete", Name: "Delete Scans", Description: "Delete scans and results", Resource: "scan", Action: "delete"},
		{ID: "plugin.read", Name: "View Plugins", Description: "View available plugins", Resource: "plugin", Action: "read"},
		{ID: "plugin.manage", Name: "Manage Plugins", Description: "Install/remove plugins", Resource: "plugin", Action: "manage"},
		{ID: "report.read", Name: "View Reports", Description: "Access scan reports", Resource: "report", Action: "read"},
		{ID: "report.export", Name: "Export Reports", Description: "Export reports in various formats", Resource: "report", Action: "export"},
		{ID: "config.read", Name: "View Config", Description: "View system configuration", Resource: "config", Action: "read"},
		{ID: "config.write", Name: "Modify Config", Description: "Modify system configuration", Resource: "config", Action: "write"},
		{ID: "user.read", Name: "View Users", Description: "View user accounts", Resource: "user", Action: "read"},
		{ID: "user.manage", Name: "Manage Users", Description: "Create/modify user accounts", Resource: "user", Action: "manage"},
		{ID: "system.admin", Name: "System Admin", Description: "Full system administration", Resource: "system", Action: "admin"},
	}

	for _, perm := range defaultPermissions {
		r.permissions[perm.ID] = perm
	}

	// Define default roles
	defaultRoles := []*Role{
		{
			ID: "viewer", Name: "Viewer", Description: "Read-only access to scans and reports",
			Permissions: []string{"scan.read", "plugin.read", "report.read"},
			CreatedAt:   time.Now(),
		},
		{
			ID: "analyst", Name: "Security Analyst", Description: "Can create scans and access reports",
			Permissions: []string{"scan.create", "scan.read", "scan.update", "plugin.read", "report.read", "report.export"},
			CreatedAt:   time.Now(),
		},
		{
			ID: "operator", Name: "Security Operator", Description: "Can manage scans and plugins",
			Permissions: []string{"scan.create", "scan.read", "scan.update", "scan.delete", "plugin.read", "plugin.manage", "report.read", "report.export", "config.read"},
			CreatedAt:   time.Now(),
		},
		{
			ID: "admin", Name: "Administrator", Description: "Full system access",
			Permissions: []string{"scan.create", "scan.read", "scan.update", "scan.delete", "plugin.read", "plugin.manage", "report.read", "report.export", "config.read", "config.write", "user.read", "user.manage", "system.admin"},
			CreatedAt:   time.Now(),
		},
	}

	for _, role := range defaultRoles {
		r.roles[role.ID] = role
	}
}

// CreateUser creates a new user account
func (r *RBAC) CreateUser(username, email, password string, roles []string) (*User, error) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	// Check if user already exists
	for _, user := range r.users {
		if user.Username == username || user.Email == email {
			return nil, fmt.Errorf("user with username or email already exists")
		}
	}

	// Validate password
	if len(password) < r.config.PasswordMinLength {
		return nil, fmt.Errorf("password must be at least %d characters", r.config.PasswordMinLength)
	}

	// Generate salt and hash password
	salt, err := r.generateSalt()
	if err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}

	passwordHash := r.hashPassword(password, salt)

	// Validate roles
	if len(roles) == 0 {
		roles = []string{r.config.DefaultRole}
	}

	for _, roleID := range roles {
		if _, exists := r.roles[roleID]; !exists {
			return nil, fmt.Errorf("role %s does not exist", roleID)
		}
	}

	// Create user
	userID := r.generateID()
	user := &User{
		ID:           userID,
		Username:     username,
		Email:        email,
		PasswordHash: passwordHash,
		Salt:         salt,
		Roles:        roles,
		Metadata:     make(map[string]string),
		CreatedAt:    time.Now(),
		Disabled:     false,
	}

	r.users[userID] = user

	r.auditLog("user.create", "user", userID, "success", map[string]interface{}{
		"username": username,
		"email":    email,
		"roles":    roles,
	})

	return user, nil
}

// Authenticate verifies user credentials and creates a session
func (r *RBAC) Authenticate(username, password string, metadata map[string]string) (*Session, error) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	// Find user
	var user *User
	for _, u := range r.users {
		if u.Username == username {
			user = u
			break
		}
	}

	if user == nil || user.Disabled {
		r.auditLog("auth.login", "user", "", "failure", map[string]interface{}{
			"username": username,
			"reason":   "user_not_found_or_disabled",
		})
		return nil, fmt.Errorf("authentication failed")
	}

	// Verify password
	if !r.verifyPassword(password, user.Salt, user.PasswordHash) {
		r.auditLog("auth.login", "user", user.ID, "failure", map[string]interface{}{
			"username": username,
			"reason":   "invalid_password",
		})
		return nil, fmt.Errorf("authentication failed")
	}

	// Check MFA if enabled
	if r.config.RequireMFA && !user.MFAEnabled {
		return nil, fmt.Errorf("MFA is required but not enabled for user")
	}

	// Clean up old sessions for this user
	r.cleanupUserSessions(user.ID)

	// Create new session
	sessionID := r.generateSessionID()
	session := &Session{
		ID:        sessionID,
		UserID:    user.ID,
		Username:  user.Username,
		CreatedAt: time.Now(),
		LastSeen:  time.Now(),
		IPAddress: metadata["ip_address"],
		UserAgent: metadata["user_agent"],
		Metadata:  metadata,
	}

	r.sessions[sessionID] = session

	// Update user's last login
	now := time.Now()
	user.LastLogin = &now

	r.auditLog("auth.login", "user", user.ID, "success", map[string]interface{}{
		"username":   username,
		"session_id": sessionID,
		"ip_address": metadata["ip_address"],
	})

	return session, nil
}

// Authorize checks if a user has permission to perform an action
func (r *RBAC) Authorize(sessionID, resource, action string) error {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	// Get session
	session, exists := r.sessions[sessionID]
	if !exists {
		return fmt.Errorf("invalid session")
	}

	// Check session timeout
	if time.Since(session.LastSeen) > r.config.SessionTimeout {
		delete(r.sessions, sessionID)
		return fmt.Errorf("session expired")
	}

	// Update last seen
	session.LastSeen = time.Now()

	// Get user
	user, exists := r.users[session.UserID]
	if !exists || user.Disabled {
		return fmt.Errorf("user not found or disabled")
	}

	// Check permissions
	permissionID := fmt.Sprintf("%s.%s", resource, action)
	if r.hasPermission(user, permissionID) {
		r.auditLog("auth.authorize", resource, session.UserID, "success", map[string]interface{}{
			"permission": permissionID,
			"session_id": sessionID,
		})
		return nil
	}

	r.auditLog("auth.authorize", resource, session.UserID, "denied", map[string]interface{}{
		"permission": permissionID,
		"session_id": sessionID,
	})

	return fmt.Errorf("permission denied")
}

// hasPermission checks if a user has a specific permission
func (r *RBAC) hasPermission(user *User, permissionID string) bool {
	for _, roleID := range user.Roles {
		if role, exists := r.roles[roleID]; exists {
			for _, perm := range role.Permissions {
				if perm == permissionID || perm == "system.admin" {
					return true
				}
			}
		}
	}
	return false
}

// GetSession returns session information
func (r *RBAC) GetSession(sessionID string) (*Session, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	session, exists := r.sessions[sessionID]
	if !exists {
		return nil, fmt.Errorf("session not found")
	}

	// Check if session is expired
	if time.Since(session.LastSeen) > r.config.SessionTimeout {
		delete(r.sessions, sessionID)
		return nil, fmt.Errorf("session expired")
	}

	return session, nil
}

// Logout terminates a user session
func (r *RBAC) Logout(sessionID string) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	session, exists := r.sessions[sessionID]
	if !exists {
		return fmt.Errorf("session not found")
	}

	delete(r.sessions, sessionID)

	r.auditLog("auth.logout", "user", session.UserID, "success", map[string]interface{}{
		"session_id": sessionID,
	})

	return nil
}

// GetUser returns user information
func (r *RBAC) GetUser(userID string) (*User, error) {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	user, exists := r.users[userID]
	if !exists {
		return nil, fmt.Errorf("user not found")
	}

	// Return a copy without sensitive data
	userCopy := *user
	userCopy.PasswordHash = ""
	userCopy.Salt = ""
	userCopy.MFASecret = ""

	return &userCopy, nil
}

// UpdateUser updates user information
func (r *RBAC) UpdateUser(userID string, updates map[string]interface{}) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	user, exists := r.users[userID]
	if !exists {
		return fmt.Errorf("user not found")
	}

	// Apply updates
	for key, value := range updates {
		switch key {
		case "email":
			if email, ok := value.(string); ok {
				user.Email = email
			}
		case "roles":
			if roles, ok := value.([]string); ok {
				// Validate roles
				for _, roleID := range roles {
					if _, exists := r.roles[roleID]; !exists {
						return fmt.Errorf("role %s does not exist", roleID)
					}
				}
				user.Roles = roles
			}
		case "disabled":
			if disabled, ok := value.(bool); ok {
				user.Disabled = disabled
			}
		}
	}

	r.auditLog("user.update", "user", userID, "success", map[string]interface{}{
		"updates": updates,
	})

	return nil
}

// ChangePassword changes a user's password
func (r *RBAC) ChangePassword(userID, oldPassword, newPassword string) error {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	user, exists := r.users[userID]
	if !exists {
		return fmt.Errorf("user not found")
	}

	// Verify old password
	if !r.verifyPassword(oldPassword, user.Salt, user.PasswordHash) {
		r.auditLog("user.password_change", "user", userID, "failure", map[string]interface{}{
			"reason": "invalid_old_password",
		})
		return fmt.Errorf("invalid old password")
	}

	// Validate new password
	if len(newPassword) < r.config.PasswordMinLength {
		return fmt.Errorf("password must be at least %d characters", r.config.PasswordMinLength)
	}

	// Generate new salt and hash
	salt, err := r.generateSalt()
	if err != nil {
		return fmt.Errorf("failed to generate salt: %w", err)
	}

	user.Salt = salt
	user.PasswordHash = r.hashPassword(newPassword, salt)

	r.auditLog("user.password_change", "user", userID, "success", nil)

	return nil
}

// CreateRole creates a new role
func (r *RBAC) CreateRole(name, description string, permissions []string) (*Role, error) {
	r.mutex.Lock()
	defer r.mutex.Unlock()

	// Validate permissions
	for _, permID := range permissions {
		if _, exists := r.permissions[permID]; !exists {
			return nil, fmt.Errorf("permission %s does not exist", permID)
		}
	}

	roleID := strings.ToLower(strings.ReplaceAll(name, " ", "_"))
	
	// Check if role already exists
	if _, exists := r.roles[roleID]; exists {
		return nil, fmt.Errorf("role already exists")
	}

	role := &Role{
		ID:          roleID,
		Name:        name,
		Description: description,
		Permissions: permissions,
		CreatedAt:   time.Now(),
	}

	r.roles[roleID] = role

	r.auditLog("role.create", "role", roleID, "success", map[string]interface{}{
		"name":        name,
		"permissions": permissions,
	})

	return role, nil
}

// GetRoles returns all roles
func (r *RBAC) GetRoles() map[string]*Role {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	// Return a copy
	roles := make(map[string]*Role)
	for k, v := range r.roles {
		roleCopy := *v
		roles[k] = &roleCopy
	}

	return roles
}

// GetPermissions returns all permissions
func (r *RBAC) GetPermissions() map[string]*Permission {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	// Return a copy
	permissions := make(map[string]*Permission)
	for k, v := range r.permissions {
		permCopy := *v
		permissions[k] = &permCopy
	}

	return permissions
}

// Helper methods

func (r *RBAC) generateID() string {
	bytes := make([]byte, 16)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

func (r *RBAC) generateSessionID() string {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

func (r *RBAC) generateSalt() (string, error) {
	bytes := make([]byte, 32)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

func (r *RBAC) hashPassword(password, salt string) string {
	hash := sha256.Sum256([]byte(password + salt))
	return hex.EncodeToString(hash[:])
}

func (r *RBAC) verifyPassword(password, salt, hash string) bool {
	return r.hashPassword(password, salt) == hash
}

func (r *RBAC) cleanupUserSessions(userID string) {
	count := 0
	for sessionID, session := range r.sessions {
		if session.UserID == userID {
			count++
			if count > r.config.MaxSessions {
				delete(r.sessions, sessionID)
			}
		}
	}
}

func (r *RBAC) sessionCleanup() {
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for range ticker.C {
		r.mutex.Lock()
		for sessionID, session := range r.sessions {
			if time.Since(session.LastSeen) > r.config.SessionTimeout {
				delete(r.sessions, sessionID)
			}
		}
		r.mutex.Unlock()
	}
}

func (r *RBAC) auditLog(action, resource, userID, result string, details map[string]interface{}) {
	if !r.config.AuditLog {
		return
	}

	entry := &AuditEntry{
		ID:        r.generateID(),
		UserID:    userID,
		Action:    action,
		Resource:  resource,
		Result:    result,
		Details:   details,
		Timestamp: time.Now(),
	}

	// In a production system, this would write to a persistent audit log
	// For now, we just log to stdout
	fmt.Printf("AUDIT: %+v\n", entry)
}

// GetActiveSessions returns information about active sessions
func (r *RBAC) GetActiveSessions() map[string]*Session {
	r.mutex.RLock()
	defer r.mutex.RUnlock()

	// Return a copy
	sessions := make(map[string]*Session)
	for k, v := range r.sessions {
		sessionCopy := *v
		sessions[k] = &sessionCopy
	}

	return sessions
}
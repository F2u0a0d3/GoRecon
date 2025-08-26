// GoRecon Dashboard - Interactive Features
class DashboardManager {
    constructor() {
        this.wsConnection = null;
        this.retryCount = 0;
        this.maxRetries = 5;
        this.updateInterval = null;
        this.currentTheme = localStorage.getItem('theme') || 'dark';
        
        this.init();
    }

    init() {
        this.setupTheme();
        this.setupWebSocket();
        this.setupEventListeners();
        this.startPeriodicUpdates();
        this.animateOnLoad();
    }

    // Theme Management
    setupTheme() {
        document.body.className = this.currentTheme;
        this.createThemeToggle();
    }

    createThemeToggle() {
        const toggle = document.createElement('div');
        toggle.className = 'theme-toggle';
        toggle.innerHTML = this.currentTheme === 'dark' ? '🌙' : '☀️';
        toggle.title = `Switch to ${this.currentTheme === 'dark' ? 'light' : 'dark'} theme`;
        toggle.addEventListener('click', () => this.toggleTheme());
        document.body.appendChild(toggle);
    }

    toggleTheme() {
        this.currentTheme = this.currentTheme === 'dark' ? 'light' : 'dark';
        document.body.className = this.currentTheme;
        localStorage.setItem('theme', this.currentTheme);
        
        const toggle = document.querySelector('.theme-toggle');
        toggle.innerHTML = this.currentTheme === 'dark' ? '🌙' : '☀️';
        toggle.title = `Switch to ${this.currentTheme === 'dark' ? 'light' : 'dark'} theme`;
    }

    // WebSocket Connection
    setupWebSocket() {
        if (!window.WebSocket) {
            console.warn('WebSocket not supported');
            return;
        }

        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${protocol}//${window.location.host}/ws`;
        
        try {
            this.wsConnection = new WebSocket(wsUrl);
            
            this.wsConnection.onopen = () => {
                console.log('WebSocket connected');
                this.retryCount = 0;
                this.showConnectionStatus('online');
            };

            this.wsConnection.onmessage = (event) => {
                try {
                    const data = JSON.parse(event.data);
                    this.handleWebSocketMessage(data);
                } catch (error) {
                    console.error('Error parsing WebSocket message:', error);
                }
            };

            this.wsConnection.onclose = () => {
                console.log('WebSocket disconnected');
                this.showConnectionStatus('offline');
                this.scheduleReconnect();
            };

            this.wsConnection.onerror = (error) => {
                console.error('WebSocket error:', error);
                this.showConnectionStatus('error');
            };
        } catch (error) {
            console.error('Failed to create WebSocket connection:', error);
        }
    }

    scheduleReconnect() {
        if (this.retryCount < this.maxRetries) {
            const delay = Math.min(1000 * Math.pow(2, this.retryCount), 30000);
            setTimeout(() => {
                this.retryCount++;
                this.setupWebSocket();
            }, delay);
        }
    }

    handleWebSocketMessage(data) {
        switch (data.type) {
            case 'stats_update':
                this.updateStats(data.data);
                break;
            case 'scan_update':
                this.updateScanStatus(data.data);
                break;
            case 'notification':
                this.showNotification(data.data);
                break;
            case 'pong':
                // Handle ping/pong for connection keep-alive
                break;
            default:
                console.log('Unknown message type:', data.type);
        }
    }

    // Stats Updates
    async updateStats(data = null) {
        try {
            if (!data) {
                const response = await fetch('/api/stats');
                if (!response.ok) throw new Error('Failed to fetch stats');
                data = await response.json();
            }

            this.animateStatUpdate('total-scans', data.totalScans || 0);
            this.animateStatUpdate('active-scans', data.activeScans || 0);
            this.animateStatUpdate('plugins-loaded', data.pluginsLoaded || 0);
            this.animateStatUpdate('reports-generated', data.reportsGenerated || 0);

        } catch (error) {
            console.error('Error updating stats:', error);
            this.showError('Failed to update statistics');
        }
    }

    animateStatUpdate(elementId, newValue) {
        const element = document.getElementById(elementId);
        if (!element) return;

        const currentValue = parseInt(element.textContent) || 0;
        if (currentValue === newValue) return;

        // Add loading animation
        element.classList.add('loading');
        
        // Animate number change
        const duration = 1000;
        const start = performance.now();
        const startValue = currentValue;
        const difference = newValue - startValue;

        const animate = (currentTime) => {
            const elapsed = currentTime - start;
            const progress = Math.min(elapsed / duration, 1);
            
            // Easing function
            const easeOut = 1 - Math.pow(1 - progress, 3);
            const value = Math.round(startValue + (difference * easeOut));
            
            element.textContent = value.toLocaleString();
            
            if (progress < 1) {
                requestAnimationFrame(animate);
            } else {
                element.classList.remove('loading');
            }
        };

        requestAnimationFrame(animate);
    }

    // Event Listeners
    setupEventListeners() {
        // Stat card hover effects
        document.querySelectorAll('.stat-card').forEach(card => {
            card.addEventListener('mouseenter', () => {
                card.style.transform = 'translateY(-8px) scale(1.02)';
            });
            
            card.addEventListener('mouseleave', () => {
                card.style.transform = '';
            });
        });

        // Button interactions
        document.querySelectorAll('.btn').forEach(btn => {
            btn.addEventListener('click', (e) => {
                this.createRippleEffect(e, btn);
            });
        });

        // Health check button
        const healthBtn = document.querySelector('a[href="/api/health"]');
        if (healthBtn) {
            healthBtn.addEventListener('click', (e) => {
                e.preventDefault();
                this.performHealthCheck();
            });
        }

        // Keyboard shortcuts
        document.addEventListener('keydown', (e) => {
            if (e.ctrlKey || e.metaKey) {
                switch (e.key) {
                    case 'r':
                        e.preventDefault();
                        this.refreshDashboard();
                        break;
                    case 't':
                        e.preventDefault();
                        this.toggleTheme();
                        break;
                }
            }
        });
    }

    createRippleEffect(event, element) {
        const rect = element.getBoundingClientRect();
        const ripple = document.createElement('span');
        const size = Math.max(rect.width, rect.height);
        const x = event.clientX - rect.left - size / 2;
        const y = event.clientY - rect.top - size / 2;

        ripple.style.cssText = `
            position: absolute;
            width: ${size}px;
            height: ${size}px;
            left: ${x}px;
            top: ${y}px;
            background: rgba(255, 255, 255, 0.3);
            border-radius: 50%;
            transform: scale(0);
            animation: ripple 0.6s ease-out;
            pointer-events: none;
        `;

        element.style.position = 'relative';
        element.style.overflow = 'hidden';
        element.appendChild(ripple);

        // Add animation keyframes if not already added
        if (!document.querySelector('#ripple-style')) {
            const style = document.createElement('style');
            style.id = 'ripple-style';
            style.textContent = `
                @keyframes ripple {
                    to {
                        transform: scale(2);
                        opacity: 0;
                    }
                }
            `;
            document.head.appendChild(style);
        }

        setTimeout(() => ripple.remove(), 600);
    }

    // Periodic Updates
    startPeriodicUpdates() {
        this.updateStats();
        this.updateInterval = setInterval(() => {
            this.updateStats();
            this.sendPing();
        }, 30000);
    }

    sendPing() {
        if (this.wsConnection && this.wsConnection.readyState === WebSocket.OPEN) {
            this.wsConnection.send(JSON.stringify({
                type: 'ping',
                data: { timestamp: Date.now() }
            }));
        }
    }

    // Health Check
    async performHealthCheck() {
        try {
            this.showLoading('Checking system health...');
            
            const response = await fetch('/api/health');
            const data = await response.json();
            
            if (response.ok) {
                this.showNotification({
                    type: 'success',
                    title: 'Health Check',
                    message: `System is ${data.status}`,
                    duration: 3000
                });
            } else {
                throw new Error(data.error || 'Health check failed');
            }
        } catch (error) {
            this.showError(`Health check failed: ${error.message}`);
        } finally {
            this.hideLoading();
        }
    }

    // Dashboard Refresh
    async refreshDashboard() {
        this.showLoading('Refreshing dashboard...');
        
        try {
            await Promise.all([
                this.updateStats(),
                this.updateRecentScans(),
                this.updateRecentReports()
            ]);
            
            this.showNotification({
                type: 'success',
                title: 'Dashboard Refreshed',
                message: 'All data has been updated',
                duration: 2000
            });
        } catch (error) {
            this.showError('Failed to refresh dashboard');
        } finally {
            this.hideLoading();
        }
    }

    async updateRecentScans() {
        try {
            const response = await fetch('/api/scans');
            if (!response.ok) throw new Error('Failed to fetch scans');
            
            const scans = await response.json();
            // Update scan list in UI
            console.log('Updated scans:', scans);
        } catch (error) {
            console.error('Error updating scans:', error);
        }
    }

    async updateRecentReports() {
        try {
            const response = await fetch('/api/reports');
            if (!response.ok) throw new Error('Failed to fetch reports');
            
            const reports = await response.json();
            // Update report list in UI
            console.log('Updated reports:', reports);
        } catch (error) {
            console.error('Error updating reports:', error);
        }
    }

    // UI Helpers
    showConnectionStatus(status) {
        let existing = document.querySelector('.connection-status');
        if (existing) existing.remove();

        const indicator = document.createElement('div');
        indicator.className = 'connection-status';
        indicator.innerHTML = `
            <span class="status-indicator status-${status}"></span>
            ${status === 'online' ? 'Connected' : status === 'offline' ? 'Disconnected' : 'Connection Error'}
        `;
        indicator.style.cssText = `
            position: fixed;
            bottom: 20px;
            right: 20px;
            background: var(--glass-bg);
            backdrop-filter: blur(10px);
            border: 1px solid var(--glass-border);
            border-radius: 25px;
            padding: 8px 16px;
            color: white;
            font-size: 0.9rem;
            z-index: 1000;
            display: flex;
            align-items: center;
            gap: 8px;
        `;

        document.body.appendChild(indicator);
        
        if (status === 'online') {
            setTimeout(() => indicator.remove(), 3000);
        }
    }

    showNotification({ type, title, message, duration = 5000 }) {
        const notification = document.createElement('div');
        notification.className = `notification notification-${type}`;
        notification.innerHTML = `
            <div class="notification-content">
                <strong>${title}</strong>
                <p>${message}</p>
            </div>
            <button class="notification-close">&times;</button>
        `;
        
        notification.style.cssText = `
            position: fixed;
            top: 20px;
            right: 20px;
            background: var(--glass-bg);
            backdrop-filter: blur(10px);
            border: 1px solid var(--glass-border);
            border-radius: 12px;
            padding: 16px;
            color: white;
            max-width: 300px;
            z-index: 1001;
            animation: slideIn 0.3s ease-out;
        `;

        const closeBtn = notification.querySelector('.notification-close');
        closeBtn.addEventListener('click', () => notification.remove());

        document.body.appendChild(notification);
        
        if (duration > 0) {
            setTimeout(() => notification.remove(), duration);
        }
    }

    showError(message) {
        this.showNotification({
            type: 'error',
            title: 'Error',
            message: message,
            duration: 5000
        });
    }

    showLoading(message = 'Loading...') {
        let existing = document.querySelector('.loading-overlay');
        if (existing) return;

        const overlay = document.createElement('div');
        overlay.className = 'loading-overlay';
        overlay.innerHTML = `
            <div class="loading-content">
                <div class="loading"></div>
                <p>${message}</p>
            </div>
        `;
        
        overlay.style.cssText = `
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.5);
            display: flex;
            align-items: center;
            justify-content: center;
            z-index: 1002;
            backdrop-filter: blur(5px);
        `;

        document.body.appendChild(overlay);
    }

    hideLoading() {
        const overlay = document.querySelector('.loading-overlay');
        if (overlay) overlay.remove();
    }

    animateOnLoad() {
        // Animate elements on page load
        const cards = document.querySelectorAll('.stat-card');
        cards.forEach((card, index) => {
            card.style.opacity = '0';
            card.style.transform = 'translateY(30px)';
            
            setTimeout(() => {
                card.style.transition = 'all 0.6s ease-out';
                card.style.opacity = '1';
                card.style.transform = 'translateY(0)';
            }, index * 100);
        });

        // Animate sections
        const sections = document.querySelectorAll('.section');
        sections.forEach((section, index) => {
            section.style.opacity = '0';
            section.style.transform = 'translateY(30px)';
            
            setTimeout(() => {
                section.style.transition = 'all 0.6s ease-out';
                section.style.opacity = '1';
                section.style.transform = 'translateY(0)';
            }, (cards.length * 100) + (index * 150));
        });
    }

    updateScanStatus(scanData) {
        // Update specific scan status in real-time
        console.log('Scan update:', scanData);
    }

    destroy() {
        if (this.updateInterval) {
            clearInterval(this.updateInterval);
        }
        
        if (this.wsConnection) {
            this.wsConnection.close();
        }
    }
}

// Initialize dashboard when DOM is loaded
let dashboardManager;

document.addEventListener('DOMContentLoaded', () => {
    dashboardManager = new DashboardManager();
});

// Cleanup on page unload
window.addEventListener('beforeunload', () => {
    if (dashboardManager) {
        dashboardManager.destroy();
    }
});

// Add slide-in animation styles
const animationStyles = document.createElement('style');
animationStyles.textContent = `
    @keyframes slideIn {
        from {
            transform: translateX(100%);
            opacity: 0;
        }
        to {
            transform: translateX(0);
            opacity: 1;
        }
    }

    .loading-content {
        background: var(--glass-bg);
        backdrop-filter: blur(10px);
        border: 1px solid var(--glass-border);
        border-radius: 12px;
        padding: 30px;
        text-align: center;
        color: white;
    }

    .loading-content p {
        margin-top: 15px;
        font-size: 1.1rem;
    }

    .notification-content strong {
        display: block;
        margin-bottom: 5px;
        font-size: 1.1rem;
    }

    .notification-close {
        position: absolute;
        top: 8px;
        right: 12px;
        background: none;
        border: none;
        color: white;
        font-size: 1.5rem;
        cursor: pointer;
        line-height: 1;
    }
`;

document.head.appendChild(animationStyles);
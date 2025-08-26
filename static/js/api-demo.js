// Interactive API Demo Functions
class GoReconAPIDemo {
    constructor() {
        this.baseURL = '/api/v1';
        this.wsURL = (window.location.protocol === 'https:' ? 'wss:' : 'ws:') + 
                     '//' + window.location.host + '/ws';
    }

    async makeRequest(endpoint, method = 'GET', data = null) {
        const options = {
            method: method,
            headers: {
                'Content-Type': 'application/json'
            }
        };

        if (data) {
            options.body = JSON.stringify(data);
        }

        try {
            const response = await fetch(this.baseURL + endpoint, options);
            const result = await response.json();
            return { success: true, data: result, status: response.status };
        } catch (error) {
            return { success: false, error: error.message };
        }
    }

    async demoHealthCheck() {
        const result = await this.makeRequest('/health');
        this.displayResult('Health Check', result);
    }

    async demoListPlugins() {
        const result = await this.makeRequest('/plugins');
        this.displayResult('List Plugins', result);
    }

    async demoListStages() {
        const result = await this.makeRequest('/stages');
        this.displayResult('List Stages', result);
    }

    displayResult(title, result) {
        const output = document.createElement('div');
        output.className = 'response-viewer';
        output.innerHTML = `<strong>${title} Response:</strong>\n${JSON.stringify(result.data, null, 2)}`;
        
        // Find demo container or create one
        let container = document.querySelector('.demo-container');
        if (!container) {
            container = document.createElement('div');
            container.className = 'demo-container';
            document.body.appendChild(container);
        }
        
        container.appendChild(output);
    }

    createWebSocketConnection() {
        const ws = new WebSocket(this.wsURL);
        
        ws.onopen = () => {
            console.log('WebSocket connected for demo');
            ws.send(JSON.stringify({ type: 'ping', data: Date.now() }));
        };
        
        ws.onmessage = (event) => {
            const message = JSON.parse(event.data);
            console.log('WebSocket demo message:', message);
        };
        
        ws.onerror = (error) => {
            console.error('WebSocket demo error:', error);
        };
        
        return ws;
    }
}

// Initialize demo when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    window.apiDemo = new GoReconAPIDemo();
});

// Utility functions for interactive elements
function copyCodeToClipboard(elementId) {
    const element = document.getElementById(elementId);
    if (element) {
        navigator.clipboard.writeText(element.textContent).then(() => {
            showCopyFeedback();
        });
    }
}

function showCopyFeedback() {
    const feedback = document.createElement('div');
    feedback.textContent = 'Copied to clipboard!';
    feedback.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        background: #4CAF50;
        color: white;
        padding: 10px 20px;
        border-radius: 5px;
        z-index: 10000;
    `;
    document.body.appendChild(feedback);
    
    setTimeout(() => {
        document.body.removeChild(feedback);
    }, 2000);
}
/**
 * SSL Certificate Manager - Single Page Application
 * Modern JavaScript application for certificate management
 */

class SSLManagerApp {
    constructor() {
        this.apiBase = '/api';
        this.token = localStorage.getItem('access_token');
        this.refreshToken = localStorage.getItem('refresh_token');
        this.currentUser = null;
        this.currentPage = 'dashboard';
        
        this.init();
    }
    
    async init() {
        this.setupEventListeners();
        
        // Check if user is logged in
        if (this.token) {
            const isValid = await this.validateToken();
            if (isValid) {
                this.showMainApp();
                this.loadUserProfile();
                this.loadDashboard();
            } else {
                this.showLogin();
            }
        } else {
            this.showLogin();
        }
        
        this.hideLoading();
    }
    
    setupEventListeners() {
        // Login form
        const loginForm = document.getElementById('login-form');
        if (loginForm) {
            loginForm.addEventListener('submit', (e) => this.handleLogin(e));
        }
        
        // Navigation
        document.querySelectorAll('.nav-item').forEach(item => {
            item.addEventListener('click', (e) => this.handleNavigation(e));
        });
        
        // User dropdown
        const userButton = document.querySelector('.user-button');
        const dropdownMenu = document.querySelector('.dropdown-menu');
        if (userButton && dropdownMenu) {
            userButton.addEventListener('click', () => {
                dropdownMenu.classList.toggle('show');
            });
            
            document.addEventListener('click', (e) => {
                if (!userButton.contains(e.target)) {
                    dropdownMenu.classList.remove('show');
                }
            });
        }
        
        // Logout
        const logoutBtn = document.getElementById('logout-btn');
        if (logoutBtn) {
            logoutBtn.addEventListener('click', (e) => this.handleLogout(e));
        }
        
        // Modal close
        const modalCloseBtn = document.getElementById('modal-close-btn');
        const modalOverlay = document.getElementById('modal-overlay');
        if (modalCloseBtn && modalOverlay) {
            modalCloseBtn.addEventListener('click', () => this.hideModal());
            modalOverlay.addEventListener('click', (e) => {
                if (e.target === modalOverlay) {
                    this.hideModal();
                }
            });
        }
        
        // Certificate search
        const certificateSearch = document.getElementById('certificate-search');
        if (certificateSearch) {
            certificateSearch.addEventListener('input', 
                this.debounce(() => this.loadCertificates(), 300)
            );
        }
        
        // Filters
        const statusFilter = document.getElementById('status-filter');
        const issuerFilter = document.getElementById('issuer-filter');
        if (statusFilter) {
            statusFilter.addEventListener('change', () => this.loadCertificates());
        }
        if (issuerFilter) {
            issuerFilter.addEventListener('change', () => this.loadCertificates());
        }
        
        // Action buttons
        this.setupActionButtons();
    }
    
    setupActionButtons() {
        // Scan directory
        const scanBtn = document.getElementById('scan-directory-btn');
        if (scanBtn) {
            scanBtn.addEventListener('click', () => this.showScanDirectoryModal());
        }
        
        // Refresh certificates
        const refreshBtn = document.getElementById('refresh-certificates-btn');
        if (refreshBtn) {
            refreshBtn.addEventListener('click', () => this.loadCertificates());
        }
        
        // Test configuration
        const testConfigBtn = document.getElementById('test-config-btn');
        if (testConfigBtn) {
            testConfigBtn.addEventListener('click', () => this.testConfiguration());
        }
        
        // Test notifications
        const testNotificationsBtn = document.getElementById('test-notifications-btn');
        if (testNotificationsBtn) {
            testNotificationsBtn.addEventListener('click', () => this.showTestEmailModal());
        }
    }
    
    // Authentication methods
    async handleLogin(e) {
        e.preventDefault();
        
        const username = document.getElementById('username').value;
        const password = document.getElementById('password').value;
        const errorDiv = document.getElementById('login-error');
        
        try {
            const response = await fetch(`${this.apiBase}/auth/login`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ username, password })
            });
            
            const data = await response.json();
            
            if (response.ok && data.success) {
                this.token = data.access_token;
                this.refreshToken = data.refresh_token;
                this.currentUser = data.user;
                
                localStorage.setItem('access_token', this.token);
                localStorage.setItem('refresh_token', this.refreshToken);
                
                this.showMainApp();
                this.loadUserProfile();
                this.loadDashboard();
                this.showToast('Login successful', 'success');
            } else {
                errorDiv.textContent = data.error || 'Login failed';
                errorDiv.classList.remove('hidden');
            }
        } catch (error) {
            console.error('Login error:', error);
            errorDiv.textContent = 'Network error. Please try again.';
            errorDiv.classList.remove('hidden');
        }
    }
    
    async handleLogout(e) {
        e.preventDefault();
        
        try {
            await fetch(`${this.apiBase}/auth/logout`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${this.token}`
                }
            });
        } catch (error) {
            console.error('Logout error:', error);
        }
        
        this.token = null;
        this.refreshToken = null;
        this.currentUser = null;
        
        localStorage.removeItem('access_token');
        localStorage.removeItem('refresh_token');
        
        this.showLogin();
        this.showToast('Logged out successfully', 'success');
    }
    
    async validateToken() {
        if (!this.token) return false;
        
        try {
            const response = await fetch(`${this.apiBase}/auth/profile`, {
                headers: {
                    'Authorization': `Bearer ${this.token}`
                }
            });
            
            if (response.ok) {
                return true;
            } else if (response.status === 401 && this.refreshToken) {
                return await this.refreshAccessToken();
            }
            
            return false;
        } catch (error) {
            console.error('Token validation error:', error);
            return false;
        }
    }
    
    async refreshAccessToken() {
        try {
            const response = await fetch(`${this.apiBase}/auth/refresh`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ refresh_token: this.refreshToken })
            });
            
            if (response.ok) {
                const data = await response.json();
                this.token = data.access_token;
                localStorage.setItem('access_token', this.token);
                return true;
            }
            
            return false;
        } catch (error) {
            console.error('Token refresh error:', error);
            return false;
        }
    }
    
    // API methods
    async apiCall(endpoint, options = {}) {
        const url = `${this.apiBase}${endpoint}`;
        const headers = {
            'Content-Type': 'application/json',
            ...options.headers
        };
        
        if (this.token) {
            headers['Authorization'] = `Bearer ${this.token}`;
        }
        
        try {
            const response = await fetch(url, {
                ...options,
                headers
            });
            
            if (response.status === 401 && this.refreshToken) {
                const refreshed = await this.refreshAccessToken();
                if (refreshed) {
                    headers['Authorization'] = `Bearer ${this.token}`;
                    return await fetch(url, { ...options, headers });
                } else {
                    this.showLogin();
                    return null;
                }
            }
            
            return response;
        } catch (error) {
            console.error('API call error:', error);
            this.showToast('Network error occurred', 'error');
            return null;
        }
    }
    
    // UI methods
    showLoading() {
        document.getElementById('loading-screen').classList.remove('hidden');
    }
    
    hideLoading() {
        document.getElementById('loading-screen').classList.add('hidden');
    }
    
    showLogin() {
        document.getElementById('login-screen').classList.remove('hidden');
        document.getElementById('main-app').classList.add('hidden');
        document.getElementById('login-error').classList.add('hidden');
    }
    
    showMainApp() {
        document.getElementById('login-screen').classList.add('hidden');
        document.getElementById('main-app').classList.remove('hidden');
    }
    
    showPage(pageName, params = '') {
        // Hide all pages
        document.querySelectorAll('.page').forEach(page => {
            page.classList.remove('active');
        });
        
        // Show selected page
        const targetPage = document.getElementById(`${pageName}-page`);
        if (targetPage) {
            targetPage.classList.add('active');
        }
        
        // Update navigation
        document.querySelectorAll('.nav-item').forEach(item => {
            item.classList.remove('active');
        });
        
        const navItem = document.querySelector(`[data-page="${pageName}"]`);
        if (navItem) {
            navItem.classList.add('active');
        }
        
        this.currentPage = pageName;
        
        // Load page content
        switch (pageName) {
            case 'dashboard':
                this.loadDashboard();
                break;
            case 'certificates':
                this.loadCertificates(params);
                break;
            case 'renewals':
                this.loadRenewals();
                break;
            case 'notifications':
                this.loadNotifications();
                break;
            case 'settings':
                this.loadSettings();
                break;
        }
    }
    
    handleNavigation(e) {
        e.preventDefault();
        const pageName = e.currentTarget.dataset.page;
        if (pageName) {
            this.showPage(pageName);
        }
    }
    
    showModal(title, content) {
        document.getElementById('modal-title').textContent = title;
        document.getElementById('modal-content').innerHTML = content;
        document.getElementById('modal-overlay').classList.remove('hidden');
    }
    
    hideModal() {
        document.getElementById('modal-overlay').classList.add('hidden');
    }
    
    showToast(message, type = 'info', duration = 5000) {
        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        
        const icon = type === 'success' ? 'check-circle' : 
                    type === 'error' ? 'exclamation-circle' : 
                    type === 'warning' ? 'exclamation-triangle' : 'info-circle';
        
        toast.innerHTML = `
            <i class="fas fa-${icon}"></i>
            <span>${message}</span>
        `;
        
        const container = document.getElementById('toast-container');
        container.appendChild(toast);
        
        setTimeout(() => {
            toast.remove();
        }, duration);
    }
    
    // Data loading methods
    async loadUserProfile() {
        const response = await this.apiCall('/auth/profile');
        if (response && response.ok) {
            const data = await response.json();
            if (data.success) {
                this.currentUser = data.user;
                document.getElementById('user-name').textContent = data.user.username;
            }
        }
    }
    
    async loadDashboard() {
        try {
            // Load statistics
            const statsResponse = await this.apiCall('/statistics');
            if (statsResponse && statsResponse.ok) {
                const stats = await statsResponse.json();
                this.updateStatistics(stats);
            }
            
            // Load expiring certificates
            const expiringResponse = await this.apiCall('/certificates/expiring?days=30');
            if (expiringResponse && expiringResponse.ok) {
                const expiring = await expiringResponse.json();
                this.updateExpiringList(expiring);
            }
            
        } catch (error) {
            console.error('Dashboard loading error:', error);
        }
    }
    
    updateStatistics(stats) {
        document.getElementById('total-certificates').textContent = stats.total_certificates || 0;
        document.getElementById('expiring-certificates').textContent = stats.expiring_soon || 0;
        document.getElementById('valid-certificates').textContent = stats.valid_certificates || 0;
        document.getElementById('expired-certificates').textContent = stats.expired_certificates || 0;
    }
    
    updateExpiringList(certificates) {
        const container = document.getElementById('expiring-list');
        
        if (!certificates || certificates.length === 0) {
            container.innerHTML = '<p class="no-data">No certificates expiring soon</p>';
            return;
        }
        
        const html = certificates.map(cert => `
            <div class="certificate-item">
                <div class="cert-info">
                    <strong>${cert.common_name}</strong>
                    <span class="cert-issuer">${cert.issuer}</span>
                </div>
                <div class="cert-expires">
                    Expires: ${new Date(cert.not_after).toLocaleDateString()}
                </div>
            </div>
        `).join('');
        
        container.innerHTML = html;
    }
    
    async loadCertificates(params = '') {
        const searchTerm = document.getElementById('certificate-search')?.value || '';
        const statusFilter = document.getElementById('status-filter')?.value || '';
        const issuerFilter = document.getElementById('issuer-filter')?.value || '';
        
        const queryParams = new URLSearchParams({
            search: searchTerm,
            status: statusFilter,
            issuer: issuerFilter,
            ...this.parseParams(params)
        });
        
        const response = await this.apiCall(`/certificates?${queryParams}`);
        if (response && response.ok) {
            const data = await response.json();
            this.updateCertificatesTable(data.certificates || []);
            this.updatePagination(data.pagination);
        }
    }
    
    updateCertificatesTable(certificates) {
        const tbody = document.getElementById('certificates-tbody');
        
        if (!certificates || certificates.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" class="no-data">No certificates found</td></tr>';
            return;
        }
        
        const html = certificates.map(cert => {
            const expiresDate = new Date(cert.not_after);
            const now = new Date();
            const daysUntilExpiry = Math.ceil((expiresDate - now) / (1000 * 60 * 60 * 24));
            
            let statusClass = 'status-valid';
            let statusText = 'Valid';
            
            if (daysUntilExpiry < 0) {
                statusClass = 'status-expired';
                statusText = 'Expired';
            } else if (daysUntilExpiry <= 30) {
                statusClass = 'status-expiring';
                statusText = 'Expiring Soon';
            }
            
            return `
                <tr>
                    <td><input type="checkbox" value="${cert.id}"></td>
                    <td>${cert.common_name}</td>
                    <td>${cert.issuer}</td>
                    <td>${expiresDate.toLocaleDateString()}</td>
                    <td><span class="status-badge ${statusClass}">${statusText}</span></td>
                    <td>
                        <button class="btn btn-sm btn-outline" onclick="app.viewCertificate(${cert.id})">
                            <i class="fas fa-eye"></i>
                        </button>
                        <button class="btn btn-sm btn-primary" onclick="app.renewCertificate(${cert.id})">
                            <i class="fas fa-sync-alt"></i>
                        </button>
                    </td>
                </tr>
            `;
        }).join('');
        
        tbody.innerHTML = html;
    }
    
    updatePagination(pagination) {
        // Implementation for pagination controls
        const container = document.getElementById('certificates-pagination');
        if (pagination && pagination.pages > 1) {
            // Add pagination controls here
        } else {
            container.innerHTML = '';
        }
    }
    
    async loadRenewals() {
        // Load renewal history
        console.log('Loading renewals...');
    }
    
    async loadNotifications() {
        // Load notification settings
        console.log('Loading notifications...');
    }
    
    async loadSettings() {
        // Load system settings
        console.log('Loading settings...');
    }
    
    // Certificate actions
    async viewCertificate(certId) {
        const response = await this.apiCall(`/certificates/${certId}`);
        if (response && response.ok) {
            const data = await response.json();
            if (data.success) {
                this.showCertificateModal(data.certificate);
            }
        }
    }
    
    showCertificateModal(certificate) {
        const content = `
            <div class="certificate-details">
                <div class="detail-group">
                    <label>Common Name:</label>
                    <span>${certificate.common_name}</span>
                </div>
                <div class="detail-group">
                    <label>Issuer:</label>
                    <span>${certificate.issuer}</span>
                </div>
                <div class="detail-group">
                    <label>Valid From:</label>
                    <span>${new Date(certificate.not_before).toLocaleString()}</span>
                </div>
                <div class="detail-group">
                    <label>Valid Until:</label>
                    <span>${new Date(certificate.not_after).toLocaleString()}</span>
                </div>
                <div class="detail-group">
                    <label>Serial Number:</label>
                    <span>${certificate.serial_number}</span>
                </div>
                <div class="detail-group">
                    <label>Subject Alt Names:</label>
                    <span>${certificate.subject_alt_names || 'None'}</span>
                </div>
            </div>
        `;
        
        this.showModal('Certificate Details', content);
    }
    
    async renewCertificate(certId) {
        if (!confirm('Are you sure you want to renew this certificate?')) {
            return;
        }
        
        const response = await this.apiCall(`/certificates/${certId}/renew`, {
            method: 'POST'
        });
        
        if (response && response.ok) {
            const data = await response.json();
            if (data.success) {
                this.showToast('Certificate renewal initiated', 'success');
            } else {
                this.showToast(data.error || 'Renewal failed', 'error');
            }
        }
    }
    
    showScanDirectoryModal() {
        const content = `
            <form id="scan-form">
                <div class="form-group">
                    <label for="scan-directory">Directory Path:</label>
                    <input type="text" id="scan-directory" name="directory" 
                           placeholder="/path/to/certificates" required>
                </div>
                <div class="form-group">
                    <label>
                        <input type="checkbox" id="update-ownership" name="update_ownership">
                        Update ownership information
                    </label>
                </div>
                <div class="form-actions">
                    <button type="button" class="btn btn-outline" onclick="app.hideModal()">Cancel</button>
                    <button type="submit" class="btn btn-primary">Scan Directory</button>
                </div>
            </form>
        `;
        
        this.showModal('Scan Directory', content);
        
        document.getElementById('scan-form').addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const directory = document.getElementById('scan-directory').value;
            const updateOwnership = document.getElementById('update-ownership').checked;
            
            const response = await this.apiCall('/certificates/scan', {
                method: 'POST',
                body: JSON.stringify({ directory, update_ownership: updateOwnership })
            });
            
            if (response && response.ok) {
                const data = await response.json();
                this.showToast(`Scan completed: ${data.processed} certificates processed`, 'success');
                this.hideModal();
                this.loadCertificates();
            } else {
                this.showToast('Scan failed', 'error');
            }
        });
    }
    
    showTestEmailModal() {
        const content = `
            <form id="test-email-form">
                <div class="form-group">
                    <label for="test-email">Email Address:</label>
                    <input type="email" id="test-email" name="email" 
                           placeholder="test@example.com" required>
                </div>
                <div class="form-actions">
                    <button type="button" class="btn btn-outline" onclick="app.hideModal()">Cancel</button>
                    <button type="submit" class="btn btn-primary">Send Test Email</button>
                </div>
            </form>
        `;
        
        this.showModal('Test Email Configuration', content);
        
        document.getElementById('test-email-form').addEventListener('submit', async (e) => {
            e.preventDefault();
            
            const email = document.getElementById('test-email').value;
            
            const response = await this.apiCall('/notifications/test-email', {
                method: 'POST',
                body: JSON.stringify({ email })
            });
            
            if (response && response.ok) {
                const data = await response.json();
                if (data.success) {
                    this.showToast('Test email sent successfully', 'success');
                } else {
                    this.showToast(data.error || 'Test email failed', 'error');
                }
                this.hideModal();
            }
        });
    }
    
    async testConfiguration() {
        const response = await this.apiCall('/config/test', { method: 'POST' });
        if (response && response.ok) {
            const data = await response.json();
            this.displayHealthStatus(data);
        }
    }
    
    displayHealthStatus(results) {
        const container = document.getElementById('health-status');
        
        const html = Object.entries(results).map(([service, result]) => {
            const statusClass = result.success ? 'status-valid' : 'status-expired';
            const icon = result.success ? 'check-circle' : 'times-circle';
            
            return `
                <div class="health-item">
                    <i class="fas fa-${icon}"></i>
                    <span class="service-name">${service.toUpperCase()}</span>
                    <span class="status-badge ${statusClass}">
                        ${result.success ? 'OK' : 'Error'}
                    </span>
                    ${result.error ? `<div class="error-detail">${result.error}</div>` : ''}
                </div>
            `;
        }).join('');
        
        container.innerHTML = html;
    }
    
    // Utility methods
    debounce(func, wait) {
        let timeout;
        return function executedFunction(...args) {
            const later = () => {
                clearTimeout(timeout);
                func(...args);
            };
            clearTimeout(timeout);
            timeout = setTimeout(later, wait);
        };
    }
    
    parseParams(params) {
        if (!params) return {};
        
        const urlParams = new URLSearchParams(params.startsWith('?') ? params.slice(1) : params);
        const result = {};
        
        for (const [key, value] of urlParams) {
            result[key] = value;
        }
        
        return result;
    }
}

// Initialize the application
const app = new SSLManagerApp();

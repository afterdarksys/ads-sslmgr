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
        this.setupActionButtons();

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
            case 'my-certificates':
                this.loadMyCertificates(params);
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
    
    updateCertificatesTable(certificates, tableBodyId = 'certificates-tbody', columnCount = 8) {
        const tbody = document.getElementById(tableBodyId);

        if (!certificates || certificates.length === 0) {
            tbody.innerHTML = `<tr><td colspan="${columnCount}" class="no-data">No certificates found</td></tr>`;
            return;
        }

        const html = certificates.map(cert => {
            const expiresDate = new Date(cert.not_after);
            const now = new Date();
            const daysUntilExpiry = Math.ceil((expiresDate - now) / (1000 * 60 * 60 * 24));

            let statusClass = 'status-valid';
            let statusText = 'Valid';

            if (cert.is_expired || daysUntilExpiry < 0) {
                statusClass = 'status-expired';
                statusText = 'Expired';
            } else if (daysUntilExpiry <= 30) {
                statusClass = 'status-expiring';
                statusText = 'Expiring Soon';
            }

            // Handle ownership info
            const owner = cert.ownership ?
                (cert.ownership.owner_email || cert.ownership.owner_username || 'Unassigned') :
                'Unassigned';
            const environment = cert.ownership ?
                (cert.ownership.environment || 'Unknown') :
                'Unknown';
            const application = cert.ownership ?
                (cert.ownership.application_name || 'N/A') :
                'N/A';

            // Different layouts for different tables
            if (tableBodyId === 'my-certificates-tbody') {
                return `
                    <tr>
                        <td><input type="checkbox" value="${cert.id}" class="cert-checkbox"></td>
                        <td>
                            <div class="cert-name">
                                <strong>${cert.common_name}</strong>
                                ${cert.subject_alt_names ? `<div class="alt-names">${cert.subject_alt_names.slice(0, 2).join(', ')}${cert.subject_alt_names.length > 2 ? '...' : ''}</div>` : ''}
                            </div>
                        </td>
                        <td>${cert.issuer}</td>
                        <td><span class="environment-badge ${environment.toLowerCase()}">${environment}</span></td>
                        <td>${application}</td>
                        <td>
                            <div class="expires-info">
                                <div>${expiresDate.toLocaleDateString()}</div>
                                <div class="days-remaining ${daysUntilExpiry <= 30 ? 'warning' : ''}">${daysUntilExpiry} days</div>
                            </div>
                        </td>
                        <td><span class="status-badge ${statusClass}">${statusText}</span></td>
                        <td>
                            <div class="action-buttons">
                                <button class="btn btn-sm btn-outline" onclick="app.viewCertificate(${cert.id})" title="View Details">
                                    <i class="fas fa-eye"></i>
                                </button>
                                <button class="btn btn-sm btn-info" onclick="app.editOwnership(${cert.id})" title="Edit Ownership">
                                    <i class="fas fa-user-edit"></i>
                                </button>
                                <button class="btn btn-sm btn-primary" onclick="app.renewCertificate(${cert.id})" title="Renew">
                                    <i class="fas fa-sync-alt"></i>
                                </button>
                            </div>
                        </td>
                    </tr>
                `;
            } else {
                return `
                    <tr>
                        <td><input type="checkbox" value="${cert.id}" class="cert-checkbox"></td>
                        <td>
                            <div class="cert-name">
                                <strong>${cert.common_name}</strong>
                                ${cert.subject_alt_names ? `<div class="alt-names">${cert.subject_alt_names.slice(0, 2).join(', ')}${cert.subject_alt_names.length > 2 ? '...' : ''}</div>` : ''}
                            </div>
                        </td>
                        <td>${cert.issuer}</td>
                        <td><span class="owner-info">${owner}</span></td>
                        <td><span class="environment-badge ${environment.toLowerCase()}">${environment}</span></td>
                        <td>
                            <div class="expires-info">
                                <div>${expiresDate.toLocaleDateString()}</div>
                                <div class="days-remaining ${daysUntilExpiry <= 30 ? 'warning' : ''}">${daysUntilExpiry} days</div>
                            </div>
                        </td>
                        <td><span class="status-badge ${statusClass}">${statusText}</span></td>
                        <td>
                            <div class="action-buttons">
                                <button class="btn btn-sm btn-outline" onclick="app.viewCertificate(${cert.id})" title="View Details">
                                    <i class="fas fa-eye"></i>
                                </button>
                                <button class="btn btn-sm btn-info" onclick="app.editOwnership(${cert.id})" title="Edit Ownership">
                                    <i class="fas fa-user-edit"></i>
                                </button>
                                <button class="btn btn-sm btn-primary" onclick="app.renewCertificate(${cert.id})" title="Renew">
                                    <i class="fas fa-sync-alt"></i>
                                </button>
                                ${this.currentUser && this.currentUser.role === 'admin' ?
                                    `<button class="btn btn-sm btn-danger" onclick="app.revokeCertificate(${cert.id})" title="Revoke">
                                        <i class="fas fa-ban"></i>
                                    </button>` : ''}
                            </div>
                        </td>
                    </tr>
                `;
            }
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

    // My Certificates functionality
    async loadMyCertificates(params = '') {
        const searchTerm = document.getElementById('my-certificate-search')?.value || '';
        const statusFilter = document.getElementById('my-status-filter')?.value || '';
        const issuerFilter = document.getElementById('my-issuer-filter')?.value || '';
        const environmentFilter = document.getElementById('my-environment-filter')?.value || '';

        const queryParams = new URLSearchParams({
            search: searchTerm,
            is_expired: statusFilter,
            issuer_category: issuerFilter,
            environment: environmentFilter,
            ...this.parseParams(params)
        });

        // Load my certificates and statistics in parallel
        const [certificatesResponse, statisticsResponse] = await Promise.all([
            this.apiCall(`/certificates/mine?${queryParams}`),
            this.apiCall(`/users/${this.currentUser.id}/certificates/statistics`)
        ]);

        if (certificatesResponse && certificatesResponse.ok) {
            const data = await certificatesResponse.json();
            this.updateCertificatesTable(data.certificates || [], 'my-certificates-tbody', 8);
            this.updatePagination(data.pagination, 'my-certificates-pagination');
        }

        if (statisticsResponse && statisticsResponse.ok) {
            const stats = await statisticsResponse.json();
            this.updateMyCertificateStatistics(stats.statistics || {});
        }
    }

    updateMyCertificateStatistics(stats) {
        document.getElementById('my-total-certificates').textContent = stats.total_certificates || 0;
        document.getElementById('my-expiring-certificates').textContent = stats.expiring_30_days || 0;
        document.getElementById('my-valid-certificates').textContent = stats.valid_certificates || 0;
        document.getElementById('my-expired-certificates').textContent = stats.expired_certificates || 0;
    }

    // Certificate upload functionality
    showUploadCertificateModal() {
        const content = `
            <form id="upload-certificate-form" enctype="multipart/form-data">
                <div class="form-group">
                    <label for="certificate-file">Certificate File (Multiple formats supported):</label>
                    <input type="file" id="certificate-file" name="certificate"
                           accept=".pem,.crt,.cer,.der,.p7b,.p7c,.p10,.csr,.req,.p12,.pfx,.pvk,.cose,.cbor,.cwt" required>
                    <small class="format-help">
                        <strong>Supported formats:</strong><br>
                        • PEM (.pem, .crt) - Standard format<br>
                        • DER (.der, .cer) - Binary format<br>
                        • PKCS#7 (.p7b, .p7c) - Certificate chain<br>
                        • PKCS#10 (.p10, .csr, .req) - Certificate request<br>
                        • PKCS#12 (.p12, .pfx) - Certificate bundle (may require password)<br>
                        • PVK (.pvk) - <em>Legacy format, import only</em><br>
                        • COSE (.cose, .cbor) - CBOR Object Signing and Encryption<br>
                        • CWT (.cwt) - CBOR Web Token
                    </small>
                </div>

                <div class="form-group" id="password-group" style="display: none;">
                    <label for="certificate-password">Certificate Password (if encrypted):</label>
                    <input type="password" id="certificate-password" name="password" placeholder="Leave blank if not encrypted">
                    <small>Required for encrypted PKCS#12 (.p12, .pfx) and some PVK files</small>
                </div>

                <div class="form-group">
                    <label for="upload-owner-email">Owner Email:</label>
                    <input type="email" id="upload-owner-email" name="owner_email" value="${this.currentUser?.email || ''}" required>
                </div>

                <div class="form-group">
                    <label for="upload-department">Department:</label>
                    <input type="text" id="upload-department" name="department" placeholder="IT, Security, etc.">
                </div>

                <div class="form-group">
                    <label for="upload-environment">Environment:</label>
                    <select id="upload-environment" name="environment">
                        <option value="production">Production</option>
                        <option value="staging">Staging</option>
                        <option value="development">Development</option>
                        <option value="testing">Testing</option>
                    </select>
                </div>

                <div class="form-group">
                    <label for="upload-application">Application Name:</label>
                    <input type="text" id="upload-application" name="application_name" placeholder="Web Server, API, etc.">
                </div>

                <div class="form-group">
                    <label for="upload-description">Description:</label>
                    <textarea id="upload-description" name="description" rows="3" placeholder="Certificate purpose, notes, etc."></textarea>
                </div>

                <div class="form-actions">
                    <button type="button" class="btn btn-outline" onclick="app.hideModal()">Cancel</button>
                    <button type="submit" class="btn btn-success">
                        <i class="fas fa-upload"></i>
                        Upload Certificate
                    </button>
                </div>
            </form>
        `;

        this.showModal('Upload Certificate', content);

        document.getElementById('upload-certificate-form').addEventListener('submit', async (e) => {
            e.preventDefault();

            const formData = new FormData(e.target);

            try {
                const response = await fetch('/api/certificates/upload', {
                    method: 'POST',
                    headers: {
                        'Authorization': `Bearer ${this.token}`
                    },
                    body: formData
                });

                const data = await response.json();

                if (response.ok && data.success) {
                    this.showToast('Certificate uploaded successfully', 'success');
                    this.hideModal();
                    // Refresh current page
                    if (this.currentPage === 'certificates') {
                        this.loadCertificates();
                    } else if (this.currentPage === 'my-certificates') {
                        this.loadMyCertificates();
                    }
                } else {
                    this.showToast(data.error || 'Upload failed', 'error');
                }
            } catch (error) {
                console.error('Upload error:', error);
                this.showToast('Upload failed: Network error', 'error');
            }
        });
    }

    // Edit ownership modal
    async editOwnership(certId) {
        // Get current certificate details
        const response = await this.apiCall(`/certificates/${certId}`);
        if (!response || !response.ok) {
            this.showToast('Failed to load certificate details', 'error');
            return;
        }

        const data = await response.json();
        const cert = data.certificate;
        const ownership = cert.ownership || {};

        const content = `
            <form id="edit-ownership-form">
                <div class="certificate-info">
                    <h4>Certificate: ${cert.common_name}</h4>
                    <p>Serial: ${cert.serial_number}</p>
                </div>

                <div class="form-group">
                    <label for="edit-owner-email">Owner Email:</label>
                    <input type="email" id="edit-owner-email" name="owner_email" value="${ownership.owner_email || ''}">
                </div>

                <div class="form-group">
                    <label for="edit-owner-username">Owner Username:</label>
                    <input type="text" id="edit-owner-username" name="owner_username" value="${ownership.owner_username || ''}">
                </div>

                <div class="form-group">
                    <label for="edit-department">Department:</label>
                    <input type="text" id="edit-department" name="department" value="${ownership.department || ''}">
                </div>

                <div class="form-group">
                    <label for="edit-contact-phone">Contact Phone:</label>
                    <input type="tel" id="edit-contact-phone" name="contact_phone" value="${ownership.contact_phone || ''}">
                </div>

                <div class="form-group">
                    <label for="edit-environment">Environment:</label>
                    <select id="edit-environment" name="environment">
                        <option value="">Select Environment</option>
                        <option value="production" ${ownership.environment === 'production' ? 'selected' : ''}>Production</option>
                        <option value="staging" ${ownership.environment === 'staging' ? 'selected' : ''}>Staging</option>
                        <option value="development" ${ownership.environment === 'development' ? 'selected' : ''}>Development</option>
                        <option value="testing" ${ownership.environment === 'testing' ? 'selected' : ''}>Testing</option>
                    </select>
                </div>

                <div class="form-group">
                    <label for="edit-application">Application Name:</label>
                    <input type="text" id="edit-application" name="application_name" value="${ownership.application_name || ''}">
                </div>

                <div class="form-group">
                    <label for="edit-owner-url">Related URL:</label>
                    <input type="url" id="edit-owner-url" name="owner_url" value="${ownership.owner_url || ''}" placeholder="https://example.com">
                </div>

                <div class="form-group">
                    <label for="edit-description">Description:</label>
                    <textarea id="edit-description" name="description" rows="3">${ownership.description || ''}</textarea>
                </div>

                <div class="form-actions">
                    <button type="button" class="btn btn-outline" onclick="app.hideModal()">Cancel</button>
                    <button type="submit" class="btn btn-primary">
                        <i class="fas fa-save"></i>
                        Update Ownership
                    </button>
                </div>
            </form>
        `;

        this.showModal('Edit Certificate Ownership', content);

        document.getElementById('edit-ownership-form').addEventListener('submit', async (e) => {
            e.preventDefault();

            const formData = new FormData(e.target);
            const ownershipData = {};

            for (const [key, value] of formData.entries()) {
                ownershipData[key] = value;
            }

            try {
                const response = await this.apiCall(`/certificates/${certId}/ownership`, {
                    method: 'PUT',
                    body: JSON.stringify(ownershipData)
                });

                if (response && response.ok) {
                    this.showToast('Ownership updated successfully', 'success');
                    this.hideModal();
                    // Refresh current page
                    if (this.currentPage === 'certificates') {
                        this.loadCertificates();
                    } else if (this.currentPage === 'my-certificates') {
                        this.loadMyCertificates();
                    }
                } else {
                    const errorData = await response.json();
                    this.showToast(errorData.error || 'Failed to update ownership', 'error');
                }
            } catch (error) {
                console.error('Ownership update error:', error);
                this.showToast('Update failed: Network error', 'error');
            }
        });
    }

    // Revoke certificate (admin only)
    async revokeCertificate(certId) {
        const reason = prompt('Enter revocation reason:');
        if (!reason) return;

        if (!confirm(`Are you sure you want to revoke this certificate?\nReason: ${reason}`)) {
            return;
        }

        try {
            const response = await this.apiCall(`/certificates/${certId}/revoke`, {
                method: 'POST',
                body: JSON.stringify({ reason })
            });

            if (response && response.ok) {
                const data = await response.json();
                this.showToast(data.message || 'Certificate revoked successfully', 'success');
                // Refresh current page
                if (this.currentPage === 'certificates') {
                    this.loadCertificates();
                } else if (this.currentPage === 'my-certificates') {
                    this.loadMyCertificates();
                }
            } else {
                const errorData = await response.json();
                this.showToast(errorData.error || 'Failed to revoke certificate', 'error');
            }
        } catch (error) {
            console.error('Revocation error:', error);
            this.showToast('Revocation failed: Network error', 'error');
        }
    }

    // Bulk operations
    getSelectedCertificates() {
        const checkboxes = document.querySelectorAll('.cert-checkbox:checked');
        return Array.from(checkboxes).map(cb => parseInt(cb.value));
    }

    async bulkUpdateOwnership() {
        const certIds = this.getSelectedCertificates();
        if (certIds.length === 0) {
            this.showToast('Please select certificates to update', 'warning');
            return;
        }

        const content = `
            <form id="bulk-ownership-form">
                <div class="selected-count">
                    <p><strong>Updating ownership for ${certIds.length} certificates</strong></p>
                </div>

                <div class="form-group">
                    <label for="bulk-owner-email">Owner Email:</label>
                    <input type="email" id="bulk-owner-email" name="owner_email">
                </div>

                <div class="form-group">
                    <label for="bulk-owner-username">Owner Username:</label>
                    <input type="text" id="bulk-owner-username" name="owner_username">
                </div>

                <div class="form-group">
                    <label for="bulk-department">Department:</label>
                    <input type="text" id="bulk-department" name="department">
                </div>

                <div class="form-group">
                    <label for="bulk-environment">Environment:</label>
                    <select id="bulk-environment" name="environment">
                        <option value="">Keep Current</option>
                        <option value="production">Production</option>
                        <option value="staging">Staging</option>
                        <option value="development">Development</option>
                        <option value="testing">Testing</option>
                    </select>
                </div>

                <div class="form-actions">
                    <button type="button" class="btn btn-outline" onclick="app.hideModal()">Cancel</button>
                    <button type="submit" class="btn btn-primary">
                        <i class="fas fa-save"></i>
                        Update All Selected
                    </button>
                </div>
            </form>
        `;

        this.showModal('Bulk Update Ownership', content);

        document.getElementById('bulk-ownership-form').addEventListener('submit', async (e) => {
            e.preventDefault();

            const formData = new FormData(e.target);
            const ownershipData = {};

            for (const [key, value] of formData.entries()) {
                if (value.trim()) { // Only include non-empty values
                    ownershipData[key] = value;
                }
            }

            try {
                const response = await this.apiCall('/certificates/bulk-update-ownership', {
                    method: 'POST',
                    body: JSON.stringify({
                        cert_ids: certIds,
                        ownership_data: ownershipData
                    })
                });

                if (response && response.ok) {
                    const data = await response.json();
                    this.showToast(`Updated ${data.updated_count} certificates successfully`, 'success');
                    if (data.failed_updates && data.failed_updates.length > 0) {
                        this.showToast(`${data.failed_updates.length} updates failed`, 'warning');
                    }
                    this.hideModal();
                    // Refresh and clear selections
                    if (this.currentPage === 'certificates') {
                        this.loadCertificates();
                    } else if (this.currentPage === 'my-certificates') {
                        this.loadMyCertificates();
                    }
                } else {
                    const errorData = await response.json();
                    this.showToast(errorData.error || 'Bulk update failed', 'error');
                }
            } catch (error) {
                console.error('Bulk update error:', error);
                this.showToast('Bulk update failed: Network error', 'error');
            }
        });
    }

    async bulkRevokeCertificates() {
        const certIds = this.getSelectedCertificates();
        if (certIds.length === 0) {
            this.showToast('Please select certificates to revoke', 'warning');
            return;
        }

        const reason = prompt(`Enter revocation reason for ${certIds.length} certificates:`);
        if (!reason) return;

        if (!confirm(`Are you sure you want to revoke ${certIds.length} certificates?\nReason: ${reason}\n\nThis action cannot be undone!`)) {
            return;
        }

        try {
            const response = await this.apiCall('/certificates/bulk-revoke', {
                method: 'POST',
                body: JSON.stringify({
                    cert_ids: certIds,
                    reason: reason
                })
            });

            if (response && response.ok) {
                const data = await response.json();
                this.showToast(`Revoked ${data.revoked_count} certificates successfully`, 'success');
                if (data.failed_revocations && data.failed_revocations.length > 0) {
                    this.showToast(`${data.failed_revocations.length} revocations failed`, 'warning');
                }
                // Refresh and clear selections
                if (this.currentPage === 'certificates') {
                    this.loadCertificates();
                } else if (this.currentPage === 'my-certificates') {
                    this.loadMyCertificates();
                }
            } else {
                const errorData = await response.json();
                this.showToast(errorData.error || 'Bulk revocation failed', 'error');
            }
        } catch (error) {
            console.error('Bulk revocation error:', error);
            this.showToast('Bulk revocation failed: Network error', 'error');
        }
    }

    // Enhanced setup for new event listeners
    setupActionButtons() {
        // Existing buttons
        const scanBtn = document.getElementById('scan-directory-btn');
        if (scanBtn) {
            scanBtn.addEventListener('click', () => this.showScanDirectoryModal());
        }

        const refreshBtn = document.getElementById('refresh-certificates-btn');
        if (refreshBtn) {
            refreshBtn.addEventListener('click', () => this.loadCertificates());
        }

        const testConfigBtn = document.getElementById('test-config-btn');
        if (testConfigBtn) {
            testConfigBtn.addEventListener('click', () => this.testConfiguration());
        }

        const testNotificationsBtn = document.getElementById('test-notifications-btn');
        if (testNotificationsBtn) {
            testNotificationsBtn.addEventListener('click', () => this.showTestEmailModal());
        }

        // New buttons
        const uploadBtn = document.getElementById('upload-certificate-btn');
        if (uploadBtn) {
            uploadBtn.addEventListener('click', () => this.showUploadCertificateModal());
        }

        const uploadMyBtn = document.getElementById('upload-my-certificate-btn');
        if (uploadMyBtn) {
            uploadMyBtn.addEventListener('click', () => this.showUploadCertificateModal());
        }

        const refreshMyBtn = document.getElementById('refresh-my-certificates-btn');
        if (refreshMyBtn) {
            refreshMyBtn.addEventListener('click', () => this.loadMyCertificates());
        }

        // Bulk actions
        const bulkActionsBtn = document.getElementById('bulk-actions-btn');
        const bulkActionsMenu = document.getElementById('bulk-actions-menu');
        if (bulkActionsBtn && bulkActionsMenu) {
            bulkActionsBtn.addEventListener('click', (e) => {
                e.stopPropagation();
                bulkActionsMenu.classList.toggle('show');
            });

            document.addEventListener('click', () => {
                bulkActionsMenu.classList.remove('show');
            });
        }

        const bulkUpdateBtn = document.getElementById('bulk-update-ownership-btn');
        if (bulkUpdateBtn) {
            bulkUpdateBtn.addEventListener('click', (e) => {
                e.preventDefault();
                this.bulkUpdateOwnership();
            });
        }

        const bulkRevokeBtn = document.getElementById('bulk-revoke-btn');
        if (bulkRevokeBtn) {
            bulkRevokeBtn.addEventListener('click', (e) => {
                e.preventDefault();
                this.bulkRevokeCertificates();
            });
        }

        // Enhanced search for my certificates page
        const myCertificateSearch = document.getElementById('my-certificate-search');
        if (myCertificateSearch) {
            myCertificateSearch.addEventListener('input',
                this.debounce(() => this.loadMyCertificates(), 300)
            );
        }

        // Enhanced filters for my certificates page
        const myFilters = ['my-status-filter', 'my-issuer-filter', 'my-environment-filter'];
        myFilters.forEach(filterId => {
            const filter = document.getElementById(filterId);
            if (filter) {
                filter.addEventListener('change', () => this.loadMyCertificates());
            }
        });

        // Enhanced filters for certificates page
        const filters = ['status-filter', 'issuer-filter', 'owner-filter', 'environment-filter'];
        filters.forEach(filterId => {
            const filter = document.getElementById(filterId);
            if (filter) {
                filter.addEventListener('change', () => this.loadCertificates());
            }
        });
    }
}

// Initialize the application
const app = new SSLManagerApp();

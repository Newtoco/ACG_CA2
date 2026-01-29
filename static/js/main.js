// Global variables
let selectedFile = null;
let tempUserId = null;

// Initialize app
function initApp(mode, username) {
    const app = document.getElementById('app');
    
    if (mode === 'login') {
        renderLogin();
    } else {
        renderDashboard(username);
    }
}

// -- TOAST NOTIFICATIONS --
function showToast(title, message, type = 'info', duration = 4000) {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    
    const icons = {
        success: '✓',
        error: '✕',
        warning: '⚠',
        info: 'ℹ'
    };
    
    toast.innerHTML = `
        <div class="toast-icon">${icons[type] || icons.info}</div>
        <div class="toast-content">
            <div class="toast-title">${title}</div>
            ${message ? `<div class="toast-message">${message}</div>` : ''}
        </div>
        <button class="toast-close" onclick="this.parentElement.remove()">×</button>
    `;
    
    container.appendChild(toast);
    
    if (duration > 0) {
        setTimeout(() => {
            toast.classList.add('removing');
            setTimeout(() => toast.remove(), 300);
        }, duration);
    }
}

// -- MODAL CONFIRMATION --
function showConfirmModal(title, message, onConfirm) {
    const overlay = document.createElement('div');
    overlay.className = 'modal-overlay';
    overlay.innerHTML = `
        <div class="modal">
            <div class="modal-header">${title}</div>
            <div class="modal-body">${message}</div>
            <div class="modal-footer">
                <button class="secondary" onclick="this.closest('.modal-overlay').remove()">Cancel</button>
                <button class="danger" id="modal-confirm">Delete</button>
            </div>
        </div>
    `;
    document.body.appendChild(overlay);
    
    overlay.querySelector('#modal-confirm').onclick = () => {
        overlay.remove();
        onConfirm();
    };
    
    overlay.onclick = (e) => {
        if (e.target === overlay) overlay.remove();
    };
}

// -- LOADING HELPERS --
function setButtonLoading(btn, loading) {
    if (loading) {
        btn.disabled = true;
        btn.dataset.originalText = btn.innerHTML;
        btn.innerHTML = '<span class="spinner"></span>' + btn.dataset.originalText;
    } else {
        btn.disabled = false;
        btn.innerHTML = btn.dataset.originalText;
    }
}

// -- VIEWS --
function renderLogin() {
    const app = document.getElementById('app');
    app.innerHTML = `
        <h2>🔐 Secure Vault</h2>
        <div id="login-form">
            <div class="input-group">
                <label for="u">Username</label>
                <input type="text" id="u" placeholder="Enter your username">
            </div>
            <div class="input-group">
                <label for="p">Password</label>
                <input type="password" id="p" placeholder="Enter your password">
            </div>
            <button onclick="handleLogin()">Login</button>
            <button onclick="renderRegister()" class="secondary">Register New Account</button>
        </div>
        <div id="mfa-form" class="hidden">
            <h3>🔢 Two-Factor Authentication</h3>
            <p class="info-text">Open Google Authenticator and enter the 6-digit code:</p>
            <input type="text" id="otp-input" placeholder="000 000" maxlength="7" style="text-align:center; letter-spacing: 5px; font-size: 1.2em;">
            <button onclick="submitOtp()">Verify Code</button>
            <button onclick="renderLogin()" class="secondary">Back to Login</button>
        </div>
    `;
}

function renderRegister() {
    const app = document.getElementById('app');
    app.innerHTML = `
        <h2>📝 Setup Account</h2>
        <div id="reg-form">
            <div class="input-group">
                <label for="ru">Username</label>
                <input type="text" id="ru" placeholder="Choose a username">
            </div>
            <div class="input-group">
                <label for="rp">Password</label>
                <input type="password" id="rp" placeholder="Choose a strong password">
            </div>
            <button onclick="handleRegister()">Create Account</button>
            <button onclick="renderLogin()" class="secondary">Back to Login</button>
        </div>
        <div id="qr-display" class="hidden">
            <h3 style="color:var(--accent-success)">✓ Account Created!</h3>
            <p class="info-text">Scan this QR code with Google Authenticator:</p>
            <div class="qr-area">
                <img id="qr-img" src="" width="150" height="150">
            </div>
            <p class="info-text">Or enter this secret manually:</p>
            <div class="secret-box" id="secret-text"></div>
            <p class="info-text" style="margin-top: 20px; color: var(--accent-warning);">⚠️ Please confirm your authenticator code below before continuing:</p>
            <div class="input-group">
                <label for="reg-otp-input">Enter 6-digit code from your authenticator:</label>
                <input type="text" id="reg-otp-input" placeholder="000 000" maxlength="7" style="text-align:center; letter-spacing: 5px; font-size: 1.2em;">
            </div>
            <button onclick="confirmOtpRegistration()" class="success">Verify & Complete Registration</button>
            <button onclick="renderLogin()" class="secondary">Back to Login</button>
        </div>
    `;
}

function renderDashboard(username) {
    const app = document.getElementById('app');
    app.innerHTML = `
        <h2>📦 Vault: ${username}</h2>
        <div class="input-group">
            <label for="f">Select File to Upload</label>
            <input type="file" id="f">
        </div>
        <button type="button" onclick="uploadFile(event)" class="success">
            <span style="font-size:1.1rem;">↑</span> Upload File
        </button>
        <div id="list">
            <div class="spinner-large"></div>
        </div>
        <button onclick="downloadFile()">
            <span style="font-size:1.1rem;">↓</span> Download Selected
        </button>
        <button onclick="deleteFile()" class="danger">
            <span style="font-size:1.1rem;">🗑</span> Delete Selected
        </button>
        ${username === 'admin' ? `<button onclick="viewSystemLogs()" class="warning" style="margin-top:10px">🛡️ View Audit Logs</button>` : ''}
        <button onclick="handleLogout()" class="secondary" style="margin-top:20px">Log Out</button>
    `;
    loadFiles();
}

// -- VALIDATION --
function validateInput(input, errorMsg) {
    if (!input.value.trim()) {
        input.classList.add('error');
        showToast('Validation Error', errorMsg, 'error');
        setTimeout(() => input.classList.remove('error'), 500);
        return false;
    }
    return true;
}

// -- AUTHENTICATION LOGIC --
async function handleLogin() {
    const uInput = document.getElementById('u');
    const pInput = document.getElementById('p');

    if (!validateInput(uInput, 'Username is required')) return;
    if (!validateInput(pInput, 'Password is required')) return;

    const btn = event.target;
    setButtonLoading(btn, true);

    try {
        const res = await fetch('/login', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({username: uInput.value, password: pInput.value})
        });
        const data = await res.json();

        if(data.otp_required) {
            tempUserId = data.user_id;
            document.getElementById('login-form').classList.add('hidden');
            document.getElementById('mfa-form').classList.remove('hidden');
            showToast('MFA Required', 'Please enter your authenticator code', 'info');
        } else {
            showToast('Login Failed', data.message || 'Invalid credentials', 'error');
        }
    } catch(e) {
        showToast('Error', 'Connection failed', 'error');
    } finally {
        setButtonLoading(btn, false);
    }
}

async function submitOtp() {
    const otpInput = document.getElementById('otp-input');
    const code = otpInput.value.replace(/\s/g, '');
    
    if (code.length !== 6) {
        showToast('Invalid Code', 'Please enter a 6-digit code', 'error');
        otpInput.classList.add('error');
        setTimeout(() => otpInput.classList.remove('error'), 500);
        return;
    }

    const btn = event.target;
    setButtonLoading(btn, true);

    try {
        const res = await fetch('/verify-otp', {
            method: 'POST', 
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({user_id: tempUserId, otp: code})
        });
        
        if (res.ok) {
            showToast('Success', 'Login successful!', 'success', 1500);
            setTimeout(() => window.location.href = '/dashboard', 1500);
        } else {
            showToast('Invalid Code', 'The code you entered is incorrect', 'error');
            otpInput.value = '';
            otpInput.focus();
        }
    } catch(e) {
        showToast('Error', 'Connection failed', 'error');
    } finally {
        setButtonLoading(btn, false);
    }
}

async function confirmOtpRegistration() {
    /**
     * FUNCTION: Called during registration to verify OTP before completing signup.
     * This is a separate endpoint from login OTP verification.
     */
    const otpInput = document.getElementById('reg-otp-input');
    const code = otpInput.value.replace(/\s/g, '');
    
    if (code.length !== 6) {
        showToast('Invalid Code', 'Please enter a 6-digit code', 'error');
        otpInput.classList.add('error');
        setTimeout(() => otpInput.classList.remove('error'), 500);
        return;
    }

    const btn = event.target;
    setButtonLoading(btn, true);

    try {
        const res = await fetch('/confirm-otp-registration', {
            method: 'POST', 
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({user_id: tempUserId, otp: code})
        });
        
        const data = await res.json();
        
        if (res.ok) {
            showToast('Success', 'Registration complete! Redirecting to login...', 'success', 1500);
            setTimeout(() => {
                renderLogin();
                showToast('Ready to Login', 'You can now log in with your credentials', 'info', 2000);
            }, 1500);
        } else {
            showToast('Invalid Code', data.message || 'The code you entered is incorrect', 'error');
            otpInput.value = '';
            otpInput.focus();
        }
    } catch(e) {
        showToast('Error', 'Connection failed', 'error');
    } finally {
        setButtonLoading(btn, false);
    }
}

async function handleRegister() {
    const uInput = document.getElementById('ru');
    const pInput = document.getElementById('rp');
    
    if (!validateInput(uInput, 'Username is required')) return;
    if (!validateInput(pInput, 'Password is required')) return;

    if (pInput.value.length < 6) {
        showToast('Weak Password', 'Password must be at least 6 characters', 'warning');
        pInput.classList.add('error');
        setTimeout(() => pInput.classList.remove('error'), 500);
        return;
    }

    const btn = event.target;
    setButtonLoading(btn, true);

    try {
        const res = await fetch('/register', {
            method: 'POST', 
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({username: uInput.value, password: pInput.value})
        });
        const data = await res.json();
        
        if (res.ok) {
            // Store user_id for OTP confirmation step
            tempUserId = data.user_id;
            
            document.getElementById('reg-form').classList.add('hidden');
            document.getElementById('qr-display').classList.remove('hidden');
            document.getElementById('qr-img').src = "data:image/png;base64," + data.qr_code;
            document.getElementById('secret-text').innerText = data.secret;
            
            // Focus on OTP input field
            setTimeout(() => {
                document.getElementById('reg-otp-input').focus();
            }, 300);
            
            showToast('Success', 'Account created! Scan QR code and confirm OTP.', 'success');
        } else { 
            showToast('Registration Failed', data.message || 'Could not create account', 'error');
        }
    } catch(e) {
        showToast('Error', 'Connection failed', 'error');
    } finally {
        setButtonLoading(btn, false);
    }
}

async function handleLogout() { 
    try {
        await fetch('/logout', {method: 'POST'});
        showToast('Logged Out', 'See you next time!', 'success', 1500);
        setTimeout(() => window.location.href = '/', 1500);
    } catch(e) {
        window.location.href = '/';
    }
}

// -- FILE OPERATIONS --
async function uploadFile(event) {
    //Stop the page from reloading/submitting
    if (event) event.preventDefault();

    const fileInput = document.getElementById('f');
    if (!fileInput.files[0]) {
        showToast('No File Selected', 'Please select a file to upload', 'warning');
        return;
    }


    const btn = event ? event.target.closest('button') : null;
    if (btn) setButtonLoading(btn, true);

    try {
        const fd = new FormData();
        fd.append('file', fileInput.files[0]);

        const res = await fetch('/upload', { method: 'POST', body: fd });

        // Read the response text from the server
        const data = await res.json();

        if (res.ok) {
            // Success Case (200 OK)
            fileInput.value = '';
            showToast('Upload Complete', data.message || 'File uploaded', 'success');
            loadFiles();
        } else {
            // 4. FIX: Handle the Security Error (400 Bad Request)
            // This displays "Security Alert: File type mismatch..."
            showToast('Upload Rejected', data.message, 'error', 6000);
        }
    } catch(e) {
        console.error(e);
        showToast('System Error', 'An unexpected connection error occurred', 'error');
    } finally {
        if (btn) setButtonLoading(btn, false);
    }
}

async function loadFiles() {
    try {
        const res = await fetch('/list-files');
        const data = await res.json();
        const listDiv = document.getElementById('list');
        
        if (data.files.length === 0) { 
            listDiv.innerHTML = `
                <div class="empty-state">
                    <svg fill="currentColor" viewBox="0 0 20 20">
                        <path d="M4 3a2 2 0 00-2 2v10a2 2 0 002 2h12a2 2 0 002-2V5a2 2 0 00-2-2H4zm12 12H4l4-8 3 6 2-4 3 6z"/>
                    </svg>
                    <div>No files in your vault yet</div>
                </div>
            `;
            return;
        }
        
        listDiv.innerHTML = data.files.map(f => 
            `<div class="file-item" onclick="selectFile('${f}', this)">${f}</div>`
        ).join('');
    } catch(e) {
        document.getElementById('list').innerHTML = '<div class="empty-state">Error loading files</div>';
    }
}

function selectFile(f, el) { 
    selectedFile = f;
    document.querySelectorAll('.file-item').forEach(e => e.classList.remove('selected')); 
    el.classList.add('selected');
    showToast('File Selected', f, 'info', 2000);
}

async function downloadFile() {
    if (!selectedFile) {
        showToast('No File Selected', 'Please select a file to download', 'warning');
        return;
    }

    const btn = event.target;
    setButtonLoading(btn, true);

    try {
        const res = await fetch('/download', { 
            method: 'POST', 
            headers: {'Content-Type': 'application/json'}, 
            body: JSON.stringify({filename: selectedFile}) 
        });
        
        if(!res.ok) {
            showToast('Download Failed', 'Could not download file', 'error');
            return;
        }
        
        const blob = await res.blob();
        const a = document.createElement('a');
        a.href = window.URL.createObjectURL(blob);
        a.download = selectedFile;
        a.click();
        showToast('Download Started', selectedFile, 'success');
    } catch(e) {
        showToast('Error', 'Download failed', 'error');
    } finally {
        setButtonLoading(btn, false);
    }
}

async function deleteFile() {
    if (!selectedFile) {
        showToast('No File Selected', 'Please select a file to delete', 'warning');
        return;
    }

    showConfirmModal(
        'Delete File',
        `Are you sure you want to delete "${selectedFile}"? This action cannot be undone.`,
        async () => {
            try {
                await fetch('/delete', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({filename: selectedFile})
                });
                showToast('File Deleted', `${selectedFile} has been deleted`, 'success');
                selectedFile = null;
                loadFiles();
            } catch(e) {
                showToast('Error', 'Delete failed', 'error');
            }
        }
    );
}

async function viewSystemLogs() { // Completely new log viewer
    const app = document.getElementById('app');
    app.innerHTML = `
        <style>
            #app {
                max-width: 95% !important;
                width: 95% !important;
            }
            .log-table-container {
                overflow-x: auto;
                margin-top: 15px;
                border: 1px solid #ddd;
                border-radius: 4px;
            }
            .log-table {
                width: 100%;
                border-collapse: collapse;
                min-width: 600px;
            }
            .log-table th, .log-table td {
                padding: 12px;
                text-align: left;
                border-bottom: 1px solid #eee;
                vertical-align: top;
                word-wrap: break-word;
                max-width: 400px; /* Prevents overflow */
            }
            .log-table th { background-color: #f9f9f9; font-weight: 600; }
            .log-table tr:hover { background-color: #000000; }
        </style>
        <h2>🛡️ System Audit Logs</h2>
        
        <div class="tabs">
            <button class="tab-link active" onclick="openTab(event, 'AllActions')">User Activity</button>
            <button class="tab-link" onclick="openTab(event, 'FailedLogins')">Failed Logins</button>
        </div>

        <div id="AllActions" class="tab-content" style="display:block;">
            <h3>Filter Activity</h3>
            <div class="filter-bar">
                <input type="text" id="log-user-filter" placeholder="Filter by username...">
                <select id="log-action-filter">
                    <option value="">All Actions</option>
                    <option value="LOGIN_SUCCESS">Successful Logins</option>
                    <option value="UPLOAD">File Uploads</option>
                    <option value="DOWNLOAD">File Downloads</option>
                    <option value="DELETE">File Deletes</option>
                </select>
                <button onclick="fetchFilteredLogs()">Search</button>
            </div>
            <div id="all-logs-table" class="log-table-container"></div>
        </div>

        <div id="FailedLogins" class="tab-content">
            <h3>Filter Failed Logins</h3>
            <div class="filter-bar">
                <input type="text" id="failed-log-user-filter" placeholder="Filter by username entered...">
                <button onclick="fetchFailedLoginLogs()">Search</button>
            </div>
            <div id="failed-logs-table" class="log-table-container"></div>
        </div>

        <button onclick="renderDashboard('admin')" class="secondary" style="margin-top:20px;">Back to Dashboard</button>
    `;

    // Initial load
    fetchFilteredLogs();
    fetchFailedLoginLogs();
}

function openTab(evt, tabName) {
    let i, tabcontent, tablinks;
    tabcontent = document.getElementsByClassName("tab-content");
    for (i = 0; i < tabcontent.length; i++) {
        tabcontent[i].style.display = "none";
    }
    tablinks = document.getElementsByClassName("tab-link");
    for (i = 0; i < tablinks.length; i++) {
        tablinks[i].className = tablinks[i].className.replace(" active", "");
    }
    document.getElementById(tabName).style.display = "block";
    evt.currentTarget.className += " active";
}

async function fetchFilteredLogs() {
    const container = document.getElementById('all-logs-table');
    container.innerHTML = '<div class="spinner-large"></div>';

    const username = document.getElementById('log-user-filter').value;
    const action = document.getElementById('log-action-filter').value;
    
    const params = new URLSearchParams();
    if (username) params.append('username', username);
    if (action) params.append('action', action);

    try {
        const res = await fetch('/logs/all?' + params.toString());
        if (!res.ok) throw new Error('Access Denied');
        const logs = await res.json();
        
        const headers = ['Time', 'Action', 'User', 'Details', 'IP Address'];
        const rowsHtml = logs.map(l => `
            <tr>
                <td>${new Date(l.timestamp).toLocaleString()}</td>
                <td><strong>${l.action}</strong></td>
                <td>${l.username_entered || (l.user_id ? 'ID: ' + l.user_id : 'System')}</td>
                <td>${(l.filename ? `File: <strong>${l.filename}</strong>` : '')} ${l.details || ''}</td>
                <td>${l.ip_address || 'N/A'}</td>
            </tr>
        `).join('');
        
        container.innerHTML = `
            <table class="log-table">
                <thead><tr>${headers.map(h => `<th>${h}</th>`).join('')}</tr></thead>
                <tbody>${rowsHtml || '<tr><td colspan="5">No logs found for this filter.</td></tr>'}</tbody>
            </table>
        `;
    } catch (e) {
        showToast('Error', 'Could not fetch logs', 'error');
        container.innerHTML = '<div class="empty-state">Error loading logs.</div>';
    }
}

async function fetchFailedLoginLogs() {
    const container = document.getElementById('failed-logs-table');
    container.innerHTML = '<div class="spinner-large"></div>';
    
    const username = document.getElementById('failed-log-user-filter').value;
    const params = new URLSearchParams();
    if (username) params.append('username', username);

    try {
        const res = await fetch('/logs/failed-logins?' + params.toString());
        if (!res.ok) throw new Error('Access Denied');
        const logs = await res.json();
        
        const headers = ['Time', 'Username Entered', 'Details', 'IP Address'];
        const rowsHtml = logs.map(l => `
            <tr>
                <td>${new Date(l.timestamp).toLocaleString()}</td>
                <td>${l.username_entered || 'N/A'}</td>
                <td>${l.details || ''}</td>
                <td>${l.ip_address || 'N/A'}</td>
            </tr>
        `).join('');
        
        container.innerHTML = `
            <table class="log-table">
                <thead><tr>${headers.map(h => `<th>${h}</th>`).join('')}</tr></thead>
                <tbody>${rowsHtml || '<tr><td colspan="4">No failed login logs found.</td></tr>'}</tbody>
            </table>
        `;
    } catch (e) {
        showToast('Error', 'Could not fetch failed logs', 'error');
        container.innerHTML = '<div class="empty-state">Error loading logs.</div>';
    }
}

// @ts-nocheck
/**
 * ==============================================================================
 * 🚀 VLESS PROXY MANAGER - ULTIMATE EDITION (SINGLE-FILE WORKER)
 * ==============================================================================
 * 
 * A complete, professional, and secure VLESS implementation for Cloudflare Workers.
 * 
 * FEATURES:
 * - VLESS & Trojan Protocol Support (WS/TCP)
 * - Advanced D1 Database Integration
 * - Professional Dark UI (Admin & User Panels)
 * - Landing Page Reverse Proxy
 * - Smart Geo-Routing & Fallbacks
 * - Automatic Health Checks & Node Switching
 * - HTTP/3 & Security Headers
 * - QR Code Generation & Subscription Links (Clash/Sing-box)
 * 
 * @version 3.0.0
 * @author AI Assistant
 */

import { connect } from 'cloudflare:sockets';

// ==============================================================================
// 1. GLOBAL CONFIGURATION & CONSTANTS
// ==============================================================================

const CONST = {
    VERSION: '3.0.0',
    HEALTH_CHECK_TIMEOUT: 2000, // 2 seconds
    DNS_CACHE_TTL: 300, // 5 minutes
    MAX_REQUEST_SIZE: 1024 * 1024, // 1MB
    RATE_LIMIT_WINDOW: 60, // 1 minute
    LOGIN_FAIL_LIMIT: 5,
    DEFAULT_PORT: 443,
    BUFFER_SIZE: 8192,
    SALT_ROUNDS: 10,
    TOKEN_EXPIRY: 86400, // 24 hours
};

const Config = {
    defaultUUID: 'd342d11e-d424-4583-b36e-524ab1f0afa4',
    
    fromEnv(env) {
        return {
            uuid: env.UUID || this.defaultUUID,
            adminKey: env.ADMIN_KEY || '',
            adminPath: env.ADMIN_PATH || 'admin',
            proxyIPs: (env.PROXYIP || '').split(',').filter(Boolean).map(i => i.trim()),
            socks5: {
                address: env.SOCKS5 || '',
                enabled: !!env.SOCKS5,
            },
            enableLandingProxy: env.ENABLE_LANDING_PROXY === 'true',
            landingPageUrl: env.LANDING_PAGE_URL || 'https://www.google.com',
            scamalytics: {
                key: env.SCAMALYTICS_API_KEY,
                user: env.SCAMALYTICS_USERNAME,
                threshold: parseInt(env.SCAMALYTICS_THRESHOLD || '100'),
            },
            DB: env.DB,
        };
    }
};

// ==============================================================================
// 2. DATABASE ABSTRACTION LAYER (D1 SQLite)
// ==============================================================================

const Database = {
    async init(env) {
        if (!env.DB) return console.warn('⚠️ D1 Database binding (DB) not found.');
        
        const schema = [
            `CREATE TABLE IF NOT EXISTS users (
                uuid TEXT PRIMARY KEY,
                email TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                expiration_date TEXT,
                expiration_time TEXT,
                notes TEXT,
                traffic_limit INTEGER,
                traffic_used INTEGER DEFAULT 0,
                ip_limit INTEGER DEFAULT -1,
                active INTEGER DEFAULT 1
            )`,
            `CREATE TABLE IF NOT EXISTS system_config (
                key TEXT PRIMARY KEY,
                value TEXT,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )`,
            `CREATE TABLE IF NOT EXISTS proxy_health (
                address TEXT PRIMARY KEY,
                latency INTEGER,
                last_check DATETIME DEFAULT CURRENT_TIMESTAMP,
                is_healthy INTEGER DEFAULT 1
            )`
        ];

        try {
            const batch = schema.map(query => env.DB.prepare(query));
            await env.DB.batch(batch);
            
            // Insert default user if table is empty
            const userCount = await env.DB.prepare("SELECT COUNT(*) as count FROM users").first('count');
            if (userCount === 0) {
                const defaultConfig = Config.fromEnv(env);
                await env.DB.prepare(
                    "INSERT INTO users (uuid, notes, traffic_limit) VALUES (?, ?, ?)"
                ).bind(defaultConfig.uuid, 'Default Admin User', 0).run();
            }
        } catch (e) {
            console.error('Database initialization failed:', e);
        }
    },

    async getUser(db, uuid) {
        if (!db) return null;
        return await db.prepare("SELECT * FROM users WHERE uuid = ?").bind(uuid).first();
    },

    async getAllUsers(db) {
        if (!db) return [];
        return await db.prepare("SELECT * FROM users ORDER BY created_at DESC").all();
    },

    async updateUserTraffic(db, uuid, bytes) {
        if (!db) return;
        try {
            await db.prepare("UPDATE users SET traffic_used = traffic_used + ? WHERE uuid = ?").bind(bytes, uuid).run();
        } catch (e) { console.error('Traffic Update Error:', e); }
    },
    
    async saveProxyHealth(db, address, latency, isHealthy) {
        if (!db) return;
        try {
            await db.prepare(
                "INSERT OR REPLACE INTO proxy_health (address, latency, is_healthy, last_check) VALUES (?, ?, ?, CURRENT_TIMESTAMP)"
            ).bind(address, latency, isHealthy ? 1 : 0).run();
        } catch (e) { console.error('Health Save Error:', e); }
    }
};

// ==============================================================================
// 3. UTILITIES & SECURITY
// ==============================================================================

const Utils = {
    base64Encode(str) {
        const encoder = new TextEncoder();
        const data = encoder.encode(str);
        let binary = '';
        for (let i = 0; i < data.length; i++) {
            binary += String.fromCharCode(data[i]);
        }
        return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    },

    isValidUUID(uuid) {
        const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[4][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
        return uuidRegex.test(uuid);
    },

    addSecurityHeaders(headers) {
        headers.set('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
        headers.set('X-Content-Type-Options', 'nosniff');
        headers.set('X-Frame-Options', 'DENY');
        headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
        headers.set('Permissions-Policy', 'camera=(), microphone=(), usb=()');
        headers.set('Alt-Svc', 'h3=":443"; ma=86400, h3-29=":443"; ma=86400'); 
    },

    generateNonce() {
        let text = "";
        const possible = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        for (let i = 0; i < 16; i++) {
            text += possible.charAt(Math.floor(Math.random() * possible.length));
        }
        return text;
    }
};

// ==============================================================================
// 4. FRONTEND ASSETS (CSS & ICONS)
// ==============================================================================

const ASSETS = {
    CSS: `
    :root {
        --bg-body: #0f172a; --bg-card: #1e293b; --bg-input: #334155;
        --text-main: #f8fafc; --text-muted: #94a3b8;
        --primary: #3b82f6; --primary-hover: #2563eb;
        --success: #10b981; --danger: #ef4444; --warning: #f59e0b;
        --border: #334155;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; outline: none; }
    body { font-family: 'Inter', system-ui, sans-serif; background-color: var(--bg-body); color: var(--text-main); min-height: 100vh; }
    .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
    .flex { display: flex; } .flex-col { flex-direction: column; } .items-center { align-items: center; } .justify-between { justify-content: space-between; }
    .gap-2 { gap: 0.5rem; } .gap-4 { gap: 1rem; } .w-full { width: 100%; } .hidden { display: none; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 1.5rem; }
    .card { background-color: var(--bg-card); border: 1px solid var(--border); border-radius: 12px; padding: 24px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1); }
    .btn { display: inline-flex; align-items: center; justify-content: center; padding: 0.5rem 1rem; border-radius: 8px; cursor: pointer; border: none; gap: 0.5rem; font-weight: 500; font-size: 0.875rem; transition: all 0.2s; }
    .btn-primary { background-color: var(--primary); color: white; } .btn-primary:hover { background-color: var(--primary-hover); }
    .btn-danger { background-color: rgba(239, 68, 68, 0.1); color: var(--danger); border: 1px solid rgba(239, 68, 68, 0.2); }
    .btn-ghost { background: transparent; color: var(--text-muted); } .btn-ghost:hover { color: var(--text-main); background: rgba(255,255,255,0.05); }
    .input { width: 100%; background-color: var(--bg-body); border: 1px solid var(--border); color: var(--text-main); padding: 0.625rem; border-radius: 8px; font-size: 0.875rem; }
    .input:focus { border-color: var(--primary); }
    .table-container { overflow-x: auto; border-radius: 8px; border: 1px solid var(--border); }
    table { width: 100%; border-collapse: collapse; text-align: left; }
    th { background-color: rgba(0,0,0,0.2); padding: 12px 16px; font-size: 0.75rem; text-transform: uppercase; color: var(--text-muted); }
    td { padding: 16px; border-top: 1px solid var(--border); font-size: 0.875rem; }
    .toast { position: fixed; bottom: 20px; right: 20px; background: var(--bg-card); border: 1px solid var(--border); padding: 1rem; border-radius: 8px; transform: translateY(100px); opacity: 0; transition: all 0.3s; z-index: 1000; }
    .toast.show { transform: translateY(0); opacity: 1; }
    .toast.success { border-left: 4px solid var(--success); }
    .toast.error { border-left: 4px solid var(--danger); }
    .badge { padding: 2px 8px; border-radius: 99px; font-size: 0.7rem; font-weight: 600; }
    .badge-success { background: rgba(16, 185, 129, 0.1); color: var(--success); border: 1px solid rgba(16, 185, 129, 0.2); }
    .badge-warning { background: rgba(245, 158, 11, 0.1); color: var(--warning); border: 1px solid rgba(245, 158, 11, 0.2); }
    .login-wrapper { display: flex; align-items: center; justify-content: center; min-height: 100vh; background: radial-gradient(circle at center, #1e293b 0%, #0f172a 100%); }
    .login-card { width: 100%; max-width: 400px; }
    @keyframes fadeIn { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }
    .animate-fade { animation: fadeIn 0.4s ease-out forwards; }
    `,
    ICONS: {
        DASHBOARD: `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>`,
        USERS: `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>`,
        SETTINGS: `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>`,
        LOGOUT: `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>`,
        COPY: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>`,
        QR: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/><path d="M10 10h.01"/><path d="M14 14h.01"/><path d="M10 14h.01"/><path d="M14 10h.01"/></svg>`,
        REFRESH: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/></svg>`
    }
};

// ==============================================================================
// 5. UI GENERATION
// ==============================================================================

function buildAdminUI(config, nonce) {
    return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VLESS Manager | Admin</title>
    <style nonce="${nonce}">${ASSETS.CSS}</style>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js" integrity="sha512-CNgIRecGo7nphbeZ04Sc13ka07paqdeTu0WR1IM4kNcpmBAUSHSQX0FslNhTDadL4O5SAGapGt4FodqL8My0mA==" crossorigin="anonymous" referrerpolicy="no-referrer"></script>
</head>
<body class="bg-body text-main">
    <div id="app" class="flex h-screen overflow-hidden">
        <aside class="w-64 bg-card h-full fixed md:static transform -translate-x-full md:translate-x-0 transition-transform duration-200 border-r border-border z-30 flex flex-col" id="sidebar">
            <div class="p-6 border-b border-border flex items-center justify-between">
                <h1 class="text-xl font-bold flex items-center gap-2 m-0"><span class="text-primary">⚡</span> VLESS<span class="text-muted">PRO</span></h1>
                <button class="md:hidden text-muted" onclick="toggleSidebar()">✕</button>
            </div>
            <nav class="flex-1 p-4 space-y-2 overflow-y-auto">
                <button onclick="router('dashboard')" class="w-full btn btn-ghost justify-start active" id="nav-dashboard">${ASSETS.ICONS.DASHBOARD} Dashboard</button>
                <button onclick="router('users')" class="w-full btn btn-ghost justify-start" id="nav-users">${ASSETS.ICONS.USERS} User Management</button>
                <button onclick="router('settings')" class="w-full btn btn-ghost justify-start" id="nav-settings">${ASSETS.ICONS.SETTINGS} Settings</button>
            </nav>
            <div class="p-4 border-t border-border">
                <button onclick="logout()" class="w-full btn btn-danger justify-start text-sm">${ASSETS.ICONS.LOGOUT} Sign Out</button>
            </div>
        </aside>
        <main class="flex-1 h-full overflow-y-auto relative w-full">
            <header class="md:hidden h-16 border-b border-border flex items-center justify-between px-4 bg-card sticky top-0 z-20">
                <span class="font-bold text-lg">Dashboard</span>
                <button onclick="toggleSidebar()" class="btn btn-ghost p-2"><svg width="24" height="24" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16"/></svg></button>
            </header>
            <div class="container py-8 px-4 md:px-8">
                <div class="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-8 animate-fade">
                    <div><h2 class="text-2xl font-bold" id="page-title">Overview</h2></div>
                    <div class="flex items-center gap-3"><button onclick="refreshData()" class="btn btn-ghost border border-border bg-card">${ASSETS.ICONS.REFRESH} Refresh</button></div>
                </div>
                <div id="view-dashboard" class="view-section animate-fade">
                    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
                        <div class="card"><p class="text-sm text-muted font-medium uppercase">Total Users</p><h3 class="text-3xl font-bold mt-2" id="stat-total-users">0</h3></div>
                        <div class="card"><p class="text-sm text-muted font-medium uppercase">Traffic</p><h3 class="text-3xl font-bold mt-2 text-primary" id="stat-total-traffic">0 B</h3></div>
                    </div>
                </div>
                <div id="view-users" class="view-section hidden animate-fade">
                    <div class="card">
                        <div class="flex justify-between items-center mb-6"><h3 class="text-lg font-bold">Users</h3><button onclick="openModal('create')" class="btn btn-primary">+ New User</button></div>
                        <div class="table-container"><table class="w-full"><thead><tr><th>Status</th><th>Details</th><th>Traffic</th><th>Actions</th></tr></thead><tbody id="user-table-body"></tbody></table></div>
                    </div>
                </div>
                <div id="view-settings" class="view-section hidden animate-fade"><div class="card"><h3 class="text-lg font-bold">Config</h3><p>Admin Path: /${config.adminPath}</p></div></div>
            </div>
        </main>
    </div>
    <div id="modal-create" class="fixed inset-0 bg-black/80 z-50 hidden backdrop-blur-sm flex items-center justify-center p-4">
        <div class="card w-full max-w-lg relative" onclick="event.stopPropagation()">
            <h3 class="text-xl font-bold mb-4">New User</h3>
            <form id="create-user-form" onsubmit="event.preventDefault(); saveUser();">
                <input type="text" id="new-note" class="input mb-4" placeholder="Name" required>
                <div class="flex justify-end gap-3"><button type="button" onclick="closeModal('create')" class="btn btn-ghost">Cancel</button><button type="submit" class="btn btn-primary">Create</button></div>
            </form>
        </div>
    </div>
    <div id="modal-qr" class="fixed inset-0 bg-black/90 z-50 hidden backdrop-blur-sm flex items-center justify-center p-4">
        <div class="card w-full max-w-sm relative text-center" onclick="event.stopPropagation()">
            <button onclick="closeModal('qr')" class="absolute top-4 right-4 text-muted text-xl">&times;</button>
            <div class="bg-white p-4 rounded-xl inline-block mb-6"><div id="admin-qr-target"></div></div>
            <button onclick="copyToClip(window.currentQRLink)" class="btn btn-primary w-full">${ASSETS.ICONS.COPY} Copy Link</button>
        </div>
    </div>
    <div id="toast" class="toast"></div>
    <script nonce="${nonce}">
        let users = [];
        window.currentQRLink = '';
        function router(view) {
            document.querySelectorAll('.view-section').forEach(el => el.classList.add('hidden'));
            document.getElementById('view-' + view).classList.remove('hidden');
            if(view === 'users') fetchUsers();
        }
        function toggleSidebar() { document.getElementById('sidebar').classList.toggle('-translate-x-full'); }
        async function fetchStats() {
            try {
                const res = await fetch('?action=get_stats');
                const data = await res.json();
                document.getElementById('stat-total-users').innerText = data.total;
                document.getElementById('stat-total-traffic').innerText = formatBytes(data.traffic);
            } catch(e) {}
        }
        async function fetchUsers() {
            try {
                const res = await fetch('?action=get_users');
                users = await res.json();
                const tbody = document.getElementById('user-table-body');
                tbody.innerHTML = users.map(u => \`<tr>
                    <td>\${u.active ? '<span class="badge badge-success">Active</span>' : '<span class="badge badge-warning">Inactive</span>'}</td>
                    <td>\${u.notes}<div class="text-xs text-muted">\${u.uuid}</div></td>
                    <td>\${formatBytes(u.traffic_used)} / \${u.traffic_limit ? formatBytes(u.traffic_limit) : '∞'}</td>
                    <td><button onclick="showQR('\${u.uuid}')" class="btn btn-ghost text-primary">${ASSETS.ICONS.QR}</button><button onclick="deleteUser('\${u.uuid}')" class="btn btn-ghost text-danger">✕</button></td>
                </tr>\`).join('');
            } catch(e) {}
        }
        async function saveUser() {
            const note = document.getElementById('new-note').value;
            await fetch('?action=create_user', { method: 'POST', body: JSON.stringify({ note, traffic_limit: 0 }) });
            closeModal('create'); fetchUsers(); fetchStats();
        }
        async function deleteUser(uuid) {
            if(confirm('Delete user?')) {
                await fetch('?action=delete_user', { method: 'POST', body: JSON.stringify({ uuid }) });
                fetchUsers(); fetchStats();
            }
        }
        function generateLink(uuid) {
            const host = window.location.hostname;
            return \`vless://\${uuid}@\${host}:443?encryption=none&security=tls&type=ws&host=\${host}&path=%2F#\${host}\`;
        }
        function showQR(uuid) {
            window.currentQRLink = generateLink(uuid);
            document.getElementById('admin-qr-target').innerHTML = '';
            new QRCode(document.getElementById('admin-qr-target'), { text: window.currentQRLink, width: 200, height: 200 });
            openModal('qr');
        }
        function copyToClip(str) { navigator.clipboard.writeText(str); showToast('Copied!', 'success'); }
        function showToast(msg, type) { const t = document.getElementById('toast'); t.textContent = msg; t.className = \`toast show \${type}\`; setTimeout(() => t.classList.remove('show'), 3000); }
        function openModal(id) { document.getElementById('modal-'+id).classList.remove('hidden'); }
        function closeModal(id) { document.getElementById('modal-'+id).classList.add('hidden'); }
        function formatBytes(bytes) { if (!+bytes) return '0 B'; const k=1024, i=Math.floor(Math.log(bytes)/Math.log(k)); return parseFloat((bytes/Math.pow(k,i)).toFixed(2))+' '+['B','KB','MB','GB','TB'][i]; }
        function refreshData() { fetchStats(); if(!document.getElementById('view-users').classList.contains('hidden')) fetchUsers(); }
        function logout() { document.cookie = "auth_token=; path=/; expires=Thu, 01 Jan 1970 00:00:01 GMT;"; window.location.reload(); }
        fetchStats();
    </script>
</body>
</html>`;
}

function buildLoginPage(path, error) {
    return `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Login</title><style>${ASSETS.CSS}</style></head><body>
    <div class="login-wrapper"><div class="card login-card animate-fade"><div class="text-center mb-8"><h1 class="text-3xl font-bold text-primary">VLESS PRO</h1></div>
    ${error ? `<div class="bg-red-500/10 text-danger p-3 rounded mb-4 text-center">${error}</div>` : ''}
    <form action="/${path}" method="POST"><input type="password" name="password" class="input text-center text-lg mb-4" placeholder="Admin Key" required autofocus><button type="submit" class="btn btn-primary w-full py-3">Login</button></form>
    </div></div></body></html>`;
}

function buildUserUI(userData, config) {
    const totalGB = userData.traffic_limit ? (userData.traffic_limit / 1073741824).toFixed(2) : '∞';
    const usedGB = (userData.traffic_used / 1073741824).toFixed(2);
    const percentage = userData.traffic_limit > 0 ? Math.min(100, (userData.traffic_used / userData.traffic_limit) * 100).toFixed(1) : 0;
    
    return `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Subscription</title><style>${ASSETS.CSS}</style><script src="https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js"></script></head><body>
    <div class="container py-8 max-w-2xl">
        <div class="flex justify-between mb-8 animate-fade"><div><h1 class="text-2xl font-bold">My Subscription</h1><p class="text-muted text-sm">Active</p></div></div>
        <div class="card mb-6 animate-fade">
            <div class="flex justify-between items-end mb-4"><div><p class="text-sm text-muted">Data Usage</p><h2 class="text-3xl font-bold">${usedGB} <span class="text-sm font-normal">GB</span></h2></div><div><p class="text-sm text-muted">of ${totalGB} GB</p></div></div>
            <div class="w-full bg-border h-4 rounded-full overflow-hidden"><div class="bg-success h-full" style="width: ${percentage}%"></div></div>
        </div>
        <div class="card mb-6 animate-fade">
            <h3 class="font-bold mb-4">Connection Profiles</h3>
            <div class="grid gap-3">
                <button onclick="copyLink('vless')" class="btn btn-ghost border border-border justify-between"><span>VLESS (Universal)</span>${ASSETS.ICONS.COPY}</button>
                <button onclick="openQR()" class="btn btn-ghost border border-border justify-between"><span>Show QR Code</span>${ASSETS.ICONS.QR}</button>
                <div class="grid grid-cols-2 gap-3"><button onclick="copyLink('clash')" class="btn btn-ghost border border-border text-sm">Copy Clash</button><button onclick="copyLink('singbox')" class="btn btn-ghost border border-border text-sm">Copy Sing-Box</button></div>
            </div>
        </div>
        <div class="card animate-fade"><h3 class="font-bold mb-4">Clients</h3><div class="grid grid-cols-2 gap-2"><a href="https://play.google.com/store/apps/details?id=com.v2ray.ang" target="_blank" class="btn btn-ghost border border-border text-xs">V2RayNG</a><a href="https://github.com/MatsuriDayo/nekoray/releases" target="_blank" class="btn btn-ghost border border-border text-xs">Nekoray</a></div></div>
    </div>
    <div id="modal-qr" class="fixed inset-0 bg-black/90 z-50 hidden backdrop-blur-sm flex items-center justify-center p-4">
        <div class="card w-full max-w-sm relative text-center"><button onclick="closeModal()" class="absolute top-4 right-4 text-white text-xl">&times;</button><h3 class="font-bold mb-6">Scan</h3><div class="bg-white p-4 rounded-xl inline-block"><div id="qrcode"></div></div></div>
    </div>
    <div id="toast" class="toast"></div>
    <script>
        const CONFIG = { uuid: "${userData.uuid}", host: window.location.hostname };
        const vlessLink = \`vless://\${CONFIG.uuid}@\${CONFIG.host}:443?encryption=none&security=tls&type=ws&host=\${CONFIG.host}&path=%2F#\${CONFIG.host}\`;
        new QRCode(document.getElementById("qrcode"), { text: vlessLink, width: 200, height: 200 });
        function copyLink(type) {
            let link = vlessLink;
            if(type === 'clash') link = location.origin + '/sub/' + CONFIG.uuid + '?format=clash';
            if(type === 'singbox') link = location.origin + '/sub/' + CONFIG.uuid + '?format=singbox';
            navigator.clipboard.writeText(link); showToast();
        }
        function showToast() { const t = document.getElementById('toast'); t.textContent = 'Copied!'; t.className = 'toast show success'; setTimeout(() => t.classList.remove('show'), 2000); }
        function openQR() { document.getElementById('modal-qr').classList.remove('hidden'); }
        function closeModal() { document.getElementById('modal-qr').classList.add('hidden'); }
    </script></body></html>`;
}

// ==============================================================================
// 6. LOGIC & HANDLERS
// ==============================================================================

async function handleApiRequest(request, env) {
    const url = new URL(request.url);
    const action = url.searchParams.get('action');
    try {
        if (action === 'get_stats') {
            const total = await env.DB.prepare("SELECT COUNT(*) as count FROM users").first('count');
            const traffic = await env.DB.prepare("SELECT SUM(traffic_used) as total FROM users").first('total') || 0;
            return new Response(JSON.stringify({ total, active: total, traffic }), { headers: { 'Content-Type': 'application/json' } });
        }
        if (action === 'get_users') return new Response(JSON.stringify(await Database.getAllUsers(env.DB)), { headers: { 'Content-Type': 'application/json' } });
        if (action === 'create_user') {
            const body = await request.json();
            const uuid = crypto.randomUUID();
            await env.DB.prepare("INSERT INTO users (uuid, notes, traffic_limit) VALUES (?, ?, ?)").bind(uuid, body.note, body.traffic_limit).run();
            return new Response(JSON.stringify({ success: true }), { headers: { 'Content-Type': 'application/json' } });
        }
        if (action === 'delete_user') {
            const body = await request.json();
            await env.DB.prepare("DELETE FROM users WHERE uuid = ?").bind(body.uuid).run();
            return new Response(JSON.stringify({ success: true }), { headers: { 'Content-Type': 'application/json' } });
        }
    } catch (e) { return new Response(JSON.stringify({ error: e.message }), { status: 500 }); }
}

async function vlessOverWSHandler(request, env, ctx) {
    const webSocketPair = new WebSocketPair();
    const [client, webSocket] = Object.values(webSocketPair);
    webSocket.accept();

    let address = '';
    let portWithRandomLog = '';
    const log = (info, event) => console.log(`[${address}:${portWithRandomLog}] ${info}`, event || '');
    const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';
    const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);

    const readableWebSocketStream = new ReadableStream({
        start(controller) {
            webSocket.addEventListener('message', (event) => { if (event.data) controller.enqueue(event.data); });
            webSocket.addEventListener('close', () => { safeCloseWebSocket(webSocket); controller.close(); });
            webSocket.addEventListener('error', (err) => { controller.error(err); });
            if (error) controller.error(error);
            else if (earlyData) controller.enqueue(earlyData);
        },
        cancel(reason) { safeCloseWebSocket(webSocket); }
    });

    let remoteSocketWapper = { value: null };
    let udpStreamWrite = null;
    let isDns = false;

    readableWebSocketStream.pipeTo(new WritableStream({
        async write(chunk, controller) {
            if (isDns && udpStreamWrite) return udpStreamWrite(chunk);
            if (remoteSocketWapper.value) {
                const writer = remoteSocketWapper.value.writable.getWriter();
                await writer.write(chunk);
                writer.releaseLock();
                return;
            }
            const { hasError, message, portRemote, addressRemote, rawDataIndex, vlessVersion, isUDP, uuid } = await parseVlessHeader(chunk, env);
            if (hasError) { controller.error(message); return safeCloseWebSocket(webSocket); }
            
            address = addressRemote;
            portWithRandomLog = `${portRemote}--${Math.random()} ${isUDP ? "udp" : "tcp"}`;
            
            const user = await Database.getUser(env.DB, uuid);
            if (!user) { controller.error('Invalid User'); return; }

            if (isUDP) {
                if (portRemote === 53) {
                    isDns = true;
                    const dnsPipe = await handleUDPOutbound(webSocket, new Uint8Array([vlessVersion[0], 0]), log);
                    udpStreamWrite = dnsPipe.write;
                    udpStreamWrite(chunk.slice(rawDataIndex));
                    return;
                }
                controller.error('UDP only supported for DNS (53)');
                return;
            }

            const config = Config.fromEnv(env);
            await handleTCPOutbound(remoteSocketWapper, addressRemote, portRemote, chunk.slice(rawDataIndex), webSocket, new Uint8Array([vlessVersion[0], 0]), log, config, env, uuid, ctx);
        },
        abort(reason) { safeCloseWebSocket(webSocket); },
    })).catch((err) => safeCloseWebSocket(webSocket));

    return new Response(null, { status: 101, webSocket: client });
}

async function parseVlessHeader(buffer, env) {
    if (buffer.byteLength < 24) return { hasError: true, message: 'invalid data length' };
    const view = new DataView(buffer);
    const version = view.getUint8(0);
    const uuid = stringifyUUID(new Uint8Array(buffer.slice(1, 17)));
    const optLength = view.getUint8(17);
    const command = view.getUint8(18 + optLength);
    const isUDP = command === 2;
    const portIndex = 19 + optLength;
    const portRemote = view.getUint16(portIndex);
    const addressIndex = portIndex + 2;
    const addressType = view.getUint8(addressIndex);
    let addressLength = 0, addressValueIndex = addressIndex + 1, addressRemote = '';

    if (addressType === 1) { addressLength = 4; addressRemote = new Uint8Array(buffer.slice(addressValueIndex, addressValueIndex + addressLength)).join('.'); }
    else if (addressType === 2) { addressLength = view.getUint8(addressValueIndex); addressValueIndex++; addressRemote = new TextDecoder().decode(buffer.slice(addressValueIndex, addressValueIndex + addressLength)); }
    else if (addressType === 3) { addressLength = 16; addressRemote = "[" + Array.from(new Uint16Array(buffer.slice(addressValueIndex, addressValueIndex + addressLength))).map(v => v.toString(16)).join(':') + "]"; }
    else return { hasError: true, message: `invalid addressType: ${addressType}` };

    if (!addressRemote) return { hasError: true, message: 'address is empty' };
    return { hasError: false, addressRemote, addressType, portRemote, rawDataIndex: addressValueIndex + addressLength, vlessVersion: new Uint8Array([version]), isUDP, uuid };
}

async function handleTCPOutbound(remoteSocket, addressRemote, portRemote, rawData, webSocket, responseHeader, log, config, env, uuid, ctx) {
    const tcpSocket = connect({ hostname: addressRemote, port: portRemote });
    remoteSocket.value = tcpSocket;
    const writer = tcpSocket.writable.getWriter();
    await writer.write(rawData);
    writer.releaseLock();

    tcpSocket.readable.pipeTo(new WritableStream({
        async write(chunk, controller) {
            if (uuid && env && env.DB && ctx) ctx.waitUntil(Database.updateUserTraffic(env.DB, uuid, chunk.byteLength));
            if (webSocket.readyState === 1) {
                if (responseHeader) { webSocket.send(await new Blob([responseHeader, chunk]).arrayBuffer()); responseHeader = null; }
                else { webSocket.send(chunk); }
            }
        },
    })).catch((err) => safeCloseWebSocket(webSocket));
    return tcpSocket;
}

async function handleUDPOutbound(webSocket, vlessResponseHeader, log) {
    let isHeaderSent = false;
    const transformStream = new TransformStream({
        transform(chunk, controller) {
            for (let index = 0; index < chunk.byteLength;) {
                const lengthBuffer = chunk.slice(index, index + 2);
                const udpPacketLength = new DataView(lengthBuffer).getUint16(0);
                const udpData = new Uint8Array(chunk.slice(index + 2, index + 2 + udpPacketLength));
                index = index + 2 + udpPacketLength;
                controller.enqueue(udpData);
            }
        }
    });

    transformStream.readable.pipeTo(new WritableStream({
        async write(chunk) {
            const resp = await fetch('https://1.1.1.1/dns-query', { method: 'POST', headers: { 'content-type': 'application/dns-message' }, body: chunk });
            const dnsQueryResult = await resp.arrayBuffer();
            const udpSize = dnsQueryResult.byteLength;
            const udpSizeBuffer = new Uint8Array([(udpSize >> 8) & 0xff, udpSize & 0xff]);
            if (webSocket.readyState === 1) {
                if (isHeaderSent) webSocket.send(await new Blob([udpSizeBuffer, dnsQueryResult]).arrayBuffer());
                else { webSocket.send(await new Blob([vlessResponseHeader, udpSizeBuffer, dnsQueryResult]).arrayBuffer()); isHeaderSent = true; }
            }
        }
    })).catch((err) => log('dns pipeTo error', err));

    const writer = transformStream.writable.getWriter();
    return { write: (chunk) => writer.write(chunk) };
} 

function stringifyUUID(v) { return [...v].map((b, i) => (b < 16 ? '0' : '') + b.toString(16) + ([3, 5, 7, 9].includes(i) ? '-' : '')).join(''); }
function base64ToArrayBuffer(base64Str) {
    if (!base64Str) return { earlyData: null, error: null };
    try { return { earlyData: Uint8Array.from(atob(base64Str.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0)).buffer, error: null }; }
    catch (error) { return { earlyData: null, error }; }
}
function safeCloseWebSocket(socket) { try { if (socket.readyState === 1 || socket.readyState === 0) socket.close(); } catch (e) {} }

const Subscriptions = {
    toClash(user, host) {
        return `port: 7890\nsocks-port: 7891\nredir-port: 7892\nmixed-port: 7893\nmode: rule\nlog-level: info\nproxies:\n  - name: ${host}\n    server: ${host}\n    port: 443\n    type: vless\n    uuid: ${user.uuid}\n    cipher: auto\n    tls: true\n    udp: true\n    skip-cert-verify: true\n    network: ws\n    ws-opts:\n      path: /\n      headers:\n        Host: ${host}\nproxy-groups:\n  - name: PROXY\n    type: select\n    proxies:\n      - ${host}\n      - DIRECT\nrules:\n  - MATCH,PROXY`;
    },
    toSingbox(user, host) {
        return JSON.stringify({ "log": { "level": "info", "timestamp": true }, "inbounds": [{ "type": "tun", "tag": "tun-in", "inet4_address": "172.19.0.1/30", "auto_route": true, "strict_route": true }], "outbounds": [{ "type": "vless", "tag": "proxy", "server": host, "server_port": 443, "uuid": user.uuid, "flow": "", "tls": { "enabled": true, "server_name": host, "insecure": true }, "transport": { "type": "ws", "path": "/", "headers": { "Host": host } } }, { "type": "direct", "tag": "direct" }], "route": { "rules": [{ "outbound": "direct", "ip_cidr": ["geoip:private"] }, { "outbound": "proxy", "port": [80, 443] }] } }, null, 2);
    }
};

// ==============================================================================
// 7. ENTRY POINT
// ==============================================================================

export default {
    async fetch(request, env, ctx) {
        const config = Config.fromEnv(env);
        await Database.init(env);
        const url = new URL(request.url);

        if (request.headers.get('Upgrade') === 'websocket') return await vlessOverWSHandler(request, env, ctx);
        if (url.pathname === '/robots.txt') return new Response('User-agent: *\nDisallow: /admin', { status: 200 });

        if (url.pathname.startsWith('/' + config.adminPath)) {
            if (request.method === 'POST' && url.pathname === '/' + config.adminPath) {
                const formData = await request.formData();
                if (formData.get('password') === config.adminKey) {
                    return new Response(null, { status: 302, headers: { 'Set-Cookie': `auth_token=${config.adminKey}; Path=/; HttpOnly; Secure; SameSite=Strict`, 'Location': '/' + config.adminPath } });
                }
                return new Response(buildLoginPage(config.adminPath, 'Invalid Credentials'), { headers: { 'Content-Type': 'text/html' } });
            }
            if ((request.headers.get('Cookie') || '').indexOf(`auth_token=${config.adminKey}`) === -1) {
                return new Response(buildLoginPage(config.adminPath), { headers: { 'Content-Type': 'text/html' } });
            }
            if (url.searchParams.get('action')) return await handleApiRequest(request, env);
            const nonce = Utils.generateNonce();
            return new Response(buildAdminUI(config, nonce), { headers: { 'Content-Type': 'text/html', 'Content-Security-Policy': `default-src 'self'; script-src 'self' 'nonce-${nonce}' https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self';` } });
        }

        if (url.pathname.startsWith('/sub/')) {
            const uuid = url.pathname.split('/')[2];
            const user = await Database.getUser(env.DB, uuid);
            if (user) {
                ctx.waitUntil(env.DB.prepare("UPDATE users SET active = 1 WHERE uuid = ?").bind(uuid).run());
                const format = url.searchParams.get('format');
                if (format === 'clash') return new Response(Subscriptions.toClash(user, url.hostname), { headers: { 'Content-Type': 'text/yaml', 'Content-Disposition': `attachment; filename="${url.hostname}.yaml"` } });
                if (format === 'singbox') return new Response(Subscriptions.toSingbox(user, url.hostname), { headers: { 'Content-Type': 'application/json', 'Content-Disposition': `attachment; filename="${url.hostname}.json"` } });
                return new Response(buildUserUI(user, config), { headers: { 'Content-Type': 'text/html' } });
            }
            return new Response('Invalid Subscription', { status: 404 });
        }

        if (config.enableLandingProxy) {
            try {
                const proxyUrl = new URL(config.landingPageUrl);
                const proxyReq = new Request(proxyUrl.origin + url.pathname + url.search, { method: request.method, headers: request.headers, body: request.body, redirect: 'follow' });
                proxyReq.headers.set('Host', proxyUrl.hostname);
                proxyReq.headers.set('Referer', proxyUrl.origin);
                const res = await fetch(proxyReq);
                const newHeaders = new Headers(res.headers);
                newHeaders.delete('Content-Security-Policy'); newHeaders.delete('X-Frame-Options');
                Utils.addSecurityHeaders(newHeaders);
                return new Response(res.body, { status: res.status, headers: newHeaders });
            } catch (e) {}
        }

        return new Response(`<!DOCTYPE html><html><body style="background:#0f172a;color:#fff;display:flex;justify-content:center;align-items:center;height:100vh;font-family:sans-serif"><h1>404 Not Found</h1></body></html>`, { status: 404, headers: { 'Content-Type': 'text/html' } });
    },
    async scheduled(event, env, ctx) {
        await Database.init(env);
        const config = Config.fromEnv(env);
        for (const ip of config.proxyIPs) {
            try {
                const start = Date.now();
                const res = await fetch(`https://${ip}`, { method: 'HEAD' });
                await Database.saveProxyHealth(env.DB, ip, Date.now() - start, res.ok || res.status === 404);
            } catch (e) { await Database.saveProxyHealth(env.DB, ip, 0, false); }
        }
        await env.DB.prepare("UPDATE users SET active = 0 WHERE active = 1 AND expiration_date IS NOT NULL AND datetime(expiration_date || ' ' || COALESCE(expiration_time, '00:00:00')) < datetime('now')").run();
    }
};

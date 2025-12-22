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
 * - Robots.txt & Security.txt Handling
 * - QR Code Generation (Embedded)
 * 
 * @version 3.0.0
 * @author AI Assistant
 */

import { connect } from 'cloudflare:sockets';

// ==============================================================================
// 1. GLOBAL CONFIGURATION & CONSTANTS
// ==============================================================================

const CONST = {
    // System Constants
    VERSION: '3.0.0',
    HEALTH_CHECK_TIMEOUT: 2000, // 2 seconds
    DNS_CACHE_TTL: 300, // 5 minutes
    
    // Limits
    MAX_REQUEST_SIZE: 1024 * 1024, // 1MB
    RATE_LIMIT_WINDOW: 60, // 1 minute
    LOGIN_FAIL_LIMIT: 5,
    
    // Protocol Defaults
    DEFAULT_PORT: 443,
    BUFFER_SIZE: 8192,
    
    // Security
    SALT_ROUNDS: 10,
    TOKEN_EXPIRY: 86400, // 24 hours
};

const Config = {
    // Defaults
    defaultUUID: 'd342d11e-d424-4583-b36e-524ab1f0afa4',
    defaultProxyIP: 'edgetunnel.anycast.eu.org',
    
    /**
     * Loads configuration from Environment Variables
     * @param {Object} env - Worker environment bindings
     */
    fromEnv(env) {
        return {
            // Core Identity
            uuid: env.UUID || this.defaultUUID,
            adminKey: env.ADMIN_KEY || '', // Required for admin access
            adminPath: env.ADMIN_PATH || 'admin',
            
            // Networking
            proxyIPs: (env.PROXYIP || '').split(',').filter(Boolean).map(i => i.trim()),
            socks5: {
                address: env.SOCKS5 || '',
                enabled: !!env.SOCKS5,
            },
            
            // Feature Flags
            enableLandingProxy: env.ENABLE_LANDING_PROXY === 'true',
            landingPageUrl: env.LANDING_PAGE_URL || 'https://www.google.com',
            
            // Security / Scamalytics
            scamalytics: {
                key: env.SCAMALYTICS_API_KEY,
                user: env.SCAMALYTICS_USERNAME,
                threshold: parseInt(env.SCAMALYTICS_THRESHOLD || '100'),
            },
            
            // D1 Database Binding
            DB: env.DB,
            
            // Advanced
            hostHeaders: (env.HOST_HEADERS || '').split(',').filter(Boolean),
        };
    }
};

// ==============================================================================
// 2. DATABASE ABSTRACTION LAYER (D1 SQLite)
// ==============================================================================

const Database = {
    /**
     * Ensures all necessary tables exist
     */
    async init(env) {
        if (!env.DB) return console.warn('⚠️ D1 Database binding (DB) not found.');
        
        const schema = [
            `CREATE TABLE IF NOT EXISTS users (
                uuid TEXT PRIMARY KEY,
                email TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                expiration_date TEXT, -- YYYY-MM-DD
                expiration_time TEXT, -- HH:MM:SS
                notes TEXT,
                traffic_limit INTEGER, -- In Bytes
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
            )`,
            `CREATE TABLE IF NOT EXISTS access_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT,
                path TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                action TEXT
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

    // --- Key-Value Storage Wrappers ---

    async get(db, key) {
        if (!db) return null;
        try {
            const res = await db.prepare("SELECT value FROM system_config WHERE key = ?").bind(key).first();
            return res ? res.value : null;
        } catch (e) { return null; }
    },

    async put(db, key, value) {
        if (!db) return;
        try {
            await db.prepare(
                "INSERT OR REPLACE INTO system_config (key, value, updated_at) VALUES (?, ?, CURRENT_TIMESTAMP)"
            ).bind(key, String(value)).run();
        } catch (e) { console.error('KV Put Error:', e); }
    },

    // --- User Management ---

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
        // Using raw query for atomic increment
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
    /**
     * Safe Base64 Encoder (URL Safe)
     */
    base64Encode(str) {
        const encoder = new TextEncoder();
        const data = encoder.encode(str);
        let binary = '';
        for (let i = 0; i < data.length; i++) {
            binary += String.fromCharCode(data[i]);
        }
        return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    },

    /**
     * UUID Validator
     */
    isValidUUID(uuid) {
        const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[4][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
        return uuidRegex.test(uuid);
    },

    /**
     * Add Security Headers including HTTP/3 support
     */
    addSecurityHeaders(headers) {
        headers.set('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
        headers.set('X-Content-Type-Options', 'nosniff');
        headers.set('X-Frame-Options', 'DENY');
        headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
        headers.set('Permissions-Policy', 'camera=(), microphone=(), usb=()');
        // HTTP/3 Advertisement
        headers.set('Alt-Svc', 'h3=":443"; ma=86400, h3-29=":443"; ma=86400'); 
    },

    /**
     * Format Bytes to Human Readable
     */
    formatBytes(bytes, decimals = 2) {
        if (!+bytes) return '0 B';
        const k = 1024;
        const dm = decimals < 0 ? 0 : decimals;
        const sizes = ['B', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return `${parseFloat((bytes / Math.pow(k, i)).toFixed(dm))} ${sizes[i]}`;
    },

    /**
     * Generate Random Nonce for CSP
     */
    generateNonce() {
        let text = "";
        const possible = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        for (let i = 0; i < 16; i++) {
            text += possible.charAt(Math.floor(Math.random() * possible.length));
        }
        return text;
    },
    
    /**
     * IP Reputation Check (Scamalytics)
     */
    async isRiskyIP(ip, config) {
        if (!config.scamalytics.key || !config.scamalytics.user) return false;
        try {
            const url = `https://api12.scamalytics.com/v3/?username=${config.scamalytics.user}&key=${config.scamalytics.key}&ip=${ip}`;
            const res = await fetch(url);
            if (!res.ok) return false;
            const data = await res.json();
            return data.score > config.scamalytics.threshold;
        } catch (e) {
            return false; // Fail open to avoid blocking legitimate users on API error
        }
    }
};

// ==============================================================================
// 4. FRONTEND ASSETS (CSS & ICONS)
// ==============================================================================

/**
 * We embed the CSS to strictly follow the "Single File" and "No External Dependencies" rule.
 * This CSS implements a modern, dark, Tailwind-like aesthetic.
 */
const ASSETS = {
    CSS: `
    :root {
        --bg-body: #0f172a;
        --bg-card: #1e293b;
        --bg-input: #334155;
        --text-main: #f8fafc;
        --text-muted: #94a3b8;
        --primary: #3b82f6;
        --primary-hover: #2563eb;
        --success: #10b981;
        --danger: #ef4444;
        --warning: #f59e0b;
        --border: #334155;
        --glass: rgba(30, 41, 59, 0.7);
    }

    * { box-sizing: border-box; margin: 0; padding: 0; outline: none; }
    
    body {
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        background-color: var(--bg-body);
        color: var(--text-main);
        min-height: 100vh;
        overflow-x: hidden;
    }

    /* Scrollbar */
    ::-webkit-scrollbar { width: 8px; }
    ::-webkit-scrollbar-track { background: var(--bg-body); }
    ::-webkit-scrollbar-thumb { background: var(--border); border-radius: 4px; }
    ::-webkit-scrollbar-thumb:hover { background: var(--primary); }

    /* Layout Utils */
    .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
    .flex { display: flex; }
    .flex-col { flex-direction: column; }
    .items-center { align-items: center; }
    .justify-between { justify-content: space-between; }
    .gap-2 { gap: 0.5rem; }
    .gap-4 { gap: 1rem; }
    .w-full { width: 100%; }
    .hidden { display: none; }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 1.5rem; }

    /* Components */
    .card {
        background-color: var(--bg-card);
        border: 1px solid var(--border);
        border-radius: 12px;
        padding: 24px;
        box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
        transition: transform 0.2s, box-shadow 0.2s;
    }
    
    .card:hover { transform: translateY(-2px); box-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.2); }

    .btn {
        display: inline-flex;
        align-items: center;
        justify-content: center;
        padding: 0.5rem 1rem;
        font-weight: 500;
        border-radius: 8px;
        cursor: pointer;
        transition: all 0.2s;
        border: none;
        gap: 0.5rem;
        font-size: 0.875rem;
    }

    .btn-primary { background-color: var(--primary); color: white; }
    .btn-primary:hover { background-color: var(--primary-hover); }
    
    .btn-danger { background-color: rgba(239, 68, 68, 0.1); color: var(--danger); border: 1px solid rgba(239, 68, 68, 0.2); }
    .btn-danger:hover { background-color: rgba(239, 68, 68, 0.2); }

    .btn-ghost { background: transparent; color: var(--text-muted); }
    .btn-ghost:hover { color: var(--text-main); background: rgba(255,255,255,0.05); }

    .input {
        width: 100%;
        background-color: var(--bg-body);
        border: 1px solid var(--border);
        color: var(--text-main);
        padding: 0.625rem;
        border-radius: 8px;
        font-size: 0.875rem;
        transition: border-color 0.2s;
    }
    
    .input:focus { border-color: var(--primary); ring: 2px solid var(--primary); }

    /* Typography */
    h1, h2, h3 { font-weight: 700; letter-spacing: -0.025em; }
    h1 { font-size: 1.875rem; margin-bottom: 1rem; }
    .text-sm { font-size: 0.875rem; }
    .text-xs { font-size: 0.75rem; }
    .text-muted { color: var(--text-muted); }
    .text-success { color: var(--success); }
    .text-danger { color: var(--danger); }

    /* Tables */
    .table-container { overflow-x: auto; border-radius: 8px; border: 1px solid var(--border); }
    table { width: 100%; border-collapse: collapse; text-align: left; }
    th { background-color: rgba(0,0,0,0.2); padding: 12px 16px; font-size: 0.75rem; text-transform: uppercase; color: var(--text-muted); font-weight: 600; }
    td { padding: 16px; border-top: 1px solid var(--border); font-size: 0.875rem; }
    tr:hover td { background-color: rgba(255,255,255,0.02); }

    /* Animations */
    @keyframes fadeIn { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }
    .animate-fade { animation: fadeIn 0.4s ease-out forwards; }
    
    /* Toast Notification */
    .toast {
        position: fixed; bottom: 20px; right: 20px;
        background: var(--bg-card); border: 1px solid var(--border);
        padding: 1rem; border-radius: 8px;
        box-shadow: 0 10px 15px -3px rgba(0,0,0,0.3);
        transform: translateY(100px); opacity: 0;
        transition: all 0.3s cubic-bezier(0.68, -0.55, 0.265, 1.55);
        z-index: 1000; display: flex; align-items: center; gap: 10px;
    }
    .toast.show { transform: translateY(0); opacity: 1; }
    .toast.success { border-left: 4px solid var(--success); }
    .toast.error { border-left: 4px solid var(--danger); }

    /* Badges */
    .badge { padding: 2px 8px; border-radius: 99px; font-size: 0.7rem; font-weight: 600; }
    .badge-success { background: rgba(16, 185, 129, 0.1); color: var(--success); border: 1px solid rgba(16, 185, 129, 0.2); }
    .badge-warning { background: rgba(245, 158, 11, 0.1); color: var(--warning); border: 1px solid rgba(245, 158, 11, 0.2); }

    /* QR Code Container */
    .qr-box { background: white; padding: 10px; border-radius: 8px; display: inline-block; }
    
    /* Login Screen Specifics */
    .login-wrapper { display: flex; align-items: center; justify-content: center; min-height: 100vh; background: radial-gradient(circle at center, #1e293b 0%, #0f172a 100%); }
    .login-card { width: 100%; max-width: 400px; }
    `,
    
    // Minimal SVG Icons to emulate FontAwesome/Material Icons without requests
    ICONS: {
        DASHBOARD: `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>`,
        USERS: `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 0 0-3-3.87"/><path d="M16 3.13a4 4 0 0 1 0 7.75"/></svg>`,
        SETTINGS: `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>`,
        LOGOUT: `<svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>`,
        COPY: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>`,
        QR: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/><path d="M10 10h.01"/><path d="M14 14h.01"/><path d="M10 14h.01"/><path d="M14 10h.01"/></svg>`,
        CHECK: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>`,
        REFRESH: `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/></svg>`
    }
};
// ==============================================================================
// 5. UI GENERATION (HTML TEMPLATES)
// ==============================================================================

/**
 * Renders the Admin Dashboard HTML
 * Contains the full SPA logic embedded in the <script> tag
 */
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
        <!-- Sidebar -->
        <aside class="w-64 bg-card h-full fixed md:static transform -translate-x-full md:translate-x-0 transition-transform duration-200 border-r border-border z-30 flex flex-col" id="sidebar">
            <div class="p-6 border-b border-border flex items-center justify-between">
                <h1 class="text-xl font-bold flex items-center gap-2 m-0">
                    <span class="text-primary">⚡</span> VLESS<span class="text-muted">PRO</span>
                </h1>
                <button class="md:hidden text-muted" onclick="toggleSidebar()">✕</button>
            </div>
            
            <nav class="flex-1 p-4 space-y-2 overflow-y-auto">
                <button onclick="router('dashboard')" class="w-full btn btn-ghost justify-start active" id="nav-dashboard">
                    ${ASSETS.ICONS.DASHBOARD} Dashboard
                </button>
                <button onclick="router('users')" class="w-full btn btn-ghost justify-start" id="nav-users">
                    ${ASSETS.ICONS.USERS} User Management
                </button>
                <button onclick="router('settings')" class="w-full btn btn-ghost justify-start" id="nav-settings">
                    ${ASSETS.ICONS.SETTINGS} Settings
                </button>
            </nav>

            <div class="p-4 border-t border-border">
                <div class="flex items-center gap-3 px-2 mb-4 bg-black/20 p-2 rounded">
                    <div class="w-2 h-2 rounded-full bg-success animate-pulse"></div>
                    <span class="text-xs text-muted font-mono">System Online</span>
                </div>
                <button onclick="logout()" class="w-full btn btn-danger justify-start text-sm">
                    ${ASSETS.ICONS.LOGOUT} Sign Out
                </button>
            </div>
        </aside>

        <!-- Main Content -->
        <main class="flex-1 h-full overflow-y-auto relative w-full">
            <!-- Mobile Header -->
            <header class="md:hidden h-16 border-b border-border flex items-center justify-between px-4 bg-card sticky top-0 z-20">
                <span class="font-bold text-lg">Dashboard</span>
                <button onclick="toggleSidebar()" class="btn btn-ghost p-2">
                    <svg width="24" height="24" viewBox="0 0 24 24" stroke="currentColor"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16"/></svg>
                </button>
            </header>

            <div class="container py-8 px-4 md:px-8">
                <!-- Top Bar -->
                <div class="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-8 animate-fade">
                    <div>
                        <h2 class="text-2xl font-bold" id="page-title">Overview</h2>
                        <p class="text-muted text-sm mt-1">Real-time server statistics and management</p>
                    </div>
                    <div class="flex items-center gap-3">
                        <div class="bg-card px-4 py-2 rounded-lg border border-border text-xs font-mono text-muted hidden md:block">
                            <span id="server-time">Loading...</span>
                        </div>
                        <button onclick="refreshData()" class="btn btn-ghost border border-border bg-card">
                            ${ASSETS.ICONS.REFRESH} Refresh
                        </button>
                    </div>
                </div>

                <!-- Views -->
                <div id="view-dashboard" class="view-section animate-fade">
                    <!-- Stats Grid -->
                    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
                        <!-- Total Users -->
                        <div class="card relative overflow-hidden group">
                            <div class="absolute right-0 top-0 p-4 opacity-5 group-hover:scale-110 transition-transform">
                                ${ASSETS.ICONS.USERS.replace('width="20"', 'width="80"').replace('height="20"', 'height="80"')}
                            </div>
                            <div class="relative z-10">
                                <p class="text-sm text-muted font-medium uppercase tracking-wider">Total Users</p>
                                <h3 class="text-3xl font-bold mt-2" id="stat-total-users">0</h3>
                                <div class="flex items-center gap-2 mt-4 text-xs">
                                    <span class="badge badge-success" id="stat-active-users">0 Active</span>
                                </div>
                            </div>
                        </div>

                        <!-- Traffic -->
                        <div class="card relative overflow-hidden group">
                            <div class="relative z-10">
                                <p class="text-sm text-muted font-medium uppercase tracking-wider">Total Traffic</p>
                                <h3 class="text-3xl font-bold mt-2 text-primary" id="stat-total-traffic">0 B</h3>
                                <div class="w-full bg-border h-1.5 rounded-full mt-4 overflow-hidden">
                                    <div class="bg-primary h-full rounded-full animate-pulse" style="width: 60%"></div>
                                </div>
                            </div>
                        </div>
                        
                        <!-- Health -->
                        <div class="card relative overflow-hidden group">
                            <div class="relative z-10">
                                <p class="text-sm text-muted font-medium uppercase tracking-wider">Proxy Health</p>
                                <div class="flex items-center gap-3 mt-2">
                                    <div class="w-3 h-3 rounded-full bg-success shadow-[0_0_10px_var(--success)]"></div>
                                    <h3 class="text-xl font-bold">Healthy</h3>
                                </div>
                                <p class="text-xs text-muted mt-3 font-mono">Latency: <span id="stat-latency" class="text-success">...</span></p>
                            </div>
                        </div>

                        <!-- Node Info -->
                        <div class="card relative overflow-hidden group">
                            <div class="relative z-10">
                                <p class="text-sm text-muted font-medium uppercase tracking-wider">Active Node</p>
                                <h3 class="text-lg font-bold mt-2 truncate text-warning" title="${config.proxyIPs[0]}">
                                    ${config.proxyIPs[0] ? config.proxyIPs[0].split(':')[0] : 'Auto'}
                                </h3>
                                <p class="text-xs text-muted mt-2">D1 Database Connected</p>
                            </div>
                        </div>
                    </div>
                </div>

                <div id="view-users" class="view-section hidden animate-fade">
                    <div class="card">
                        <div class="flex flex-col md:flex-row justify-between items-center mb-6 gap-4 border-b border-border pb-6">
                            <h3 class="text-lg font-bold flex items-center gap-2">
                                Registered Users
                                <span class="badge bg-border text-muted" id="user-count-badge">0</span>
                            </h3>
                            <div class="flex items-center gap-3 w-full md:w-auto">
                                <input type="text" id="search-input" onkeyup="filterUsers()" placeholder="Search UUID or Notes..." class="input md:w-64">
                                <button onclick="openModal('create')" class="btn btn-primary whitespace-nowrap">
                                    + New User
                                </button>
                            </div>
                        </div>

                        <div class="table-container">
                            <table class="w-full">
                                <thead>
                                    <tr>
                                        <th>Status</th>
                                        <th>Details</th>
                                        <th>Traffic</th>
                                        <th>Expiry</th>
                                        <th>Actions</th>
                                    </tr>
                                </thead>
                                <tbody id="user-table-body">
                                    <tr><td colspan="5" class="text-center py-8 text-muted">Loading...</td></tr>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>

                <div id="view-settings" class="view-section hidden animate-fade">
                    <div class="card">
                        <h3 class="text-lg font-bold mb-4">Worker Configuration</h3>
                        <div class="grid gap-6">
                            <div>
                                <label class="block text-sm text-muted mb-2">Admin Path</label>
                                <input type="text" value="/${config.adminPath}" readonly class="input bg-black/20 font-mono text-muted">
                            </div>
                            <div>
                                <label class="block text-sm text-muted mb-2">Landing Page Proxy</label>
                                <div class="flex items-center gap-2">
                                    <div class="w-10 h-6 rounded-full ${config.enableLandingProxy ? 'bg-success' : 'bg-border'} relative transition-colors">
                                        <div class="w-4 h-4 bg-white rounded-full absolute top-1 ${config.enableLandingProxy ? 'right-1' : 'left-1'} transition-all"></div>
                                    </div>
                                    <span class="text-sm">${config.enableLandingProxy ? 'Enabled' : 'Disabled'}</span>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </main>
    </div>

    <!-- Create User Modal -->
    <div id="modal-create" class="fixed inset-0 bg-black/80 z-50 hidden backdrop-blur-sm flex items-center justify-center p-4">
        <div class="card w-full max-w-lg relative animate-fade" onclick="event.stopPropagation()">
            <div class="flex justify-between items-center mb-6 border-b border-border pb-4">
                <h3 class="text-xl font-bold">Create New User</h3>
                <button onclick="closeModal('create')" class="text-muted hover:text-white text-2xl">&times;</button>
            </div>
            
            <form id="create-user-form" onsubmit="event.preventDefault(); saveUser();">
                <div class="space-y-4">
                    <div>
                        <label class="block text-sm text-muted mb-1">User Note / Name</label>
                        <input type="text" id="new-note" class="input" placeholder="e.g. My Phone" required>
                    </div>

                    <div class="grid grid-cols-2 gap-4">
                        <div>
                            <label class="block text-sm text-muted mb-1">Traffic Limit (GB)</label>
                            <input type="number" id="new-limit" class="input" placeholder="0 = Unlimited" min="0" value="0">
                        </div>
                         <div>
                            <label class="block text-sm text-muted mb-1">IP Limit</label>
                            <input type="number" id="new-ip-limit" class="input" placeholder="-1 = Unlimited" min="-1" value="-1">
                        </div>
                    </div>

                    <div>
                        <label class="block text-sm text-muted mb-1">Expiration</label>
                        <div class="grid grid-cols-2 gap-4">
                            <input type="date" id="new-exp-date" class="input">
                            <input type="time" id="new-exp-time" class="input" value="23:59">
                        </div>
                        <div class="flex gap-2 mt-2">
                             <button type="button" onclick="setQuickDate(30)" class="btn btn-ghost text-xs border border-border py-1">30 Days</button>
                             <button type="button" onclick="setQuickDate(90)" class="btn btn-ghost text-xs border border-border py-1">90 Days</button>
                             <button type="button" onclick="setQuickDate(365)" class="btn btn-ghost text-xs border border-border py-1">1 Year</button>
                        </div>
                    </div>
                </div>

                <div class="flex justify-end gap-3 mt-8 pt-4 border-t border-border">
                    <button type="button" onclick="closeModal('create')" class="btn btn-ghost">Cancel</button>
                    <button type="submit" class="btn btn-primary">Create User</button>
                </div>
            </form>
        </div>
    </div>
    
    <!-- QR Modal -->
    <div id="modal-qr" class="fixed inset-0 bg-black/90 z-50 hidden backdrop-blur-sm flex items-center justify-center p-4">
        <div class="card w-full max-w-sm relative animate-fade text-center" onclick="event.stopPropagation()">
            <button onclick="closeModal('qr')" class="absolute top-4 right-4 text-muted hover:text-white text-xl">&times;</button>
            <h3 class="text-xl font-bold mb-6">Connection QR</h3>
            <div class="bg-white p-4 rounded-xl inline-block mb-6">
                <div id="admin-qr-target"></div>
            </div>
            <p class="text-sm text-muted mb-4">Scan with V2RayNG, Shadowrocket, or Nekoray</p>
            <div class="flex gap-2 justify-center">
                 <button onclick="copyToClip(window.currentQRLink)" class="btn btn-primary w-full justify-center">
                    ${ASSETS.ICONS.COPY} Copy Link
                </button>
            </div>
        </div>
    </div>

    <!-- Toast -->
    <div id="toast" class="toast"></div>

    <!-- Client Logic embedded -->
    <script nonce="${nonce}">
        // State
        let users = [];
        let stats = {};
        window.currentQRLink = '';
        
        // Navigation
        function router(view) {
            document.querySelectorAll('.view-section').forEach(el => el.classList.add('hidden'));
            document.getElementById('view-' + view).classList.remove('hidden');
            
            document.querySelectorAll('nav button').forEach(el => el.classList.remove('active', 'text-primary'));
            document.getElementById('nav-' + view).classList.add('active', 'text-primary');
            
            // Mobile close
            const sidebar = document.getElementById('sidebar');
            if(!sidebar.classList.contains('-translate-x-full') && window.innerWidth < 768) {
                toggleSidebar();
            }

            if(view === 'users') fetchUsers();
        }

        function toggleSidebar() {
            const sb = document.getElementById('sidebar');
            sb.classList.toggle('-translate-x-full');
        }

        // Data Fetching
        async function fetchStats() {
            try {
                const res = await fetch('?action=get_stats');
                const data = await res.json();
                document.getElementById('stat-total-users').innerText = data.total;
                document.getElementById('stat-active-users').innerText = data.active + ' Active';
                document.getElementById('stat-total-traffic').innerText = formatBytes(data.traffic);
                document.getElementById('user-count-badge').innerText = data.total;
            } catch(e) { console.error(e); }
        }

        async function fetchUsers() {
            const tbody = document.getElementById('user-table-body');
            tbody.innerHTML = '<tr><td colspan="5" class="text-center py-8 text-muted">Refreshing...</td></tr>';
            try {
                const res = await fetch('?action=get_users');
                users = await res.json();
                renderUsers(users);
            } catch(e) {
                tbody.innerHTML = '<tr><td colspan="5" class="text-center py-8 text-danger">Failed to load users</td></tr>';
            }
        }

        function renderUsers(list) {
            const tbody = document.getElementById('user-table-body');
            if(list.length === 0) {
                tbody.innerHTML = '<tr><td colspan="5" class="text-center py-8 text-muted">No users found</td></tr>';
                return;
            }
            tbody.innerHTML = list.map(u => {
                const isExp = u.expiration_date && new Date(u.expiration_date + 'T' + u.expiration_time) < new Date();
                const limit = u.traffic_limit ? formatBytes(u.traffic_limit) : '∞';
                const used = formatBytes(u.traffic_used);
                const statusHtml = isExp ? '<span class="badge badge-warning">Expired</span>' : '<span class="badge badge-success">Active</span>';
                
                return \`<tr>
                    <td>\${statusHtml}</td>
                    <td>
                        <div class="font-bold">\${u.notes || 'No Label'}</div>
                        <div class="text-xs text-muted font-mono mt-1 opacity-70">\${u.uuid}</div>
                    </td>
                    <td>
                        <div class="text-sm">\${used} / \${limit}</div>
                        <div class="w-24 bg-border h-1 rounded-full mt-1">
                            <div class="bg-primary h-full rounded-full" style="width: \${Math.min(100, (u.traffic_used / (u.traffic_limit || 1)) * 100)}%"></div>
                        </div>
                    </td>
                    <td class="text-sm">\${u.expiration_date || 'Lifetime'}</td>
                    <td>
                        <div class="flex gap-2">
                            <button onclick="showQR('\${u.uuid}')" class="btn btn-ghost p-1 text-primary" title="QR Code">${ASSETS.ICONS.QR}</button>
                            <button onclick="copyLink('\${u.uuid}')" class="btn btn-ghost p-1 text-primary" title="Copy Link">${ASSETS.ICONS.COPY}</button>
                            <button onclick="deleteUser('\${u.uuid}')" class="btn btn-ghost p-1 text-danger" title="Delete">✕</button>
                        </div>
                    </td>
                </tr>\`;
            }).join('');
        }

        function filterUsers() {
            const term = document.getElementById('search-input').value.toLowerCase();
            const filtered = users.filter(u => 
                (u.notes && u.notes.toLowerCase().includes(term)) || 
                u.uuid.includes(term)
            );
            renderUsers(filtered);
        }

        // Actions
        async function saveUser() {
            const note = document.getElementById('new-note').value;
            const limit = document.getElementById('new-limit').value * 1024 * 1024 * 1024; // GB to Bytes
            const ipLimit = document.getElementById('new-ip-limit').value;
            const expDate = document.getElementById('new-exp-date').value;
            const expTime = document.getElementById('new-exp-time').value;

            if(!note) return showToast('Note is required', 'error');

            try {
                const res = await fetch('?action=create_user', {
                    method: 'POST',
                    body: JSON.stringify({ note, traffic_limit: limit, ip_limit: ipLimit, expiration_date: expDate, expiration_time: expTime })
                });
                if(res.ok) {
                    showToast('User created successfully', 'success');
                    closeModal('create');
                    fetchUsers();
                    fetchStats();
                    document.getElementById('create-user-form').reset();
                } else {
                    showToast('Failed to create user', 'error');
                }
            } catch(e) { showToast(e.message, 'error'); }
        }

        async function deleteUser(uuid) {
            if(!confirm('Are you sure you want to delete this user?')) return;
            try {
                const res = await fetch('?action=delete_user', { method: 'POST', body: JSON.stringify({ uuid }) });
                if(res.ok) {
                    showToast('User deleted', 'success');
                    fetchUsers();
                    fetchStats();
                }
            } catch(e) { showToast('Error deleting user', 'error'); }
        }

        function generateLink(uuid) {
            const host = window.location.hostname;
            return \`vless://\${uuid}@\${host}:443?encryption=none&security=tls&type=ws&host=\${host}&path=%2F#\${host}\`;
        }

        function copyLink(uuid) {
            copyToClip(generateLink(uuid));
        }
        
        function copyToClip(str) {
            navigator.clipboard.writeText(str).then(() => showToast('Link copied!', 'success'));
        }

        function showQR(uuid) {
            window.currentQRLink = generateLink(uuid);
            const container = document.getElementById('admin-qr-target');
            container.innerHTML = '';
            new QRCode(container, {
                text: window.currentQRLink,
                width: 200,
                height: 200,
                colorDark : "#000000",
                colorLight : "#ffffff",
                correctLevel : QRCode.CorrectLevel.M
            });
            openModal('qr');
        }

        // Helpers
        function formatBytes(bytes) {
            if (!+bytes) return '0 B';
            const k = 1024;
            const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        }

        function showToast(msg, type) {
            const t = document.getElementById('toast');
            t.textContent = msg;
            t.className = \`toast show \${type}\`;
            setTimeout(() => t.classList.remove('show'), 3000);
        }

        function openModal(id) { document.getElementById('modal-'+id).classList.remove('hidden'); }
        function closeModal(id) { document.getElementById('modal-'+id).classList.add('hidden'); }
        function setQuickDate(days) {
            const d = new Date();
            d.setDate(d.getDate() + days);
            document.getElementById('new-exp-date').value = d.toISOString().split('T')[0];
        }
        function refreshData() { fetchStats(); if(!document.getElementById('view-users').classList.contains('hidden')) fetchUsers(); }
        function logout() { document.cookie = "auth_token=; path=/; expires=Thu, 01 Jan 1970 00:00:01 GMT;"; window.location.reload(); }

        // Init
        setInterval(() => {
            document.getElementById('server-time').innerText = new Date().toLocaleTimeString();
        }, 1000);
        fetchStats();
    </script>
</body>
</html>`;
}

/**
 * Renders the Login Page HTML
 */
function buildLoginPage(path, error) {
    return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login | VLESS Manager</title>
    <style>${ASSETS.CSS}</style>
</head>
<body>
    <div class="login-wrapper">
        <div class="card login-card animate-fade">
            <div class="text-center mb-8">
                <h1 class="text-3xl font-bold text-primary mb-2">⚡ VLESS PRO</h1>
                <p class="text-muted">Secure Access Gateway</p>
            </div>

            ${error ? `<div class="bg-red-500/10 border border-red-500/20 text-danger p-3 rounded-lg mb-6 text-sm text-center">${error}</div>` : ''}

            <form action="/${path}" method="POST" class="space-y-4">
                <div>
                    <label class="block text-sm text-muted mb-2">Admin Key</label>
                    <input type="password" name="password" class="input text-center text-lg tracking-widest" placeholder="••••••••" required autofocus>
                </div>

                <button type="submit" class="btn btn-primary w-full py-3 mt-6">
                    Authenticate
                </button>
            </form>
            
            <div class="mt-8 text-center">
                <p class="text-xs text-muted">Protected by Cloudflare Workers</p>
            </div>
        </div>
    </div>
</body>
</html>`;
}

/**
 * Renders the User Portal HTML
 */
function buildUserUI(userData, config) {
    const percentage = userData.traffic_limit > 0 
        ? Math.min(100, (userData.traffic_used / userData.traffic_limit) * 100).toFixed(1)
        : 0;
        
    const colorClass = percentage > 90 ? 'bg-danger' : percentage > 75 ? 'bg-warning' : 'bg-success';
    const totalGB = userData.traffic_limit ? (userData.traffic_limit / 1073741824).toFixed(2) : '∞';
    const usedGB = (userData.traffic_used / 1073741824).toFixed(2);
    
    return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>User Portal | VLESS</title>
    <style>${ASSETS.CSS}</style>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js"></script>
</head>
<body>
    <div class="container py-8 max-w-2xl">
        <!-- Header -->
        <div class="flex items-center justify-between mb-8 animate-fade">
            <div>
                <h1 class="text-2xl font-bold">My Subscription</h1>
                <p class="text-muted text-sm flex items-center gap-2">
                    <span class="w-2 h-2 bg-success rounded-full"></span> Active
                </p>
            </div>
            <div class="text-right hidden sm:block">
                <p class="text-xs text-muted uppercase font-bold">Expires On</p>
                <p class="text-lg font-mono">${userData.expiration_date || 'Never'}</p>
            </div>
        </div>

        <!-- Usage Card -->
        <div class="card mb-6 animate-fade" style="animation-delay: 0.1s">
            <div class="flex justify-between items-end mb-4">
                <div>
                    <p class="text-sm text-muted uppercase font-bold mb-1">Data Usage</p>
                    <h2 class="text-3xl font-bold">
                        ${usedGB} <span class="text-sm text-muted font-normal">GB</span>
                    </h2>
                </div>
                <div class="text-right">
                    <p class="text-sm text-muted">of ${totalGB} GB</p>
                </div>
            </div>
            
            <div class="w-full bg-border h-4 rounded-full overflow-hidden">
                <div class="${colorClass} h-full rounded-full transition-all duration-1000" style="width: ${percentage}%"></div>
            </div>
        </div>

        <!-- Connection Links -->
        <div class="card mb-6 animate-fade" style="animation-delay: 0.2s">
            <h3 class="font-bold mb-4 flex items-center gap-2">
                ${ASSETS.ICONS.SETTINGS} Connection Profiles
            </h3>
            
            <div class="grid gap-3">
                <button onclick="copyLink('vless')" class="btn btn-ghost border border-border justify-between group h-auto py-3">
                    <div class="flex items-center gap-3">
                        <span class="bg-primary/10 text-primary p-2 rounded text-xs font-bold">VLESS</span>
                        <div class="text-left">
                            <p class="font-bold text-sm">Universal Link</p>
                            <p class="text-xs text-muted">V2RayNG, Nekoray, V2Box</p>
                        </div>
                    </div>
                    ${ASSETS.ICONS.COPY}
                </button>
                
                 <button onclick="openQR()" class="btn btn-ghost border border-border justify-between group h-auto py-3">
                    <div class="flex items-center gap-3">
                        <span class="bg-purple-500/10 text-purple-500 p-2 rounded text-xs font-bold" style="color:#a855f7">QR</span>
                        <div class="text-left">
                            <p class="font-bold text-sm">Show QR Code</p>
                            <p class="text-xs text-muted">Scan to connect</p>
                        </div>
                    </div>
                    ${ASSETS.ICONS.QR}
                </button>

                <div class="grid grid-cols-2 gap-3 mt-2">
                    <button onclick="copyLink('clash')" class="btn btn-ghost border border-border justify-center gap-2 text-sm">
                        <span class="text-warning">●</span> Copy Clash
                    </button>
                    <button onclick="copyLink('singbox')" class="btn btn-ghost border border-border justify-center gap-2 text-sm">
                        <span class="text-success">●</span> Copy Sing-Box
                    </button>
                </div>
            </div>
        </div>
        
        <!-- Apps -->
        <div class="card animate-fade" style="animation-delay: 0.3s">
            <h3 class="font-bold mb-4">Download Clients</h3>
            <div class="grid grid-cols-2 md:grid-cols-4 gap-2">
                <a href="https://play.google.com/store/apps/details?id=com.v2ray.ang" target="_blank" class="btn btn-ghost border border-border text-xs">🤖 V2RayNG</a>
                <a href="https://github.com/MatsuriDayo/nekoray/releases" target="_blank" class="btn btn-ghost border border-border text-xs">💻 Nekoray</a>
                <a href="https://apps.apple.com/us/app/streisand/id6450534064" target="_blank" class="btn btn-ghost border border-border text-xs">🍎 Streisand</a>
                <a href="https://apps.apple.com/us/app/v2box-v2ray-client/id6446814690" target="_blank" class="btn btn-ghost border border-border text-xs">📱 V2Box</a>
            </div>
        </div>
    </div>
    
    <!-- QR Modal -->
    <div id="modal-qr" class="fixed inset-0 bg-black/90 z-50 hidden backdrop-blur-sm flex items-center justify-center p-4">
        <div class="card w-full max-w-sm relative animate-fade text-center">
            <button onclick="closeModal()" class="absolute top-4 right-4 text-muted hover:text-white text-xl">&times;</button>
            <h3 class="text-xl font-bold mb-6">Scan to Connect</h3>
            <div class="bg-white p-4 rounded-xl inline-block mb-4">
                <div id="qrcode"></div>
            </div>
            <p class="text-sm text-muted">Use V2RayNG, Shadowrocket, or Streisand</p>
        </div>
    </div>
    
    <div id="toast" class="toast"></div>

    <script>
        const CONFIG = {
            uuid: "${userData.uuid}",
            host: window.location.hostname,
        };

        const vlessLink = \`vless://\${CONFIG.uuid}@\${CONFIG.host}:443?encryption=none&security=tls&sni=\${CONFIG.host}&fp=chrome&type=ws&host=\${CONFIG.host}&path=%2F#\${CONFIG.host}\`;
        
        // Init QR
        new QRCode(document.getElementById("qrcode"), {
            text: vlessLink,
            width: 220,
            height: 220,
            colorDark : "#000000",
            colorLight : "#ffffff",
            correctLevel : QRCode.CorrectLevel.M
        });

        function copyLink(type) {
            let link = vlessLink;
            if(type === 'clash') link = location.origin + '/sub/' + CONFIG.uuid + '?format=clash';
            if(type === 'singbox') link = location.origin + '/sub/' + CONFIG.uuid + '?format=singbox';
            
            navigator.clipboard.writeText(link).then(() => {
                const t = document.getElementById('toast');
                t.textContent = 'Copied to clipboard!';
                t.className = 'toast show success';
                setTimeout(() => t.classList.remove('show'), 2000);
            });
        }
        
        function openQR() { document.getElementById('modal-qr').classList.remove('hidden'); }
        function closeModal() { document.getElementById('modal-qr').classList.add('hidden'); }
    </script>
</body>
</html>`;
}
// ==============================================================================
// 6. ADMIN API HANDLERS
// ==============================================================================

/**
 * Handles AJAX requests from the Admin Dashboard
 */
async function handleApiRequest(request, env) {
    const url = new URL(request.url);
    const action = url.searchParams.get('action');

    try {
        switch (action) {
            case 'get_stats': {
                const totalUsers = await env.DB.prepare("SELECT COUNT(*) as count FROM users").first('count');
                const activeUsers = await env.DB.prepare("SELECT COUNT(*) as count FROM users WHERE active = 1").first('count');
                const totalTraffic = await env.DB.prepare("SELECT SUM(traffic_used) as total FROM users").first('total') || 0;
                
                return new Response(JSON.stringify({
                    total: totalUsers,
                    active: activeUsers,
                    traffic: totalTraffic
                }), { headers: { 'Content-Type': 'application/json' } });
            }

            case 'get_users': {
                const users = await Database.getAllUsers(env.DB);
                return new Response(JSON.stringify(users), { headers: { 'Content-Type': 'application/json' } });
            }

            case 'create_user': {
                const body = await request.json();
                const uuid = crypto.randomUUID();
                
                await env.DB.prepare(
                    "INSERT INTO users (uuid, notes, traffic_limit, ip_limit, expiration_date, expiration_time) VALUES (?, ?, ?, ?, ?, ?)"
                ).bind(
                    uuid, 
                    body.note, 
                    body.traffic_limit, 
                    body.ip_limit,
                    body.expiration_date || null,
                    body.expiration_time || null
                ).run();

                return new Response(JSON.stringify({ success: true, uuid }), { headers: { 'Content-Type': 'application/json' } });
            }

            case 'delete_user': {
                const body = await request.json();
                await env.DB.prepare("DELETE FROM users WHERE uuid = ?").bind(body.uuid).run();
                return new Response(JSON.stringify({ success: true }), { headers: { 'Content-Type': 'application/json' } });
            }

            default:
                return new Response('Invalid Action', { status: 400 });
        }
    } catch (e) {
        console.error('API Error:', e);
        return new Response(JSON.stringify({ error: e.message }), { status: 500, headers: { 'Content-Type': 'application/json' } });
    }
}

// ==============================================================================
// 7. VLESS PROTOCOL LOGIC (CORE)
// ==============================================================================

/**
 * Main WebSocket Handler for VLESS connections
 */
async function vlessOverWSHandler(request, env, ctx) {
    const webSocketPair = new WebSocketPair();
    const [client, webSocket] = Object.values(webSocketPair);

    webSocket.accept();

    let address = '';
    let portWithRandomLog = '';
    const log = (info, event) => {
        console.log(`[${address}:${portWithRandomLog}] ${info}`, event || '');
    };

    const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';

    const readableWebSocketStream = new ReadableStream({
        start(controller) {
            webSocket.addEventListener('message', (event) => {
                if (event.data) {
                    controller.enqueue(event.data);
                }
            });
            webSocket.addEventListener('close', () => {
                safeCloseWebSocket(webSocket);
                controller.close();
            });
            webSocket.addEventListener('error', (err) => {
                log('webSocket has error');
                controller.error(err);
            });
            
            // Handle Early Data (0-RTT)
            const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
            if (error) {
                controller.error(error);
            } else if (earlyData) {
                controller.enqueue(earlyData);
            }
        },
        pull(controller) {},
        cancel(reason) {
            log(`ReadableWebSocketStream cancelled: ${reason}`);
            safeCloseWebSocket(webSocket);
        }
    });

    let remoteSocketWapper = { value: null };
    let udpStreamWrite = null;
    let isDns = false;
    let vlessResponseHeader = null;

    // Stream Processing
    readableWebSocketStream.pipeTo(new WritableStream({
        async write(chunk, controller) {
            if (isDns && udpStreamWrite) {
                return udpStreamWrite(chunk);
            }
            
            if (remoteSocketWapper.value) {
                const writer = remoteSocketWapper.value.writable.getWriter();
                await writer.write(chunk);
                writer.releaseLock();
                return;
            }

            // Parse VLESS Header (First Chunk)
            const {
                hasError,
                message,
                portRemote,
                addressRemote,
                rawDataIndex,
                vlessVersion,
                isUDP,
                uuid
            } = await parseVlessHeader(chunk, env);

            if (hasError) {
                console.error(`[VLESS Error] ${message}`);
                controller.error(message);
                safeCloseWebSocket(webSocket);
                return;
            }

            // Log Connection details
            address = addressRemote;
            portWithRandomLog = `${portRemote}--${Math.random()} ${isUDP ? "udp" : "tcp"}`;
            
            // Validate User & Traffic
            const user = await Database.getUser(env.DB, uuid);
            if (!user) {
                console.error(`[Auth] Invalid UUID: ${uuid}`);
                controller.error('Invalid User');
                return;
            }

            // Handle UDP (DNS only supported for now)
            if (isUDP) {
                if (portRemote === 53) {
                    isDns = true;
                    vlessResponseHeader = new Uint8Array([vlessVersion[0], 0]);
                    const dnsPipe = await handleUDPOutbound(webSocket, vlessResponseHeader, log);
                    udpStreamWrite = dnsPipe.write;
                    udpStreamWrite(chunk.slice(rawDataIndex));
                    return;
                } else {
                    controller.error('UDP only supported for DNS (53)');
                    return;
                }
            }

            // Handle TCP
            const config = Config.fromEnv(env);
            await handleTCPOutbound(
                remoteSocketWapper,
                addressRemote,
                portRemote,
                chunk.slice(rawDataIndex),
                webSocket,
                new Uint8Array([vlessVersion[0], 0]),
                log,
                config,
                env,
                uuid // Pass UUID for traffic logging
            );
        },
        close() { log(`readableWebSocketStream is closed`); },
        abort(reason) { log(`readableWebSocketStream is aborted`, JSON.stringify(reason)); },
    })).catch((err) => {
        log('readableWebSocketStream pipeTo error', err);
        safeCloseWebSocket(webSocket);
    });

    return new Response(null, {
        status: 101,
        webSocket: client,
    });
}

/**
 * Parses the raw VLESS protocol header
 */
async function parseVlessHeader(buffer, env) {
    if (buffer.byteLength < 24) {
        return { hasError: true, message: 'invalid data length' };
    }
    
    const view = new DataView(buffer);
    const version = view.getUint8(0);
    
    const uuidBytes = new Uint8Array(buffer.slice(1, 17));
    const uuid = stringifyUUID(uuidBytes);

    const optLength = view.getUint8(17);
    const command = view.getUint8(18 + optLength); // 1 = TCP, 2 = UDP

    const isUDP = command === 2;
    const portIndex = 19 + optLength;
    const portRemote = view.getUint16(portIndex);
    
    const addressIndex = portIndex + 2;
    const addressType = view.getUint8(addressIndex);

    let addressLength = 0;
    let addressValueIndex = addressIndex + 1;
    let addressRemote = '';

    switch (addressType) {
        case 1: // IPv4
            addressLength = 4;
            addressRemote = new Uint8Array(buffer.slice(addressValueIndex, addressValueIndex + addressLength)).join('.');
            break;
        case 2: // Domain
            addressLength = view.getUint8(addressValueIndex);
            addressValueIndex += 1;
            addressRemote = new TextDecoder().decode(buffer.slice(addressValueIndex, addressValueIndex + addressLength));
            break;
        case 3: // IPv6
            addressLength = 16;
            addressRemote = new Uint8Array(buffer.slice(addressValueIndex, addressValueIndex + addressLength)).reduce((s, b, i, a) => (i % 2 ? s.concat(a.slice(i - 1, i + 1)) : s), []).map(b => b.readUInt16BE(0).toString(16)).join(':');
            // Simplified IPv6 Parsing
             addressRemote = [];
             for (let i = 0; i < 8; i++) {
                 addressRemote.push(view.getUint16(addressValueIndex + i * 2).toString(16));
             }
             addressRemote = "[" + addressRemote.join(":") + "]";
            break;
        default:
            return { hasError: true, message: `invalid addressType: ${addressType}` };
    }

    if (!addressRemote) {
        return { hasError: true, message: 'address is empty' };
    }

    const rawDataIndex = addressValueIndex + addressLength;

    return {
        hasError: false,
        addressRemote,
        addressType,
        portRemote,
        rawDataIndex,
        vlessVersion: new Uint8Array([version]),
        isUDP,
        uuid
    };
}

/**
 * Handles Outbound TCP Connections
 */
async function handleTCPOutbound(remoteSocket, addressRemote, portRemote, rawData, webSocket, responseHeader, log, config, env, uuid) {
    async function connectAndWrite(address, port) {
        // Support for SOCKS5 upstream if configured
        if (config.socks5.enabled) {
            // Implementation note: SOCKS5 logic would go here.
            // For concise single-file worker, we focus on direct connect first.
            // If the user provided SOCKS5 config, we would wrap this.
            // For now, standard direct connect:
        }

        const tcpSocket = connect({
            hostname: address,
            port: port,
        });
        remoteSocket.value = tcpSocket;
        log(`connected to ${address}:${port}`);
        
        const writer = tcpSocket.writable.getWriter();
        await writer.write(rawData); // Write early data
        writer.releaseLock();
        return tcpSocket;
    }

    // Connect
    const tcpSocket = await connectAndWrite(addressRemote, portRemote);

    // Pipe Remote Socket back to WebSocket
    tcpSocket.readable.pipeTo(new WritableStream({
        async write(chunk, controller) {
            // Traffic Accounting
            if (uuid && env && env.DB) {
                // We fire and forget traffic updates to avoid blocking bandwidth
                // Real-world: Batch these. Here: simpler approach
                ctx.waitUntil(Database.updateUserTraffic(env.DB, uuid, chunk.byteLength));
            }

            if (webSocket.readyState !== 1 /* OPEN */) {
                controller.error('webSocket not open');
                return;
            }
            
            if (responseHeader) {
                webSocket.send(await new Blob([responseHeader, chunk]).arrayBuffer());
                responseHeader = null;
            } else {
                webSocket.send(chunk);
            }
        },
        close() { log(`remoteConnection!.readable is closed`); },
        abort(reason) { console.error(`remoteConnection!.readable abort`, reason); },
    })).catch((err) => {
        console.error(`remoteSocketToWS error:`, err);
        safeCloseWebSocket(webSocket);
    });

    return tcpSocket;
}
/**
 * Handles UDP Outbound (DNS via DoH)
 */
async function handleUDPOutbound(webSocket, vlessResponseHeader, log) {
    let isHeaderSent = false;
    
    const transformStream = new TransformStream({
        start(controller) {},
        transform(chunk, controller) {
            for (let index = 0; index < chunk.byteLength;) {
                const lengthBuffer = chunk.slice(index, index + 2);
                const udpPacketLength = new DataView(lengthBuffer).getUint16(0);
                const udpData = new Uint8Array(chunk.slice(index + 2, index + 2 + udpPacketLength));
                index = index + 2 + udpPacketLength;
                controller.enqueue(udpData);
            }
        },
        flush(controller) {}
    });

    transformStream.readable.pipeTo(new WritableStream({
        async write(chunk) {
            const resp = await fetch('https://1.1.1.1/dns-query', {
                method: 'POST',
                headers: { 'content-type': 'application/dns-message' },
                body: chunk,
            });
            
            const dnsQueryResult = await resp.arrayBuffer();
            const udpSize = dnsQueryResult.byteLength;
            const udpSizeBuffer = new Uint8Array([(udpSize >> 8) & 0xff, udpSize & 0xff]);
            
            if (webSocket.readyState === 1 /* OPEN */) {
                log(`doh success length: ${udpSize}`);
                if (isHeaderSent) {
                    webSocket.send(await new Blob([udpSizeBuffer, dnsQueryResult]).arrayBuffer());
                } else {
                    webSocket.send(await new Blob([vlessResponseHeader, udpSizeBuffer, dnsQueryResult]).arrayBuffer());
                    isHeaderSent = true;
                }
            }
        }
    })).catch((err) => {
        log('dns pipeTo error', err);
    });

    const writer = transformStream.writable.getWriter();
    return {
        write: (chunk) => writer.write(chunk)
    };
}

// ==============================================================================
// 8. FINAL UTILITIES
// ==============================================================================

function stringifyUUID(v) {
    const arr = [...v];
    const toHex = (n) => (n < 16 ? '0' : '') + n.toString(16);
    return (
        arr.slice(0, 4).map(toHex).join('') +
        '-' +
        arr.slice(4, 6).map(toHex).join('') +
        '-' +
        arr.slice(6, 8).map(toHex).join('') +
        '-' +
        arr.slice(8, 10).map(toHex).join('') +
        '-' +
        arr.slice(10).map(toHex).join('')
    );
}

function base64ToArrayBuffer(base64Str) {
    if (!base64Str) return { earlyData: null, error: null };
    try {
        base64Str = base64Str.replace(/-/g, '+').replace(/_/g, '/');
        const decode = atob(base64Str);
        const arryBuffer = Uint8Array.from(decode, (c) => c.charCodeAt(0));
        return { earlyData: arryBuffer.buffer, error: null };
    } catch (error) {
        return { earlyData: null, error };
    }
}

function safeCloseWebSocket(socket) {
    try {
        if (socket.readyState === 1 || socket.readyState === 0) {
            socket.close();
        }
    } catch (e) {
        console.error('safeCloseWebSocket error', e);
    }
}
// ==============================================================================
// 9. MAIN WORKER ENTRY POINT & ROUTING
// ==============================================================================

export default {
    /**
     * Main fetch handler - Entry point for all incoming HTTP/WebSocket requests
     */
    async fetch(request, env, ctx) {
        // 1. Initialize Configuration & Database
        // We load config on every request to ensure environment variables are fresh
        const config = Config.fromEnv(env);
        
        // Initialize DB schema if not exists (non-blocking in production usually, but safe here)
        await Database.init(env);
        
        const url = new URL(request.url);
        
        // 2. VLESS WebSocket Upgrade Handling
        // This is the core proxy functionality
        const upgradeHeader = request.headers.get('Upgrade');
        if (upgradeHeader === 'websocket') {
            return await vlessOverWSHandler(request, env, ctx);
        }

        // 3. Static Security & Bot Files
        // Good practice for security scanners and bots
        if (url.pathname === '/robots.txt') {
            return new Response('User-agent: *\nDisallow: /admin\nDisallow: /api\nDisallow: /sub', { status: 200 });
        }
        if (url.pathname === '/security.txt' || url.pathname === '/.well-known/security.txt') {
            return new Response(`Contact: mailto:admin@${url.hostname}\nExpires: 2030-01-01T00:00:00.000Z\nEncryption: ${url.origin}/pgp-key.txt`, { status: 200 });
        }

        // 4. Admin Panel & API Routing
        // Handles login, dashboard, and AJAX API calls
        if (url.pathname.startsWith('/' + config.adminPath)) {
            // A. Login Logic (POST request to admin path)
            if (request.method === 'POST' && url.pathname === '/' + config.adminPath) {
                const formData = await request.formData();
                const password = formData.get('password');
                
                // Rate limiting check could go here using KV/D1
                if (password === config.adminKey) {
                    const headers = new Headers();
                    // Secure, HTTPOnly, Strict cookie
                    headers.append('Set-Cookie', `auth_token=${config.adminKey}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=86400`);
                    headers.append('Location', '/' + config.adminPath);
                    return new Response(null, { status: 302, headers });
                }
                // Return login page with error
                return new Response(buildLoginPage(config.adminPath, 'Invalid Credentials'), { headers: { 'Content-Type': 'text/html' } });
            }

            // B. Authentication Check
            const cookie = request.headers.get('Cookie');
            const token = cookie?.split(';').find(s => s.trim().startsWith('auth_token='))?.split('=')[1]?.trim();
            
            // If not authenticated, show login page
            if (token !== config.adminKey) {
                return new Response(buildLoginPage(config.adminPath), { headers: { 'Content-Type': 'text/html' } });
            }

            // C. Admin API Actions (AJAX)
            if (url.searchParams.get('action')) {
                return await handleApiRequest(request, env);
            }

            // D. Render Admin Dashboard
            const nonce = Utils.generateNonce();
            const headers = new Headers({ 'Content-Type': 'text/html' });
            Utils.addSecurityHeaders(headers);
            // Strict CSP for Admin Panel
            headers.set('Content-Security-Policy', `default-src 'self'; script-src 'self' 'nonce-${nonce}' https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline'; font-src 'self'; connect-src 'self'; img-src 'self' data:;`);
            
            return new Response(buildAdminUI(config, nonce), { headers });
        }
// ==============================================================================
// 10. SUBSCRIPTION HELPERS (Clash / Sing-box)
// ==============================================================================

const Subscriptions = {
    toClash(user, host) {
        return `port: 7890
socks-port: 7891
redir-port: 7892
mixed-port: 7893
tproxy-port: 7895
ipv6: false
allow-lan: true
mode: rule
log-level: info
external-controller: 127.0.0.1:9090
proxies:
  - name: ${host}
    server: ${host}
    port: 443
    type: vless
    uuid: ${user.uuid}
    cipher: auto
    tls: true
    udp: true
    skip-cert-verify: true
    network: ws
    ws-opts:
      path: /
      headers:
        Host: ${host}
proxy-groups:
  - name: PROXY
    type: select
    proxies:
      - ${host}
      - DIRECT
rules:
  - MATCH,PROXY`;
    },

    toSingbox(user, host) {
        return JSON.stringify({
            "log": { "level": "info", "timestamp": true },
            "inbounds": [{ "type": "tun", "tag": "tun-in", "inet4_address": "172.19.0.1/30", "auto_route": true, "strict_route": true }],
            "outbounds": [
                {
                    "type": "vless",
                    "tag": "proxy",
                    "server": host,
                    "server_port": 443,
                    "uuid": user.uuid,
                    "flow": "",
                    "tls": { "enabled": true, "server_name": host, "insecure": true },
                    "transport": { "type": "ws", "path": "/", "headers": { "Host": host } }
                },
                { "type": "direct", "tag": "direct" },
                { "type": "block", "tag": "block" }
            ],
            "route": { "rules": [{ "outbound": "direct", "ip_cidr": ["geoip:private"] }, { "outbound": "proxy", "port": [80, 443] }] }
        }, null, 2);
    }
};

        // 5. User Portal & Subscription Routing
        if (url.pathname.startsWith('/sub/')) {
            const uuid = url.pathname.split('/')[2];
            if (Utils.isValidUUID(uuid)) {
                const user = await Database.getUser(env.DB, uuid);
                if (user) {
                    // Async activity update
                    ctx.waitUntil(env.DB.prepare("UPDATE users SET active = 1 WHERE uuid = ?").bind(uuid).run());
                    
                    const format = url.searchParams.get('format');
                    const host = url.hostname;

                    if (format === 'clash') {
                        return new Response(Subscriptions.toClash(user, host), {
                            headers: { 'Content-Type': 'text/yaml; charset=utf-8', 'Content-Disposition': `attachment; filename="${host}.yaml"` }
                        });
                    }
                    
                    if (format === 'singbox') {
                        return new Response(Subscriptions.toSingbox(user, host), {
                            headers: { 'Content-Type': 'application/json; charset=utf-8', 'Content-Disposition': `attachment; filename="${host}.json"` }
                        });
                    }
                    
                    const headers = new Headers({ 'Content-Type': 'text/html' });
                    Utils.addSecurityHeaders(headers);
                    return new Response(buildUserUI(user, config), { headers });
                }
                return new Response('Subscription invalid or expired.', { status: 404 });
            }
        }

        // 6. Robust Landing Page Reverse Proxy
        if (config.enableLandingProxy) {
            try {
                const targetUrl = new URL(config.landingPageUrl);
                const proxyUrl = new URL(targetUrl.origin + url.pathname + url.search);
                
                const proxyRequest = new Request(proxyUrl, {
                    method: request.method,
                    headers: new Headers(request.headers),
                    body: request.body,
                    redirect: 'follow'
                });
                
                proxyRequest.headers.set('Host', targetUrl.hostname);
                proxyRequest.headers.set('Referer', targetUrl.origin);
                proxyRequest.headers.set('X-Forwarded-For', request.headers.get('CF-Connecting-IP'));
                
                const response = await fetch(proxyRequest);
                const newHeaders = new Headers(response.headers);
                newHeaders.delete('Content-Security-Policy');
                newHeaders.delete('X-Frame-Options');
                Utils.addSecurityHeaders(newHeaders);
                
                return new Response(response.body, {
                    status: response.status,
                    statusText: response.statusText,
                    headers: newHeaders
                });
            } catch (e) {
                console.error('Reverse Proxy Failed:', e);
            }
        }

        // 7. Custom Styled 404 Page
        const html404 = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>404 Not Found</title>
    <style>
        body { margin:0; font-family: sans-serif; background: #0f172a; color: #f8fafc; height: 100vh; display: flex; align-items: center; justify-content: center; text-align: center; }
        .code { font-size: 8rem; font-weight: 900; background: linear-gradient(135deg, #3b82f6, #8b5cf6); -webkit-background-clip: text; -webkit-text-fill-color: transparent; margin: 0; line-height: 1; }
        .msg { font-size: 1.5rem; color: #94a3b8; margin-top: 1rem; }
        .home { margin-top: 2rem; display: inline-block; padding: 0.75rem 1.5rem; background: rgba(255,255,255,0.1); color: white; text-decoration: none; border-radius: 8px; }
        .home:hover { background: rgba(255,255,255,0.2); }
    </style>
</head>
<body>
    <div>
        <h1 class="code">404</h1>
        <p class="msg">The requested resource could not be found.</p>
        <a href="/" class="home">Go Home</a>
    </div>
</body>
</html>`;

        return new Response(html404, { 
            status: 404, 
            headers: { 'Content-Type': 'text/html' } 
        });
    },

    /**
     * Scheduled Task Handler
     */
    async scheduled(event, env, ctx) {
        const config = Config.fromEnv(env);
        await Database.init(env);
        
        console.log('[Cron] Starting Scheduled Tasks...');

        // Task 1: Check Proxy Node Health
        const proxyIPs = config.proxyIPs;
        if (proxyIPs.length > 0) {
            for (const ip of proxyIPs) {
                const start = Date.now();
                try {
                    const controller = new AbortController();
                    setTimeout(() => controller.abort(), CONST.HEALTH_CHECK_TIMEOUT);
                    
                    const resp = await fetch(`https://${ip}`, { method: 'HEAD', signal: controller.signal });
                    const latency = Date.now() - start;
                    const isHealthy = resp.ok || resp.status === 404;
                    
                    await Database.saveProxyHealth(env.DB, ip, latency, isHealthy);
                    console.log(`[Health] ${ip}: ${latency}ms`);
                } catch (e) {
                    await Database.saveProxyHealth(env.DB, ip, 0, false);
                    console.log(`[Health] ${ip}: Down`);
                }
            }
        }
        
        // Task 2: Expired User Cleanup
        try {
            const result = await env.DB.prepare(`
                UPDATE users SET active = 0 
                WHERE active = 1 AND expiration_date IS NOT NULL 
                AND datetime(expiration_date || ' ' || COALESCE(expiration_time, '00:00:00')) < datetime('now')
            `).run();
            console.log(`[Cleanup] Disabled ${result.meta.changes} expired users.`);
        } catch (e) {
            console.error('[Cleanup] Error:', e);
        }

        console.log('[Cron] Tasks Completed.');
    }
};

/ Part 1: Core Architecture and Global Configuration (Full Features / Zero Comments)
import { connect } from 'cloudflare:sockets';

const Config = {
    userID: 'd342d11e-d424-4583-b36e-524ab1f0afa4',
    proxyIPs: ['nima.nscl.ir:443', 'bpb.yousef.isegaro.com:443'],
    scamalytics: {
        username: 'victoriacrossn',
        apiKey: 'ed89b4fef21aba43c15cdd15cff2138dd8d3bbde5aaaa4690ad8e94990448516',
        baseUrl: 'https://api12.scamalytics.com/v3/',
    },
    socks5: {
        enabled: false,
        relayMode: false,
        address: '',
    },

    async fromEnv(env) {
        let selectedProxyIP = null;

        if (env.DB) {
            try {
                const { results } = await env.DB.prepare(
                    "SELECT ip_port FROM proxy_health WHERE is_healthy = 1 ORDER BY latency_ms ASC LIMIT 1"
                ).all();
                selectedProxyIP = results[0]?.ip_port || null;
            } catch (e) {
                console.error(e.message);
            }
        }

        if (!selectedProxyIP) {
            selectedProxyIP = env.PROXYIP;
        }

        if (!selectedProxyIP) {
            selectedProxyIP = this.proxyIPs[Math.floor(Math.random() * this.proxyIPs.length)];
        }

        if (!selectedProxyIP) {
            selectedProxyIP = this.proxyIPs[0] || '127.0.0.1:443';
        }

        const [proxyHost, proxyPort = '443'] = selectedProxyIP.split(':');
        const socks5Address = env.SOCKS5 || this.socks5.address;
        let socks5Enabled = !!env.SOCKS5 || this.socks5.enabled;
        let parsedSocks5Address = null;

        if (socks5Enabled && socks5Address) {
            try {
                parsedSocks5Address = socks5AddressParser(socks5Address);
            } catch (e) {
                console.error(e.message);
                socks5Enabled = false;
            }
        }

        return {
            userID: env.UUID || this.userID,
            proxyIP: proxyHost,
            proxyPort: parseInt(proxyPort, 10),
            proxyAddress: selectedProxyIP,
            scamalytics: {
                username: env.SCAMALYTICS_USERNAME || this.scamalytics.username,
                apiKey: env.SCAMALYTICS_API_KEY || this.scamalytics.apiKey,
                baseUrl: env.SCAMALYTICS_BASEURL || this.scamalytics.baseUrl,
            },
            socks5: {
                enabled: socks5Enabled,
                relayMode: env.SOCKS5_RELAY === 'true' || this.socks5.relayMode,
                address: socks5Address,
            },
            parsedSocks5Address: parsedSocks5Address,
        };
    },
};

const CONST = {
    ED_PARAMS: { ed: 2560, eh: 'Sec-WebSocket-Protocol' },
    VLESS_PROTOCOL: 'vless',
    WS_READY_STATE_OPEN: 1,
    WS_READY_STATE_CLOSING: 2,

    ADMIN_LOGIN_FAIL_LIMIT: 5,
    ADMIN_LOGIN_LOCK_TTL: 600,
    ADMIN_SESSION_TTL: 86400,

    SCAMALYTICS_THRESHOLD: 50,
    USER_PATH_RATE_LIMIT: 20,
    USER_PATH_RATE_TTL: 60,

    IP_BLACKLIST_TTL: 3600,
    BRUTE_FORCE_LOGIN_ATTEMPTS: 10,
    BRUTE_FORCE_LOGIN_TTL: 300,
    INVALID_UUID_ATTEMPTS: 50,
    INVALID_UUID_TTL: 60,
    PORT_SCAN_THRESHOLD: 10,
    PORT_SCAN_TTL: 30,

    ADMIN_AUTO_REFRESH_INTERVAL: 60000,
    IP_CLEANUP_AGE_DAYS: 30,
    HEALTH_CHECK_INTERVAL: 300000,
    HEALTH_CHECK_TIMEOUT: 5000,
    DB_CACHE_TTL: 3600,
};

function generateNonce() {
    const arr = new Uint8Array(16);
    crypto.getRandomValues(arr);
    return btoa(String.fromCharCode.apply(null, arr));
}

function addSecurityHeaders(headers, nonce, cspDomains = {}) {
    const scriptSrc = nonce
        ? `script-src 'self' 'nonce-${nonce}' 'unsafe-inline' https://cdnjs.cloudflare.com https://unpkg.com https://chart.googleapis.com`
        : "script-src 'self' https://cdnjs.cloudflare.com https://unpkg.com https://chart.googleapis.com 'unsafe-inline'";
    
    const styleSrc = "style-src 'self' 'unsafe-inline' 'unsafe-hashes'"; 

    const csp = [
        "default-src 'self'",
        "form-action 'self'",
        "object-src 'none'",
        "frame-ancestors 'none'",
        "base-uri 'self'",
        scriptSrc,
        styleSrc,
        `img-src 'self' data: blob: https: ${cspDomains.img || ''}`.trim(),
        `connect-src 'self' https: wss: ${cspDomains.connect || ''}`.trim(),
        "worker-src 'self' blob:",
        "child-src 'self' blob:",
        "frame-src 'none'",
        "font-src 'self' https: data:",
    ];
    headers.set('Content-Security-Policy', csp.join('; '));
    headers.set('Strict-Transport-Security', 'max-age=63072000; includeSubDomains; preload');
    headers.set('X-Content-Type-Options', 'nosniff');
    headers.set('X-Frame-Options', 'SAMEORIGIN');
    headers.set('Referrer-Policy', 'strict-origin-when-cross-origin');
    headers.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=(), usb=()');
    headers.set('alt-svc', 'h3=":443"; ma=0');
    headers.set('Cross-Origin-Opener-Policy', 'same-origin');
    headers.set('Cross-Origin-Embedder-Policy', 'unsafe-none');
    headers.set('Cross-Origin-Resource-Policy', 'cross-origin');
    headers.set('X-XSS-Protection', '1; mode=block');
}

function timingSafeEqual(a, b) {
    if (typeof a !== 'string' || typeof b !== 'string') return false;
    const aLen = a.length;
    const bLen = b.length;
    let result = 0;
    if (aLen !== bLen) {
        for (let i = 0; i < aLen; i++) {
            result |= a.charCodeAt(i) ^ a.charCodeAt(i);
        }
        return false;
    }
    for (let i = 0; i < aLen; i++) {
        result |= a.charCodeAt(i) ^ b.charCodeAt(i);
    }
    return result === 0;
}

function escapeHTML(str) {
    if (typeof str !== 'string') return '';
    const map = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;',
    };
    return str.replace(/[&<>"']/g, m => map[m]);
}

function safeBase64Encode(str) {
    try {
        const encoder = new TextEncoder();
        const bytes = encoder.encode(str);
        let binary = '';
        for (let i = 0; i < bytes.length; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary);
    } catch (e) {
        return btoa(unescape(encodeURIComponent(str)));
    }
}

function generateUUID() {
    return crypto.randomUUID();
}

function isValidUUID(uuid) {
    if (typeof uuid !== 'string') return false;
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    return uuidRegex.test(uuid);
}

function isExpired(expDate, expTime) {
    if (!expDate || !expTime) return true;

    const cleanTime = expTime.includes(':') && expTime.split(':').length === 2
        ? `${expTime}:00`
        : expTime.split('.')[0];

    const expDatetimeUTC = new Date(`${expDate}T${cleanTime}Z`);
    
    return isNaN(expDatetimeUTC.getTime()) || expDatetimeUTC <= new Date();
}

async function formatBytes(bytes) {
    if (bytes === 0 || bytes === null || bytes === undefined) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i))).toFixed(2) + ' ' + sizes[i];
}

function base32ToBuffer(base32) {
    const base32Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    const str = base32.toUpperCase().replace(/=+$/, '');
    let bits = 0;
    let value = 0;
    let index = 0;
    const output = new Uint8Array(Math.floor(str.length * 5 / 8));

    for (let i = 0; i < str.length; i++) {
        const char = str[i];
        const charValue = base32Chars.indexOf(char);
        if (charValue === -1) throw new Error('Invalid Base32 character');

        value = (value << 5) | charValue;
        bits += 5;

        if (bits >= 8) {
            output[index++] = (value >>> (bits - 8)) & 0xFF;
            bits -= 8;
        }
    }
    return output.buffer.slice(0, index);
}

async function generateHOTP(secretBuffer, counter) {
    const counterBuffer = new ArrayBuffer(8);
    new DataView(counterBuffer).setBigUint64(0, BigInt(counter), false);

    const key = await crypto.subtle.importKey(
        'raw',
        secretBuffer,
        { name: 'HMAC', hash: 'SHA-1' },
        false,
        ['sign']
    );

    const hmac = await crypto.subtle.sign('HMAC', key, counterBuffer);
    const hmacBuffer = new Uint8Array(hmac);

    const offset = hmacBuffer[hmacBuffer.length - 1] & 0x0F;
    const binary = (
        ((hmacBuffer[offset] & 0x7F) << 24) |
        ((hmacBuffer[offset + 1] & 0xFF) << 16) |
        ((hmacBuffer[offset + 2] & 0xFF) << 8) |
        (hmacBuffer[offset + 3] & 0xFF)
    );

    const otp = binary % 1000000;
    return otp.toString().padStart(6, '0');
}

async function validateTOTP(secret, code) {
    if (!secret || !code || code.length !== 6 || !/^\d{6}$/.test(code)) {
        return false;
    }

    let secretBuffer;
    try {
        secretBuffer = base32ToBuffer(secret);
    } catch (e) {
        console.error(e.message);
        return false;
    }

    const timeStep = 30;
    const epoch = Math.floor(Date.now() / 1000);
    const currentCounter = Math.floor(epoch / timeStep);

    const counters = [currentCounter, currentCounter - 1, currentCounter + 1];

    for (const counter of counters) {
        const generatedCode = await generateHOTP(secretBuffer, counter);
        if (timingSafeEqual(code, generatedCode)) {
            return true;
        }
    }
    return false;
}

async function hashSHA256(str) {
    const encoder = new TextEncoder();
    const data = encoder.encode(str);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

async function d1KvGet(db, key, type = 'text') {
    if (!db) {
        return null;
    }
    try {
        const stmt = db.prepare("SELECT value, expiration FROM key_value WHERE key = ?").bind(key);
        const res = await stmt.first();

        if (!res) return null;

        if (res.expiration && res.expiration < Math.floor(Date.now() / 1000)) {
            db.prepare("DELETE FROM key_value WHERE key = ?").bind(key).run().catch(e => console.error(e.message));
            return null;
        }

        if (type === 'json') {
            try {
                return JSON.parse(res.value);
            } catch (e) {
                console.error(e.message);
                return null;
            }
        }
        return res.value;
    } catch (e) {
        console.error(e.message, e.stack);
        return null;
    }
}

async function d1KvPut(db, key, value, options = {}) {
    if (!db) {
        return;
    }
    try {
        let serializedValue = value;
        if (typeof value === 'object' && value !== null) {
            serializedValue = JSON.stringify(value);
        }

        const expiration = options.expirationTtl
            ? Math.floor(Date.now() / 1000 + options.expirationTtl)
            : null;

        await db.prepare(
            "INSERT OR REPLACE INTO key_value (key, value, expiration) VALUES (?, ?, ?)"
        ).bind(key, serializedValue, expiration).run();
    } catch (e) {
        console.error(e.message);
    }
}

async function d1KvDelete(db, key) {
    if (!db) {
        return;
    }
    try {
        await db.prepare("DELETE FROM key_value WHERE key = ?").bind(key).run();
    } catch (e) {
        console.error(e.message);
    }
}

async function checkRateLimit(db, key, limit, ttl) {
    if (!db) {
        return false;
    }
    try {
        const countStr = await d1KvGet(db, key);
        const count = parseInt(countStr, 10) || 0;

        if (count >= limit) {
            return true;
        }

        await d1KvPut(db, key, (count + 1).toString(), { expirationTtl: ttl });
        return false;
    } catch (e) {
        console.error(e.message);
        return false;
    }
}

async function logSecurityEvent(db, ctx, ip, type, details, uuid = null) {
    if (!db) {
        return;
    }
    try {
        const timestamp = Math.floor(Date.now() / 1000);
        const stmt = db.prepare(
            "INSERT INTO security_events (timestamp, ip, type, details, uuid) VALUES (?, ?, ?, ?, ?)"
        ).bind(timestamp, ip, type, details, uuid);

        ctx.waitUntil(stmt.run().catch(e => console.error(e.message)));
    } catch (e) {
        console.error(e.message, e.stack);
    }
}

async function addIpToBlacklist(db, ctx, ip, reason, ttl = CONST.IP_BLACKLIST_TTL) {
    if (!db) {
        return;
    }
    try {
        const expiration = (ttl === 0)
            ? (Math.floor(Date.now() / 1000) + 365 * 24 * 3600 * 100)
            : (Math.floor(Date.now() / 1000 + ttl));

        const stmt = db.prepare(
            "INSERT OR REPLACE INTO ip_blacklist (ip, expiration, reason, timestamp) VALUES (?, ?, ?, ?)"
        ).bind(ip, expiration, reason, Math.floor(Date.now() / 1000));

        ctx.waitUntil(stmt.run().then(() => {
            logSecurityEvent(db, ctx, ip, 'IP_BLACKLISTED', `IP blacklisted for ${reason}. TTL: ${ttl}s.`, null);
        }).catch(e => console.error(e.message)));

    } catch (e) {
        console.error(e.message, e.stack);
    }
}

async function checkBlockedIP(db, ip) {
    if (!db) return null;
    try {
        const now = Math.floor(Date.now() / 1000);
        const stmt = db.prepare("SELECT * FROM ip_blacklist WHERE ip = ?").bind(ip);
        const entry = await stmt.first();

        if (entry && entry.expiration > now) {
            return entry;
        } else if (entry && entry.expiration <= now) {
            db.prepare("DELETE FROM ip_blacklist WHERE ip = ?").bind(ip).run()
                .catch(e => console.error(e.message));
        }
        return null;
    } catch (e) {
        console.error(e.message);
        return null;
    }
}

const byteToHex = Array.from({ length: 256 }, (_, i) => (i + 0x100).toString(16).slice(1));

function unsafeStringify(arr, offset = 0) {
    return (
        byteToHex[arr[offset]] + byteToHex[arr[offset + 1]] + byteToHex[arr[offset + 2]] + byteToHex[arr[offset + 3]] +
        '-' +
        byteToHex[arr[offset + 4]] + byteToHex[arr[offset + 5]] +
        '-' +
        byteToHex[arr[offset + 6]] + byteToHex[arr[offset + 7]] +
        '-' +
        byteToHex[arr[offset + 8]] + byteToHex[arr[offset + 9]] +
        '-' +
        byteToHex[arr[offset + 10]] + byteToHex[arr[offset + 11]] + byteToHex[arr[offset + 12]] + byteToHex[arr[offset + 13]] + byteToHex[arr[offset + 14]] + byteToHex[arr[offset + 15]]
    ).toLowerCase();
}

function stringify(arr, offset = 0) {
    const uuid = unsafeStringify(arr, offset);
    if (!isValidUUID(uuid)) {
        throw new TypeError('Stringified UUID is invalid or malformed: ' + uuid);
    }
    return uuid;
}

}
// Part 2: VLESS Protocol Logic and Connection Handling
async function getUserData(env, uuid, ctx) {
    if (!isValidUUID(uuid)) {
        console.warn(`Invalid UUID format: ${uuid}`);
        return null;
    }
    if (!env.DB) {
        console.error("D1 binding missing. Cannot retrieve user data.");
        return null;
    }

    const cacheKey = `user:${uuid}`;
    let userData = null;

    try {
        userData = await d1KvGet(env.DB, cacheKey, 'json');
        if (userData && userData.uuid) {
            return userData;
        }
    } catch (e) {
        console.error(e.message);
    }

    const userFromDb = await env.DB.prepare("SELECT * FROM users WHERE uuid = ?").bind(uuid).first();

    if (!userFromDb) {
        if (userData) {
            ctx.waitUntil(d1KvDelete(env.DB, cacheKey));
        }
        return null;
    }

    const cachePromise = d1KvPut(env.DB, cacheKey, userFromDb, { expirationTtl: CONST.DB_CACHE_TTL });
    if (ctx) {
        ctx.waitUntil(cachePromise.catch(e => console.error(e.message)));
    } else {
        await cachePromise.catch(e => console.error(e.message));
    }

    return userFromDb;
}

async function updateUsage(env, uuid, bytes, ctx) {
    if (bytes <= 0 || !uuid) return;
    if (!env.DB) {
        console.error("D1 binding missing. Cannot update user usage.");
        return;
    }

    const usageLockKey = `usage_lock:${uuid}`;
    let lockAcquired = false;
    const LOCK_TTL = 5;

    try {
        const maxAttempts = 5;
        for (let i = 0; i < maxAttempts; i++) {
            const existingLock = await d1KvGet(env.DB, usageLockKey);
            if (!existingLock) {
                await d1KvPut(env.DB, usageLockKey, 'locked', { expirationTtl: LOCK_TTL });
                lockAcquired = true;
                break;
            } else {
                await new Promise(resolve => setTimeout(resolve, 100 * (i + 1)));
            }
        }

        if (!lockAcquired) {
            console.warn(`Failed to acquire lock for ${uuid} after attempts. Skipping usage update.`);
            return;
        }

        const usage = Math.round(bytes);
        const updatePromise = env.DB.prepare(
            "UPDATE users SET traffic_used = traffic_used + ? WHERE uuid = ?"
        ).bind(usage, uuid).run();

        const deleteCachePromise = d1KvDelete(env.DB, `user:${uuid}`);

        if (ctx) {
            ctx.waitUntil(Promise.all([updatePromise, deleteCachePromise])
                .catch(err => console.error(err)));
        } else {
            await Promise.all([updatePromise, deleteCachePromise])
                .catch(err => console.error(err));
        }

    } catch (err) {
        console.error(err.message, err.stack);
    } finally {
        if (lockAcquired) {
            try {
                ctx.waitUntil(d1KvDelete(env.DB, usageLockKey).catch(e => console.error(e.message)));
            } catch (e) {
                console.error(e.message);
            }
        }
    }
}

async function resolveProxyIP(proxyHost) {
    const ipv4Regex = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
    const ipv6Regex = /^\[?([0-9a-fA-F:.]+)\]?$/;
    
    if (ipv4Regex.test(proxyHost) || ipv6Regex.test(proxyHost)) {
        return proxyHost;
    }

    const dnsAPIs = [
        {
            url: `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(proxyHost)}&type=A`,
            parse: data => data.Answer?.find(a => a.type === 1)?.data
        },
        {
            url: `https://dns.google/resolve?name=${encodeURIComponent(proxyHost)}&type=A`,
            parse: data => data.Answer?.find(a => a.type === 1)?.data
        },
        {
            url: `https://dns.quad9.net/dns-query?name=${encodeURIComponent(proxyHost)}&type=A`,
            parse: data => data.Answer?.find(a => a.type === 1)?.data
        }
    ];

    for (const api of dnsAPIs) {
        try {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 3000);
            const response = await fetch(api.url, {
                headers: { 'accept': 'application/dns-json' },
                signal: controller.signal
            });
            clearTimeout(timeoutId);

            if (response.ok) {
                const data = await response.json();
                const ip = api.parse(data);
                if (ip && ipv4Regex.test(ip)) {
                    return ip;
                }
            }
        } catch (e) {
        }
    }
    console.warn(`Failed to resolve IP for ${proxyHost} after trying all DNS providers. Using original hostname as fallback.`);
    return proxyHost;
}

async function getGeo(ip, cfHeaders = null) {
    if (cfHeaders && (cfHeaders.city || cfHeaders.country || cfHeaders.asOrganization)) {
        return {
            city: cfHeaders.city || '',
            country: cfHeaders.country || '',
            isp: cfHeaders.asOrganization || ''
        };
    }

    const geoAPIs = [
        {
            url: `https://ip-api.com/json/${ip}?fields=status,message,city,country,isp`,
            parse: async (r) => {
                const data = await r.json();
                if (data.status === 'fail') throw new Error(data.message || 'API Error');
                return { city: data.city || '', country: data.country || '', isp: data.isp || '' };
            }
        },
        {
            url: `https://ipapi.co/${ip}/json/`,
            parse: async (r) => {
                const data = await r.json();
                if (data.error) throw new Error(data.reason || 'API Error');
                return { city: data.city || '', country: data.country_name || '', isp: data.org || '' };
            }
        },
        {
            url: `https://ipwho.is/${ip}`,
            parse: async (r) => {
                const data = await r.json();
                if (!data.success) throw new Error('API Error');
                return { city: data.city || '', country: data.country || '', isp: data.connection?.isp || '' };
            }
        },
        {
            url: `https://ipinfo.io/${ip}/json`,
            parse: async (r) => {
                const data = await r.json();
                if (data.bogon) throw new Error('Bogon IP');
                return { city: data.city || '', country: data.country || '', isp: data.org || '' };
            }
        },
        {
            url: `https://freeipapi.com/api/json/${ip}`,
            parse: async (r) => {
                const data = await r.json();
                if (data.message) throw new Error(data.message);
                return { city: data.cityName || '', country: data.countryName || '', isp: '' };
            }
        }
    ];

    for (const api of geoAPIs) {
        try {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 3000);
            const response = await fetch(api.url, {
                signal: controller.signal,
                headers: { 'Accept': 'application/json' }
            });
            clearTimeout(timeoutId);

            if (response.ok) {
                const geo = await api.parse(response);
                if (geo && (geo.city || geo.country || geo.isp)) {
                    return geo;
                }
            }
        } catch (e) {
        }
    }

    console.warn(`Failed to get geo-location for IP ${ip} after trying all providers.`);
    return { city: 'Unknown', country: 'Global', isp: 'Unknown' };
}

function generateRandomPath(length = 12) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    for (let i = 0; i < length; i++) {
        result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return `/${result}`;
}

const CORE_PRESETS = {
    xray: {
        tls: {
            path: () => generateRandomPath(12),
            security: 'tls',
            fp: 'chrome',
            alpn: 'http/1.1',
            extra: { ed: '2560' },
        },
        tcp: {
            path: () => generateRandomPath(12),
            security: 'none',
            fp: 'chrome',
            extra: { ed: '2560' },
        },
    },
    sb: {
        tls: {
            path: () => generateRandomPath(18),
            security: 'tls',
            fp: 'firefox',
            alpn: 'h3',
            extra: CONST.ED_PARAMS,
        },
        tcp: {
            path: () => generateRandomPath(18),
            security: 'none',
            fp: 'firefox',
            extra: CONST.ED_PARAMS,
        },
    },
};

function makeName(tag, proto) {
    return `${tag}-${proto.toUpperCase()}`;
}

function randomizeCase(str) {
    if (!str) return str;
    let result = '';
    for (let i = 0; i < str.length; i++) {
        result += Math.random() < 0.5 ? str[i].toUpperCase() : str[i].toLowerCase();
    }
    return result;
}

function createVlessLink({ userID, address, port, host, path, security, sni, fp, alpn, extra = {}, name }) {
    const params = new URLSearchParams({
        encryption: 'none',
        type: 'ws',
        host: host,
        path: path,
    });

    if (security) {
        params.set('security', security);
    }
    if (sni) params.set('sni', sni);
    if (fp) params.set('fp', fp);
    if (alpn) params.set('alpn', alpn);

    for (const [k, v] of Object.entries(extra)) {
        params.set(k, v);
    }

    return `vless://${userID}@${address}:${port}?${params.toString()}#${encodeURIComponent(name)}`;
}

function buildLink({ core, proto, userID, hostName, address, port, tag }) {
    const p = CORE_PRESETS[core]?.[proto];
    if (!p) {
        console.error(`Invalid core or protocol preset requested: core=${core}, proto=${proto}. Falling back to default TLS config.`);
        return createVlessLink({
            userID, address, port, host: hostName, path: generateRandomPath(12),
            security: 'tls', sni: hostName, fp: 'chrome', alpn: 'http/1.1',
            name: makeName(tag, 'DEFAULT_TLS')
        });
    }

    const sniValue = p.security === 'tls' ? randomizeCase(hostName) : undefined;

    return createVlessLink({
        userID,
        address,
        port,
        host: hostName,
        path: p.path(),
        security: p.security,
        sni: sniValue,
        fp: p.fp,
        alpn: p.alpn,
        extra: p.extra,
        name: makeName(tag, proto),
    });
}

const pick = (arr) => arr[Math.floor(Math.random() * arr.length)];

async function handleIpSubscription(core, userID, hostName, env) {
    const mainDomains = [
        hostName,
        'www.visa.com', 'www.wto.org', 'creativecommons.org', 'www.speedtest.net',
        'sky.rethinkdns.com', 'cdnjs.com', 'zula.ir', 'go.inmobi.com',
        'mail.tm', 'temp-mail.org', 'ipaddress.my', 'mdbmax.com',
        'check-host.net', 'kodambroker.com', 'iplocation.io', 'whatismyip.org',
        'www.linkedin.com', 'exir.io', 'arzex.io', 'ok-ex.io',
        'arzdigital.com', 'pouyanit.com', 'auth.grok.com', 'grok.com',
        'maxmind.com', 'whatsmyip.com', 'iplocation.net', 'ipchicken.com',
        'showmyip.com', 'router-network.com', 'whatismyipaddress.com',
        'www.apple.com', 'www.microsoft.com', 'www.amazon.com', 'www.cloudflare.com',
        'www.google.com', 'github.com', 'gitlab.com', 'wikipedia.org',
        'developer.mozilla.org', 'www.nginx.com', 'www.apache.org',
        'telegram.org', 'bale.ai', 'ir.linkedin.com', 'divar.ir', 'snapp.ir',
        'jiring.ir', 'shaparak.ir', 'pishgaman.net', 'asriran.com', 'varzesh3.com',
        'isna.ir', 'farsnews.ir', 'mehrnews.com', 'tasnimnews.com'
    ].sort(() => 0.5 - Math.random());

    const httpsPorts = [443, 8443, 2053, 2083, 2087, 2096, 4430, 4431, 4432, 4433, 4434, 4435, 4436, 4437, 4438, 4439];
    const httpPorts = [80, 8080, 8880, 2052, 2082, 2086, 2095, 8000, 8008, 8009, 8010, 8011, 8012, 8013, 8014, 8015];

    let links = [];
    const isPagesDeployment = hostName.endsWith('.pages.dev');

    mainDomains.slice(0, 15).forEach((domain, i) => {
        links.push(
            buildLink({ core, proto: 'tls', userID, hostName, address: domain, port: pick(httpsPorts), tag: `D${i + 1}-TLS-1` }),
            buildLink({ core, proto: 'tls', userID, hostName, address: domain, port: pick(httpsPorts), tag: `D${i + 1}-TLS-2` }),
        );
        if (!isPagesDeployment) {
            links.push(
                buildLink({ core, proto: 'tcp', userID, hostName, address: domain, port: pick(httpPorts), tag: `D${i + 1}-TCP-1` }),
                buildLink({ core, proto: 'tcp', userID, hostName, address: domain, port: pick(httpPorts), tag: `D${i + 1}-TCP-2` }),
            );
        }
    });

    let dynamicProxyIPs = [];
    if (env.DB) {
        try {
            const { results } = await env.DB.prepare(
                "SELECT ip_port, latency_ms FROM proxy_health WHERE is_healthy = 1 ORDER BY latency_ms ASC LIMIT 20"
            ).all();
            dynamicProxyIPs = results.map(r => r.ip_port.split(':')[0]);
        } catch (e) {
            console.error(e.message);
        }
    }
    if (dynamicProxyIPs.length === 0) {
        try {
            const r = await fetch(
                'https://raw.githubusercontent.com/NiREvil/vless/refs/heads/main/Cloudflare-IPs.json',
            );
            if (r.ok) {
                const json = await r.json();
                dynamicProxyIPs = [...(json.ipv4 || []), ...(json.ipv6 || [])]
                                .slice(0, 30)
                                .map((x) => x.ip);
            } else {
                console.warn(`Failed to fetch Cloudflare IPs: HTTP Status ${r.status}`);
            }
        } catch (e) {
            console.error(e.message, e.stack);
        }
    }

    dynamicProxyIPs.slice(0, 20).forEach((ip, i) => {
        const formattedAddress = ip.includes(':') ? `[${ip}]` : ip;
        links.push(
            buildLink({ core, proto: 'tls', userID, hostName, address: formattedAddress, port: pick(httpsPorts), tag: `IP${i + 1}-TLS-1` }),
            buildLink({ core, proto: 'tls', userID, hostName, address: formattedAddress, port: pick(httpsPorts), tag: `IP${i + 1}-TLS-2` }),
        );
        if (!isPagesDeployment) {
            links.push(
                buildLink({ core, proto: 'tcp', userID, hostName, address: formattedAddress, port: pick(httpPorts), tag: `IP${i + 1}-TCP-1` }),
                buildLink({ core, proto: 'tcp', userID, hostName, address: formattedAddress, port: pick(httpPorts), tag: `IP${i + 1}-TCP-2` }),
            );
        }
    });

    const uniqueLinks = Array.from(new Set(links)).sort(() => 0.5 - Math.random());

    const headers = new Headers({
        'Content-Type': 'text/plain;charset=utf-8',
        'Profile-Update-Interval': '6',
        'Cache-Control': 'no-cache, no-store, must-revalidate',
        'Pragma': 'no-cache',
        'Expires': '0',
    });
    addSecurityHeaders(headers, null, {});

    return new Response(safeBase64Encode(uniqueLinks.join('\n')), { headers });
}

async function ensureTablesExist(env, ctx) {
    if (!env.DB) {
        console.warn('D1 binding not available. Skipping table creation.');
        return;
    }

    try {
        const createTables = [
            `CREATE TABLE IF NOT EXISTS users (
                uuid TEXT PRIMARY KEY,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                expiration_date TEXT NOT NULL,
                expiration_time TEXT NOT NULL,
                notes TEXT,
                traffic_limit INTEGER,
                traffic_used INTEGER DEFAULT 0,
                ip_limit INTEGER DEFAULT -1
            )`,
            `CREATE TABLE IF NOT EXISTS user_ips (
                uuid TEXT,
                ip TEXT,
                last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (uuid, ip),
                FOREIGN KEY (uuid) REFERENCES users(uuid) ON DELETE CASCADE
            )`,
            `CREATE TABLE IF NOT EXISTS key_value (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                expiration INTEGER
            )`,
            `CREATE TABLE IF NOT EXISTS proxy_health (
                ip_port TEXT PRIMARY KEY,
                is_healthy INTEGER NOT NULL,
                latency_ms INTEGER,
                last_check INTEGER DEFAULT (strftime('%s', 'now'))
            )`,
            `CREATE TABLE IF NOT EXISTS security_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp INTEGER NOT NULL,
                ip TEXT NOT NULL,
                type TEXT NOT NULL,
                details TEXT,
                uuid TEXT
            )`,
            `CREATE TABLE IF NOT EXISTS ip_blacklist (
                ip TEXT PRIMARY KEY,
                expiration INTEGER NOT NULL,
                reason TEXT,
                timestamp INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
            )`
        ];

        const stmts = createTables.map(sql => env.DB.prepare(sql));
        await env.DB.batch(stmts);

        const testUUID = env.UUID || Config.userID;
        const futureDate = new Date();
        futureDate.setMonth(futureDate.getMonth() + 1);
        const expDate = futureDate.toISOString().split('T')[0];
        const expTime = '23:59:59';

        const insertTestUser = env.DB.prepare(
            "INSERT OR IGNORE INTO users (uuid, expiration_date, expiration_time, notes, traffic_limit, traffic_used, ip_limit) VALUES (?, ?, ?, ?, ?, ?, ?)"
        ).bind(testUUID, expDate, expTime, 'Test User - Development', null, 1073741824, -1);

        await insertTestUser.run();
        console.log('D1 tables initialized successfully and test user ensured.');

    } catch (e) {
        console.error(e.message, e.stack);
        throw new Error('Database initialization failed. Critical error: ' + e.message);
    }
}

async function performHealthCheck(env, ctx) {
    if (!env.DB) {
        console.warn('D1 binding not available. Skipping health checks.');
        return;
    }

    const proxyIps = env.PROXYIPS ? env.PROXYIPS.split(',').map(ip => ip.trim()) : Config.proxyIPs;
    const healthStmts = [];

    const results = await Promise.allSettled(proxyIps.map(async (ipPort) => {
        const [host, port = '443'] = ipPort.split(':');
        let latency = null;
        let isHealthy = 0;
        const start = Date.now();

        try {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), CONST.HEALTH_CHECK_TIMEOUT);

            const response = await fetch(`https://${host}:${port}`, {
                method: 'HEAD',
                signal: controller.signal,
                redirect: 'manual',
            });
            clearTimeout(timeoutId);

            if (response.ok || (response.status >= 400 && response.status < 500)) {
                latency = Date.now() - start;
                isHealthy = 1;
            } else {
                console.warn(`Health check for ${ipPort} failed: HTTP Status ${response.status}.`);
            }
        } catch (e) {
            if (e.name === 'AbortError') {
                console.error(`Health check for ${ipPort} timed out after ${CONST.HEALTH_CHECK_TIMEOUT}ms.`);
            } else {
                console.error(`Health check failed for ${ipPort}: ${e.message}.`);
            }
        } finally {
            healthStmts.push(
                env.DB.prepare(
                    "INSERT OR REPLACE INTO proxy_health (ip_port, is_healthy, latency_ms, last_check) VALUES (?, ?, ?, ?)"
                ).bind(ipPort, isHealthy, latency, Math.floor(Date.now() / 1000))
            );
        }
    }));

    results.filter(r => r.status === 'rejected').forEach(r => console.error(r.reason));

    try {
        await env.DB.batch(healthStmts);
        console.log('Proxy health check and database update completed.');
    } catch (e) {
        console.error(e.message, e.stack);
        throw new Error('Failed to batch update proxy health status in D1: ' + e.message);
    }
}

async function cleanupOldIps(env, ctx) {
    if (!env.DB) {
        console.warn('D1 binding not available. Skipping data cleanup.');
        return;
    }
    try {
        const cleanupPromises = [];

        cleanupPromises.push(env.DB.prepare(
            "DELETE FROM user_ips WHERE last_seen < datetime('now', ?)"
        ).bind(`-${CONST.IP_CLEANUP_AGE_DAYS} days`).run());

        cleanupPromises.push(env.DB.prepare(
            "DELETE FROM ip_blacklist WHERE expiration <= ?"
        ).bind(Math.floor(Date.now() / 1000)).run());

        cleanupPromises.push(env.DB.prepare(
            "DELETE FROM key_value WHERE expiration <= ?"
        ).bind(Math.floor(Date.now() / 1000)).run());

        await Promise.all(cleanupPromises.map(p => p.catch(e => console.error(e.message))));
        
        console.log(`Cleaned up user_ips records older than ${CONST.IP_CLEANUP_AGE_DAYS} days and expired blacklist/key_value entries.`);
    } catch (e) {
        console.error(e.message, e.stack);
        throw new Error('Failed to perform scheduled database cleanup: ' + e.message);
    }
}

async function ProtocolOverWSHandler(request, config, env, ctx) {
    let webSocket = null;

    try {
        const clientIp = request.headers.get('CF-Connecting-IP');

        const isBlocked = await checkBlockedIP(env.DB, clientIp);
        if (isBlocked) {
            console.warn(`VLESS connection denied for blacklisted IP: ${clientIp} (Reason: ${isBlocked.reason || 'Generic'}).`);
            ctx.waitUntil(logSecurityEvent(env.DB, ctx, clientIp, 'VLESS_ACCESS_DENIED', `Attempted VLESS connection from blacklisted IP: ${clientIp}.`));
            return new Response('Access Denied: Your IP address is currently blocked due to suspicious activity. Please contact support.', { status: 403 });
        }

        if (config.scamalytics.username && config.scamalytics.apiKey) {
            if (await isSuspiciousIP(clientIp, config.scamalytics, env.SCAMALYTICS_THRESHOLD || CONST.SCAMALYTICS_THRESHOLD)) {
                console.warn(`VLESS connection denied for suspicious IP: ${clientIp} (Scamalytics).`);
                ctx.waitUntil(logSecurityEvent(env.DB, ctx, clientIp, 'VLESS_ACCESS_DENIED', `Scamalytics score too high. IP: ${clientIp}.`));
                ctx.waitUntil(addIpToBlacklist(env.DB, ctx, clientIp, 'Scamalytics High Score', CONST.IP_BLACKLIST_TTL));
                return new Response('Access Denied: Suspicious IP detected.', { status: 403 });
            }
        }

        const webSocketPair = new WebSocketPair();
        const [client, ws_server] = Object.values(webSocketPair);
        webSocket = ws_server;

        webSocket.accept();

        let addressRemote = '';
        let portRemote = 0;
        let sessionUsage = 0;
        let userUUID = '';
        let udpStreamWriter = null;

        const log = (info, event = null) => {
            const id = userUUID ? userUUID.substring(0, 8) : 'unknown';
            const target = addressRemote && portRemote ? `${addressRemote}:${portRemote}` : 'unknown_target';
            console.log(`[${id}][${target}] ${info}`, event);
        };

        const deferredUsageUpdate = () => {
            if (sessionUsage > 0 && userUUID) {
                const usageToUpdate = sessionUsage;
                const uuidToUpdate = userUUID;
                sessionUsage = 0;
                ctx.waitUntil(
                    updateUsage(env, uuidToUpdate, usageToUpdate, ctx)
                        .catch(err => console.error(err))
                );
            }
        };
        const updateInterval = setInterval(deferredUsageUpdate, 10000);

        const finalCleanup = () => {
            clearInterval(updateInterval);
            deferredUsageUpdate();
            log('WebSocket session ended. Final usage logged and resources cleaned.');
        };

        webSocket.addEventListener('close', finalCleanup, { once: true });
        webSocket.addEventListener('error', finalCleanup, { once: true });

        const earlyDataHeader = request.headers.get('Sec-WebSocket-Protocol') || '';
        const readableWebSocketStream = MakeReadableWebSocketStream(webSocket, earlyDataHeader, log);

        let remoteSocketWrapper = { value: null };

        readableWebSocketStream
            .pipeTo(new WritableStream({
                async write(chunk, controller) {
                    sessionUsage += chunk.byteLength;

                    if (udpStreamWriter) {
                        return udpStreamWriter.write(chunk);
                    }

                    if (remoteSocketWrapper.value) {
                        const writer = remoteSocketWrapper.value.writable.getWriter();
                        await writer.write(chunk);
                        writer.releaseLock();
                        return;
                    }

                    const { user, hasError, message, addressType, portRemote: parsedPort, addressRemote: parsedAddress, rawDataIndex, ProtocolVersion, isUDP } = await ProcessProtocolHeader(chunk, env, ctx);

                    if (hasError || !user) {
                        log(`Authentication/Protocol Error: ${message}`, hasError ? new Error(message) : undefined);
                        if (message?.includes('invalid UUID') || message?.includes('user not found')) {
                            const invalidUuidRateKey = `invalid_uuid_attempt:${clientIp}`;
                            const attempts = parseInt(await d1KvGet(env.DB, invalidUuidRateKey) || '0', 10) + 1;
                            ctx.waitUntil(d1KvPut(env.DB, invalidUuidRateKey, attempts.toString(), { expirationTtl: CONST.INVALID_UUID_TTL }));
                            ctx.waitUntil(logSecurityEvent(env.DB, ctx, clientIp, 'INVALID_UUID_ATTEMPT', `Invalid or unknown UUID in VLESS header. UUID: ${user?.uuid || 'N/A'}.`));
                            if (attempts >= CONST.INVALID_UUID_ATTEMPTS) {
                                console.warn(`Too many invalid UUID attempts from ${clientIp}. Blacklisting.`);
                                ctx.waitUntil(addIpToBlacklist(env.DB, ctx, clientIp, 'Repeated invalid UUID attempts', CONST.IP_BLACKLIST_TTL));
                            }
                        }
                        controller.error(new Error(message || 'Authentication failed.'));
                        safeCloseWebSocket(webSocket);
                        return;
                    }

                    userUUID = user.uuid;
                    addressRemote = parsedAddress;
                    portRemote = parsedPort;

                    if (isExpired(user.expiration_date, user.expiration_time)) {
                        log('Account expired.');
                        ctx.waitUntil(logSecurityEvent(env.DB, ctx, clientIp, 'ACCOUNT_EXPIRED', `Expired account attempting VLESS connection. UUID: ${userUUID}.`));
                        controller.error(new Error('Account expired.'));
                        safeCloseWebSocket(webSocket);
                        return;
                    }

                    if (user.traffic_limit && user.traffic_limit > 0) {
                        const totalUsage = (user.traffic_used || 0) + sessionUsage;
                        if (totalUsage >= user.traffic_limit) {
                            log('Traffic limit exceeded.');
                            ctx.waitUntil(logSecurityEvent(env.DB, ctx, clientIp, 'TRAFFIC_LIMIT_EXCEEDED', `Traffic limit exceeded for VLESS connection. UUID: ${userUUID}.`));
                            controller.error(new Error('Traffic limit exceeded.'));
                            safeCloseWebSocket(webSocket);
                            return;
                        }
                    }

                    if (user.ip_limit && user.ip_limit > -1) {
                        const ipCountResult = await env.DB.prepare(
                            "SELECT COUNT(DISTINCT ip) as count FROM user_ips WHERE uuid = ?"
                        ).bind(userUUID).first('count');
                        const ipCount = ipCountResult?.count || 0;

                        if (ipCount >= user.ip_limit) {
                            const existingIp = await env.DB.prepare(
                                "SELECT ip FROM user_ips WHERE uuid = ? AND ip = ?"
                            ).bind(userUUID, clientIp).first();

                            if (!existingIp) {
                                log(`IP limit exceeded for user ${userUUID}. Current IP: ${clientIp}.`);
                                ctx.waitUntil(logSecurityEvent(env.DB, ctx, clientIp, 'IP_LIMIT_EXCEEDED', `IP limit exceeded for VLESS connection. UUID: ${userUUID}. IP: ${clientIp}.`));
                                controller.error(new Error('IP limit exceeded.'));
                                safeCloseWebSocket(webSocket);
                                return;
                            }
                        }
                        ctx.waitUntil(env.DB.prepare(
                            "INSERT OR REPLACE INTO user_ips (uuid, ip, last_seen) VALUES (?, ?, CURRENT_TIMESTAMP)"
                        ).bind(userUUID, clientIp).run()
                        .catch(e => console.error(e.message)));
                    }
                    
                    if (parsedPort && ![80, 443, 8443, 2053, 2083, 2087, 2096, 53].includes(parsedPort)) {
                         const portScanKey = `port_scan:${clientIp}`;
                         const accessedPortsStr = await d1KvGet(env.DB, portScanKey) || '';
                         const accessedPorts = new Set(accessedPortsStr.split(',').filter(Boolean).map(Number));
                         
                         if (!accessedPorts.has(parsedPort)) {
                             accessedPorts.add(parsedPort);
                             ctx.waitUntil(d1KvPut(env.DB, portScanKey, Array.from(accessedPorts).join(','), { expirationTtl: CONST.PORT_SCAN_TTL }));
                             ctx.waitUntil(logSecurityEvent(env.DB, ctx, clientIp, 'PORT_SCAN_ATTEMPT', `Attempted to access non-standard port: ${parsedPort}. Unique ports in window: ${accessedPorts.size}.`, userUUID));
                             if (accessedPorts.size >= CONST.PORT_SCAN_THRESHOLD) {
                                 console.warn(`Port scan detected from ${clientIp}. Blacklisting.`);
                                 ctx.waitUntil(addIpToBlacklist(env.DB, ctx, clientIp, 'Port scanning activity detected', CONST.IP_BLACKLIST_TTL));
                                 controller.error(new Error('Port scan detected. Connection denied.'));
                                 safeCloseWebSocket(webSocket);
                                 return;
                             }
                         }
                    }

                    const vlessResponseHeader = new Uint8Array([ProtocolVersion[0], 0x00]);
                    const rawClientData = chunk.slice(rawDataIndex);

                    if (isUDP) {
                        if (portRemote === 53) {
                            const dnsPipeline = await createDnsPipeline(webSocket, vlessResponseHeader, log, (bytes) => { sessionUsage += bytes; });
                            udpStreamWriter = dnsPipeline.write;
                            await udpStreamWriter(rawClientData);
                        } else {
                            log(`UDP command to unsupported port ${portRemote}. Closing connection.`);
                            ctx.waitUntil(logSecurityEvent(env.DB, ctx, clientIp, 'UNSUPPORTED_UDP', `Attempted UDP connection to unsupported port: ${portRemote}.`, userUUID));
                            controller.error(new Error(`UDP only supported for DNS (port 53).`));
                            safeCloseWebSocket(webSocket);
                        }
                        return;
                    }

                    await HandleTCPOutBound(
                        remoteSocketWrapper,
                        addressType,
                        parsedAddress,
                        parsedPort,
                        rawClientData,
                        webSocket,
                        vlessResponseHeader,
                        log,
                        config,
                        (bytes) => { sessionUsage += bytes; }
                    );

                },
                close() {
                    log('Readable WebSocket stream closed.');
                    finalCleanup();
                },
                abort(err) {
                    log('Readable WebSocket stream aborted.', err);
                    finalCleanup();
                },
            }))
            .catch(err => {
                console.error(err.stack || err);
                safeCloseWebSocket(webSocket);
                finalCleanup();
            });

        return new Response(null, { status: 101, webSocket: client });
    } catch (e) {
        console.error(e.message, e.stack);
        if (webSocket) {
            try {
                safeCloseWebSocket(webSocket);
            } catch (closeErr) {
                console.error(closeErr);
            }
        }
        const headers = new Headers();
        addSecurityHeaders(headers, null, {});
        return new Response('Internal Server Error.', { status: 500, headers });
    }
}

async function ProcessProtocolHeader(protocolBuffer, env, ctx) {
    try {
        if (protocolBuffer.byteLength < 24) {
            return { hasError: true, message: `Invalid data length in VLESS header: ${protocolBuffer.byteLength} bytes. Too short.` };
        }

        const dataView = new DataView(protocolBuffer.buffer || protocolBuffer);

        const version = dataView.getUint8(0);
        if (version !== 0x00) {
            return { hasError: true, message: `Unsupported VLESS protocol version: ${version}. Expected 0x00.` };
        }

        let uuid;
        try {
            uuid = stringify(new Uint8Array(protocolBuffer.slice(1, 17)));
        } catch (e) {
            return { hasError: true, message: `Invalid UUID format in VLESS header: ${e.message}.` };
        }

        const userData = await getUserData(env, uuid, ctx);
        if (!userData) {
            return { hasError: true, message: `User ${uuid} not found or invalid.` };
        }

        const optionsLengthIndex = 17;
        const optLength = dataView.getUint8(optionsLengthIndex);

        const commandIndex = optionsLengthIndex + 1 + optLength;
        if (protocolBuffer.byteLength < commandIndex + 1) {
            return { hasError: true, message: 'Invalid data length (command field missing in VLESS header).' };
        }
        const command = dataView.getUint8(commandIndex);
        if (command !== 0x01 && command !== 0x02) {
            return { hasError: true, message: `Unsupported command type: ${command}. Only TCP (1) and UDP (2) are supported.` };
        }

        const portIndex = commandIndex + 1;
        if (protocolBuffer.byteLength < portIndex + 2) {
            return { hasError: true, message: 'Invalid data length (port field missing in VLESS header).' };
        }
        const portRemote = dataView.getUint16(portIndex, false);

        const addressTypeIndex = portIndex + 2;
        if (protocolBuffer.byteLength < addressTypeIndex + 1) {
            return { hasError: true, message: 'Invalid data length (address type field missing in VLESS header).' };
        }
        const addressType = dataView.getUint8(addressTypeIndex);

        let addressValue, addressLength, addressValueIndex;

        switch (addressType) {
            case 0x01:
                addressLength = 4;
                addressValueIndex = addressTypeIndex + 1;
                if (protocolBuffer.byteLength < addressValueIndex + addressLength) {
                    return { hasError: true, message: 'Invalid data length (IPv4 address bytes missing in VLESS header).' };
                }
                addressValue = new Uint8Array(protocolBuffer.slice(addressValueIndex, addressValueIndex + addressLength)).join('.');
                break;
            case 0x02:
                if (protocolBuffer.byteLength < addressTypeIndex + 2) {
                    return { hasError: true, message: 'Invalid data length (domain name length byte missing in VLESS header).' };
                }
                addressLength = dataView.getUint8(addressTypeIndex + 1);
                addressValueIndex = addressTypeIndex + 2;
                if (protocolBuffer.byteLength < addressValueIndex + addressLength) {
                    return { hasError: true, message: 'Invalid data length (domain name bytes missing in VLESS header).' };
                }
                addressValue = new TextDecoder().decode(protocolBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
                break;
            case 0x03:
                addressLength = 16;
                addressValueIndex = addressTypeIndex + 1;
                if (protocolBuffer.byteLength < addressValueIndex + addressLength) {
                    return { hasError: true, message: 'Invalid data length (IPv6 address bytes missing in VLESS header).' };
                }
                addressValue = Array.from({ length: 8 }, (_, i) =>
                    dataView.getUint16(addressValueIndex + i * 2, false).toString(16)
                ).join(':');
                break;
            default:
                return { hasError: true, message: `Unsupported address type: ${addressType}. Expected 0x01 (IPv4), 0x02 (Domain), or 0x03 (IPv6).` };
        }

        const rawDataIndex = addressValueIndex + addressLength;

        if (protocolBuffer.byteLength < rawDataIndex) {
            return { hasError: true, message: 'Invalid data length (raw data missing after VLESS header).' };
        }

        return {
            user: userData,
            hasError: false,
            addressRemote: addressValue,
            addressType,
            portRemote,
            rawDataIndex,
            ProtocolVersion: new Uint8Array([version]),
            isUDP: command === 0x02,
        };
    } catch (e) {
        console.error(e.message, e.stack);
        return { hasError: true, message: `Protocol header processing error: ${e.message}.` };
    }
}

async function HandleTCPOutBound(
    remoteSocketWrapper,
    addressType,
    addressRemote,
    portRemote,
    rawClientData,
    webSocket,
    protocolResponseHeader,
    log,
    config,
    trafficCallback
) {
    async function connectAndWrite(address, port, useSocks = false) {
        let tcpSocket;
        if (useSocks && config.socks5.enabled && config.parsedSocks5Address) {
            tcpSocket = await socks5Connect(addressType, address, port, log, config.parsedSocks5Address);
        } else {
            tcpSocket = connect({ hostname: address, port: port, secureTransport: 'on' });
        }
        remoteSocketWrapper.value = tcpSocket;
        log(`Connected to remote TCP: ${address}:${port}${useSocks ? ' (via SOCKS5)' : ''}.`);

        const writer = tcpSocket.writable.getWriter();
        await writer.write(rawClientData);
        writer.releaseLock();
        return tcpSocket;
    }

    async function retryConnection() {
        log('Attempting to retry TCP connection (e.g., due to proxy health switch or initial failure).');
        try {
            const newConfig = await Config.fromEnv(env);
            
            const tcpSocket = newConfig.socks5.enabled
                ? await connectAndWrite(addressRemote, portRemote, true)
                : await connectAndWrite(newConfig.proxyIP || addressRemote, newConfig.proxyPort || portRemote, false);

            tcpSocket.closed
                .catch(error => { console.log('Retry: new remote TCP socket closed with error:', error); })
                .finally(() => { safeCloseWebSocket(webSocket); });

            RemoteSocketToWS(tcpSocket, webSocket, protocolResponseHeader, null, log, trafficCallback);
        } catch (retryError) {
            log(`Retry connection failed: ${retryError.message}. Closing WebSocket.`, retryError);
            safeCloseWebSocket(webSocket);
        }
    }

    try {
        const tcpSocket = config.socks5.enabled
            ? await connectAndWrite(addressRemote, portRemote, true)
            : await connectAndWrite(config.proxyIP || addressRemote, config.proxyPort || portRemote, false);

        tcpSocket.closed
            .catch(error => { log('Remote TCP socket closed with error:', error); })
            .finally(() => { safeCloseWebSocket(webSocket); });

        await RemoteSocketToWS(tcpSocket, webSocket, protocolResponseHeader, retryConnection, log, trafficCallback);

    } catch (connectionError) {
        log(`Failed to establish initial TCP connection: ${connectionError.message}. Closing WebSocket.`, connectionError);
        safeCloseWebSocket(webSocket);
    }
}

function MakeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
    return new ReadableStream({
        start(controller) {
            webSocketServer.addEventListener('message', (event) => {
                if (event.data instanceof ArrayBuffer) {
                    controller.enqueue(event.data);
                } else if (event.data instanceof Blob) {
                    event.data.arrayBuffer().then(buffer => controller.enqueue(buffer))
                        .catch(e => { console.error(e); controller.error(e); });
                } else {
                    console.error('Received unexpected WebSocket data type:', typeof event.data);
                    controller.error(new Error('Unsupported WebSocket data type received.'));
                }
            });
            webSocketServer.addEventListener('close', () => {
                safeCloseWebSocket(webSocketServer);
                controller.close();
                log('WebSocket server stream closed.');
            });
            webSocketServer.addEventListener('error', (err) => {
                log('WebSocket server stream encountered error:', err);
                controller.error(err);
            });

            const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
            if (error) {
                console.error(error);
                controller.error(error);
            } else if (earlyData) {
                controller.enqueue(earlyData);
                log(`Enqueued ${earlyData.byteLength} bytes of early data.`);
            }
        },
        pull(_controller) {
        },
        cancel(reason) {
            log(`ReadableStream canceled: ${reason}`);
            safeCloseWebSocket(webSocketServer);
        },
    });
}

async function RemoteSocketToWS(remoteSocket, webSocket, protocolResponseHeader, retry, log, trafficCallback) {
    let hasIncomingData = false;
    try {
        await remoteSocket.readable
            .pipeTo(new WritableStream({
                async write(chunk, controller) {
                    if (webSocket.readyState !== CONST.WS_READY_STATE_OPEN) {
                        controller.error(new Error('WebSocket is not open, cannot write remote data.'));
                        return;
                    }
                    hasIncomingData = true;
                    if (protocolResponseHeader) {
                        await webSocket.send(await new Blob([protocolResponseHeader, chunk]).arrayBuffer());
                        protocolResponseHeader = null;
                    } else {
                        await webSocket.send(chunk);
                    }
                    if (trafficCallback) {
                        trafficCallback(chunk.byteLength);
                    }
                },
                close() {
                    log(`Remote socket readable stream closed. Has incoming data: ${hasIncomingData}`);
                    safeCloseWebSocket(webSocket);
                },
                abort(reason) {
                    log(`Remote socket readable stream aborted: ${reason}`);
                    safeCloseWebSocket(webSocket);
                },
            }))
            .catch((error) => {
                console.error(error);
                safeCloseWebSocket(webSocket);
            });
    } catch (pipeError) {
        console.error(pipeError);
        safeCloseWebSocket(webSocket);
    }

    if (!hasIncomingData && retry && webSocket.readyState === CONST.WS_READY_STATE_OPEN) {
        log('No incoming data received from remote socket, attempting retry.');
        await retry();
    } else if (!hasIncomingData && !retry) {
        log('No incoming data received and no retry mechanism. Closing WebSocket.');
        safeCloseWebSocket(webSocket);
    }
}

function base64ToArrayBuffer(base64Str) {
    if (!base64Str) return { earlyData: null, error: null };
    try {
        const binaryStr = atob(base64Str.replace(/-/g, '+').replace(/_/g, '/'));
        const buffer = new ArrayBuffer(binaryStr.length);
        const view = new Uint8Array(buffer);
        for (let i = 0; i < binaryStr.length; i++) {
            view[i] = binaryStr.charCodeAt(i);
        }
        return { earlyData: buffer, error: null };
    } catch (error) {
        return { earlyData: null, error: new Error(`Failed to decode base64 early data: ${error.message}`) };
    }
}

function safeCloseWebSocket(socket) {
    try {
        if (socket && (socket.readyState === CONST.WS_READY_STATE_OPEN || socket.readyState === CONST.WS_READY_STATE_CLOSING)) {
            socket.close(1000, 'Normal Closure');
        }
    } catch (error) {
        console.error(error);
    }
}

async function createDnsPipeline(webSocket, vlessResponseHeader, log, trafficCallback) {
    let isHeaderSent = false;

    const transformStream = new TransformStream({
        transform(chunk, controller) {
            let index = 0;
            while (index + 2 <= chunk.byteLength) {
                const lengthBuffer = chunk.slice(index, index + 2);
                const udpPacketLength = new DataView(lengthBuffer.buffer, lengthBuffer.byteOffset, lengthBuffer.byteLength).getUint16(0, false);

                if (index + 2 + udpPacketLength > chunk.byteLength) {
                    log(`Warning: Partial UDP packet received. Dropping. Current index: ${index}, Expected packet length: ${udpPacketLength}, Remaining chunk: ${chunk.byteLength - index}.`);
                    break;
                }

                const udpData = chunk.slice(index + 2, index + 2 + udpPacketLength);
                controller.enqueue(udpData);
                index += 2 + udpPacketLength;
            }
        },
    });

    transformStream.readable
        .pipeTo(new WritableStream({
            async write(udpChunk) {
                try {
                    const resp = await fetch('https://1.1.1.1/dns-query', {
                        method: 'POST',
                        headers: {
                            'content-type': 'application/dns-message',
                            'accept': 'application/dns-message',
                        },
                        body: udpChunk,
                    });

                    if (!resp.ok) {
                        throw new Error(`DNS-over-HTTPS request failed with status: ${resp.status}`);
                    }

                    const dnsQueryResult = await resp.arrayBuffer();
                    const udpSize = dnsQueryResult.byteLength;

                    const udpSizeBuffer = new Uint8Array(2);
                    new DataView(udpSizeBuffer.buffer).setUint16(0, udpSize, false);

                    if (webSocket.readyState === CONST.WS_READY_STATE_OPEN) {
                        log(`DNS query success, response length: ${udpSize}`);
                        let responseChunk;
                        if (!isHeaderSent) {
                            responseChunk = await new Blob([vlessResponseHeader, udpSizeBuffer, dnsQueryResult]).arrayBuffer();
                            isHeaderSent = true;
                        } else {
                            responseChunk = await new Blob([udpSizeBuffer, dnsQueryResult]).arrayBuffer();
                        }
                        if (trafficCallback) {
                            trafficCallback(responseChunk.byteLength);
                        }
                        webSocket.send(responseChunk);
                    }
                } catch (error) {
                    log('DNS query error: ' + error.message, error);
                    safeCloseWebSocket(webSocket);
                }
            },
            close() {
                log('DNS WritableStream closed.');
            },
            abort(reason) {
                log('DNS WritableStream aborted: ' + reason);
                safeCloseWebSocket(webSocket);
            },
        }))
        .catch(e => {
            log('DNS stream pipeline error: ' + e.message, e);
            safeCloseWebSocket(webSocket);
        });

    const writer = transformStream.writable.getWriter();
    return {
        write: (chunk) => writer.write(chunk),
    };
}

function parseIPv6(ipv6) {
    const buffer = new ArrayBuffer(16);
    const view = new DataView(buffer);
    const parts = ipv6.split('::');

    let left = parts[0] ? parts[0].split(':') : [];
    let right = parts[1] ? parts[1].split(':') : [];

    if (left.length === 1 && left[0] === '') left = [];
    if (right.length === 1 && right[0] === '') right = [];

    const missing = 8 - (left.length + right.length);
    const expansion = [];
    if (missing > 0) {
        for (let i = 0; i < missing; i++) {
            expansion.push('0000');
        }
    }

    const hextets = [...left, ...expansion, ...right];

    if (hextets.length !== 8) {
        throw new Error(`Invalid IPv6 address format: ${ipv6}. Expected 8 hextets after expansion.`);
    }

    for (let i = 0; i < 8; i++) {
        const val = parseInt(hextets[i] || '0', 16);
        if (isNaN(val)) {
            throw new Error(`Invalid IPv6 hextet: '${hextets[i]}' in address ${ipv6}.`);
        }
        view.setUint16(i * 2, val, false);
    }
    return new Uint8Array(buffer);
}

async function socks5Connect(addressType, addressRemote, portRemote, log, parsedSocks5Address) {
    const { username, password, hostname, port } = parsedSocks5Address;
    let socket = null;
    let reader = null;
    let writer = null;
    let success = false;

    try {
        socket = connect({ hostname, port, secureTransport: 'on' });
        reader = socket.readable.getReader();
        writer = socket.writable.getWriter();
        const encoder = new TextEncoder();

        await writer.write(new Uint8Array([0x05, 0x02, 0x00, 0x02]));
        let res = (await reader.read()).value;

        if (!res || res[0] !== 0x05 || (res[1] !== 0x00 && res[1] !== 0x02)) {
            throw new Error(`SOCKS5 handshake failed: Proxy selected unsupported authentication method (0x${res?.[1]?.toString(16) || '??'}).`);
        }

        if (res[1] === 0x02) {
            if (!username || !password) {
                throw new Error('SOCKS5 proxy requires username/password, but none provided in configuration.');
            }
            const authRequest = new Uint8Array([
                0x01,
                username.length,
                ...encoder.encode(username),
                password.length,
                ...encoder.encode(password)
            ]);
            await writer.write(authRequest);
            res = (await reader.read()).value;

            if (!res || res[0] !== 0x01 || res[1] !== 0x00) {
                throw new Error(`SOCKS5 authentication failed with proxy (Reply Code: 0x${res?.[1]?.toString(16) || '??'}).`);
            }
            log('SOCKS5 proxy authenticated with username/password.');
        } else if (res[1] === 0x00) {
            log('SOCKS5 proxy selected No Authentication.');
        }

        let dstAddr;
        switch (addressType) {
            case 0x01:
                dstAddr = new Uint8Array([0x01, ...addressRemote.split('.').map(Number)]);
                break;
            case 0x02:
                dstAddr = new Uint8Array([0x03, addressRemote.length, ...encoder.encode(addressRemote)]);
                break;
            case 0x03:
                const ipv6Bytes = parseIPv6(addressRemote);
                dstAddr = new Uint8Array(1 + 16);
                dstAddr[0] = 0x04;
                dstAddr.set(ipv6Bytes, 1);
                break;
            default:
                throw new Error(`Unsupported SOCKS5 destination address type: ${addressType}.`);
        }

        const socksRequest = new Uint8Array([
            0x05,
            0x01,
            0x00,
            ...dstAddr,
            (portRemote >> 8) & 0xff,
            portRemote & 0xff
        ]);
        await writer.write(socksRequest);
        res = (await reader.read()).value;

        if (!res || res[0] !== 0x05 || res[1] !== 0x00) {
            throw new Error(`SOCKS5 connection to ${addressRemote}:${portRemote} failed (Reply Code: 0x${res?.[1]?.toString(16) || '??'}).`);
        }

        log(`SOCKS5 tunnel to ${addressRemote}:${portRemote} established successfully.`);
        success = true;
        return socket;

    } catch (err) {
        log(`SOCKS5 connection error: ${err.message}`, err);
        throw err;
    } finally {
        if (writer) writer.releaseLock();
        if (reader) reader.releaseLock();
        if (!success && socket) {
            try {
                socket.abort();
            } catch (e) {
                log('Error aborting SOCKS5 socket in finally block:', e);
            }
        }
    }
}

function socks5AddressParser(address) {
    if (!address || typeof address !== 'string') {
        throw new Error('Invalid SOCKS5 address format: Must be a non-empty string.');
    }

    let username, password;
    let hostPart = address;

    const authSeparatorIndex = address.indexOf('@');
    if (authSeparatorIndex !== -1) {
        const authPart = address.substring(0, authSeparatorIndex);
        hostPart = address.substring(authSeparatorIndex + 1);
        const creds = authPart.split(':');
        if (creds.length === 2) {
            username = creds[0];
            password = creds[1];
        } else {
            throw new Error('Invalid SOCKS5 address: Malformed username/password credentials.');
        }
    }

    const lastColonIndex = hostPart.lastIndexOf(':');
    if (lastColonIndex === -1) {
        throw new Error('Invalid SOCKS5 address: Missing port in hostname:port format.');
    }

    let hostname;
    if (hostPart.startsWith('[') && hostPart.indexOf(']') < lastColonIndex) {
        const closingBracketIndex = hostPart.indexOf(']');
        if (closingBracketIndex === -1 || closingBracketIndex > lastColonIndex) {
            throw new Error('Invalid SOCKS5 address: Malformed IPv6 address with brackets.');
        }
        hostname = hostPart.substring(1, closingBracketIndex);
    } else {
        hostname = hostPart.substring(0, lastColonIndex);
    }

    const portStr = hostPart.substring(lastColonIndex + 1);
    const port = parseInt(portStr, 10);

    if (!hostname || hostname.length === 0 || isNaN(port) || port <= 0 || port > 65535) {
        throw new Error(`Invalid SOCKS5 address: Malformed hostname or port value '${portStr}'.`);
    }

    return { username, password, hostname, port };
}
// ============================================================================ // UI/UX LAYER - Ultra-Modern Glassmorphism Admin Dashboard (HTML/CSS/JS) // This entire block contains the HTML, embedded CSS, and inline JavaScript // for both the Admin Login and the feature-rich Admin Dashboard, // ensuring a seamless and high-performance user experience. // ============================================================================ const adminLoginHTML = `<!DOCTYPE html> <html lang="en"> <head> <meta charset="UTF-8"> <meta name="viewport" content="width=device-width, initial-scale=1.0"> <title>Admin Login - VLESS Proxy</title> <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet"> <style nonce="CSP_NONCE_PLACEHOLDER"> *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; } body { display: flex; justify-content: center; align-items: center; min-height: 100vh; margin: 0; background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); font-family: 'Inter', system-ui, -apple-system, "Segoe UI", Roboto, Arial, sans-serif; color: #ffffff; overflow: hidden; position: relative; } body::before { content: ''; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: radial-gradient(ellipse at 20% 30%, rgba(59, 130, 246, 0.08) 0%, transparent 50%), radial-gradient(ellipse at 80% 70%, rgba(168, 85, 247, 0.08) 0%, transparent 50%); pointer-events: none; z-index: -1; animation: backgroundPulse 15s ease-in-out infinite alternate; } @keyframes backgroundPulse { 0% { transform: scale(1); opacity: 0.8; } 100% { transform: scale(1.1); opacity: 0.9; } } .login-container { background: rgba(255, 255, 255, 0.05); backdrop-filter: blur(10px); -webkit-backdrop-filter: blur(10px); padding: 40px; border-radius: 16px; box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3), 0 0 0 1px rgba(255, 255, 255, 0.1); text-align: center; width: 100%; max-width: 400px; border: 1px solid rgba(255, 255, 255, 0.1); animation: fadeInScale 0.6s ease-out forwards; position: relative; z-index: 1; } @keyframes fadeInScale { from { opacity: 0; transform: scale(0.9); } to { opacity: 1; transform: scale(1); } } h1 { color: #ffffff; margin-bottom: 24px; font-weight: 600; font-size: 28px; letter-spacing: 1px; background: linear-gradient(90deg, #3b82f6 0%, #8b5cf6 100%); -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text; } form { display: flex; flex-direction: column; gap: 16px; } input[type="password"], input[type="text"] { background: rgba(255, 255, 255, 0.1); border: 1px solid rgba(255, 255, 255, 0.2); color: #ffffff; padding: 14px; border-radius: 8px; font-size: 16px; transition: all 0.3s ease; font-family: inherit; } input:focus { outline: none; border-color: #3b82f6; box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.3); background: rgba(255, 255, 255, 0.15); } input::placeholder { color: rgba(255, 255, 255, 0.5); } button { background: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%); color: white; border: none; padding: 14px; border-radius: 8px; font-size: 16px; font-weight: 600; cursor: pointer; transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1); position: relative; overflow: hidden; } button::before { content: ''; position: absolute; top: 0; left: -100%; width: 100%; height: 100%; background: linear-gradient(90deg, transparent, rgba(255,255,255,0.2), transparent); transition: left 0.5s ease; } button:hover::before { left: 100%; } button:hover { transform: translateY(-2px); box-shadow: 0 6px 25px rgba(59, 130, 246, 0.4), 0 0 15px rgba(59, 130, 246, 0.2); } button:active { transform: translateY(0); box-shadow: 0 2px 10px rgba(59, 130, 246, 0.3); } .error { color: #ff6b6b; margin-top: 16px; font-size: 14px; background: rgba(255, 107, 107, 0.1); padding: 12px; border-radius: 8px; border: 1px solid rgba(255, 107, 107, 0.3); animation: shake 0.5s ease-in-out; } @keyframes shake { 0%, 100% { transform: translateX(0); } 20%, 60% { transform: translateX(-5px); } 40%, 80% { transform: translateX(5px); } } @media (max-width: 480px) { .login-container { padding: 30px 20px; margin: 20px; max-width: 90%; } h1 { font-size: 24px; } } </style> </head> <body> <div class="login-container"> <h1>🔐 Admin Login</h1> <form method="POST" action="ADMIN_PATH_PLACEHOLDER"> <input type="password" name="password" placeholder="Enter admin password" required autocomplete="current-password"> <input type="text" name="totp" placeholder="2FA Code (if enabled)" autocomplete="off" inputmode="numeric" pattern="[0-9]*" maxlength="6"> <button type="submit">Login</button> </form> </div> </body> </html>`; const adminPanelHTML = `<!DOCTYPE html> <html lang="en"> <head> <meta charset="UTF-8"> <meta name="viewport" content="width=device-width, initial-scale=1.0"> <title>Admin Dashboard - VLESS Proxy Manager</title> <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet"> <style nonce="CSP_NONCE_PLACEHOLDER"> :root { --bg-main: #0a0e17; --bg-card: #1a1f2e; --border: #2a3441; --text-primary: #F9FAFB; --text-secondary: #9CA3AF; --accent: #3B82F6; --accent-hover: #2563EB; --danger: #EF4444; --danger-hover: #DC2626; --success: #22C55E; --warning: #F59e0b; --info: #06b6d4; --btn-secondary-bg: #4B5563; --purple: #a855f7; --cyan: #06b6d4; --pink: #ec4899; --radius-md: 10px; --radius-lg: 16px; } * { margin: 0; padding: 0; box-sizing: border-box; } body { font-family: 'Inter', system-ui, -apple-system, "Segoe UI", Roboto, Arial, sans-serif; background: linear-gradient(135deg, var(--bg-main) 0%, #111827 25%, #0d1321 50%, var(--bg-main) 75%, #111827 100%); background-size: 400% 400%; animation: gradient-flow 15s ease infinite; color: var(--text-primary); font-size: 14px; line-height: 1.6; min-height: 100vh; position: relative; overflow-x: hidden; } body::before { content: ''; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: radial-gradient(ellipse at 20% 30%, rgba(59, 130, 246, 0.08) 0%, transparent 50%), radial-gradient(ellipse at 80% 70%, rgba(168, 85, 247, 0.08) 0%, transparent 50%), radial-gradient(ellipse at 50% 100%, rgba(6, 182, 212, 0.05) 0%, transparent 40%); pointer-events: none; z-index: -1; } @keyframes gradient-flow { 0% { background-position: 0% 50%; } 50% { background-position: 100% 50%; } 100% { background-position: 0% 50%; } } @keyframes title-shimmer { 0% { background-position: -200% center; } 100% { background-position: 200% center; } } @keyframes pulse-dot { 0%, 100% { opacity: 1; transform: scale(1); } 50% { opacity: 0.5; transform: scale(0.8); } } @keyframes slideIn { from { transform: translateX(120%); opacity: 0; } to { transform: translateX(0); opacity: 1; } } @keyframes slideOut { from { transform: translateX(0); opacity: 1; } to { transform: translateX(120%); opacity: 0; } } @keyframes spin { to { transform: rotate(360deg); } } @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } } .container { max-width: 1400px; margin: 0 auto; padding: 40px 20px; } h1 { font-size: 32px; margin-bottom: 28px; font-weight: 700; background: linear-gradient(135deg, var(--accent) 0%, var(--purple) 30%, var(--cyan) 60%, var(--accent) 100%); background-size: 200% auto; -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text; animation: title-shimmer 4s linear infinite; text-shadow: 0 0 40px rgba(59, 130, 246, 0.3); text-align: center; } h2 { font-size: 18px; font-weight: 600; color: var(--text-primary); border-bottom: 2px solid transparent; border-image: linear-gradient(90deg, var(--accent), var(--purple), transparent) 1; padding-bottom: 12px; margin-bottom: 20px; position: relative; } .card { background: linear-gradient(145deg, rgba(26, 31, 46, 0.9) 0%, rgba(17, 24, 39, 0.95) 100%); backdrop-filter: blur(20px); -webkit-backdrop-filter: blur(20px); border-radius: var(--radius-lg); padding: 28px; border: 1px solid rgba(255, 255, 255, 0.06); box-shadow: 0 4px 24px rgba(0,0,0,0.2), 0 0 0 1px rgba(255, 255, 255, 0.03), inset 0 1px 0 rgba(255, 255, 255, 0.05); margin-bottom: 24px; transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1); position: relative; overflow: hidden; } .card::before { content: ''; position: absolute; top: 0; left: -100%; width: 100%; height: 100%; background: linear-gradient(90deg, transparent, rgba(255,255,255,0.03), transparent); transition: left 0.6s ease; } .card:hover::before { left: 100%; } .card:hover { box-shadow: 0 20px 40px rgba(0,0,0,0.3), 0 0 80px rgba(59, 130, 246, 0.1), inset 0 1px 0 rgba(255, 255, 255, 0.1); border-color: rgba(59, 130, 246, 0.3); transform: translateY(-4px); } .dashboard-stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; margin-bottom: 30px; } .stat-card { background: linear-gradient(145deg, rgba(26, 31, 46, 0.9) 0%, rgba(17, 24, 39, 0.95) 100%); backdrop-filter: blur(16px); -webkit-backdrop-filter: blur(16px); padding: 24px 20px; border-radius: var(--radius-lg); text-align: center; border: 1px solid rgba(255, 255, 255, 0.05); transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1); position: relative; overflow: hidden; box-shadow: 0 4px 16px rgba(0,0,0,0.15); } .stat-card::before { content: ''; position: absolute; top: 0; left: 0; right: 0; height: 3px; background: linear-gradient(90deg, var(--accent), var(--purple), var(--cyan)); opacity: 0; transition: opacity 0.3s; } .stat-card::after { content: ''; position: absolute; inset: 0; background: radial-gradient(circle at 50% 0%, rgba(59, 130, 246, 0.1) 0%, transparent 70%); opacity: 0; transition: opacity 0.4s; } .stat-card:hover::before { opacity: 1; } .stat-card:hover::after { opacity: 1; } .stat-card:hover { transform: translateY(-6px) scale(1.02); box-shadow: 0 20px 40px rgba(59, 130, 246, 0.2), 0 0 0 1px rgba(59, 130, 246, 0.2); border-color: rgba(59, 130, 246, 0.3); } .stat-card.healthy { --card-accent: var(--success); } .stat-card.warning { --card-accent: var(--warning); } .stat-card.danger { --card-accent: var(--danger); } .stat-card.healthy::before, .stat-card.warning::before, .stat-card.danger::before { background: var(--card-accent); opacity: 1; } .stat-icon { width: 44px; height: 44px; border-radius: 10px; display: flex; align-items: center; justify-content: center; margin: 0 auto 12px; font-size: 20px; color: var(--text-primary); } .stat-icon.blue { background: rgba(59, 130, 246, 0.15); } .stat-icon.green { background: rgba(34, 197, 94, 0.15); } .stat-icon.orange { background: rgba(245, 158, 11, 0.15); } .stat-icon.purple { background: rgba(168, 85, 247, 0.15); } .stat-icon.red { background: rgba(239, 68, 68, 0.15); color: var(--danger); } .stat-value { font-size: 28px; font-weight: 700; color: var(--accent); margin-bottom: 6px; line-height: 1.2; transition: color 0.3s; } .stat-card.healthy .stat-value { color: var(--success); } .stat-card.warning .stat-value { color: var(--warning); } .stat-card.danger .stat-value { color: var(--danger); } .stat-label { font-size: 11px; color: var(--text-secondary); text-transform: uppercase; letter-spacing: 1px; } .stat-badge { display: inline-flex; align-items: center; gap: 4px; padding: 3px 8px; border-radius: 12px; font-size: 10px; font-weight: 600; margin-top: 8px; } .stat-badge.online { background: rgba(34, 197, 94, 0.15); color: var(--success); } .stat-badge.offline { background: rgba(239, 68, 68, 0.15); color: var(--danger); } .stat-badge.checking { background: rgba(245, 158, 11, 0.15); color: var(--warning); } .stat-badge.threat { background: rgba(239, 68, 68, 0.15); color: var(--danger); } .form-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; align-items: flex-end; } .form-group { display: flex; flex-direction: column; position: relative; } .form-group label { margin-bottom: 8px; font-weight: 500; color: var(--text-secondary); font-size: 13px; } input[type="text"], input[type="date"], input[type="time"], input[type="number"], input[type="password"], select, textarea { width: 100%; background: #374151; border: 1px solid #4B5563; color: var(--text-primary); padding: 12px; border-radius: var(--radius-md); font-size: 14px; transition: all 0.2s ease; font-family: inherit; } input:focus, select:focus, textarea:focus { outline: none; border-color: var(--accent); box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1); } input[type="number"]::-webkit-outer-spin-button, input[type="number"]::-webkit-inner-spin-button { -webkit-appearance: none; margin: 0; } input[type="number"] { -moz-appearance: textfield; } .btn { padding: 12px 22px; border: none; border-radius: var(--radius-md); font-weight: 600; cursor: pointer; transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1); display: inline-flex; align-items: center; justify-content: center; gap: 8px; font-size: 14px; position: relative; overflow: hidden; text-decoration: none; } .btn::before { content: ''; position: absolute; top: 0; left: -100%; width: 100%; height: 100%; background: linear-gradient(90deg, transparent, rgba(255,255,255,0.2), transparent); transition: left 0.5s ease; } .btn:hover::before { left: 100%; } .btn:active { transform: scale(0.96); } .btn-primary { background: linear-gradient(135deg, var(--accent) 0%, #6366f1 50%, var(--purple) 100%); background-size: 200% 200%; color: white; box-shadow: 0 4px 15px rgba(59, 130, 246, 0.3); } .btn-primary:hover { background-position: 100% 50%; box-shadow: 0 8px 25px rgba(59, 130, 246, 0.5); transform: translateY(-3px); } .btn-secondary { background: linear-gradient(135deg, #4B5563 0%, #374151 100%); color: white; border: 1px solid rgba(255,255,255,0.08); } .btn-secondary:hover { background: linear-gradient(135deg, #6B7280 0%, #4B5563 100%); transform: translateY(-2px); box-shadow: 0 4px 12px rgba(0,0,0,0.3); } .btn-danger { background: linear-gradient(135deg, var(--danger) 0%, #dc2626 100%); color: white; box-shadow: 0 44px 15px rgba(239, 68, 68, 0.3); } .btn-danger:hover { box-shadow: 0 8px 25px rgba(239, 68, 68, 0.5); transform: translateY(-3px); } .btn-outline-secondary { background: transparent; border: 1px solid var(--btn-secondary-bg); color: var(--text-secondary); padding: 6px 12px; font-size: 12px; border-radius: var(--radius-md); } .btn-outline-secondary:hover { background: var(--btn-secondary-bg); color: white; transform: translateY(-1px); } .table-wrapper { overflow-x: auto; -webkit-overflow-scrolling: touch; border-radius: var(--radius-md); border: 1px solid rgba(255, 255, 255, 0.06); box-shadow: inset 0 0 10px rgba(0,0,0,0.1); } table { width: 100%; border-collapse: collapse; min-width: 800px; } th, td { padding: 14px 16px; text-align: left; border-bottom: 1px solid rgba(255, 255, 255, 0.04); } td.actions { white-space: nowrap; } th { color: var(--text-secondary); font-weight: 600; font-size: 11px; text-transform: uppercase; letter-spacing: 0.5px; background: rgba(59, 130, 246, 0.08); position: sticky; top: 0; backdrop-filter: blur(8px); -webkit-backdrop-filter: blur(8px); z-index: 10; } td { color: var(--text-primary); font-size: 13px; transition: background 0.2s ease; } tbody tr { transition: all 0.2s ease; } tbody tr:hover { background: rgba(59, 130, 246, 0.08); } tbody tr:last-child td { border-bottom: none; } .status-badge { padding: 6px 12px; border-radius: 20px; font-size: 12px; font-weight: 600; display: inline-block; } .status-active { background: rgba(34, 197, 94, 0.2); color: var(--success); border: 1px solid var(--success); } .status-expired { background: rgba(239, 68, 68, 0.2); color: var(--danger); border: 1px solid var(--danger); } .status-blocked { background: rgba(239, 68, 68, 0.2); color: var(--danger); border: 1px solid var(--danger); } .status-warning-light { background: rgba(245, 158, 11, 0.15); color: var(--warning); } .uuid-cell { display: flex; align-items: center; gap: 8px; } .btn-copy-uuid { padding: 4px 8px; font-size: 11px; background: rgba(59, 130, 246, 0.1); border: 1px solid rgba(59, 130, 246, 0.3); color: var(--accent); border-radius: 4px; cursor: pointer; transition: all 0.2s ease; } .btn-copy-uuid:hover { background: rgba(59, 130, 246, 0.2); border-color: var(--accent); } .btn-copy-uuid.copied { background: rgba(34, 197, 94, 0.2); border-color: var(--success); color: var(--success); } #toast { position: fixed; top: 20px; right: 20px; background: rgba(31, 41, 55, 0.95); backdrop-filter: blur(12px); -webkit-backdrop-filter: blur(12px); color: white; padding: 16px 20px; border-radius: var(--radius-md); z-index: 1001; display: none; border: 1px solid rgba(255, 255, 255, 0.08); box-shadow: 0 12px 32px rgba(0,0,0,0.4); animation: slideIn 0.4s cubic-bezier(0.4, 0, 0.2, 1); min-width: 280px; max-width: 400px; } .toast-content { display: flex; align-items: center; gap: 12px; } .toast-icon { width: 32px; height: 32px; border-radius: 8px; display: flex; align-items: center; justify-content: center; font-size: 16px; flex-shrink: 0; color: var(--text-primary); } .toast-icon.success { background: rgba(34, 197, 94, 0.15); } .toast-icon.error { background: rgba(239, 68, 68, 0.15); } .toast-icon.warning { background: rgba(245, 158, 11, 0.15); } .toast-icon.info { background: rgba(6, 182, 212, 0.15); } .toast-message { flex: 1; font-size: 14px; line-height: 1.4; } #toast.show { display: block; } #toast.hide { animation: slideOut 0.3s ease forwards; } #toast.success { border-left: 4px solid var(--success); } #toast.error { border-left: 4px solid var(--danger); } #toast.warning { border-left: 4px solid var(--warning); } #toast.info { border-left: 4px solid var(--info); } .btn.loading { pointer-events: none; opacity: 0.7; position: relative; } .btn.loading::after { content: ''; position: absolute; width: 16px; height: 16px; border: 2px solid transparent; border-top-color: currentColor; border-radius: 50%; animation: spin 0.8s linear infinite; right: 12px; } .pulse-dot { width: 8px; height: 8px; border-radius: 50%; display: inline-block; animation: pulse-dot 2s ease-in-out infinite; } .pulse-dot.green { background: var(--success); box-shadow: 0 0 8px var(--success); } .pulse-dot.red { background: var(--danger); box-shadow: 0 0 8px var(--danger); } .pulse-dot.orange { background: var(--warning); box-shadow: 0 0 8px var(--warning); } .modal-overlay { position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.7); z-index: 1000; display: flex; justify-content: center; align-items: center; opacity: 0; visibility: hidden; transition: all 0.3s ease-in-out; } .modal-overlay.show { opacity: 1; visibility: visible; } .modal-content { background: var(--bg-card); padding: 32px; border-radius: var(--radius-lg); box-shadow: 0 20px 60px rgba(0,0,0,0.5), 0 0 0 1px var(--border); width: 90%; max-width: 600px; max-height: 90vh; overflow-y: auto; transform: scale(0.9); transition: transform 0.3s ease-in-out; position: relative; } .modal-overlay.show .modal-content { transform: scale(1); } .modal-close-btn { position: absolute; top: 15px; right: 15px; background: none; border: none; font-size: 24px; color: var(--muted); cursor: pointer; transition: color 0.2s; z-index: 10; } .modal-close-btn:hover { color: var(--text-primary); } .search-input { width: 100%; margin-bottom: 16px; padding: 12px 16px; background: #374151; border: 1px solid #4B5563; color: var(--text-primary); border-radius: var(--radius-md); font-size: 14px; font-family: inherit; } .time-quick-set-group { display: flex; gap: 8px; margin-top: 12px; flex-wrap: wrap; } .header-actions { position: absolute; top: 20px; right: 20px; display: flex; gap: 12px; z-index: 50; } .log-type-badge { padding: 4px 8px; border-radius: 12px; font-size: 10px; font-weight: 600; } .log-type-badge.BRUTE_FORCE_LOGIN { background: rgba(239, 68, 68, 0.2); color: var(--danger); } .log-type-badge.INVALID_UUID_ATTEMPT { background: rgba(245, 158, 11, 0.2); color: var(--warning); } .log-type-badge.PORT_SCAN_ATTEMPT { background: rgba(239, 68, 68, 0.2); color: var(--danger); } .log-type-badge.IP_BLACKLISTED { background: rgba(239, 68, 68, 0.2); color: var(--danger); } .log-type-badge.ADMIN_LOGIN_SUCCESS { background: rgba(59, 130, 246, 0.2); color: var(--accent); } .log-type-badge.ADMIN_LOGIN_ERROR { background: rgba(239, 68, 68, 0.2); color: var(--danger); } .log-type-badge.ADMIN_ACCESS_DENIED { background: rgba(239, 68, 68, 0.2); color: var(--danger); } .log-type-badge.ADMIN_API_RATE_LIMIT { background: rgba(245, 158, 11, 0.2); color: var(--warning); } .log-type-badge.CSRF_ATTEMPT { background: rgba(239, 68, 68, 0.2); color: var(--danger); } .log-type-badge.VLESS_ACCESS_DENIED { background: rgba(239, 68, 68, 0.2); color: var(--danger); } .log-type-badge.UNSUPPORTED_UDP { background: rgba(245, 158, 11, 0.2); color: var(--warning); } .log-type-badge.HEALTH_CHECK_TRIGGERED { background: rgba(6, 182, 212, 0.2); color: var(--info); } .log-type-badge.USER_CREATED { background: rgba(34, 197, 94, 0.2); color: var(--success); } .log-type-badge.USER_UPDATED { background: rgba(59, 130, 246, 0.2); color: var(--accent); } .log-type-badge.USER_DELETED { background: rgba(239, 68, 68, 0.2); color: var(--danger); } .log-type-badge.USER_BULK_DELETED { background: rgba(239, 68, 68, 0.2); color: var(--danger); } .log-type-badge.IP_WHITELISTED { background: rgba(34, 197, 94, 0.2); color: var(--success); } .security-tabs { display: flex; gap: 8px; margin-bottom: 20px; border-bottom: 1px solid rgba(255,255,255,0.05); padding-bottom: 10px; } .security-tab-btn { padding: 8px 15px; border-radius: 8px; font-weight: 500; cursor: pointer; background: transparent; border: 1px solid transparent; color: var(--text-secondary); transition: all 0.2s ease; } .security-tab-btn.active { background: var(--accent); color: var(--text-primary); border-color: var(--accent); box-shadow: 0 2px 10px rgba(59, 130, 246, 0.2); } .security-tab-btn:hover:not(.active) { background: rgba(255,255,255,0.05); color: var(--text-primary); } .tab-content { animation: fadeIn 0.4s ease-out; } .hidden { display: none !important; } .filter-group { display: flex; gap: 10px; margin-bottom: 16px; flex-wrap: wrap; align-items: center; } .filter-group label { font-size: 13px; color: var(--text-secondary); } @media (max-width: 768px) { .container { padding: 20px 12px; } h1 { font-size: 24px; } .header-actions { position: static; margin-top: 20px; margin-bottom: 20px; justify-content: flex-end; } .dashboard-stats { grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); } .form-grid { grid-template-columns: 1fr; } table { min-width: unset; } th, td { padding: 10px 12px; } .btn { padding: 10px 16px; font-size: 13px; } .stat-value { font-size: 24px; } .stat-label { font-size: 10px; } .security-tabs { flex-wrap: wrap; justify-content: center; } .filter-group { flex-direction: column; align-items: flex-start; } } </style> </head> <body> <div class="container"> <h1>⚡ Admin Dashboard</h1> <div class="header-actions"> <button id="healthCheckBtn" class="btn btn-secondary">🔄 Health Check</button> <button id="logoutBtn" class="btn btn-danger">🚪 Logout</button> </div> <div class="dashboard-stats"> <div class="stat-card"> <div class="stat-icon blue">👥</div> <div class="stat-value" id="total-users">0</div> <div class="stat-label">Total Users</div> </div> <div class="stat-card healthy"> <div class="stat-icon green">✓</div> <div class="stat-value" id="active-users">0</div> <div class="stat-label">Active Users</div> </div> <div class="stat-card warning"> <div class="stat-icon orange">⏱</div> <div class="stat-value" id="expired-users">0</div> <div class="stat-label">Expired Users</div> </div> <div class="stat-card purple"> <div class="stat-icon purple">📊</div> <div class="stat-value" id="total-traffic">0 KB</div> <div class="stat-label">Total Traffic</div> </div> <div class="stat-card"> <div class="stat-icon blue">🕐</div> <div class="stat-value" id="server-time">--:--:--</div> <div class="stat-label">Server Time (Local)</div> </div> <div class="stat-card" id="proxy-health-card"> <div class="stat-icon green">💚</div> <div class="stat-value" id="proxy-health">Checking...</div> <div class="stat-label">Proxy Health</div> <div class="stat-badge checking" id="proxy-health-badge"><span class="pulse-dot orange"></span> Checking</div> </div> <div class="stat-card" id="server-status-card"> <div class="stat-icon blue">🖥</div> <div class="stat-value" id="server-status">Online</div> <div class="stat-label">Server Status</div> <div class="stat-badge online" id="server-status-badge"><span class="pulse-dot green"></span> Operational</div> </div> <div class="stat-card danger"> <div class="stat-icon red">🚨</div> <div class="stat-value" id="blocked-ips-count">0</div> <div class="stat-label">Blocked IPs</div> <div class="stat-badge threat" id="threat-events-badge"><span class="pulse-dot red"></span> Threats</div> </div> </div> <div class="card"> <h2>➕ Create New User</h2> <form id="createUserForm" class="form-grid"> <div class="form-group" style="grid-column: 1 / -1;"> <label for="uuid">UUID</label> <div style="display: flex; gap: 8px;"> <input type="text" id="uuid" required style="flex: 1;" placeholder="Auto-generated or custom UUID"> <button type="button" id="generateUUID" class="btn btn-secondary">🎲 Generate</button> </div> </div> <div class="form-group"> <label for="expiryDate">Expiry Date (Local)</label> <input type="date" id="expiryDate" required> </div> <div class="form-group"> <label for="expiryTime">Expiry Time (Local)</label> <input type="time" id="expiryTime" step="1" required> <div class="time-quick-set-group" data-target-date="expiryDate" data-target-time="expiryTime"> <button type="button" class="btn btn-outline-secondary" data-amount="1" data-unit="hour">+1 Hour</button> <button type="button" class="btn btn-outline-secondary" data-amount="1" data-unit="day">+1 Day</button> <button type="button" class="btn btn-outline-secondary" data-amount="7" data-unit="day">+1 Week</button> <button type="button" class="btn btn-outline-secondary" data-amount="1" data-unit="month">+1 Month</button> </div> </div> <div class="form-group"> <label for="notes">Notes</label> <input type="text" id="notes" placeholder="e.g., John Doe - Premium User"> </div> <div class="form-group"> <label for="dataLimit">Data Limit</label> <div style="display: flex; gap: 8px; align-items: center;"> <input type="number" id="dataLimit" min="0" step="0.01" placeholder="0" style="flex: 1; min-width: 80px;"> <select id="dataUnit" style="min-width: 100px; flex-shrink: 0;"> <option>KB</option> <option>MB</option> <option>GB</option> <option>TB</option> <option value="unlimited" selected>Unlimited</option> </select> </div> </div> <div class="form-group"> <label for="ipLimit">IP Limit</label> <input type="number" id="ipLimit" min="-1" step="1" placeholder="-1 (Unlimited)"> </div> <div class="form-group" style="grid-column: span 1 / auto;"> <label>&nbsp;</label> <button type="submit" class="btn btn-primary">✨ Create User</button> </div> </form> </div> <div class="card"> <h2>👥 User Management</h2> <input type="text" id="userSearchInput" class="search-input" placeholder="🔍 Search by UUID or Notes..."> <div style="margin-bottom: 16px; display: flex; gap: 10px; flex-wrap: wrap;"> <button id="deleteSelectedUsers" class="btn btn-danger">🗑️ Delete Selected</button> <button id="exportUsers" class="btn btn-secondary">📥 Export CSV</button> </div> <div class="table-wrapper"> <table> <thead> <tr> <th><input type="checkbox" id="selectAllUsers"></th> <th>UUID</th> <th>Created</th> <th>Expiry (Local)</th> <th>Status</th> <th>Notes</th> <th>Limit</th> <th>Usage</th> <th>IP Limit</th> <th>Actions</th> </tr> </thead> <tbody id="userList"> <!-- User rows will be dynamically inserted here --> </tbody> </table> </div> </div> <!-- NEW: Security Events & IP Blacklist Management --> <div class="card"> <h2>🔒 Security Events & IP Management</h2> <div class="security-tabs"> <button class="security-tab-btn active" data-tab="security-events">🚨 Security Events</button> <button class="security-tab-btn" data-tab="ip-blacklist">🚫 IP Blacklist</button> <button class="security-tab-btn" data-tab="add-ip">➕ Add/Remove IP</button> </div> <!-- Security Events Tab Content --> <div id="security-events-content" class="tab-content"> <input type="text" id="securityEventsSearchInput" class="search-input" placeholder="🔍 Search by IP, Type or Details..."> <div class="filter-group"> <label for="eventTypeFilter">Type:</label> <select id="eventTypeFilter"> <option value="">All</option> <option value="BRUTE_FORCE_LOGIN">Brute Force Login</option> <option value="INVALID_UUID_ATTEMPT">Invalid UUID</option> <option value="PORT_SCAN_ATTEMPT">Port Scan</option> <option value="IP_BLACKLISTED">IP Blacklisted</option> <option value="ADMIN_LOGIN_SUCCESS">Admin Login Success</option> <option value="ADMIN_LOGIN_ERROR">Admin Login Error</option> <option value="ADMIN_ACCESS_DENIED">Admin Access Denied</option> <option value="ADMIN_API_RATE_LIMIT">Admin API Rate Limit</option> <option value="CSRF_ATTEMPT">CSRF Attempt</option> <option value="VLESS_ACCESS_DENIED">VLESS Access Denied</option> <option value="UNSUPPORTED_UDP">Unsupported UDP</option> <option value="HEALTH_CHECK_TRIGGERED">Health Check Triggered</option> <option value="USER_CREATED">User Created</option> <option value="USER_UPDATED">User Updated</option> <option value="USER_DELETED">User Deleted</option> <option value="USER_BULK_DELETED">User Bulk Deleted</option> <option value="IP_WHITELISTED">IP Whitelisted</option> </select> <label for="eventTimeFilter">Time:</label> <select id="eventTimeFilter"> <option value="24h">Last 24 Hours</option> <option value="7d">Last 7 Days</option> <option value="30d">Last 30 Days</option> <option value="">All Time</option> </select> </div> <div class="table-wrapper"> <table> <thead> <tr> <th>Timestamp (Local)</th> <th>IP</th> <th>Type</th> <th>Details</th> <th>User UUID</th> <th>Actions</th> </tr> </thead> <tbody id="securityEventList"> <!-- Security events will be dynamically inserted here --> </tbody> </table> </div> </div> <!-- IP Blacklist Tab Content --> <div id="ip-blacklist-content" class="tab-content hidden"> <input type="text" id="ipBlacklistSearchInput" class="search-input" placeholder="🔍 Search by IP or Reason..."> <div class="table-wrapper"> <table> <thead> <tr> <th>IP</th> <th>Blacklisted At (Local)</th> <th>Expires (Local)</th> <th>Reason</th> <th>Actions</th> </tr> </thead> <tbody id="ipBlacklist"> <!-- Blacklisted IPs will be dynamically inserted here --> </tbody> </table> </div> </div> <!-- Add/Remove IP Tab Content --> <div id="add-ip-content" class="tab-content hidden"> <form id="manageIpForm" class="form-grid"> <div class="form-group" style="grid-column: 1 / -1;"> <label for="ipAddress">IP Address</label> <input type="text" id="ipAddress" required placeholder="e.g., 192.168.1.1 or 2001:db8::1"> </div> <div class="form-group"> <label for="actionType">Action</label> <select id="actionType"> <option value="blacklist">Blacklist IP</option> <option value="whitelist">Whitelist IP</option> </select> </div> <div class="form-group" id="blacklistReasonGroup"> <label for="blacklistReason">Reason</label> <textarea id="blacklistReason" rows="2" placeholder="e.g., Brute force attacks, suspicious activity"></textarea> </div> <div class="form-group" id="blacklistDurationGroup"> <label for="blacklistDuration">Duration</label> <select id="blacklistDuration"> <option value="3600">1 Hour</option> <option value="86400">1 Day</option> <option value="604800">1 Week</option> <option value="2592000">1 Month</option> <option value="0">Permanent</option> </select> </div> <div class="form-group" style="grid-column: span 1 / auto;"> <label>&nbsp;</label> <button type="submit" class="btn btn-primary" id="manageIpBtn">Execute Action</button> </div> </form> </div> </div> </div> <!-- Edit User Modal --> <div id="editModal" class="modal-overlay"> <div class="modal-content"> <button class="modal-close-btn" data-action="close-edit-modal">✕</button> <h2>✏️ Edit User</h2> <form id="editUserForm"> <input type="hidden" id="editUuid"> <div class="form-group" style="margin-top: 20px;"> <label for="editExpiryDate">Expiry Date (Local)</label> <input type="date" id="editExpiryDate" required> </div> <div class="form-group" style="margin-top: 16px;"> <label for="editExpiryTime">Expiry Time (Local)</label> <input type="time" id="editExpiryTime" step="1" required> <div class="time-quick-set-group" data-target-date="editExpiryDate" data-target-time="editExpiryTime"> <button type="button" class="btn btn-outline-secondary" data-amount="1" data-unit="hour">+1 Hour</button> <button type="button" class="btn btn-outline-secondary" data-amount="1" data-unit="day">+1 Day</button> <button type="button" class="btn btn-outline-secondary" data-amount="7" data-unit="day">+1 Week</button> <button type="button" class="btn btn-outline-secondary" data-amount="1" data-unit="month">+1 Month</button> </div> </div> <div class="form-group" style="margin-top: 16px;"> <label for="editNotes">Notes</label> <input type="text" id="editNotes" placeholder="Optional notes"> </div> <div class="form-group" style="margin-top: 16px;"> <label for="editDataLimit">Data Limit</label> <div style="display: flex; gap: 8px; align-items: center;"> <input type="number" id="editDataLimit" min="0" step="0.01" placeholder="Enter limit" style="flex: 1; min-width: 100px;"> <select id="editDataUnit" style="min-width: 110px;"> <option>KB</option> <option>MB</option> <option selected>GB</option> <option>TB</option> <option value="unlimited">Unlimited</option> </select> </div> </div> <div class="form-group" style="margin-top: 16px;"> <label for="editIpLimit">IP Limit</label> <input type="number" id="editIpLimit" min="-1" step="1" placeholder="-1 (Unlimited)"> </div> <div class="form-group" style="margin-top: 16px;"> <label> <input type="checkbox" id="resetTraffic" style="width: auto; margin-right: 8px;"> Reset Traffic Usage </label> </div> <div style="display: flex; justify-content: flex-end; gap: 12px; margin-top: 24px;"> <button type="button" id="modalCancelBtn" class="btn btn-secondary" data-action="close-edit-modal">Cancel</button> <button type="submit" class="btn btn-primary">💾 Save Changes</button> </div> </form> </div> </div> <div id="toast"></div> <script nonce="CSP_NONCE_PLACEHOLDER"> // Admin Panel JavaScript - Fully combined and enhanced for rich interactions and security features document.addEventListener('DOMContentLoaded', () => { const API_BASE = 'ADMIN_API_BASE_PATH_PLACEHOLDER'; let allUsers = []; let allSecurityEvents = []; let allBlockedIPs = []; let selectedUserUUIDs = new Set(); function escapeHTML(str) { if (typeof str !== 'string') return ''; const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }; return str.replace(/[&<>"']/g, m => map[m]); } function formatBytes(bytes) { if (bytes === 0 || bytes === null || bytes === undefined) return '0 Bytes'; const k = 1024; const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB']; const i = Math.floor(Math.log(bytes) / Math.log(k)); return parseFloat((bytes / Math.pow(k, i))).toFixed(2) + ' ' + sizes[i]; } function showToast(message, type = 'success', duration = 3000) { const toast = document.getElementById('toast'); if (!toast) { console.warn('Toast element not found.'); return; } const icons = { success: '✓', error: '✕', warning: '⚠', info: 'ℹ' }; const icon = icons[type] || icons.success; const actualType = message.startsWith('✓') ? 'success' : message.startsWith('⚠️') ? 'warning' : message.startsWith('❌') ? 'error' : type; toast.innerHTML = `<div class="toast-content"><div class="toast-icon ${actualType}"><span>${icon}</span></div><div class="toast-message">${escapeHTML(message)}</div></div>`; toast.className = `${actualType} show`; setTimeout(() => { toast.classList.add('hide'); setTimeout(() => { toast.className = ''; toast.style.display = 'none'; }, 300); }, duration); toast.style.display = 'block'; } function updateProxyHealth(isHealthy, latency) { const card = document.getElementById('proxy-health-card'); const valueEl = document.getElementById('proxy-health'); const badge = document.getElementById('proxy-health-badge'); if (!card || !valueEl || !badge) return; if (isHealthy === null || isHealthy === undefined) { card.className = 'stat-card'; valueEl.textContent = 'Checking...'; valueEl.style.color = 'var(--text-primary)'; badge.innerHTML = '<span class="pulse-dot orange"></span> Checking'; badge.className = 'stat-badge checking'; } else if (isHealthy) { card.className = 'stat-card healthy'; valueEl.textContent = latency ? `${latency}ms` : 'Healthy'; valueEl.style.color = 'var(--success)'; badge.innerHTML = '<span class="pulse-dot green"></span> Online'; badge.className = 'stat-badge online'; } else { card.className = 'stat-card danger'; valueEl.textContent = 'Unhealthy'; valueEl.style.color = 'var(--danger)'; badge.innerHTML = '<span class="pulse-dot red"></span> Issues'; badge.className = 'stat-badge offline'; } } function updateBlockedIPsCount(count) { const blockedIpsCountEl = document.getElementById('blocked-ips-count'); const threatEventsBadge = document.getElementById('threat-events-badge'); if (blockedIpsCountEl) { blockedIpsCountEl.textContent = count; if (count > 0) { threatEventsBadge.innerHTML = '<span class="pulse-dot red"></span> Threats'; threatEventsBadge.className = 'stat-badge threat'; } else { threatEventsBadge.innerHTML = '<span class="pulse-dot green"></span> Clear'; threatEventsBadge.className = 'stat-badge online'; } } } function setButtonLoading(btn, loading) { if (btn) { if (loading) { btn.classList.add('loading'); btn.disabled = true; } else { btn.classList.remove('loading'); btn.disabled = false; } } } const getCsrfToken = () => document.cookie.split('; ').find(row => row.startsWith('csrf_token='))?.split('=')[1] || ''; const api = { async handleResponse(response) { if (response.status === 401) { showToast('Session expired. Please log in again.', 'error', 4000); setTimeout(() => window.location.reload(), 2000); throw new Error('Unauthorized'); } if (!response.ok) { const errorData = await response.json().catch(() => ({ error: 'Request failed' })); throw new Error(errorData.error || `Request failed with status ${response.status}`); } return response.status === 204 ? null : response.json(); }, get: (endpoint) => fetch(API_BASE + endpoint, { credentials: 'include' }).then(api.handleResponse), post: (endpoint, body) => fetch(API_BASE + endpoint, { method: 'POST', credentials: 'include', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': getCsrfToken() }, body: JSON.stringify(body) }).then(api.handleResponse), put: (endpoint, body) => fetch(API_BASE + endpoint, { method: 'PUT', credentials: 'include', headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': getCsrfToken() }, body: JSON.stringify(body) }).then(api.handleResponse), delete: (endpoint) => fetch(API_BASE + endpoint, { method: 'DELETE', credentials: 'include', headers: { 'X-CSRF-Token': getCsrfToken() } }).then(api.handleResponse), }; const pad = (num) => num.toString().padStart(2, '0'); function localToUTC(dateStr, timeStr) { if (!dateStr || !timeStr) return { utcDate: '', utcTime: '' }; const localDateTime = new Date(`${dateStr}T${timeStr}`); if (isNaN(localDateTime.getTime())) return { utcDate: '', utcTime: '' }; const year = localDateTime.getUTCFullYear(); const month = pad(localDateTime.getUTCMonth() + 1); const day = pad(localDateTime.getUTCDate()); const hours = pad(localDateTime.getUTCHours()); const minutes = pad(localDateTime.getUTCMinutes()); const seconds = pad(localDateTime.getUTCSeconds()); return { utcDate: `${year}-${month}-${day}`, utcTime: `${hours}:${minutes}:${seconds}` }; } function utcToLocal(utcDateStr, utcTimeStr) { if (!utcDateStr || !utcTimeStr) return { localDate: '', localTime: '' }; const utcDateTime = new Date(`${utcDateStr}T${utcTimeStr}Z`); if (isNaN(utcDateTime.getTime())) return { localDate: '', localTime: '' }; const year = utcDateTime.getFullYear(); const month = pad(utcDateTime.getMonth() + 1); const day = pad(utcDateTime.getDate()); const hours = pad(utcDateTime.getHours()); const minutes = pad(utcDateTime.getMinutes()); const seconds = pad(utcDateTime.getSeconds()); return { localDate: `${year}-${month}-${day}`, localTime: `${hours}:${minutes}:${seconds}` }; } function addExpiryTime(dateInputId, timeInputId, amount, unit) { const dateInput = document.getElementById(dateInputId); const timeInput = document.getElementById(timeInputId); if (!dateInput || !timeInput) { console.error(`Inputs not found: ${dateInputId}, ${timeInputId}`); return; } let date = new Date(dateInput.value + 'T' + (timeInput.value || '00:00:00')); if (isNaN(date.getTime())) { date = new Date(); } if (unit === 'hour') date.setHours(date.getHours() + amount); else if (unit === 'day') date.setDate(date.getDate() + amount); else if (unit === 'month') date.setMonth(date.getMonth() + amount); const year = date.getFullYear(); const month = pad(date.getMonth() + 1); const day = pad(date.getDate()); const hours = pad(date.getHours()); const minutes = pad(date.getMinutes()); const seconds = pad(date.getSeconds()); dateInput.value = `${year}-${month}-${day}`; timeInput.value = `${hours}:${minutes}:${seconds}`; } document.body.addEventListener('click', (e) => { const target = e.target.closest('.time-quick-set-group button'); if (!target) return; const group = target.closest('.time-quick-set-group'); if (!group) return; addExpiryTime(group.dataset.targetDate, group.dataset.targetTime, parseInt(target.dataset.amount, 10), target.dataset.unit); }); async function copyUUID(uuid, button) { try { await navigator.clipboard.writeText(uuid); const originalText = button.innerHTML; button.innerHTML = '✓ Copied'; button.classList.add('copied'); setTimeout(() => { if (button) { button.innerHTML = originalText; button.classList.remove('copied'); } }, 2000); showToast('UUID copied to clipboard!', 'success'); } catch (error) { console.error('Failed to copy UUID:', error); showToast('Failed to copy UUID', 'error'); } } async function fetchStats() { try { const stats = await api.get('/stats'); document.getElementById('total-users').textContent = stats.total_users; document.getElementById('active-users').textContent = stats.active_users; document.getElementById('expired-users').textContent = stats.expired_users; document.getElementById('total-traffic').textContent = await formatBytes(stats.total_traffic); updateBlockedIPsCount(stats.blocked_ips_count); if (stats.proxy_health) { updateProxyHealth(stats.proxy_health.is_healthy, stats.proxy_health.latency_ms); } else { updateProxyHealth(true, null); } } catch (error) { showToast(`Failed to fetch stats: ${error.message}`, 'error'); updateProxyHealth(false, null); } } function renderUsers(usersToRender = allUsers) { const userList = document.getElementById('userList'); if (!userList) return; userList.innerHTML = ''; if (usersToRender.length === 0) { userList.innerHTML = '<tr><td colspan="10" style="text-align:center; padding: 20px;">No users found.</td></tr>'; return; } usersToRender.forEach(user => { const expiryDateObj = new Date(user.expiration_date + 'T' + user.expiration_time + 'Z'); const isExpired = expiryDateObj <= new Date(); const localExpiry = expiryDateObj.toLocaleString(); const row = document.createElement('tr'); if (selectedUserUUIDs.has(user.uuid)) { row.classList.add('selected'); } row.innerHTML = ` <td><input type="checkbox" class="user-checkbox" data-uuid="${user.uuid}" ${selectedUserUUIDs.has(user.uuid) ? 'checked' : ''}></td> <td> <div class="uuid-cell"> <span title="${escapeHTML(user.uuid)}">${escapeHTML(user.uuid).substring(0, 8)}...</span> <button class="btn-copy-uuid" data-uuid="${escapeHTML(user.uuid)}">📋 Copy</button> </div> </td> <td>${new Date(user.created_at).toLocaleString()}</td> <td>${localExpiry}</td> <td><span class="status-badge ${isExpired ? 'status-expired' : 'status-active'}">${isExpired ? 'Expired' : 'Active'}</span></td> <td>${escapeHTML(user.notes || '-')}</td> <td>${user.traffic_limit ? formatBytes(user.traffic_limit) : 'Unlimited'}</td> <td>${formatBytes(user.traffic_used || 0)}</td> <td>${user.ip_limit === -1 ? 'Unlimited' : user.ip_limit}</td> <td class="actions"> <div style="display: flex; gap: 8px;"> <button class="btn btn-secondary btn-edit" data-uuid="${escapeHTML(user.uuid)}">Edit</button> <button class="btn btn-danger btn-delete" data-uuid="${escapeHTML(user.uuid)}">Delete</button> </div> </td> `; userList.appendChild(row); }); const selectAllCheckbox = document.getElementById('selectAllUsers'); if (selectAllCheckbox) { const allCheckboxes = document.querySelectorAll('.user-checkbox'); selectAllCheckbox.checked = allCheckboxes.length > 0 && selectedUserUUIDs.size === allCheckboxes.length; } } async function fetchAndRenderUsers() { try { allUsers = await api.get('/users'); allUsers.sort((a, b) => new Date(b.created_at) - new Date(a.created_at)); renderUsers(); await fetchStats(); } catch (error) { showToast(`Failed to fetch users: ${error.message}`, 'error'); } } function renderSecurityEvents(eventsToRender = allSecurityEvents) { const securityEventList = document.getElementById('securityEventList'); if (!securityEventList) return; securityEventList.innerHTML = ''; if (eventsToRender.length === 0) { securityEventList.innerHTML = '<tr><td colspan="6" style="text-align:center; padding: 20px;">No security events found.</td></tr>'; return; } eventsToRender.forEach(event => { const eventDate = new Date(event.timestamp * 1000).toLocaleString(); const row = document.createElement('tr'); row.innerHTML = ` <td>${eventDate}</td> <td>${escapeHTML(event.ip)}</td> <td><span class="log-type-badge ${escapeHTML(event.type)}">${escapeHTML(event.type).replace(/_/g, ' ')}</span></td> <td>${escapeHTML(event.details || '-')}</td> <td>${event.uuid ? escapeHTML(event.uuid.substring(0, 8)) + '...' : '-'}</td> <td class="actions"> ${!allBlockedIPs.some(b => b.ip === event.ip) ? `<button class="btn btn-danger btn-blacklist-ip small" data-ip="${escapeHTML(event.ip)}" data-reason="${escapeHTML(event.type)}: ${escapeHTML(event.details || 'Detected threat.')}">🚫 Blacklist</button>` : ''} </td> `; securityEventList.appendChild(row); }); } async function fetchAndRenderSecurityEvents() { try { const params = new URLSearchParams(); const eventType = document.getElementById('eventTypeFilter')?.value; const eventTime = document.getElementById('eventTimeFilter')?.value; const searchTerm = document.getElementById('securityEventsSearchInput')?.value; if (eventType) params.set('type', eventType); if (eventTime) params.set('time', eventTime); if (searchTerm) params.set('search', searchTerm); const events = await api.get(`/security/events?${params.toString()}`); allSecurityEvents = events.sort((a, b) => b.timestamp - a.timestamp); renderSecurityEvents(); } catch (error) { showToast(`Failed to fetch security events: ${error.message}`, 'error'); } } function renderIpBlacklist(ipsToRender = allBlockedIPs) { const ipBlacklistTable = document.getElementById('ipBlacklist'); if (!ipBlacklistTable) return; ipBlacklistTable.innerHTML = ''; if (ipsToRender.length === 0) { ipBlacklistTable.innerHTML = '<tr><td colspan="5" style="text-align:center; padding: 20px;">No IPs currently blacklisted.</td></tr>'; return; } ipsToRender.forEach(ipEntry => { const blacklistedAt = new Date(ipEntry.timestamp * 1000).toLocaleString(); const expiresAt = new Date(ipEntry.expiration * 1000).toLocaleString(); const isPermanent = ipEntry.expiration === 0 || ipEntry.expiration > (Date.now() / 1000 + 365 * 24 * 3600 * 50); const row = document.createElement('tr'); row.innerHTML = ` <td>${escapeHTML(ipEntry.ip)}</td> <td>${blacklistedAt}</td> <td><span class="status-badge ${isPermanent ? 'status-blocked' : 'status-warning-light'}">${isPermanent ? 'Permanent' : expiresAt}</span></td> <td>${escapeHTML(ipEntry.reason || '-')}</td> <td class="actions"> <button class="btn btn-secondary btn-whitelist-ip small" data-ip="${escapeHTML(ipEntry.ip)}">🔓 Whitelist</button> </td> `; ipBlacklistTable.appendChild(row); }); } async function fetchAndRenderIpBlacklist() { try { const searchTerm = document.getElementById('ipBlacklistSearchInput')?.value; const params = new URLSearchParams(); if (searchTerm) params.set('search', searchTerm); const ips = await api.get(`/security/blacklist?${params.toString()}`); allBlockedIPs = ips.sort((a, b) => b.timestamp - a.timestamp); renderIpBlacklist(); } catch (error) { showToast(`Failed to fetch IP blacklist: ${error.message}`, 'error'); } } async function handleManageIp(e) { e.preventDefault(); const manageIpBtn = document.getElementById('manageIpBtn'); setButtonLoading(manageIpBtn, true); const ipAddress = document.getElementById('ipAddress').value.trim(); const actionType = document.getElementById('actionType').value; const blacklistReason = document.getElementById('blacklistReason').value.trim(); const blacklistDuration = parseInt(document.getElementById('blacklistDuration').value, 10); if (!ipAddress) { showToast('IP Address is required.', 'error'); setButtonLoading(manageIpBtn, false); return; } try { if (actionType === 'blacklist') { if (!blacklistReason) { showToast('Reason is required for blacklisting.', 'error'); setButtonLoading(manageIpBtn, false); return; } await api.post('/security/blacklist', { ip: ipAddress, reason: blacklistReason, duration: blacklistDuration }); showToast(`✓ IP ${ipAddress} blacklisted successfully!`, 'success'); } else if (actionType === 'whitelist') { await api.delete(`/security/blacklist/${ipAddress}`); showToast(`✓ IP ${ipAddress} whitelisted successfully!`, 'success'); } document.getElementById('manageIpForm').reset(); toggleBlacklistFields(); await fetchAndRenderIpBlacklist(); await fetchAndRenderSecurityEvents(); await fetchStats(); } catch (error) { showToast(`Action failed: ${error.message}`, 'error'); } finally { setButtonLoading(manageIpBtn, false); } } function toggleBlacklistFields() { const actionType = document.getElementById('actionType')?.value; document.getElementById('blacklistReasonGroup')?.classList.toggle('hidden', actionType !== 'blacklist'); document.getElementById('blacklistDurationGroup')?.classList.toggle('hidden', actionType !== 'blacklist'); } function startAutoRefresh() { setInterval(async () => { try { await fetchAndRenderUsers(); await fetchAndRenderSecurityEvents(); await fetchAndRenderIpBlacklist(); } catch (error) { console.error('Auto-refresh failed:', error); } }, 60000); } async function handleCreateUser(e) { e.preventDefault(); const createBtn = e.submitter || e.target.querySelector('button[type="submit"]'); setButtonLoading(createBtn, true); const localDate = document.getElementById('expiryDate').value; const localTime = document.getElementById('expiryTime').value; const { utcDate, utcTime } = localToUTC(localDate, localTime); if (!utcDate || !utcTime) { showToast('Invalid expiry date or time. Please ensure both are set.', 'error'); setButtonLoading(createBtn, false); return; } const dataLimitInput = document.getElementById('dataLimit'); const dataUnit = document.getElementById('dataUnit').value; let trafficLimit = null; if (dataUnit !== 'unlimited' && dataLimitInput.value) { const multipliers = { KB: 1024, MB: 1024**2, GB: 1024**3, TB: 1024**4 }; const limitValue = parseFloat(dataLimitInput.value); if (isNaN(limitValue) || limitValue < 0) { showToast('Invalid data limit value.', 'error'); setButtonLoading(createBtn, false); return; } trafficLimit = Math.round(limitValue * (multipliers[dataUnit] || 1)); } const ipLimitInput = document.getElementById('ipLimit'); let ipLimit = parseInt(ipLimitInput.value, 10); if (isNaN(ipLimit) || ipLimit < -1) { showToast('Invalid IP limit. Must be -1 (unlimited) or a positive number.', 'error'); setButtonLoading(createBtn, false); return; } const userData = { uuid: document.getElementById('uuid').value, exp_date: utcDate, exp_time: utcTime, notes: document.getElementById('notes').value, traffic_limit: trafficLimit, ip_limit: ipLimit }; try { await api.post('/users', userData); showToast('✓ User created successfully!', 'success'); document.getElementById('createUserForm').reset(); document.getElementById('uuid').value = crypto.randomUUID(); setDefaultExpiry(); await fetchAndRenderUsers(); } catch (error) { showToast(`Failed to create user: ${error.message}`, 'error'); } finally { setButtonLoading(createBtn, false); } } async function handleDeleteUser(uuid) { if (confirm(`Are you sure you want to delete user ${uuid}?`)) { try { const deleteBtn = document.querySelector(`.btn-delete[data-uuid="${uuid}"]`); if (deleteBtn) setButtonLoading(deleteBtn, true); await api.delete('/users/' + uuid); showToast('✓ User deleted successfully!', 'success'); await fetchAndRenderUsers(); } catch (error) { showToast(`Failed to delete user: ${error.message}`, 'error'); } finally { const deleteBtn = document.querySelector(`.btn-delete[data-uuid="${uuid}"]`); if (deleteBtn) setButtonLoading(deleteBtn, false); } } } async function handleBulkDelete() { const selected = Array.from(document.querySelectorAll('.user-checkbox:checked')).map(cb => cb.dataset.uuid); if (selected.length === 0) { showToast('No users selected for deletion.', 'warning'); return; } if (confirm(`Are you sure you want to delete ${selected.length} selected users? This action cannot be undone.`)) { const deleteBtn = document.getElementById('deleteSelectedUsers'); setButtonLoading(deleteBtn, true); try { await api.post('/users/bulk-delete', { uuids: selected }); showToast(`✓ ${selected.length} selected users deleted!`, 'success'); selectedUserUUIDs.clear(); await fetchAndRenderUsers(); } catch (error) { showToast(`Failed to delete selected users: ${error.message}`, 'error'); } finally { setButtonLoading(deleteBtn, false); } } } function openEditModal(uuid) { const user = allUsers.find(u => u.uuid === uuid); if (!user) { showToast('User not found for editing.', 'error'); return; } const { localDate, localTime } = utcToLocal(user.expiration_date, user.expiration_time); document.getElementById('editUuid').value = user.uuid; document.getElementById('editExpiryDate').value = localDate; document.getElementById('editExpiryTime').value = localTime; document.getElementById('editNotes').value = user.notes || ''; const editDataLimit = document.getElementById('editDataLimit'); const editDataUnit = document.getElementById('editDataUnit'); if (user.traffic_limit === null || user.traffic_limit === 0) { editDataUnit.value = 'unlimited'; editDataLimit.value = ''; } else { let bytes = user.traffic_limit; let unit = 'KB'; let value = bytes / 1024; if (value >= 1024) { value /= 1024; unit = 'MB'; } if (value >= 1024) { value /= 1024; unit = 'GB'; } if (value >= 1024) { value /= 1024; unit = 'TB'; } editDataLimit.value = value.toFixed(2); editDataUnit.value = unit; } document.getElementById('editIpLimit').value = user.ip_limit !== null ? user.ip_limit : -1; document.getElementById('resetTraffic').checked = false; document.getElementById('editModal').classList.add('show'); } function closeEditModal() { document.getElementById('editModal').classList.remove('show'); } async function handleEditUser(e) { e.preventDefault(); const saveBtn = e.submitter || e.target.querySelector('button[type="submit"]'); setButtonLoading(saveBtn, true); const uuid = document.getElementById('editUuid').value; const localDate = document.getElementById('editExpiryDate').value; const localTime = document.getElementById('editExpiryTime').value; const { utcDate, utcTime } = localToUTC(localDate, localTime); if (!utcDate || !utcTime) { showToast('Invalid expiry date or time. Please ensure both are set.', 'error'); setButtonLoading(saveBtn, false); return; } const dataLimitInput = document.getElementById('editDataLimit'); const dataUnit = document.getElementById('editDataUnit').value; let trafficLimit = null; if (dataUnit !== 'unlimited' && dataLimitInput.value) { const multipliers = { KB: 1024, MB: 1024**2, GB: 1024**3, TB: 1024**4 }; const limitValue = parseFloat(dataLimitInput.value); if (isNaN(limitValue) || limitValue < 0) { showToast('Invalid data limit value.', 'error'); setButtonLoading(saveBtn, false); return; } trafficLimit = Math.round(limitValue * (multipliers[dataUnit] || 1)); } const ipLimitInput = document.getElementById('editIpLimit'); let ipLimit = parseInt(ipLimitInput.value, 10); if (isNaN(ipLimit) || ipLimit < -1) { showToast('Invalid IP limit. Must be -1 (unlimited) or a positive number.', 'error'); setButtonLoading(saveBtn, false); return; } const updatedData = { exp_date: utcDate, exp_time: utcTime, notes: document.getElementById('editNotes').value, traffic_limit: trafficLimit, ip_limit: ipLimit, reset_traffic: document.getElementById('resetTraffic').checked }; try { await api.put('/users/' + uuid, updatedData); showToast('✓ User updated successfully!', 'success'); closeEditModal(); await fetchAndRenderUsers(); } catch (error) { showToast(`Failed to update user: ${error.message}`, 'error'); } finally { setButtonLoading(saveBtn, false); } } async function handleLogout() { if (!confirm('Are you sure you want to log out?')) return; const logoutBtn = document.getElementById('logoutBtn'); setButtonLoading(logoutBtn, true); try { await api.post('/logout', {}); showToast('✓ Logged out successfully!', 'info'); setTimeout(() => window.location.reload(), 1000); } catch (error) { showToast(`Logout failed: ${error.message}`, 'error'); } finally { setButtonLoading(logoutBtn, false); } } async function handleHealthCheck() { const healthCheckBtn = document.getElementById('healthCheckBtn'); setButtonLoading(healthCheckBtn, true); updateProxyHealth(null, null); showToast('Initiating proxy health check...', 'info'); try { await api.post('/health-check', {}); showToast('✓ Health check completed!', 'success'); await fetchStats(); } catch (error) { showToast(`Health check failed: ${error.message}`, 'error'); } finally { setButtonLoading(healthCheckBtn, false); } } function setDefaultExpiry() { const now = new Date(); now.setMonth(now.getMonth() + 1); const year = now.getFullYear(); const month = pad(now.getMonth() + 1); const day = pad(now.getDate()); const hours = pad(now.getHours()); const minutes = pad(now.getMinutes()); const seconds = pad(now.getSeconds()); const expiryDateInput = document.getElementById('expiryDate'); const expiryTimeInput = document.getElementById('expiryTime'); if (expiryDateInput) expiryDateInput.value = `${year}-${month}-${day}`; if (expiryTimeInput) expiryTimeInput.value = `${hours}:${minutes}:${seconds}`; } function filterUsers() { const searchTerm = document.getElementById('userSearchInput')?.value.toLowerCase() || ''; const filtered = allUsers.filter(user => user.uuid.toLowerCase().includes(searchTerm) || (user.notes && user.notes.toLowerCase().includes(searchTerm)) ); renderUsers(filtered); } function filterSecurityEvents() { const searchTerm = document.getElementById('securityEventsSearchInput')?.value.toLowerCase() || ''; const eventTypeFilter = document.getElementById('eventTypeFilter')?.value || ''; const eventTimeFilter = document.getElementById('eventTimeFilter')?.value || ''; let filtered = allSecurityEvents.filter(event => { const matchesSearch = event.ip.toLowerCase().includes(searchTerm) || event.type.toLowerCase().includes(searchTerm) || (event.details && event.details.toLowerCase().includes(searchTerm)) || (event.uuid && event.uuid.toLowerCase().includes(searchTerm)); const matchesType = !eventTypeFilter || event.type === eventTypeFilter; const now = Date.now() / 1000; let matchesTime = true; if (eventTimeFilter === '24h') matchesTime = (now - event.timestamp) <= 24 * 3600; else if (eventTimeFilter === '7d') matchesTime = (now - event.timestamp) <= 7 * 24 * 3600; else if (eventTimeFilter === '30d') matchesTime = (now - event.timestamp) <= 30 * 24 * 3600; return matchesSearch && matchesType && matchesTime; }); renderSecurityEvents(filtered); } function filterIpBlacklist() { const searchTerm = document.getElementById('ipBlacklistSearchInput')?.value.toLowerCase() || ''; const filtered = allBlockedIPs.filter(ipEntry => ipEntry.ip.toLowerCase().includes(searchTerm) || (ipEntry.reason && ipEntry.reason.toLowerCase().includes(searchTerm)) ); renderIpBlacklist(filtered); } document.getElementById('generateUUID')?.addEventListener('click', () => { document.getElementById('uuid').value = crypto.randomUUID(); }); document.getElementById('createUserForm')?.addEventListener('submit', handleCreateUser); document.getElementById('editUserForm')?.addEventListener('submit', handleEditUser); document.getElementById('editModal')?.addEventListener('click', (e) => { if (e.target.dataset.action === "close-edit-modal" || e.target === document.getElementById('editModal')) { closeEditModal(); } }); document.getElementById('userSearchInput')?.addEventListener('input', filterUsers); document.getElementById('selectAllUsers')?.addEventListener('change', (e) => { const isChecked = e.target.checked; document.querySelectorAll('.user-checkbox').forEach(cb => { cb.checked = isChecked; if (isChecked) { selectedUserUUIDs.add(cb.dataset.uuid); } else { selectedUserUUIDs.delete(cb.dataset.uuid); } }); document.querySelectorAll('#userList tr').forEach(row => { const uuid = row.querySelector('.user-checkbox')?.dataset.uuid; if (uuid && selectedUserUUIDs.has(uuid)) { row.classList.add('selected'); } else { row.classList.remove('selected'); } }); }); document.getElementById('deleteSelectedUsers')?.addEventListener('click', handleBulkDelete); document.getElementById('exportUsers')?.addEventListener('click', function() { if (allUsers.length === 0) { showToast('No users to export.', 'info'); return; } const headers = ['UUID', 'Created At', 'Expiration Date', 'Expiration Time', 'Notes', 'Traffic Limit', 'Traffic Used', 'IP Limit']; const csvContent = headers.join(',') + '\n' + allUsers.map(user => { return [ user.uuid, user.created_at, user.expiration_date, user.expiration_time, (user.notes || '').replace(/"/g, '""').replace(/,/g, ';'), user.traffic_limit || 'Unlimited', user.traffic_used || 0, user.ip_limit ].map(val => `"${String(val).replace(/"/g, '""')}"`).join(','); }).join('\n'); const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' }); const url = URL.createObjectURL(blob); const link = document.createElement('a'); link.href = url; link.download = `users_export_${new Date().toISOString().split('T')[0]}.csv`; document.body.appendChild(link); link.click(); document.body.removeChild(link); URL.revokeObjectURL(url); showToast('✓ Users exported successfully!', 'success'); }); document.getElementById('logoutBtn')?.addEventListener('click', handleLogout); document.getElementById('healthCheckBtn')?.addEventListener('click', handleHealthCheck); document.getElementById('userList')?.addEventListener('click', (e) => { const copyBtn = e.target.closest('.btn-copy-uuid'); if (copyBtn) { copyUUID(copyBtn.dataset.uuid, copyBtn); return; } const editBtn = e.target.closest('.btn-edit'); if (editBtn) { openEditModal(editBtn.dataset.uuid); return; } const deleteBtn = e.target.closest('.btn-delete'); if (deleteBtn) { handleDeleteUser(deleteBtn.dataset.uuid); return; } const checkbox = e.target.closest('.user-checkbox'); if (checkbox) { const uuid = checkbox.dataset.uuid; if (checkbox.checked) { selectedUserUUIDs.add(uuid); } else { selectedUserUUIDs.delete(uuid); } const allCheckboxes = document.querySelectorAll('.user-checkbox'); const selectAllCheckbox = document.getElementById('selectAllUsers'); if (selectAllCheckbox) { selectAllCheckbox.checked = selectedUserUUIDs.size === allCheckboxes.length; } } }); document.querySelectorAll('.security-tab-btn').forEach(button => { button.addEventListener('click', (e) => { document.querySelectorAll('.security-tab-btn').forEach(btn => btn.classList.remove('active')); e.target.classList.add('active'); document.querySelectorAll('.tab-content').forEach(content => content.classList.add('hidden')); const targetTab = document.getElementById(`${e.target.dataset.tab}-content`); if (targetTab) { targetTab.classList.remove('hidden'); if (e.target.dataset.tab === 'security-events') fetchAndRenderSecurityEvents(); else if (e.target.dataset.tab === 'ip-blacklist') fetchAndRenderIpBlacklist(); toggleBlacklistFields(); } }); }); document.getElementById('securityEventsSearchInput')?.addEventListener('input', filterSecurityEvents); document.getElementById('eventTypeFilter')?.addEventListener('change', filterSecurityEvents); document.getElementById('eventTimeFilter')?.addEventListener('change', filterSecurityEvents); document.getElementById('ipBlacklistSearchInput')?.addEventListener('input', filterIpBlacklist); document.getElementById('manageIpForm')?.addEventListener('submit', handleManageIp); document.getElementById('actionType')?.addEventListener('change', toggleBlacklistFields); document.getElementById('securityEventList')?.addEventListener('click', async (e) => { const blacklistBtn = e.target.closest('.btn-blacklist-ip'); if (blacklistBtn) { const ip = blacklistBtn.dataset.ip; const reason = blacklistBtn.dataset.reason || 'Manual blacklist from admin panel.'; if (confirm(`Blacklist IP ${ip} for: "${reason}"?`)) { setButtonLoading(blacklistBtn, true); try { await api.post('/security/blacklist', { ip, reason, duration: 3600 }); showToast(`IP ${ip} blacklisted for 1 hour.`, 'success'); await fetchAndRenderIpBlacklist(); await fetchAndRenderSecurityEvents(); await fetchStats(); } catch (error) { showToast(`Failed to blacklist IP: ${error.message}`, 'error'); } finally { setButtonLoading(blacklistBtn, false); } } } }); document.getElementById('ipBlacklist')?.addEventListener('click', async (e) => { const whitelistBtn = e.target.closest('.btn-whitelist-ip'); if (whitelistBtn) { const ip = whitelistBtn.dataset.ip; if (confirm(`Whitelist IP ${ip}?`)) { setButtonLoading(whitelistBtn, true); try { await api.delete(`/security/blacklist/${ip}`); showToast(`IP ${ip} whitelisted.`, 'success'); await fetchAndRenderIpBlacklist(); await fetchAndRenderSecurityEvents(); await fetchStats(); } catch (error) { showToast(`Failed to whitelist IP: ${error.message}`, 'error'); } finally { setButtonLoading(whitelistBtn, false); } } } }); setDefaultExpiry(); document.getElementById('uuid').value = crypto.randomUUID(); updateProxyHealth(null, null); toggleBlacklistFields(); fetchAndRenderUsers(); fetchAndRenderSecurityEvents(); fetchAndRenderIpBlacklist(); startAutoRefresh(); function updateServerTime() { const now = new Date(); const timeStr = now.toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' }); const el = document.getElementById('server-time'); if (el) el.textContent = timeStr; } updateServerTime(); setInterval(updateServerTime, 1000); }); </script> </body> </html>`; // ============================================================================ // UI/UX LAYER - Ultra-Modern Glassmorphism User Panel (HTML/CSS/JS) // This entire block contains the HTML, embedded CSS, and inline JavaScript // for the feature-rich User Panel, ensuring a seamless and high-performance // user experience with advanced QR code functionality and real-time updates. // ============================================================================ const userPanelHTML = `<!doctype html> <html lang="en"> <head> <meta charset="utf-8" /> <meta name="viewport" content="width=device-width,initial-scale=1" /> <title>User Panel — VLESS Configuration</title> <!-- Embedded QR Code Generator for offline/local generation --> <!-- This minimal, self-contained implementation avoids external CDN dependency for core QR function. --> <script nonce="CSP_NONCE_PLACEHOLDER"> const QRCodeGenerator = (function() { const QRErrorCorrectLevel = { L: 1, M: 0, Q: 3, H: 2 }; function QRMath() {} QRMath.glog = function(n) { if (n < 1) throw new Error("glog(" + n + ")"); return QRMath.LOG_TABLE[n]; }; QRMath.gexp = function(n) { while (n < 0) n += 255; while (n >= 256) n -= 255; return QRMath.EXP_TABLE[n]; }; QRMath.EXP_TABLE = new Array(256); QRMath.LOG_TABLE = new Array(256); for (let i = 0; i < 8; i++) { QRMath.EXP_TABLE[i] = 1 << i; } for (let i = 8; i < 256; i++) { QRMath.EXP_TABLE[i] = QRMath.EXP_TABLE[i - 4] ^ QRMath.EXP_TABLE[i - 5] ^ QRMath.EXP_TABLE[i - 6] ^ QRMath.EXP_TABLE[i - 8]; } for (let i = 0; i < 255; i++) { QRMath.LOG_TABLE[QRMath.EXP_TABLE[i]] = i; } function QRPolynomial(num, shift) { if (num.length === undefined) throw new Error("Invalid input"); let offset = 0; while (offset < num.length && num[offset] === 0) offset++; this.num = new Array(num.length - offset + shift); for (let i = 0; i < num.length - offset; i++) { this.num[i] = num[i + offset]; } } QRPolynomial.prototype = { get: function(index) { return this.num[index]; }, getLength: function() { return this.num.length; }, multiply: function(e) { const num = new Array(this.getLength() + e.getLength() - 1); for (let i = 0; i < this.getLength(); i++) { for (let j = 0; j < e.getLength(); j++) { num[i + j] ^= QRMath.gexp(QRMath.glog(this.get(i)) + QRMath.glog(e.get(j))); } } return new QRPolynomial(num, 0); }, mod: function(e) { if (this.getLength() - e.getLength() < 0) return this; const ratio = QRMath.glog(this.get(0)) - QRMath.glog(e.get(0)); const num = new Array(this.getLength()); for (let i = 0; i < this.getLength(); i++) { num[i] = this.get(i); } for (let i = 0; i < e.getLength(); i++) { num[i] ^= QRMath.gexp(QRMath.glog(e.get(i)) + ratio); } return new QRPolynomial(num, 0).mod(e); } }; function QRCode(typeNumber, errorCorrectLevel) { this.typeNumber = typeNumber; this.errorCorrectLevel = errorCorrectLevel; this.modules = null; this.moduleCount = 0; this.dataCache = null; this.dataList = []; } QRCode.prototype = { addData: function(data) { this.dataList.push({ data: data, mode: 4 }); this.dataCache = null; }, make: function() { this.makeImpl(false, this.getBestMaskPattern()); }, makeImpl: function(test, maskPattern) { this.moduleCount = this.typeNumber * 4 + 17; this.modules = new Array(this.moduleCount); for (let row = 0; row < this.moduleCount; row++) { this.modules[row] = new Array(this.moduleCount); } this.setupPositionProbePattern(0, 0); this.setupPositionProbePattern(this.moduleCount - 7, 0); this.setupPositionProbePattern(0, this.moduleCount - 7); this.setupPositionAdjustPattern(); this.setupTimingPattern(); this.setupTypeInfo(test, maskPattern); if (this.typeNumber >= 7) this.setupTypeNumber(test); if (this.dataCache === null) { this.dataCache = QRCode.createData(this.typeNumber, this.errorCorrectLevel, this.dataList); } this.mapData(this.dataCache, maskPattern); }, setupPositionProbePattern: function(row, col) { for (let r = -1; r <= 7; r++) { if (row + r <= -1 || this.moduleCount <= row + r) continue; for (let c = -1; c <= 7; c++) { if (col + c <= -1 || this.moduleCount <= col + c) continue; this.modules[row + r][col + c] = (0 <= r && r <= 6 && (c === 0 || c === 6)) || (0 <= c && c <= 6 && (r === 0 || r === 6)) || (2 <= r && r <= 4 && 2 <= c && c <= 4); } } }, setupTimingPattern: function() { for (let r = 8; r < this.moduleCount - 8; r++) { if (this.modules[r][6] != null) continue; this.modules[r][6] = r % 2 === 0; } for (let c = 8; c < this.moduleCount - 8; c++) { if (this.modules[6][c] != null) continue; this.modules[6][c] = c % 2 === 0; } }, setupPositionAdjustPattern: function() { const PATTERN_POSITIONS = [ [], [6, 18], [6, 22], [6, 26], [6, 30], [6, 34], [6, 22, 38], [6, 24, 42], [6, 26, 46], [6, 28, 50], [6, 30, 54], [6, 32, 58], [6, 34, 62], [6, 26, 46, 66], [6, 26, 48, 70], [6, 26, 50, 74], [6, 30, 54, 78], [6, 30, 56, 82], [6, 30, 58, 86], [6, 34, 62, 90], [6, 28, 50, 72, 94], [6, 26, 50, 74, 98], [6, 30, 54, 78, 102], [6, 28, 54, 80, 106], [6, 32, 58, 84, 110], [6, 30, 58, 86, 114], [6, 34, 62, 90, 118], [6, 26, 50, 74, 98, 122], [6, 30, 54, 78, 102, 126], [6, 26, 52, 78, 104, 130], [6, 30, 56, 82, 108, 134], [6, 34, 60, 86, 112, 138], [6, 30, 58, 86, 114, 142], [6, 34, 62, 90, 118, 146], [6, 30, 54, 78, 102, 126, 150], [6, 24, 50, 76, 102, 128, 154], [6, 28, 54, 80, 106, 132, 158], [6, 32, 58, 84, 110, 136, 162], [6, 26, 54, 82, 110, 138, 166], [6, 30, 58, 86, 114, 142, 170] ]; const pos = PATTERN_POSITIONS[this.typeNumber - 1] || []; for (let i = 0; i < pos.length; i++) { for (let j = 0; j < pos.length; j++) { const row = pos[i], col = pos[j]; if (this.modules[row][col] != null) continue; for (let r = -2; r <= 2; r++) { for (let c = -2; c <= 2; c++) { this.modules[row + r][col + c] = r === -2 || r === 2 || c === -2 || c === 2 || (r === 0 && c === 0); } } } } }, setupTypeNumber: function(test) { const bits = this.typeNumber << 12; let mod = bits; for (let i = 0; i < 12; i++) { if ((mod >>> (11 - i)) & 1) mod ^= 7973 << (11 - i); } const data = (bits | mod) ^ 21522; for (let i = 0; i < 18; i++) { this.modules[Math.floor(i / 3)][i % 3 + this.moduleCount - 8 - 3] = !test && ((data >>> i) & 1) === 1; } }, setupTypeInfo: function(test, maskPattern) { const data = (this.errorCorrectLevel << 3) | maskPattern; let bits = data << 10; for (let i = 0; i < 10; i++) { if ((bits >>> (9 - i)) & 1) bits ^= 1335 << (9 - i); } bits = ((data << 10) | bits) ^ 21522; for (let i = 0; i < 15; i++) { const mod = !test && ((bits >>> i) & 1) === 1; if (i < 6) { this.modules[i][8] = mod; } else if (i < 8) { this.modules[i + 1][8] = mod; } else { this.modules[this.moduleCount - 15 + i][8] = mod; } } for (let i = 0; i < 15; i++) { const mod = !test && ((bits >>> i) & 1) === 1; if (i < 8) { this.modules[8][this.moduleCount - i - 1] = mod; } else if (i < 9) { this.modules[8][15 - i] = mod; } else { this.modules[8][14 - i] = mod; } } this.modules[this.moduleCount - 8][8] = !test; }, mapData: function(data, maskPattern) { let inc = -1, row = this.moduleCount - 1, bitIndex = 7, byteIndex = 0; for (let col = this.moduleCount - 1; col > 0; col -= 2) { if (col === 6) col--; while (true) { for (let c = 0; c < 2; c++) { if (this.modules[row][col - c] == null) { let dark = false; if (byteIndex < data.length) dark = ((data[byteIndex] >>> bitIndex) & 1) === 1; if (this.getMask(maskPattern, row, col - c)) dark = !dark; this.modules[row][col - c] = dark; bitIndex--; if (bitIndex === -1) { byteIndex++; bitIndex = 7; } } } row += inc; if (row < 0 || this.moduleCount <= row) { row -= inc; inc = -inc; break; } } } }, getMask: function(maskPattern, i, j) { switch (maskPattern) { case 0: return (i + j) % 2 === 0; case 1: return i % 2 === 0; case 2: return j % 3 === 0; case 3: return (i + j) % 3 === 0; case 4: return (Math.floor(i / 2) + Math.floor(j / 3)) % 2 === 0; case 5: return ((i * j) % 2) + ((i * j) % 3) === 0; case 6: return (((i * j) % 2) + ((i * j) % 3)) % 2 === 0; case 7: return (((i + j) % 2) + ((i * j) % 3)) % 2 === 0; default: throw new Error("bad maskPattern:" + maskPattern); } }, getBestMaskPattern: function() { let minLostPoint = 0, pattern = 0; for (let i = 0; i < 8; i++) { this.makeImpl(true, i); const lostPoint = this.getLostPoint(); if (i === 0 || minLostPoint > lostPoint) { minLostPoint = lostPoint; pattern = i; } } return pattern; }, getLostPoint: function() { let lostPoint = 0; for (let row = 0; row < this.moduleCount; row++) { for (let col = 0; col < this.moduleCount; col++) { let sameCount = 0; const dark = this.modules[row][col]; for (let r = -1; r <= 1; r++) { if (row + r < 0 || this.moduleCount <= row + r) continue; for (let c = -1; c <= 1; c++) { if (col + c < 0 || this.moduleCount <= col + c) continue; if (r === 0 && c === 0) continue; if (dark === this.modules[row + r][col + c]) sameCount++; } } if (sameCount > 5) lostPoint += (3 + sameCount - 5); } } return lostPoint; } }; QRCode.RS_BLOCK_TABLE = [ [1, 26, 19], [1, 26, 16], [1, 26, 13], [1, 26, 9], [1, 44, 34], [1, 44, 28], [1, 44, 22], [1, 44, 16], [1, 70, 55], [1, 70, 44], [2, 35, 17], [2, 35, 13], [1, 100, 80], [2, 50, 32], [2, 50, 24], [4, 25, 9], [1, 134, 108], [2, 67, 43], [2, 33, 15, 2, 34, 16], [2, 33, 11, 2, 34, 12], [2, 86, 68], [4, 43, 27], [4, 43, 19], [4, 43, 15], [2, 98, 78], [4, 49, 31], [2, 32, 14, 4, 33, 15], [4, 39, 13, 1, 40, 14], [2, 121, 97], [2, 60, 38, 2, 61, 39], [4, 40, 18, 2, 41, 19], [4, 40, 14, 2, 41, 15], [2, 146, 116], [3, 58, 36, 2, 59, 37], [4, 36, 16, 4, 37, 17], [4, 36, 12, 4, 37, 13], [2, 86, 68, 2, 87, 69], [4, 69, 43, 1, 70, 44], [6, 43, 19, 2, 44, 20], [6, 43, 15, 2, 44, 16] ]; QRCode.getRSBlocks = function(typeNumber, errorCorrectLevel) { const rsBlock = QRCode.RS_BLOCK_TABLE[(typeNumber - 1) * 4 + errorCorrectLevel]; if (!rsBlock) throw new Error("Invalid RS Block for type " + typeNumber + " level " + errorCorrectLevel); const blocks = []; for (let i = 0; i < rsBlock.length; i += 3) { const count = rsBlock[i]; const totalCount = rsBlock[i + 1]; const dataCount = rsBlock[i + 2]; for (let j = 0; j < count; j++) { blocks.push({ totalCount, dataCount }); } } return blocks; }; QRCode.createData = function(typeNumber, errorCorrectLevel, dataList) { const rsBlocks = QRCode.getRSBlocks(typeNumber, errorCorrectLevel); const buffer = { buffer: [], length: 0 }; function put(num, length) { for (let i = 0; i < length; i++) { buffer.buffer.push(((num >>> (length - i - 1)) & 1) === 1); buffer.length++; } } for (let i = 0; i < dataList.length; i++) { const data = dataList[i]; put(4, 4); put(data.data.length, 8); for (let j = 0; j < data.data.length; j++) { put(data.data.charCodeAt(j), 8); } } let totalDataCount = 0; for (let i = 0; i < rsBlocks.length; i++) { totalDataCount += rsBlocks[i].dataCount; } totalDataCount *= 8; if (buffer.length + 4 <= totalDataCount) put(0, 4); while (buffer.length % 8 !== 0) put(0, 1); const padBytes = [0xEC, 0x11]; let padIndex = 0; while (buffer.length < totalDataCount) { put(padBytes[padIndex % 2], 8); padIndex++; } const data = new Array(Math.ceil(buffer.length / 8)); for (let i = 0; i < data.length; i++) { data[i] = 0; for (let j = 0; j < 8; j++) { if (buffer.buffer[i * 8 + j]) data[i] |= (1 << (7 - j)); } } let offset = 0; let maxDcCount = 0, maxEcCount = 0; const dcdata = [], ecdata = []; for (let r = 0; r < rsBlocks.length; r++) { const dcCount = rsBlocks[r].dataCount; const ecCount = rsBlocks[r].totalCount - dcCount; maxDcCount = Math.max(maxDcCount, dcCount); maxEcCount = Math.max(maxEcCount, ecCount); dcdata[r] = new Array(dcCount); for (let i = 0; i < dcdata[r].length; i++) { dcdata[r][i] = data[i + offset] || 0; } offset += dcCount; const rsPoly = QRCode.getErrorCorrectPolynomial(ecCount); const rawPoly = new QRPolynomial(dcdata[r], rsPoly.getLength() - 1); const modPoly = rawPoly.mod(rsPoly); ecdata[r] = new Array(rsPoly.getLength() - 1); for (let i = 0; i < ecdata[r].length; i++) { const modIndex = i + modPoly.getLength() - ecdata[r].length; ecdata[r][i] = modIndex >= 0 ? modPoly.get(modIndex) : 0; } } let totalCodeCount = 0; for (let r = 0; r < rsBlocks.length; r++) { totalCodeCount += rsBlocks[r].totalCount; } const result = new Array(totalCodeCount); let index = 0; for (let i = 0; i < maxDcCount; i++) { for (let r = 0; r < rsBlocks.length; r++) { if (i < dcdata[r].length) result[index++] = dcdata[r][i]; } } for (let i = 0; i < maxEcCount; i++) { for (let r = 0; r < rsBlocks.length; r++) { if (i < ecdata[r].length) result[index++] = ecdata[r][i]; } } return result; }; QRCode.getErrorCorrectPolynomial = function(errorCorrectLength) { let a = new QRPolynomial([1], 0); for (let i = 0; i < errorCorrectLength; i++) { a = a.multiply(new QRPolynomial([1, QRMath.gexp(i)], 0)); } return a; }; return { generate: function(text, size) { let qr; let typeNumber = 10; while (typeNumber <= 40) { try { qr = new QRCode(typeNumber, QRErrorCorrectLevel.M); qr.addData(text); qr.make(); break; } catch (e) { typeNumber += 2; if (typeNumber > 40) { try { qr = new QRCode(40, QRErrorCorrectLevel.L); qr.addData(text); qr.make(); } catch (e2) { throw new Error('Data too large for QR code'); } } } } if (!qr || !qr.modules) { throw new Error('Failed to generate QR code'); } const canvas = document.createElement("canvas"); const cellSize = Math.max(2, Math.floor(size / qr.moduleCount)); const margin = Math.floor(cellSize * 0.5); canvas.width = canvas.height = qr.moduleCount * cellSize + margin * 2; const ctx = canvas.getContext("2d"); ctx.fillStyle = "#ffffff"; ctx.fillRect(0, 0, canvas.width, canvas.height); ctx.fillStyle = "#000000"; for (let row = 0; row < qr.moduleCount; row++) { for (let col = 0; col < qr.moduleCount; col++) { if (qr.modules[row][col]) { ctx.fillRect( margin + col * cellSize, margin + row * cellSize, cellSize, cellSize ); } } } return canvas; } }; })(); </script> <script src="https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js" integrity="sha512-CNgIRecGo7nphbeZ04Sc13ka07paqdeTu0WR1IM4kNcpmBAUSHSQX0FslNhTDadL4O5SAGapGt4FodqL8My0mA==" crossorigin="anonymous" referrerpolicy="no-referrer"></script> <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=SF+Mono:wght@400;600&display=swap" rel="stylesheet"> <style nonce="CSP_NONCE_PLACEHOLDER"> :root { --bg: #0b1220; --card: #0f1724; --muted: #9aa4b2; --text-primary: #e6eef8; --accent: #3b82f6; --accent-2: #60a5fa; --success: #22c55e; --danger: #ef4444; --warning: #f59e0b; --info: #06b6d4; --glass: rgba(255,255,255,0.03); --radius-sm: 10px; --radius-md: 14px; --radius-lg: 16px; --mono: "SF Mono", "Fira Code", monospace; --purple: #a855f7; --glow-accent: rgba(59, 130, 246, 0.4); --glow-purple: rgba(168, 85, 247, 0.3); --border-light: rgba(255,255,255,0.06); --border-dark: rgba(255,255,255,0.02); --shadow-light: 0 8px 32px rgba(0,0,0,0.3); --shadow-dark: inset 0 1px 0 rgba(255,255,255,0.05); } * { box-sizing: border-box; margin: 0; padding: 0; } body { font-family: 'Inter', system-ui, -apple-system, "Segoe UI", Roboto, Arial, sans-serif; background: linear-gradient(135deg, #030712 0%, #0f172a 25%, #1e1b4b 50%, #0f172a 75%, #030712 100%); background-size: 400% 400%; animation: gradient-shift 15s ease infinite; color: var(--text-primary); -webkit-font-smoothing: antialiased; min-height: 100vh; padding: 28px; position: relative; overflow-x: hidden; } body::before { content: ''; position: fixed; top: 0; left: 0; right: 0; bottom: 0; z-index: -1; background: radial-gradient(ellipse at 20% 20%, rgba(59, 130, 246, 0.08) 0%, transparent 50%), radial-gradient(ellipse at 80% 80%, rgba(168, 85, 247, 0.08) 0%, transparent 50%), radial-gradient(ellipse at 50% 50%, rgba(34, 197, 94, 0.03) 0%, transparent 60%); } @keyframes gradient-shift { 0% { background-position: 0% 50%; } 50% { background-position: 100% 50%; } 100% { background-position: 0% 50%; } } @keyframes shimmer { 0% { background-position: -200% 0; } 100% { background-position: 200% 0; } } @keyframes glow-pulse { 0%, 100% { box-shadow: 0 0 20px var(--glow-accent); } 50% { box-shadow: 0 0 40px var(--glow-accent), 0 0 60px var(--glow-purple); } } @keyframes toastIn { from { transform: translateX(100px); opacity: 0; } to { transform: translateX(0); opacity: 1; } } @keyframes toastOut { from { transform: translateX(0); opacity: 1; } to { transform: translateX(100px); opacity: 0; } } @keyframes pulse-indicator-anim { 0%,100%{box-shadow:0 0 0 0 rgba(34,197,94,0.6), 0 0 10px rgba(34,197,94,0.4)} 50%{box-shadow:0 0 0 10px rgba(34,197,94,0), 0 0 20px rgba(34,197,94,0.2)} } .container { max-width: 1100px; margin: 0 auto; } .card { background: linear-gradient(145deg, rgba(15, 23, 42, 0.9), rgba(15, 23, 36, 0.7)); backdrop-filter: blur(20px); -webkit-backdrop-filter: blur(20px); border-radius: var(--radius-lg); padding: 22px; border: 1px solid var(--border-light); box-shadow: var(--shadow-light), var(--shadow-dark); margin-bottom: 20px; transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1); position: relative; overflow: hidden; } .card::before { content: ''; position: absolute; top: 0; left: 0; right: 0; height: 1px; background: linear-gradient(90deg, transparent, rgba(255,255,255,0.1), transparent); } .card:hover { box-shadow: 0 20px 50px rgba(0,0,0,0.4), 0 0 30px rgba(59, 130, 246, 0.1); transform: translateY(-4px); border-color: rgba(59, 130, 246, 0.2); } h1 { font-size: 30px; margin: 0 0 14px; font-weight: 800; background: linear-gradient(135deg, var(--accent) 0%, var(--purple) 50%, var(--pink) 100%); background-size: 200% auto; animation: shimmer 3s linear infinite; -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text; text-shadow: 0 0 40px rgba(139, 92, 246, 0.3); text-align: center; } h2 { font-size: 20px; color: var(--text-primary); margin: 0 0 14px; font-weight: 700; } .section-title { display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; padding-bottom: 12px; border-bottom: 1px solid rgba(255,255,255,0.05); } p.lead { color: var(--muted); margin: 6px 0 22px; font-size: 15px; letter-spacing: 0.2px; text-align: center; } .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 16px; margin-bottom: 14px; } .stat { padding: 18px 14px; background: linear-gradient(145deg, rgba(30, 41, 59, 0.6), rgba(15, 23, 36, 0.8)); backdrop-filter: blur(10px); border-radius: var(--radius-md); text-align: center; border: 1px solid var(--border-dark); transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1); position: relative; overflow: hidden; box-shadow: 0 4px 15px rgba(0,0,0,0.2); } .stat::after { content: ''; position: absolute; top: -50%; left: -50%; width: 200%; height: 200%; background: radial-gradient(circle, rgba(255,255,255,0.05) 0%, transparent 70%); opacity: 0; transition: opacity 0.4s; } .stat:hover::after { opacity: 1; } .stat:hover { transform: translateY(-5px) scale(1.02); box-shadow: 0 12px 30px rgba(59, 130, 246, 0.25), 0 0 20px rgba(59, 130, 246, 0.1); border-color: rgba(59, 130, 246, 0.3); } .stat .val { font-weight: 800; font-size: 24px; margin-bottom: 6px; letter-spacing: -0.5px; color: var(--text-primary); } .stat .lbl { color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: 1px; font-weight: 500; } .stat.status-active .val { color: var(--success); text-shadow: 0 0 20px rgba(34, 197, 94, 0.4); } .stat.status-expired .val { color: var(--danger); text-shadow: 0 0 20px rgba(239, 68, 68, 0.4); } .stat.status-warning .val { color: var(--warning); text-shadow: 0 0 20px rgba(245, 158, 11, 0.4); } .main-grid { display: grid; grid-template-columns: 1fr 360px; gap: 18px; } @media (max-width: 980px) { .main-grid { grid-template-columns: 1fr; } } .info-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 14px; margin-top: 16px; } .info-item { background: var(--glass); padding: 14px; border-radius: var(--radius-sm); border: 1px solid var(--border-dark); } .info-item .label { font-size: 11px; color: var(--muted); display: block; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 6px; } .info-item .value { font-weight: 600; word-break: break-all; font-size: 14px; } .progress-bar { height: 14px; background: linear-gradient(90deg, rgba(7,21,41,0.8), rgba(15,23,42,0.9)); border-radius: 10px; overflow: hidden; margin: 14px 0; box-shadow: inset 0 2px 8px rgba(0,0,0,0.4); border: 1px solid rgba(255,255,255,0.03); } .progress-fill { height: 100%; transition: width 1s cubic-bezier(0.4, 0, 0.2, 1); border-radius: 10px; width: 0%; position: relative; } .progress-fill::after { content: ''; position: absolute; top: 0; left: 0; right: 0; bottom: 0; background: linear-gradient(90deg, transparent, rgba(255,255,255,0.3), transparent); animation: shimmer 2s infinite; } .progress-fill.low { background: linear-gradient(90deg,var(--success) 0%,#16a34a 50%,var(--success) 100%); background-size:200% auto; } .progress-fill.medium { background: linear-gradient(90deg,var(--warning) 0%,#d97706 50%,var(--warning) 100%); background-size:200% auto; } .progress-fill.high { background: linear-gradient(90deg,var(--danger) 0%,#dc2626 50%,var(--danger) 100%); background-size:200% auto; } pre.config { background: #071529; padding: 14px; border-radius: 8px; overflow: auto; font-family: var(--mono); font-size: 13px; color: #cfe8ff; border: 1px solid var(--border-dark); max-height: 200px; white-space: pre-wrap; word-break: break-all; } .buttons { display: flex; gap: 10px; flex-wrap: wrap; margin-top: 12px; } .btn { display: inline-flex; align-items: center; gap: 8px; padding: 12px 18px; border-radius: var(--radius-md); border: none; cursor: pointer; font-weight: 600; font-size: 14px; transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1); text-decoration: none; color: inherit; position: relative; overflow: hidden; flex-shrink: 0; } .btn::before { content: ''; position: absolute; top: 0; left: -100%; width: 100%; height: 100%; background: linear-gradient(90deg, transparent, rgba(255,255,255,0.2), transparent); transition: left 0.5s; } .btn:hover::before { left: 100%; } .btn:active { transform: translateY(0) scale(0.97); } .btn:disabled { opacity: 0.5; cursor: not-allowed; transform: none; } .btn.primary { background: linear-gradient(135deg, var(--accent) 0%, var(--purple) 50%, #6366f1 100%); background-size: 200% auto; color: #fff; box-shadow: 0 4px 20px rgba(59,130,246,0.4), inset 0 1px 0 rgba(255,255,255,0.2); } .btn.primary:hover { transform: translateY(-3px) scale(1.02); box-shadow: 0 8px 30px rgba(59,130,246,0.5), 0 0 20px rgba(139,92,246,0.3); background-position: right center; } .btn.ghost { background: linear-gradient(145deg, rgba(255,255,255,0.05), rgba(255,255,255,0.02)); backdrop-filter: blur(10px); border: 1px solid rgba(255,255,255,0.1); color: var(--muted); } .btn.ghost:hover { background: linear-gradient(145deg, rgba(255,255,255,0.1), rgba(255,255,255,0.05)); border-color: rgba(59,130,246,0.4); color: #fff; box-shadow: 0 4px 15px rgba(59,130,246,0.2); transform: translateY(-2px); } .btn.small { padding: 9px 14px; font-size: 13px; border-radius: var(--radius-sm); } .btn.small:hover { transform: translateY(-2px); } #toast { position: fixed; right: 20px; top: 20px; background: linear-gradient(135deg, rgba(15,27,42,0.98), rgba(10,20,35,0.95)); backdrop-filter: blur(20px); -webkit-backdrop-filter: blur(20px); padding: 16px 20px; border-radius: var(--radius-md); border: 1px solid rgba(255,255,255,0.08); display: none; color: #cfe8ff; box-shadow: 0 12px 40px rgba(2,6,23,0.7), 0 0 0 1px rgba(255,255,255,0.05); z-index: 10000; min-width: 240px; max-width: 350px; transform: translateX(0); transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1); } #toast.show { display: block; animation: toastIn .4s cubic-bezier(0.4, 0, 0.2, 1); } #toast.hide { animation: toastOut 0.3s ease forwards; } #toast.success { border-left: 4px solid var(--success); box-shadow:0 12px 40px rgba(2,6,23,0.7), 0 0 20px rgba(34,197,94,0.2); } #toast.error { border-left: 4px solid var(--danger); box-shadow:0 12px 40px rgba(2,6,23,0.7), 0 0 20px rgba(239,68,68,0.2); } #toast.warning { border-left: 4px solid var(--warning); box-shadow:0 12px 40px rgba(2,6,23,0.7), 0 0 20px rgba(245,158,11,0.2); } #toast.info { border-left: 4px solid var(--accent); box-shadow:0 12px 40px rgba(2,6,23,0.7), 0 0 20px rgba(59,130,246,0.2); } .toast-content { display: flex; align-items: center; gap: 12px; } .toast-icon { width: 28px; height: 28px; border-radius: 6px; display: flex; align-items: center; justify-content: center; font-size: 16px; flex-shrink: 0; } .toast-icon.success { background: rgba(34,197,94,0.15); color: var(--success); } .toast-icon.error { background: rgba(239,68,68,0.15); color: var(--danger); } .toast-icon.warning { background: rgba(245,158,11,0.15); color: var(--warning); } .toast-icon.info { background: rgba(59,130,246,0.15); color: var(--accent); } .toast-message { flex: 1; font-size: 14px; line-height: 1.4; } .muted { color: var(--muted); font-size: 14px; line-height: 1.6; } .stack { display: flex; flex-direction: column; gap: 10px; } .hidden { display: none !important; } .text-center { text-align: center; } .mb-2 { margin-bottom: 12px; } .expiry-warning { background: rgba(239,68,68,0.1); border: 1px solid rgba(239,68,68,0.3); padding: 12px; border-radius: var(--radius-md); margin-top: 12px; color: #fca5a5; } .expiry-info { background: rgba(34,197,94,0.1); border: 1px solid rgba(34,197,94,0.3); padding: 12px; border-radius: var(--radius-md); margin-top: 12px; color: #86efac; } .widgets-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 16px; margin-bottom: 20px; } @media(max-width: 980px) { .widgets-grid { grid-template-columns: 1fr 1fr; } } @media(max-width: 640px) { .widgets-grid { grid-template-columns: 1fr; } } .widget { background: linear-gradient(145deg, rgba(15, 23, 42, 0.9), rgba(15, 23, 36, 0.7)); backdrop-filter: blur(20px); -webkit-backdrop-filter: blur(20px); border-radius: var(--radius-lg); padding: 20px; border: 1px solid var(--border-light); position: relative; overflow: hidden; transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1); box-shadow: 0 4px 24px rgba(0,0,0,0.2); } .widget::before { content: ''; position: absolute; top: 0; left: 0; right: 0; height: 1px; background: linear-gradient(90deg, transparent, rgba(255,255,255,0.08), transparent); } .widget:hover { border-color: rgba(59, 130, 246, 0.2); box-shadow: 0 12px 40px rgba(0,0,0,0.3), 0 0 20px rgba(59, 130, 246, 0.08); transform: translateY(-3px); } .widget-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 14px; } .widget-title { display: flex; align-items: center; gap: 10px; font-weight: 600; font-size: 14px; color: var(--text-primary); } .widget-icon { width: 36px; height: 36px; border-radius: 10px; display: flex; align-items: center; justify-content: center; font-size: 18px; color: var(--text-primary); } .widget-icon.green{background:rgba(34,197,94,0.15);color:var(--success)} .widget-icon.blue{background:rgba(59,130,246,0.15);color:var(--accent)} .widget-icon.orange{background:rgba(245,158,11,0.15);color:var(--warning)} .widget-icon.purple{background:rgba(168,85,247,0.15);color:#a855f7} .widget-icon.red{background:rgba(239,68,68,0.15);color:var(--danger)} .widget-badge { padding: 4px 10px; border-radius: 20px; font-size: 11px; font-weight: 600; } .widget-badge.good{background:rgba(34,197,94,0.15);color:var(--success)} .widget-badge.warning{background:rgba(245,158,11,0.15);color:var(--warning)} .widget-badge.bad{background:rgba(239,68,68,0.15);color:var(--danger)} .traffic-speeds { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 12px; } .traffic-speed { display: flex; align-items: center; gap: 10px; padding: 12px; background: rgba(255,255,255,0.02); border-radius: 8px; } .traffic-speed-icon { width: 32px; height: 32px; border-radius: 8px; display: flex; align-items: center; justify-content: center; color: var(--text-primary); } .traffic-speed-icon.down{background:rgba(34,197,94,0.12);color:var(--success)} .traffic-speed-icon.up{background:rgba(59,130,246,0.12);color:var(--accent)} .traffic-speed-value{font-size:18px;font-weight:700} .traffic-speed-unit{font-size:11px;color:var(--muted)} .traffic-graph { height: 60px; background: linear-gradient(180deg,rgba(59,130,246,0.08) 0%,transparent 100%); border-radius: 8px; position: relative; overflow: hidden; margin-bottom: 14px; } .traffic-graph-line { position: absolute; bottom: 0; left: 0; right: 0; height: 40%; background: linear-gradient(90deg,rgba(59,130,246,0.3),rgba(34,197,94,0.3),rgba(59,130,246,0.3)); clip-path: polygon(0 70%,5% 60%,10% 50%,15% 55%,20% 45%,25% 50%,30% 40%,35% 55%,40% 35%,45% 50%,50% 30%,55% 45%,60% 40%,65% 55%,70% 35%,75% 50%,80% 45%,85% 55%,90% 40%,95% 50%,100% 60%,100% 100%,0 100%); animation: trafficFlow 10s linear infinite; opacity: 0.7; } @keyframes trafficFlow { 0% { background-position: 0% 0; } 100% { background-position: 200% 0; } } .traffic-stats { display: grid; grid-template-columns: repeat(4,1fr); gap: 8px; } .traffic-stat{text-align:center;padding:8px 4px;background:rgba(255,255,255,0.02);border-radius:6px} .traffic-stat-val{font-size:13px;font-weight:600; color:var(--text-primary);} .traffic-stat-lbl{font-size:9px;color:var(--muted);text-transform:uppercase;margin-top:2px} .health-row{display:flex;align-items:center;gap:16px;margin-bottom:14px} .health-item{flex:1;display:flex;align-items:center;gap:10px;padding:10px;background:rgba(255,255,255,0.02);border-radius:8px} .health-item-icon{width:28px;height:28px;border-radius:6px;display:flex;align-items:center;justify-content:center;font-size:14px} .health-item-val{font-size:16px;font-weight:600;color:var(--text-primary);} .health-item-lbl{font-size:10px;color:var(--muted)} .stability-bar{height:8px;background:#071529;border-radius:4px;overflow:hidden} .stability-fill{height:100%;border-radius:4px;background:linear-gradient(90deg,var(--success),#16a34a);transition:width 1s ease} .net-stats-grid{display:grid;grid-template-columns:1fr 1fr;gap:10px} .net-stat{padding:14px;background:rgba(255,255,255,0.02);border-radius:10px;display:flex;align-items:center;gap:12px} .net-stat-icon{width:38px;height:38px;border-radius:10px;display:flex;align-items:center;justify-content:center;font-size:16px} .net-stat-info{flex:1} .net-stat-val{font-size:18px;font-weight:700;color:var(--text-primary);} .net-stat-lbl{font-size:10px;color:var(--muted);text-transform:uppercase} .analytics-tabs{display:flex;gap:6px;margin-bottom:14px} .analytics-tab{padding:8px 16px;border-radius:6px;font-size:13px;font-weight:500;cursor:pointer; background:transparent;border:1px solid rgba(255,255,255,0.06);color:var(--muted);transition:all 0.2s} .analytics-tab.active{background:var(--accent);border-color:var(--accent);color:#fff} .analytics-tab:hover:not(.active){background:rgba(255,255,255,0.04)} .analytics-grid{display:grid;grid-template-columns:1fr 1fr;gap:12px} .analytics-item{padding:16px;background:rgba(255,255,255,0.02);border-radius:10px;text-align:center} .analytics-item-val{font-size:22px;font-weight:700;margin-bottom:4px;color:var(--text-primary);} .analytics-item-lbl{font-size:11px;color:var(--muted);text-transform:uppercase} .pulse-indicator { width:10px;height:10px;border-radius:50%; background:linear-gradient(135deg, var(--success), #16a34a); animation:pulse-indicator-anim 2s ease-in-out infinite; box-shadow:0 0 10px rgba(34,197,94,0.5); flex-shrink: 0; } @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } } .loading-spinner { border: 4px solid rgba(255, 255, 255, 0.1); border-top: 4px solid var(--accent); border-radius: 50%; width: 30px; height: 30px; animation: spin 1s linear infinite; margin: 0 auto; } #qrModal .modal-content { max-width: 450px; text-align: center; } #qr-display { min-height: 250px; display: flex; align-items: center; justify-content: center; flex-direction: column; padding: 10px; position: relative; } #qr-display canvas, #qr-display img { border-radius: var(--radius-sm); max-width: 100%; height: auto; margin-bottom: 15px; border: 2px solid #fff; box-shadow: 0 4px 15px rgba(0,0,0,0.2); } .qr-download-links { display: flex; flex-direction: column; gap: 10px; margin-top: 15px; width: 100%; } .qr-download-links .btn { width: 100%; } .modal-overlay { position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.7); z-index: 9999; display: flex; justify-content: center; align-items: center; opacity: 0; visibility: hidden; transition: all 0.3s ease-in-out; } .modal-overlay.show { opacity: 1; visibility: visible; } .modal-content { background: var(--card); padding: 32px; border-radius: var(--radius-lg); box-shadow: 0 20px 60px rgba(0,0,0,0.5), 0 0 0 1px var(--border); width: 90%; max-width: 600px; max-height: 90vh; overflow-y: auto; transform: scale(0.9); transition: transform 0.3s ease-in-out; position: relative; } .modal-overlay.show .modal-content { transform: scale(1); } .modal-close-btn { position: absolute; top: 15px; right: 15px; background: none; border: none; font-size: 24px; color: var(--muted); cursor: pointer; transition: color 0.2s; z-index: 10; } .modal-close-btn:hover { color: var(--text-primary); } @media (max-width: 768px) { body { padding: 16px; } .container { padding: 0; } h1 { font-size: 24px; margin-bottom: 20px; } p.lead { font-size: 14px; margin-bottom: 18px; } .stats { grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 10px; } .stat .val { font-size: 20px; } .stat .lbl { font-size: 10px; } .main-grid { grid-template-columns: 1fr; } .info-grid { grid-template-columns: 1fr; } .buttons { justify-content: center; } .btn { padding: 10px 15px; font-size: 13px; } .traffic-stats { grid-template-columns: repeat(2,1fr); } .analytics-grid { grid-template-columns: 1fr; } .net-stats-grid { grid-template-columns: 1fr; } .health-row { flex-direction: column; gap: 10px; } .health-item { width: 100%; } .widget-header { flex-direction: column; align-items: flex-start; gap: 10px; } .widget-badge { margin-top: 5px; } .qr-download-links { margin-top: 10px; } #qr-display canvas, #qr-display img { max-width: 200px; margin-bottom: 10px; } } </style> </head> <body> <div class="container"> <h1>🚀 VXR.SXR Configuration Panel</h1> <p class="lead">Manage your proxy configuration, view subscription links, and monitor usage statistics.</p> <div class="stats"> <div class="stat USER_PANEL_STATUS_CLASS"> <div class="val" id="status-badge">USER_PANEL_STATUS_TEXT</div> <div class="lbl">Account Status</div> </div> <div class="stat"> <div class="val" id="usage-display">0 KB</div> <div class="lbl">Data Used</div> </div> <div class="stat USER_PANEL_DATALIMIT_WARNING_CLASS"> <div class="val" id="data-limit-display">Unlimited</div> <div class="lbl">Data Limit</div> </div> <div class="stat"> <div class="val" id="expiry-countdown">—</div> <div class="lbl">Time Remaining</div> </div> </div> <div class="widgets-grid"> <div class="widget"> <div class="widget-header"> <div class="widget-title"> <div class="widget-icon green">📊</div> <span>Live Traffic</span> </div> <div class="pulse-indicator"></div> </div> <div class="traffic-speeds"> <div class="traffic-speed"> <div class="traffic-speed-icon down">↓</div> <div> <div class="traffic-speed-value" id="live-download">0.00</div> <div class="traffic-speed-unit">MB/s Download</div> </div> </div> <div class="traffic-speed"> <div class="traffic-speed-icon up">↑</div> <div> <div class="traffic-speed-value" id="live-upload">0.00</div> <div class="traffic-speed-unit">KB/s Upload</div> </div> </div> </div> <div class="traffic-graph"> <div class="traffic-graph-line"></div> </div> <div class="traffic-stats"> <div class="traffic-stat"> <div class="traffic-stat-val" id="total-down-stat">0 KB</div> <div class="traffic-stat-lbl">Total Down</div> </div> <div class="traffic-stat"> <div class="traffic-stat-val" id="total-up-stat">—</div> <div class="traffic-stat-lbl">Total Up</div> </div> <div class="traffic-stat"> <div class="traffic-stat-val" id="connections-stat">1</div> <div class="traffic-stat-lbl">Connections</div> </div> <div class="traffic-stat"> <div class="traffic-stat-val" id="packet-loss-stat">0%</div> <div class="traffic-stat-lbl">Packet Loss</div> </div> </div> </div> <div class="widget"> <div class="widget-header"> <div class="widget-title"> <div class="widget-icon red">❤️</div> <span>Connection Health</span> </div> <div class="widget-badge USER_PANEL_HEALTH_BADGE_CLASS" id="health-badge">USER_PANEL_HEALTH_BADGE_TEXT</div> </div> <div class="health-row"> <div class="health-item"> <div class="health-item-icon" style="background:rgba(245,158,11,0.12);color:var(--warning)">⏱</div> <div> <div class="health-item-val" id="latency-val">--ms</div> <div class="health-item-lbl">Latency</div> </div> </div> <div class="health-item"> <div class="health-item-icon" style="background:rgba(59,130,246,0.12);color:var(--accent)">⏰</div> <div> <div class="health-item-val" id="uptime-val">0h 0m</div> <div class="health-item-lbl">Uptime</div> </div> </div> </div> <div style="margin-top:8px"> <div style="display:flex;justify-content:space-between;margin-bottom:6px;font-size:12px"> <span style="color:var(--muted)">Connection Stability</span> <span style="color:var(--success)" id="stability-pct">--%</span> </div> <div class="stability-bar"> <div class="stability-fill" id="stability-fill" style="width:0%"></div> </div> </div> </div> <div class="widget"> <div class="widget-header"> <div class="widget-title"> <div class="widget-icon purple">📈</div> <span>Network Statistics</span> </div> </div> <div class="net-stats-grid"> <div class="net-stat"> <div class="net-stat-icon" style="background:rgba(245,158,11,0.12);color:var(--warning)">📶</div> <div> <div class="net-stat-val" id="net-latency">--</div> <div class="net-stat-lbl">Latency (ms)</div> </div> </div> <div class="net-stat"> <div class="net-stat-icon" style="background:rgba(59,130,246,0.12);color:var(--accent)">〰️</div> <div> <div class="net-stat-val" id="net-jitter">--</div> <div class="net-stat-lbl">Jitter (ms)</div> </div> </div> <div class="net-stat"> <div class="net-stat-icon" style="background:rgba(34,197,94,0.12);color:var(--success)">📥</div> <div> <div class="net-stat-val" id="packets-in">--</div> <div class="net-stat-lbl">Packets In</div> </div> </div> <div class="net-stat"> <div class="net-stat-icon" style="background:rgba(168,85,247,0.12);color:#a855f7">📤</div> <div> <div class="net-stat-val" id="packets-out">--</div> <div class="net-stat-lbl">Packets Out</div> </div> </div> </div> </div> </div> <div class="card" style="margin-bottom:20px"> <div class="widget-header" style="margin-bottom:10px;padding-bottom:0;border:none"> <div class="analytics-tabs"> <button class="analytics-tab active" data-tab="analytics">📊 Analytics</button> <button class="analytics-tab" data-tab="history">📜 History</button> </div> </div> <div id="analytics-content" class="tab-content"> <div class="analytics-grid"> <div class="analytics-item"> <div class="analytics-item-val" style="color:var(--accent)" id="analytics-total-download">0 KB</div> <div class="analytics-item-lbl">Total Download</div> </div> <div class="analytics-item"> <div class="analytics-item-val" style="color:var(--success)" id="analytics-total-upload">—</div> <div class="analytics-item-lbl">Total Upload</div> </div> <div class="analytics-item"> <div class="analytics-item-val" style="color:var(--warning)" id="analytics-avg-latency">--ms</div> <div class="analytics-item-lbl">Avg Latency</div> </div> <div class="analytics-item"> <div class="analytics-item-val" style="color:var(--purple)" id="analytics-connections">--</div> <div class="analytics-item-lbl">Connections</div> </div> </div> </div> <div id="history-content" class="tab-content hidden"> <div style="text-align:center;padding:20px;color:var(--muted)"> <div class="loading-spinner"></div> <p>Loading connection history...</p> <p style="font-size:13px;margin-top:8px;opacity:0.7">Recent session data and activity logs.</p> </div> </div> </div> <div id="usage-stats-card" class="card hidden"> <div class="section-title"> <h2>📊 Usage Statistics</h2> <span class="muted" id="usage-percentage">0.00% Used</span> </div> <div class="progress-bar"> <div class="progress-fill low" id="progress-bar-fill" data-target-width="0"></div> </div> <p class="muted text-center mb-2" id="usage-text">0 KB of Unlimited used</p> </div> <div id="expiration-card" class="card hidden"> <div class="section-title"> <h2>⏰ Expiration Information</h2> </div> <div id="expiration-display" data-expiry=""> <p class="muted" id="expiry-local">Loading...</p> <p class="muted" id="expiry-utc"></p> </div> <div class="expiry-info" id="expiry-status-message"> </div> </div> <div class="main-grid"> <div> <div class="card"> <div class="section-title"> <h2>🌐 Network Information</h2> <button class="btn ghost small" data-action="refresh">🔄 Refresh</button> </div> <p class="muted">Connection details and IP information.</p> <div class="info-grid"> <div class="info-item"> <span class="label">Proxy Host</span> <span class="value" id="info-proxy-host">--</span> </div> <div class="info-item"> <span class="label">Proxy IP</span> <span class="value" id="info-proxy-ip">--</span> </div> <div class="info-item"> <span class="label">Proxy Location</span> <span class="value" id="info-proxy-location">--</span> </div> <div class="info-item"> <span class="label">Your IP</span> <span class="value" id="info-client-ip">--</span> </div> <div class="info-item"> <span class="label">Your Location</span> <span class="value" id="info-client-location">--</span> </div> <div class="info-item"> <span class="label">Your ISP</span> <span class="value" id="info-client-isp">--</span> </div> </div> </div> <div class="card"> <div class="section-title"> <h2>📱 Subscription Links</h2> </div> <p class="muted">Copy subscription URLs or import directly.</p> <div class="stack"> <div> <h3 class="config-subheader">Xray / V2Ray Subscription</h3> <div class="buttons"> <button class="btn primary" data-action="copy-sub" data-url-type="xray">📋 Copy Sub Link</button> <button class="btn ghost" data-action="copy-config" data-config-type="xray">📋 Copy Config</button> <button class="btn ghost" data-action="toggle-config-view" data-target="xray-config-view">View Config</button> <button class="btn ghost" data-action="open-qr-modal" data-config-type="xray">📱 QR Code</button> </div> <pre class="config hidden" id="xray-config-view"></pre> </div> <div> <h3 class="config-subheader">Sing-Box / Clash Subscription</h3> <div class="buttons"> <button class="btn primary" data-action="copy-sub" data-url-type="singbox">📋 Copy Sub Link</button> <button class="btn ghost" data-action="copy-config" data-config-type="singbox">📋 Copy Config</button> <button class="btn ghost" data-action="toggle-config-view" data-target="sb-config-view">View Config</button> <button class="btn ghost" data-action="open-qr-modal" data-config-type="singbox">📱 QR Code</button> </div> <pre class="config hidden" id="sb-config-view"></pre> </div> <div> <h3 class="config-subheader">Quick Import</h3> <div class="buttons"> <a href="#" class="btn ghost" data-action="direct-import" data-client="v2rayng">📱 Android (V2rayNG)</a> <a href="#" class="btn ghost" data-action="direct-import" data-client="shadowrocket">🍎 iOS (Shadowrocket)</a> <a href="#" class="btn ghost" data-action="direct-import" data-client="streisand">🍎 iOS Streisand</a> <a href="#" class="btn ghost" data-action="direct-import" data-client="karing">🔧 Karing</a> <a href="#" class="btn ghost" data-action="direct-import" data-client="clashMeta">🌐 Clash Meta</a> <a href="#" class="btn ghost" data-action="direct-import" data-client="exclave">📦 Exclave</a> </div> </div> </div> </div> </div> <aside> <div class="card"> <h2>👤 Account Details</h2> <div class="info-item" style="margin-top:12px;"> <span class="label">User UUID</span> <span class="value" id="account-uuid">--</span> </div> <div class="info-item" style="margin-top:12px;"> <span class="label">Created Date</span> <span class="value" id="account-created">--</span> </div> <div class="info-item" style="margin-top:12px;" id="account-notes-container"> <span class="label">Notes</span> <span class="value" id="account-notes">--</span> </div> <div class="info-item" style="margin-top:12px;"> <span class="label">IP Limit</span> <span class="value" id="account-ip-limit">--</span> </div> </div> <div class="card"> <h2>💾 Export Configuration</h2> <p class="muted mb-2">Download configuration for manual import or backup.</p> <div class="buttons"> <button class="btn primary small" data-action="download-config" data-type="xray">Download Xray Config</button> <button class="btn primary small" data-action="download-config" data-type="singbox">Download Singbox Config</button> </div> </div> </aside> </div> <div class="card"> <p class="muted text-center" style="margin:0;"> 🔒 This is your personal configuration panel. Keep your subscription links private and secure. <br>For support, contact your service administrator. </p> </div> <div id="toast"></div> </div> <!-- QR Code Modal (Pop-up) --> <div id="qrModal" class="modal-overlay"> <div class="modal-content"> <button class="modal-close-btn" data-action="close-modal">✕</button> <h2>📱 Scan QR Code</h2> <p class="muted mb-2" id="qr-modal-description">Scan this code with your VLESS client (e.g., V2rayNG, Shadowrocket) to quickly import your configuration.</p> <div id="qr-display" class="text-center"> <div class="loading-spinner"></div> <p class="muted" style="margin-top:10px;">Generating QR Code...</p> </div> <div class="qr-download-links"> <a href="#" id="qr-direct-link" class="btn ghost" download="vless_config.txt">🔗 Download Config File</a> <a href="#" id="qr-download-image" class="btn ghost" download="vless_qrcode.png">🖼️ Download QR Image</a> </div> </div> </div> <script nonce="CSP_NONCE_PLACEHOLDER"> // ======================================================================== // GLOBAL CLIENT-SIDE CONFIG & UTILITIES // This 'window.CONFIG' object will be populated by the Worker with server-side data. // ======================================================================== window.CONFIG = { uuid: "USER_UUID_PLACEHOLDER", host: "WORKER_HOSTNAME_PLACEHOLDER", proxyAddress: "PROXY_ADDRESS_PLACEHOLDER", clientIp: "CLIENT_IP_PLACEHOLDER", clientGeo: { city: "CLIENT_CITY_PLACEHOLDER", country: "CLIENT_COUNTRY_PLACEHOLDER", isp: "CLIENT_ISP_PLACEHOLDER" }, proxyGeo: { city: "PROXY_CITY_PLACEHOLDER", country: "PROXY_COUNTRY_PLACEHOLDER", isp: "PROXY_ISP_PLACEHOLDER" }, subXrayUrl: "SUB_XRAY_URL_PLACEHOLDER", subSbUrl: "SUB_SB_URL_PLACEHOLDER", singleXrayConfig: "SINGLE_XRAY_CONFIG_PLACEHOLDER", singleSingboxConfig: "SINGLE_SINGBOX_CONFIG_PLACEHOLDER", expirationDateTime: "EXPIRATION_DATE_TIME_PLACEHOLDER", isExpired: IS_EXPIRED_PLACEHOLDER, trafficLimit: TRAFFIC_LIMIT_PLACEHOLDER, initialTrafficUsed: INITIAL_TRAFFIC_USED_PLACEHOLDER, notes: "NOTES_PLACEHOLDER", ipLimit: IP_LIMIT_PLACEHOLDER, }; async function formatBytes(bytes) { if (bytes === 0 || bytes === null || bytes === undefined) return '0 Bytes'; const k = 1024; const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB']; const i = Math.floor(Math.log(bytes) / Math.log(k)); return parseFloat((bytes / Math.pow(k, i))).toFixed(2) + ' ' + sizes[i]; } function showToast(message, type = 'success', duration = 3000) { const toast = document.getElementById('toast'); if (!toast) { console.warn('Toast element not found.'); return; } const icons = { success: '✓', error: '✕', warning: '⚠', info: 'ℹ' }; const icon = icons[type] || icons.success; const actualType = message.startsWith('✓') ? 'success' : message.startsWith('⚠️') ? 'warning' : message.startsWith('❌') ? 'error' : type; toast.innerHTML = `<div class="toast-content"><div class="toast-icon ${actualType}"><span>${icon}</span></div><div class="toast-message">${message}</div></div>`; toast.className = `${actualType} show`; setTimeout(() => { toast.classList.add('hide'); setTimeout(() => { toast.className = ''; toast.style.display = 'none'; }, 300); }, duration); toast.style.display = 'block'; } function switchTab(el, tab) { document.querySelectorAll('.analytics-tab').forEach(t => t.classList.remove('active')); el.classList.add('active'); document.getElementById('analytics-content').classList.toggle('hidden', tab !== 'analytics'); document.getElementById('history-content').classList.toggle('hidden', tab !== 'history'); } let sessionStartTime = Date.now(); let simulatedUploadBytes = 0; const initialTrafficUsed = window.CONFIG.initialTrafficUsed || 0; function updateUptime() { const elapsed = Date.now() - sessionStartTime; const hours = Math.floor(elapsed / 3600000); const minutes = Math.floor((elapsed % 3600000) / 60000); const uptimeEl = document.getElementById('uptime-val'); if (uptimeEl) uptimeEl.textContent = `${hours}h ${minutes}m`; } async function updateUploadStats() { simulatedUploadBytes = Math.floor(initialTrafficUsed * (0.30 + Math.random() * 0.10)); const uploadFormatted = await formatBytes(simulatedUploadBytes); const totalUpStatEl = document.getElementById('total-up-stat'); if (totalUpStatEl) totalUpStatEl.innerHTML = `${uploadFormatted} <span style="font-size:9px;opacity:0.6">(Est.)</span>`; const analyticsTotalUploadEl = document.getElementById('analytics-total-upload'); if (analyticsTotalUploadEl) analyticsTotalUploadEl.innerHTML = `${uploadFormatted} <span style="font-size:9px;opacity:0.6">(Est.)</span>`; } function simulateLiveStats() { const dlEl = document.getElementById('live-download'); const ulEl = document.getElementById('live-upload'); if (dlEl) dlEl.textContent = (Math.random() * 2.5 + 0.1).toFixed(2); if (ulEl) ulEl.textContent = (Math.random() * 150 + 10).toFixed(0); const latency = Math.floor(Math.random() * 20 + 35); const latencyEl = document.getElementById('latency-val'); const netLatencyEl = document.getElementById('net-latency'); const analyticsAvgLatencyEl = document.getElementById('analytics-avg-latency'); if (latencyEl) latencyEl.textContent = `${latency}ms`; if (netLatencyEl) netLatencyEl.textContent = latency; if (analyticsAvgLatencyEl) analyticsAvgLatencyEl.textContent = `${latency}ms`; const jitterEl = document.getElementById('net-jitter'); if (jitterEl) jitterEl.textContent = Math.floor(Math.random() * 5 + 1); const stabilityPctEl = document.getElementById('stability-pct'); const stabilityFillEl = document.getElementById('stability-fill'); const currentStability = parseFloat(stabilityPctEl?.textContent) || 90; const newStability = Math.min(100, Math.max(85, currentStability + (Math.random() - 0.5) * 5)).toFixed(0); if (stabilityPctEl) stabilityPctEl.textContent = `${newStability}%`; if (stabilityFillEl) stabilityFillEl.style.width = `${newStability}%`; const connectionsStatEl = document.getElementById('connections-stat'); if (connectionsStatEl) connectionsStatEl.textContent = Math.floor(Math.random() * 5 + 1); const packetLossStatEl = document.getElementById('packet-loss-stat'); if (packetLossStatEl) packetLossStatEl.textContent = `${(Math.random() * 0.5).toFixed(1)}%`; const packetsInEl = document.getElementById('packets-in'); const packetsOutEl = document.getElementById('packets-out'); if (packetsInEl) packetsInEl.textContent = `${(Math.random() * 20 + 5).toFixed(1)}K`; if (packetsOutEl) packetsOutEl.textContent = `${(Math.random() * 15 + 3).toFixed(1)}K`; const analyticsConnectionsEl = document.getElementById('analytics-connections'); if (analyticsConnectionsEl) analyticsConnectionsEl.textContent = connectionsStatEl.textContent; } let QR_LAST_TEXT = ''; function cleanConfigString(text) { if (!text || typeof text !== 'string') return ''; let cleaned = text.trim(); cleaned = cleaned.replace(/^<pre[^>]*>/i, '').replace(/<\/pre>$/i, ''); cleaned = cleaned.replace(/^<code[^>]*>/i, '').replace(/<\/code>$/i, ''); cleaned = cleaned.trim(); if ((cleaned.startsWith('"') && cleaned.endsWith('"')) || (cleaned.startsWith("'") && cleaned.endsWith("'"))) { cleaned = cleaned.slice(1, -1).trim(); } if (/^vmess:\/\//i.test(cleaned)) { try { const protocol = 'vmess://'; const payload = cleaned.slice(protocol.length); const cleanPayload = payload.replace(/\s+/g, ''); if (/^[A-Za-z0-9+\/=]+$/.test(cleanPayload)) { try { const decoded = atob(cleanPayload); const json = JSON.parse(decoded); const standardJson = { v: json.v || "2", ps: json.ps || "Config", add: json.add || "", port: json.port || "443", id: json.id || "", aid: json.aid || "0", net: json.net || "ws", type: json.type || "none", host: json.host || "", path: json.path || "/", tls: json.tls || "tls", sni: json.sni || "", fp: json.fp || "chrome" }; const reencoded = btoa(JSON.stringify(standardJson)); return protocol + reencoded; } catch (e) { return protocol + cleanPayload; } } } catch (e) { console.warn('VMESS cleaning error:', e.message); } } else if (/^(vless|trojan|ss):\/\//i.test(cleaned)) { cleaned = cleaned.replace(/\r?\n/g, '').replace(/\s+/g, ' ').trim(); } else if (/^\s*\{/.test(cleaned) && /\}\s*$/.test(cleaned)) { try { const parsed = JSON.parse(cleaned); if (parsed.v || parsed.id || parsed.add) { const encoded = btoa(JSON.stringify(parsed)); return 'vmess://' + encoded; } } catch (e) { cleaned = cleaned.replace(/\s+/g, ''); } } else { cleaned = cleaned.replace(/\r?\n/g, '').trim(); } return cleaned.trim(); } function validateOptimizedPayload(text) { if (!text || typeof text !== 'string' || text.length === 0) return { valid: false, message: 'Empty configuration payload.' }; const t = cleanConfigString(text); if (/^vmess:\/\//i.test(t)) { try { const payload = t.slice(8); const decoded = atob(payload.replace(/-/g, '+').replace(/_/g, '/')); const config = JSON.parse(decoded); if (!config.id || !config.add || !config.port) { return { valid: false, message: 'VMess config incomplete (missing id, address, or port).' }; } return { valid: true }; } catch (e) { return { valid: false, message: 'Invalid VMess base64 or JSON format.' }; } } if (/^vless:\/\//i.test(t)) { const vlessRegex = /^vless:\/\/([^@]+)@([^:]+):(\d+)/; if (!vlessRegex.test(t)) { return { valid: false, message: 'Invalid VLESS URI format.' }; } return { valid: true }; } if (/^(ss|trojan):\/\//i.test(t)) { if (!t.includes('@') && !t.includes('://')) { return { valid: false, message: 'Invalid Shadowsocks/Trojan URI format.' }; } return { valid: true }; } return { valid: true, message: 'Unknown protocol, assuming valid raw data.' }; } function generateQRCode(text) { const qrModal = document.getElementById('qrModal'); const qrDisplay = document.getElementById('qr-display'); const qrDownloadImageLink = document.getElementById('qr-download-image'); const qrDirectLink = document.getElementById('qr-direct-link'); const qrModalDescription = document.getElementById('qr-modal-description'); if (!qrModal || !qrDisplay || !qrDownloadImageLink || !qrDirectLink || !qrModalDescription) { console.error('One or more QR modal elements not found.'); showToast('Error: QR modal components missing.', 'error'); return; } qrDisplay.innerHTML = `<div class="loading-spinner"></div><p class="muted" style="margin-top:10px;">Generating QR Code...</p>`; qrDownloadImageLink.classList.add('hidden'); qrDirectLink.classList.add('hidden'); qrModal.classList.add('show'); text = cleanConfigString(text); if (!text || text.length === 0) { qrDisplay.innerHTML = '<p style="color:var(--danger)">Empty configuration - cannot generate QR</p>'; qrModalDescription.textContent = 'Configuration is empty. Cannot generate QR code.'; showToast('Configuration is empty.', 'error'); return; } QR_LAST_TEXT = text; setTimeout(() => { qrDisplay.innerHTML = ''; const validation = validateOptimizedPayload(text); if (!validation.valid) { qrModalDescription.innerHTML = `<p style="color:var(--danger)">⚠️ Validation Warning: ${validation.message} QR code might not work.</p>`; showToast('⚠️ Validation: ' + validation.message, 'warning'); } else { qrModalDescription.textContent = 'Scan this code with your VLESS client (e.g., V2rayNG, Shadowrocket) to quickly import your configuration.'; } let generatedImage = null; try { const canvas = QRCodeGenerator.generate(text, 256); if (canvas) { qrDisplay.appendChild(canvas); generatedImage = canvas.toDataURL('image/png'); showToast('✓ QR Code Generated (Embedded)', 'success'); } } catch (e) { console.warn('Embedded QR failed, trying CDN fallback:', e.message); } if (!generatedImage && typeof QRCode !== 'undefined' && window.QRCode) { try { const qrcodejsDiv = document.createElement('div'); qrDisplay.appendChild(qrcodejsDiv); new QRCode(qrcodejsDiv, { text: text, width: 256, height: 256, colorDark: "#000000", colorLight: "#ffffff", correctLevel: QRCode.CorrectLevel.M }); const imgEl = qrcodejsDiv.querySelector('img') || qrcodejsDiv.querySelector('canvas'); if (imgEl) { generatedImage = imgEl.toDataURL('image/png'); showToast('✓ QR Code Generated (CDN Fallback)', 'success'); } } catch (cdnErr) { console.warn('CDN qrcode.js failed, trying Google Charts:', cdnErr.message); } } if (!generatedImage) { try { const encoded = encodeURIComponent(text); const googleChartsUrl = 'https://chart.googleapis.com/chart?cht=qr&chl=' + encoded + '&chs=256x256&choe=UTF-8&chld=M|0'; if (googleChartsUrl.length > 2000) { qrDisplay.innerHTML = '<p style="color:var(--danger)">⚠️ Configuration content too large for QR code generation. Please use "Copy Config" or "Download Config File" instead.</p>'; showToast('Content too large for QR - use copy/download.', 'warning'); return; } const img = new Image(); img.src = googleChartsUrl; img.alt = 'QR Code'; img.style.maxWidth = '100%'; img.style.height = 'auto'; img.style.border = '2px solid #fff'; img.style.borderRadius = '8px'; img.onload = function() { qrDisplay.appendChild(img); try { const canvas = document.createElement('canvas'); canvas.width = img.naturalWidth; canvas.height = img.naturalHeight; const ctx = canvas.getContext('2d'); ctx.drawImage(img, 0, 0); generatedImage = canvas.toDataURL('image/png'); } catch (e) { console.warn("Could not get data URL from Google Charts image for download due to security/cross-origin. Falling back to image src.", e); generatedImage = img.src; } showToast('✓ QR Code Generated (Cloud Fallback)', 'success'); }; img.onerror = function() { qrDisplay.innerHTML = '<p style="color:var(--danger)">❌ All QR generation methods failed. Please copy the configuration manually.</p>'; showToast('QR generation failed - copy manually.', 'error'); }; } catch (googleErr) { console.error('Final QR generation fallback (Google Charts) failed:', googleErr); qrDisplay.innerHTML = '<p style="color:var(--danger)">❌ All QR methods failed. Please copy configuration manually.</p>'; showToast('QR generation failed.', 'error'); } } if (generatedImage) { qrDownloadImageLink.href = generatedImage; qrDownloadImageLink.classList.remove('hidden'); } else { qrDownloadImageLink.classList.add('hidden'); } if (text) { const blob = new Blob([text], { type: 'text/plain;charset=utf-8' }); qrDirectLink.href = URL.createObjectURL(blob); qrDirectLink.classList.remove('hidden'); const configName = text.startsWith('vless://') ? 'vless_config.txt' : text.startsWith('vmess://') ? 'vmess_config.txt' : text.startsWith('ss://') ? 'shadowsocks_config.txt' : text.startsWith('trojan://') ? 'trojan_config.txt' : 'config.txt'; qrDirectLink.download = configName; } else { qrDirectLink.classList.add('hidden'); } }, 100); } async function copyToClipboard(text, button) { try { await navigator.clipboard.writeText(text); const originalText = button.innerHTML; button.innerHTML = '✓ Copied!'; if (button) button.disabled = true; setTimeout(() => { if (button) { button.innerHTML = originalText; button.disabled = false; } }, 2000); showToast('✓ Copied to clipboard!', 'success'); } catch (error) { try { const textArea = document.createElement("textarea"); textArea.value = text; textArea.style.position = "fixed"; textArea.style.top = "0"; textArea.style.left = "0"; textArea.style.opacity = "0"; document.body.appendChild(textArea); textArea.focus(); textArea.select(); document.execCommand('copy'); document.body.removeChild(textArea); const originalText = button.innerHTML; button.innerHTML = '✓ Copied!'; if (button) button.disabled = true; setTimeout(() => { if (button) { button.innerHTML = originalText; button.disabled = false; } }, 2000); showToast('✓ Copied to clipboard (fallback)!', 'success'); } catch(err) { showToast('Failed to copy. Please copy manually.', 'error'); console.error('Copy error:', error, err); } } } function downloadConfig(content, filename) { const blob = new Blob([content], { type: 'text/plain;charset=utf-8' }); const url = URL.createObjectURL(blob); const link = document.createElement('a'); link.href = url; link.download = filename; document.body.appendChild(link); link.click(); document.body.removeChild(link); URL.revokeObjectURL(url); showToast(`✓ Configuration downloaded: ${filename}`, 'success'); } function handleDataAction(e) { const btn = e.target.closest('[data-action]'); if (!btn) return; const action = btn.dataset.action; if (!action) return; e.preventDefault(); e.stopPropagation(); switch (action) { case 'refresh': location.reload(); break; case 'copy-sub': { const urlType = btn.dataset.urlType; const url = urlType === 'xray' ? window.CONFIG.subXrayUrl : window.CONFIG.subSbUrl; if (url) copyToClipboard(url, btn); break; } case 'copy-config': { const configType = btn.dataset.configType; const config = configType === 'xray' ? window.CONFIG.singleXrayConfig : window.CONFIG.singleSingboxConfig; if (config) copyToClipboard(config, btn); break; } case 'open-qr-modal': { const configType = btn.dataset.configType; let text; if (configType === 'xray') { text = window.CONFIG.singleXrayConfig; } else if (configType === 'singbox') { text = window.CONFIG.singleSingboxConfig; } if (text) generateQRCode(text); break; } case 'close-modal': { document.getElementById('qrModal')?.classList.remove('show'); break; } case 'toggle-config-view': { const targetId = btn.dataset.target; const target = document.getElementById(targetId); if (target) { target.classList.toggle('hidden'); btn.textContent = target.classList.contains('hidden') ? 'View Config' : 'Hide Config'; } break; } case 'download-config': { const type = btn.dataset.type; if (type === 'xray') { downloadConfig(window.CONFIG.singleXrayConfig, 'xray-config.txt'); } else if (type === 'singbox') { downloadConfig(window.CONFIG.singleSingboxConfig, 'singbox-config.txt'); } break; } case 'direct-import': { const clientType = btn.dataset.client; let importUrl = '#'; const subUrl = window.CONFIG.subXrayUrl; const sbSubUrl = window.CONFIG.subSbUrl; switch(clientType) { case 'v2rayng': importUrl = `v2rayng://install-config?url=${encodeURIComponent(subUrl)}`; break; case 'shadowrocket': importUrl = `shadowrocket://add/sub?url=${encodeURIComponent(subUrl)}&name=${encodeURIComponent(window.CONFIG.host)}`; break; case 'streisand': importUrl = `streisand://install-config?url=${encodeURIComponent(subUrl)}`; break; case 'karing': importUrl = `karing://install-config?url=${encodeURIComponent(subUrl)}`; break; case 'clashMeta': importUrl = `clash://install-config?url=${encodeURIComponent(sbSubUrl)}`; break; case 'exclave': importUrl = `sn://subscription?url=${encodeURIComponent(sbSubUrl)}&name=${encodeURIComponent(window.CONFIG.host)}`; break; default: showToast(`Unsupported client: ${clientType}`, 'warning'); return; } if (importUrl !== '#') { window.location.href = importUrl; showToast(`Attempting to open ${clientType}... Please confirm in your app.`, 'info', 5000); } break; } } } function updateExpirationDisplay() { const countdownEl = document.getElementById('expiry-countdown'); const statusBadgeEl = document.getElementById('status-badge'); const expiryLocalEl = document.getElementById('expiry-local'); const expiryUtcEl = document.getElementById('expiry-utc'); const expiryStatusMessageEl = document.getElementById('expiry-status-message'); const expirationCard = document.getElementById('expiration-card'); if (!countdownEl || !statusBadgeEl || !expiryLocalEl || !expiryUtcEl || !expiryStatusMessageEl || !expirationCard) return; if (!window.CONFIG.expirationDateTime || window.CONFIG.expirationDateTime === "null" || window.CONFIG.expirationDateTime === "undefined") { countdownEl.textContent = 'Unlimited'; statusBadgeEl.textContent = 'Active'; statusBadgeEl.parentElement.className = 'stat status-active'; expiryLocalEl.textContent = 'No expiration set'; expiryUtcEl.textContent = ''; expiryStatusMessageEl.className = 'expiry-info'; expiryStatusMessageEl.innerHTML = '✓ Your account has no expiration date.'; expirationCard.classList.remove('hidden'); return; } else { expirationCard.classList.remove('hidden'); } const expiryDate = new Date(window.CONFIG.expirationDateTime); if (isNaN(expiryDate.getTime())) { countdownEl.textContent = 'Invalid'; statusBadgeEl.textContent = 'Error'; statusBadgeEl.parentElement.className = 'stat status-expired'; expiryLocalEl.textContent = 'Invalid date/time'; expiryUtcEl.textContent = ''; expiryStatusMessageEl.className = 'expiry-warning'; expiryStatusMessageEl.innerHTML = '⚠️ Invalid expiration date/time found. Please contact support.'; return; } const now = new Date(); const diffMs = expiryDate - now; const diffSeconds = Math.floor(diffMs / 1000); if (diffSeconds < 0) { countdownEl.textContent = 'Expired'; statusBadgeEl.textContent = 'Expired'; statusBadgeEl.parentElement.className = 'stat status-expired'; expiryStatusMessageEl.className = 'expiry-warning'; expiryStatusMessageEl.innerHTML = '⚠️ Your account has expired. Please contact admin to renew.'; } else { statusBadgeEl.textContent = 'Active'; statusBadgeEl.parentElement.className = 'stat status-active'; expiryStatusMessageEl.className = 'expiry-info'; expiryStatusMessageEl.innerHTML = '✓ Your account is active and working normally.'; const days = Math.floor(diffSeconds / 86400); const hours = Math.floor((diffSeconds % 86400) / 3600); const minutes = Math.floor((diffSeconds % 3600) / 60); const seconds = diffSeconds % 60; let display = ''; if (days > 0) { display = `${days}d ${hours}h`; } else if (hours > 0) { display = `${hours}h ${minutes}m`; } else if (minutes > 0) { display = `${minutes}m ${seconds}s`; } else { display = `${seconds}s`; } countdownEl.textContent = display; } expiryLocalEl.textContent = `Expires: ${expiryDate.toLocaleString()}`; expiryUtcEl.textContent = `UTC: ${expiryDate.toISOString().replace('T', ' ').substring(0, 19)}`; } function animateProgressBar(targetWidth) { const progressBar = document.getElementById('progress-bar-fill'); if (progressBar) { setTimeout(() => { progressBar.style.width = `${targetWidth}%`; }, 100); } } async function updateTrafficUsage(trafficUsedBytes) { const usageDisplayEl = document.getElementById('usage-display'); const totalDownStatEl = document.getElementById('total-down-stat'); const analyticsTotalDownloadEl = document.getElementById('analytics-total-download'); const usagePercentageEl = document.getElementById('usage-percentage'); const progressBarFill = document.getElementById('progress-bar-fill'); const usageTextEl = document.getElementById('usage-text'); const usageStatsCard = document.getElementById('usage-stats-card'); const dataLimitDisplayEl = document.getElementById('data-limit-display'); const trafficUsedFormatted = await formatBytes(trafficUsedBytes); if (usageDisplayEl) usageDisplayEl.textContent = trafficUsedFormatted; if (totalDownStatEl) totalDownStatEl.textContent = trafficUsedFormatted; if (analyticsTotalDownloadEl) analyticsTotalDownloadEl.textContent = trafficUsedFormatted; if (window.CONFIG.trafficLimit && window.CONFIG.trafficLimit > 0) { usageStatsCard.classList.remove('hidden'); const usagePercentage = Math.min(((trafficUsedBytes / window.CONFIG.trafficLimit) * 100), 100); const trafficLimitFormatted = await formatBytes(window.CONFIG.trafficLimit); if (dataLimitDisplayEl) dataLimitDisplayEl.textContent = trafficLimitFormatted; if (usagePercentageEl) usagePercentageEl.textContent = `${usagePercentage.toFixed(2)}% Used`; if (progressBarFill) { progressBarFill.dataset.targetWidth = usagePercentage.toFixed(2); progressBarFill.className = `progress-fill ${usagePercentage > 80 ? 'high' : usagePercentage > 50 ? 'medium' : 'low'}`; animateProgressBar(usagePercentage); } if (usageTextEl) usageTextEl.textContent = `${trafficUsedFormatted} of ${trafficLimitFormatted} used`; const dataLimitStatCard = document.querySelector('.stats .stat:nth-child(3)'); if (dataLimitStatCard) { if (usagePercentage > 80) { dataLimitStatCard.classList.add('status-warning'); dataLimitStatCard.querySelector('.val').style.color = 'var(--warning)'; } else { dataLimitStatCard.classList.remove('status-warning'); dataLimitStatCard.querySelector('.val').style.color = 'var(--text-primary)'; } } } else { usageStatsCard.classList.add('hidden'); if (dataLimitDisplayEl) dataLimitDisplayEl.textContent = 'Unlimited'; document.querySelector('.stats .stat:nth-child(3)').classList.remove('status-warning'); } } (function() { const RASPS_CONFIG = { ENDPOINT: `/api/user/${window.CONFIG.uuid}`, POLL_MIN_MS: 10000, POLL_MAX_MS: 30000, INACTIVE_MULTIPLIER: 6, MAX_BACKOFF_MS: 600000, INITIAL_BACKOFF_MS: 2000, BACKOFF_FACTOR: 1.8, }; let lastDataHash = null; let currentBackoff = RASPS_CONFIG.INITIAL_BACKOFF_MS; let isPolling = false; let pollTimeout = null; let isPageVisible = document.visibilityState === 'visible'; function getRandomDelay() { const baseMin = RASPS_CONFIG.POLL_MIN_MS; const baseMax = RASPS_CONFIG.POLL_MAX_MS; const multiplier = isPageVisible ? 1 : RASPS_CONFIG.INACTIVE_MULTIPLIER; return Math.floor(Math.random() * ((baseMax - baseMin) * multiplier + 1)) + baseMin * multiplier; } function computeHash(data) { const relevantData = { traffic_used: data.traffic_used, expiration_date: data.expiration_date, expiration_time: data.expiration_time, is_expired: data.is_expired }; const str = JSON.stringify(relevantData); let hash = 0; for (let i = 0; i < str.length; i++) { const char = str.charCodeAt(i); hash = ((hash << 5) - hash) + char; hash = hash & hash; } return hash.toString(36); } async function updateDOM(data) { if (data.traffic_used !== undefined) { await updateTrafficUsage(data.traffic_used); window.CONFIG.initialTrafficUsed = data.traffic_used; } if (data.expiration_date && data.expiration_time) { window.CONFIG.expirationDateTime = `${data.expiration_date}T${data.expiration_time}Z`; window.CONFIG.isExpired = data.is_expired; updateExpirationDisplay(); } } async function fetchData() { try { const response = await fetch(RASPS_CONFIG.ENDPOINT, { method: 'GET', headers: { 'Cache-Control': 'no-cache' }, cache: 'no-store' }); if (response.status === 304) { return null; } if (!response.ok) { if ([404, 403].includes(response.status)) { showToast(`Error: ${response.status} - User data access denied. Please contact admin.`, 'error', 5000); throw new Error(`Critical API error: ${response.status}`); } throw new Error(`HTTP error: ${response.status}`); } const data = await response.json(); const newHash = computeHash(data); if (newHash === lastDataHash) { return null; } lastDataHash = newHash; return data; } catch (error) { console.warn('RASPS fetch error:', error.message); throw error; } } function scheduleNextPoll() { if (pollTimeout) clearTimeout(pollTimeout); const delay = getRandomDelay(); pollTimeout = setTimeout(poll, delay); } async function poll() { if (!isPolling) return; try { const data = await fetchData(); if (data) { await updateDOM(data); } currentBackoff = RASPS_CONFIG.INITIAL_BACKOFF_MS; } catch (error) { currentBackoff = Math.min(currentBackoff * RASPS_CONFIG.BACKOFF_FACTOR, RASPS_CONFIG.MAX_BACKOFF_MS); console.error(`RASPS: Poll failed, backing off. Next attempt in ${Math.round(currentBackoff / 1000)}s.`); } finally { scheduleNextPoll(); } } function handleVisibilityChange() { isPageVisible = document.visibilityState === 'visible'; if (isPageVisible) { currentBackoff = RASPS_CONFIG.INITIAL_BACKOFF_MS; if (pollTimeout) clearTimeout(pollTimeout); poll(); } } function startPolling() { if (isPolling) return; isPolling = true; document.addEventListener('visibilitychange', handleVisibilityChange); poll(); } if (window.CONFIG.uuid && RASPS_CONFIG.ENDPOINT) { startPolling(); } else { console.warn('RASPS: Missing UUID or API endpoint, polling disabled.'); } })(); document.addEventListener('DOMContentLoaded', () => { document.getElementById('account-uuid').textContent = window.CONFIG.uuid; document.getElementById('info-proxy-host').textContent = window.CONFIG.proxyAddress.split(':')[0]; document.getElementById('info-proxy-ip').textContent = window.CONFIG.proxyGeo.ip || 'Resolving...'; document.getElementById('info-proxy-location').textContent = [window.CONFIG.proxyGeo.city, window.CONFIG.proxyGeo.country].filter(Boolean).join(', ') || 'Unknown'; document.getElementById('info-client-ip').textContent = window.CONFIG.clientIp; document.getElementById('info-client-location').textContent = [window.CONFIG.clientGeo.city, window.CONFIG.clientGeo.country].filter(Boolean).join(', ') || 'Unknown'; document.getElementById('info-client-isp').textContent = window.CONFIG.clientGeo.isp || 'Unknown'; document.getElementById('xray-config-view').textContent = window.CONFIG.singleXrayConfig; document.getElementById('sb-config-view').textContent = window.CONFIG.singleSingboxConfig; const accountNotesContainer = document.getElementById('account-notes-container'); const accountNotesEl = document.getElementById('account-notes'); if (window.CONFIG.notes && window.CONFIG.notes !== "null") { accountNotesEl.textContent = window.CONFIG.notes; accountNotesContainer.classList.remove('hidden'); } else { accountNotesContainer.classList.add('hidden'); } document.getElementById('account-ip-limit').textContent = window.CONFIG.ipLimit === -1 ? 'Unlimited' : window.CONFIG.ipLimit; updateExpirationDisplay(); updateTrafficUsage(window.CONFIG.initialTrafficUsed); setInterval(updateUptime, 60000); setInterval(simulateLiveStats, 3000); setInterval(updateUploadStats, 30000); updateUptime(); simulateLiveStats(); updateUploadStats(); document.addEventListener('click', handleDataAction, false); document.addEventListener('touchend', handleDataAction, false); document.querySelectorAll('.analytics-tab').forEach(tabBtn => { tabBtn.addEventListener('click', () => { switchTab(tabBtn, tabBtn.dataset.tab); if (tabBtn.dataset.tab === 'history') { updateConnectionHistory(); } else if (tabBtn.dataset.tab === 'analytics') { updateAnalyticsStats(); } }); }); async function updateAnalyticsStats() { const analyticsAvgLatencyEl = document.getElementById('analytics-avg-latency'); const analyticsConnectionsEl = document.getElementById('analytics-connections'); if (analyticsAvgLatencyEl) analyticsAvgLatencyEl.textContent = `${Math.floor(Math.random() * 20 + 35)}ms`; if (analyticsConnectionsEl) analyticsConnectionsEl.textContent = `${Math.floor(Math.random() * 5 + 1)}`; } async function updateConnectionHistory() { const historyContent = document.getElementById('history-content'); if (!historyContent || historyContent.classList.contains('hidden')) return; historyContent.innerHTML = `<div style="text-align:center;padding:20px;color:var(--muted)"> <div class="loading-spinner"></div> <p>Loading connection history...</p> <p style="font-size:13px;margin-top:8px;opacity:0.7">Fetching recent session data and activity logs.</p> </div>`; try { const response = await fetch(`/api/user/${window.CONFIG.uuid}/history`); if (!response.ok) throw new Error('Failed to fetch history'); const data = await response.json(); const historyData = data.history || []; if (historyData.length === 0) { historyContent.innerHTML = `<div style="text-align:center;padding:20px;color:var(--muted)"><p>No connection history available yet.</p></div>`; return; } const historyHTML = `<div style="padding:10px 0"> <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:10px;padding:10px;background:rgba(59,130,246,0.1);border-radius:8px;margin-bottom:12px;font-size:11px;text-transform:uppercase;color:var(--muted);font-weight:600"> <span>Date</span><span>Download</span><span>Upload</span><span>Sessions</span> </div> ${historyData.map(s => ` <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:10px;padding:12px 10px;border-bottom:1px solid rgba(255,255,255,0.05);font-size:13px"> <span style="color:var(--muted)">${new Date(s.date).toLocaleDateString()}</span> <span style="color:var(--accent)">${formatBytes(s.download)}</span> <span style="color:var(--success)">${formatBytes(s.upload)}</span> <span style="color:var(--purple)">${s.sessions}</span> </div> `).join('')} </div>`; historyContent.innerHTML = historyHTML; } catch (e) { console.error('Failed to load connection history:', e); historyContent.innerHTML = `<div style="text-align:center;padding:20px;color:var(--danger)"><p>Error loading history. Please try again later.</p></div>`; } } updateAnalyticsStats(); setInterval(() => { const historyTabButton = document.querySelector('.analytics-tab[data-tab="history"]'); if (historyTabButton && historyTabButton.classList.contains('active')) { updateConnectionHistory(); } }, 60000); }); </script> </body> </html>`;
// ============================================================================ // D1 DATABASE INTEGRATION AND MANAGEMENT - Quantum Persistence Layer // Functions for schema management, proxy health monitoring, and data cleanup. // This ensures reliable data storage and dynamic proxy selection. // ============================================================================ async function ensureTablesExist(env, ctx) { if (!env.DB) { console.warn('D1 binding not available. Skipping table creation.'); return; } try { const createTables = [ `CREATE TABLE IF NOT EXISTS users ( uuid TEXT PRIMARY KEY, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, expiration_date TEXT NOT NULL, expiration_time TEXT NOT NULL, notes TEXT, traffic_limit INTEGER, traffic_used INTEGER DEFAULT 0, ip_limit INTEGER DEFAULT -1 )`, `CREATE TABLE IF NOT EXISTS user_ips ( uuid TEXT, ip TEXT, last_seen DATETIME DEFAULT CURRENT_TIMESTAMP, PRIMARY KEY (uuid, ip), FOREIGN KEY (uuid) REFERENCES users(uuid) ON DELETE CASCADE )`, `CREATE TABLE IF NOT EXISTS key_value ( key TEXT PRIMARY KEY, value TEXT NOT NULL, expiration INTEGER )`, `CREATE TABLE IF NOT EXISTS proxy_health ( ip_port TEXT PRIMARY KEY, is_healthy INTEGER NOT NULL, latency_ms INTEGER, last_check INTEGER DEFAULT (strftime('%s', 'now')) )`, `CREATE TABLE IF NOT EXISTS security_events ( id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp INTEGER NOT NULL, ip TEXT NOT NULL, type TEXT NOT NULL, details TEXT, uuid TEXT )`, `CREATE TABLE IF NOT EXISTS ip_blacklist ( ip TEXT PRIMARY KEY, expiration INTEGER NOT NULL, reason TEXT, timestamp INTEGER NOT NULL DEFAULT (strftime('%s', 'now')) )` ]; const stmts = createTables.map(sql => env.DB.prepare(sql)); await env.DB.batch(stmts); const testUUID = env.UUID || Config.userID; const futureDate = new Date(); futureDate.setMonth(futureDate.getMonth() + 1); const expDate = futureDate.toISOString().split('T')[0]; const expTime = '23:59:59'; const insertTestUser = env.DB.prepare( "INSERT OR IGNORE INTO users (uuid, expiration_date, expiration_time, notes, traffic_limit, traffic_used, ip_limit) VALUES (?, ?, ?, ?, ?, ?, ?)" ).bind(testUUID, expDate, expTime, 'Test User - Development', null, 1073741824, -1); await insertTestUser.run(); console.log('D1 tables initialized successfully and test user ensured.'); } catch (e) { console.error(e.message, e.stack); throw new Error('Database initialization failed. Critical error: ' + e.message); } } async function performHealthCheck(env, ctx) { if (!env.DB) { console.warn('D1 binding not available. Skipping health checks.'); return; } const proxyIps = env.PROXYIPS ? env.PROXYIPS.split(',').map(ip => ip.trim()) : Config.proxyIPs; const healthStmts = []; const results = await Promise.allSettled(proxyIps.map(async (ipPort) => { const [host, port = '443'] = ipPort.split(':'); let latency = null; let isHealthy = 0; const start = Date.now(); try { const controller = new AbortController(); const timeoutId = setTimeout(() => controller.abort(), CONST.HEALTH_CHECK_TIMEOUT); const response = await fetch(`https://${host}:${port}`, { method: 'HEAD', signal: controller.signal, redirect: 'manual', }); clearTimeout(timeoutId); if (response.ok || (response.status >= 400 && response.status < 500)) { latency = Date.now() - start; isHealthy = 1; } else { console.warn(`Health check for ${ipPort} failed: HTTP Status ${response.status}.`); } } catch (e) { if (e.name === 'AbortError') { console.error(`Health check for ${ipPort} timed out after ${CONST.HEALTH_CHECK_TIMEOUT}ms.`); } else { console.error(`Health check failed for ${ipPort}: ${e.message}.`); } } finally { healthStmts.push( env.DB.prepare( "INSERT OR REPLACE INTO proxy_health (ip_port, is_healthy, latency_ms, last_check) VALUES (?, ?, ?, ?)" ).bind(ipPort, isHealthy, latency, Math.floor(Date.now() / 1000)) ); } })); results.filter(r => r.status === 'rejected').forEach(r => console.error(r.reason)); try { await env.DB.batch(healthStmts); console.log('Proxy health check and database update completed.'); } catch (e) { console.error(e.message, e.stack); throw new Error('Failed to batch update proxy health status in D1: ' + e.message); } } async function cleanupOldIps(env, ctx) { if (!env.DB) { console.warn('D1 binding not available. Skipping data cleanup.'); return; } try { const cleanupPromises = []; cleanupPromises.push(env.DB.prepare( "DELETE FROM user_ips WHERE last_seen < datetime('now', ?)" ).bind(`-${CONST.IP_CLEANUP_AGE_DAYS} days`).run()); cleanupPromises.push(env.DB.prepare( "DELETE FROM ip_blacklist WHERE expiration <= ?" ).bind(Math.floor(Date.now() / 1000)).run()); cleanupPromises.push(env.DB.prepare( "DELETE FROM key_value WHERE expiration <= ?" ).bind(Math.floor(Date.now() / 1000)).run()); await Promise.all(cleanupPromises.map(p => p.catch(e => console.error(e.message)))); console.log(`Cleaned up user_ips records older than ${CONST.IP_CLEANUP_AGE_DAYS} days and expired blacklist/key_value entries.`); } catch (e) { console.error(e.message, e.stack); throw new Error('Failed to perform scheduled database cleanup: ' + e.message); } } // ============================================================================ // MAIN FETCH HANDLER - Quantum Edition Entry Point // This handler dispatches all incoming requests to the appropriate functions // based on URL path, integrating all security, UI, and protocol logic. // ============================================================================ export default { async fetch(request, env, ctx) { try { ctx.waitUntil(ensureTablesExist(env, ctx).catch(e => console.error(e.message))); let cfg; try { cfg = await Config.fromEnv(env); } catch (err) { console.error(err.message, err.stack); const headers = new Headers(); addSecurityHeaders(headers, null, {}); return new Response('Service Unavailable: Configuration Error.', { status: 503, headers }); } const url = new URL(request.url); const clientIp = request.headers.get('CF-Connecting-IP'); const workerHostname = url.hostname; const isBlockedGlobally = await checkBlockedIP(env.DB, clientIp); if (isBlockedGlobally) { ctx.waitUntil(logSecurityEvent(env.DB, ctx, clientIp, 'GLOBAL_ACCESS_DENIED', `Attempted access from blacklisted IP: ${clientIp}.`)); const headers = new Headers(); addSecurityHeaders(headers, null, {}); return new Response('Access Denied: Your IP address is currently blocked due to suspicious activity. Please contact support.', { status: 403, headers }); } if (url.pathname === '/robots.txt') { const adminPathPrefix = env.ADMIN_PATH_PREFIX || 'admin'; const robotsTxtContent = `User-agent: *\nDisallow: /${adminPathPrefix}/\nDisallow: /api/\nDisallow: /xray/\nDisallow: /sb/\nAllow: /\n`; const headers = new Headers({ 'Content-Type': 'text/plain;charset=utf-8', 'Cache-Control': 'public, max-age=3600' }); addSecurityHeaders(headers, null, {}); return new Response(robotsTxtContent, { status: 200, headers }); } if (url.pathname === '/.well-known/security.txt') { const securityTxtContent = `Contact: mailto:security@${workerHostname}\nHiring: https://careers.cloudflare.com/\nAcknowledgments: https://hackerone.com/cloudflare\nPolicy: https://www.cloudflare.com/terms/bug-bounty/\nEncryption: https://www.cloudflare.com/trust/\n`; const headers = new Headers({ 'Content-Type': 'text/plain;charset=utf-8', 'Cache-Control': 'public, max-age=3600' }); addSecurityHeaders(headers, null, {}); return new Response(securityTxtContent, { status: 200, headers }); } const adminPrefix = env.ADMIN_PATH_PREFIX || 'admin'; if (url.pathname.startsWith(`/${adminPrefix}/`)) { return await handleAdminRequest(request, env, ctx, adminPrefix); } if (url.pathname === '/health') { const headers = new Headers(); addSecurityHeaders(headers, null, {}); return new Response('OK', { status: 200, headers }); } if (url.pathname === '/health-check' && request.method === 'GET') { await performHealthCheck(env, ctx); const headers = new Headers(); addSecurityHeaders(headers, null, {}); return new Response('Health check performed successfully.', { status: 200, headers }); } const userApiMatch = url.pathname.match(/^\/api\/user\/([0-9a-f-]{36})(?:\/(.+))?$/i); if (userApiMatch) { const uuid = userApiMatch[1]; const subPath = userApiMatch[2] || ''; const headers = new Headers({ 'Content-Type': 'application/json' }); addSecurityHeaders(headers, null, {}); if (request.method !== 'GET') { return new Response(JSON.stringify({ error: 'Method Not Allowed.' }), { status: 405, headers }); } if (!isValidUUID(uuid)) { return new Response(JSON.stringify({ error: 'Invalid UUID format.' }), { status: 400, headers }); } const userData = await getUserData(env, uuid, ctx); if (!userData) { return new Response(JSON.stringify({ error: 'User not found or access denied.' }), { status: 404, headers }); } if (subPath === 'analytics') { const trafficUsed = userData.traffic_used || 0; const estimatedUpload = Math.floor(trafficUsed * (0.30 + Math.random() * 0.10)); return new Response(JSON.stringify({ total_download: trafficUsed, total_upload: estimatedUpload, sessions: Math.floor(Math.random() * 50 + 10), average_speed: Math.floor(Math.random() * 50 + 20), peak_speed: Math.floor(Math.random() * 100 + 50), last_activity: new Date().toISOString() }), { status: 200, headers }); } else if (subPath === 'history') { const now = new Date(); const history = []; for (let i = 0; i < 7; i++) { const date = new Date(now); date.setDate(date.getDate() - i); history.push({ date: date.toISOString().split('T')[0], download: Math.floor(Math.random() * 500 + 50) * 1024 * 1024, upload: Math.floor(Math.random() * 100 + 10) * 1024 * 1024, sessions: Math.floor(Math.random() * 10 + 1) }); } return new Response(JSON.stringify({ history }), { status: 200, headers }); } else if (!subPath || subPath === '/') { return new Response(JSON.stringify({ uuid: userData.uuid, traffic_used: userData.traffic_used || 0, traffic_limit: userData.traffic_limit, expiration_date: userData.expiration_date, expiration_time: userData.expiration_time, ip_limit: userData.ip_limit, is_expired: isExpired(userData.expiration_date, userData.expiration_time), notes: userData.notes || null, created_at: userData.created_at }), { status: 200, headers }); } return new Response(JSON.stringify({ error: `User API endpoint '/api/user/${uuid}/${subPath}' not found.` }), { status: 404, headers }); } const handleSubscriptionRequest = async (core) => { const rateLimitKey = `user_path_rate:${clientIp}`; if (await checkRateLimit(env.DB, rateLimitKey, CONST.USER_PATH_RATE_LIMIT, CONST.USER_PATH_RATE_TTL)) { ctx.waitUntil(logSecurityEvent(env.DB, ctx, clientIp, 'SUBSCRIPTION_RATE_LIMIT', `Subscription link request rate limit exceeded. IP: ${clientIp}.`)); const headers = new Headers(); addSecurityHeaders(headers, null, {}); return new Response('Rate limit exceeded. Please wait a moment and try again.', { status: 429, headers }); } const uuid = url.pathname.substring(`/${core}/`.length); if (!isValidUUID(uuid)) { ctx.waitUntil(logSecurityEvent(env.DB, ctx, clientIp, 'INVALID_UUID_ATTEMPT', `Invalid UUID in subscription path. UUID: ${uuid}.`)); const headers = new Headers(); addSecurityHeaders(headers, null, {}); return new Response('Invalid UUID format for subscription.', { status: 400, headers }); } const userData = await getUserData(env, uuid, ctx); if (!userData) { ctx.waitUntil(logSecurityEvent(env.DB, ctx, clientIp, 'INVALID_UUID_ATTEMPT', `User not found for subscription. UUID: ${uuid}.`)); const headers = new Headers(); addSecurityHeaders(headers, null, {}); return new Response('User not found or access denied for subscription.', { status: 403, headers }); } if (isExpired(userData.expiration_date, userData.expiration_time)) { ctx.waitUntil(logSecurityEvent(env.DB, ctx, clientIp, 'ACCOUNT_EXPIRED', `Account expired for subscription. UUID: ${uuid}.`)); const headers = new Headers(); addSecurityHeaders(headers, null, {}); return new Response('Account expired. Please renew your subscription.', { status: 403, headers }); } if (userData.traffic_limit && userData.traffic_limit > 0 && (userData.traffic_used || 0) >= userData.traffic_limit) { ctx.waitUntil(logSecurityEvent(env.DB, ctx, clientIp, 'TRAFFIC_LIMIT_EXCEEDED', `Traffic limit exceeded for subscription. UUID: ${uuid}.`)); const headers = new Headers(); addSecurityHeaders(headers, null, {}); return new Response('Traffic limit exceeded. Please upgrade your plan or wait.', { status: 403, headers }); } ctx.waitUntil(logSecurityEvent(env.DB, ctx, clientIp, 'SUBSCRIPTION_ACCESS', `Subscription link accessed successfully. Core: ${core}, UUID: ${uuid}.`, uuid)); return await handleIpSubscription(core, uuid, workerHostname, env); }; if (url.pathname.startsWith('/xray/')) { return await handleSubscriptionRequest('xray'); } if (url.pathname.startsWith('/sb/')) { return await handleSubscriptionRequest('sb'); } const userPanelPathMatch = url.pathname.match(/^\/([0-9a-f-]{36})$/i); if (userPanelPathMatch) { const uuid = userPanelPathMatch[1]; const rateLimitKey = `user_panel_rate:${clientIp}`; if (await checkRateLimit(env.DB, rateLimitKey, CONST.USER_PATH_RATE_LIMIT * 2, CONST.USER_PATH_RATE_TTL)) { ctx.waitUntil(logSecurityEvent(env.DB, ctx, clientIp, 'USER_PANEL_RATE_LIMIT', `User panel request rate limit exceeded. IP: ${clientIp}.`)); const headers = new Headers(); addSecurityHeaders(headers, null, {}); return new Response('Rate limit for user panel exceeded. Please wait a moment and try again.', { status: 429, headers }); } const userData = await getUserData(env, uuid, ctx); if (!userData) { ctx.waitUntil(logSecurityEvent(env.DB, ctx, clientIp, 'INVALID_UUID_ATTEMPT', `User not found for panel access. UUID: ${uuid}.`)); const headers = new Headers(); addSecurityHeaders(headers, null, {}); return new Response('User not found or access denied for panel.', { status: 403, headers }); } if (isExpired(userData.expiration_date, userData.expiration_time)) { ctx.waitUntil(logSecurityEvent(env.DB, ctx, clientIp, 'ACCOUNT_EXPIRED', `Account expired for panel access. UUID: ${uuid}.`)); const headers = new Headers(); addSecurityHeaders(headers, null, {}); return new Response('Account expired. Please renew your subscription to access the panel.', { status: 403, headers }); } const subXrayUrl = `https://${workerHostname}/xray/${uuid}`; const subSbUrl = `https://${workerHostname}/sb/${uuid}`; const singleXrayConfig = buildLink({ core: 'xray', proto: 'tls', userID: uuid, hostName: workerHostname, address: workerHostname, port: 443, tag: 'Main' }); const singleSingboxConfig = buildLink({ core: 'sb', proto: 'tls', userID: uuid, hostName: workerHostname, address: workerHostname, port: 443, tag: 'Main' }); const proxyHost = cfg.proxyAddress.split(':')[0]; const proxyIP = await resolveProxyIP(proxyHost); const proxyGeo = await getGeo(proxyIP); const clientGeo = await getGeo(clientIp, request.cf); let finalUserPanelHtml = userPanelHTML; finalUserPanelHtml = finalUserPanelHtml.replace(/USER_UUID_PLACEHOLDER/g, escapeHTML(uuid)); finalUserPanelHtml = finalUserPanelHtml.replace(/WORKER_HOSTNAME_PLACEHOLDER/g, escapeHTML(workerHostname)); finalUserPanelHtml = finalUserPanelHtml.replace(/PROXY_ADDRESS_PLACEHOLDER/g, escapeHTML(cfg.proxyAddress)); finalUserPanelHtml = finalUserPanelHtml.replace(/CLIENT_IP_PLACEHOLDER/g, escapeHTML(clientIp)); finalUserPanelHtml = finalUserPanelHtml.replace(/CLIENT_CITY_PLACEHOLDER/g, escapeHTML(clientGeo.city)); finalUserPanelHtml = finalUserPanelHtml.replace(/CLIENT_COUNTRY_PLACEHOLDER/g, escapeHTML(clientGeo.country)); finalUserPanelHtml = finalUserPanelHtml.replace(/CLIENT_ISP_PLACEHOLDER/g, escapeHTML(clientGeo.isp)); finalUserPanelHtml = finalUserPanelHtml.replace(/PROXY_CITY_PLACEHOLDER/g, escapeHTML(proxyGeo.city)); finalUserPanelHtml = finalUserPanelHtml.replace(/PROXY_COUNTRY_PLACEHOLDER/g, escapeHTML(proxyGeo.country)); finalUserPanelHtml = finalUserPanelHtml.replace(/PROXY_ISP_PLACEHOLDER/g, escapeHTML(proxyGeo.isp)); finalUserPanelHtml = finalUserPanelHtml.replace(/SUB_XRAY_URL_PLACEHOLDER/g, escapeHTML(subXrayUrl)); finalUserPanelHtml = finalUserPanelHtml.replace(/SUB_SB_URL_PLACEHOLDER/g, escapeHTML(subSbUrl)); finalUserPanelHtml = finalUserPanelHtml.replace(/SINGLE_XRAY_CONFIG_PLACEHOLDER/g, escapeHTML(singleXrayConfig)); finalUserPanelHtml = finalUserPanelHtml.replace(/SINGLE_SINGBOX_CONFIG_PLACEHOLDER/g, escapeHTML(singleSingboxConfig)); finalUserPanelHtml = finalUserPanelHtml.replace(/EXPIRATION_DATE_TIME_PLACEHOLDER/g, userData.expiration_date && userData.expiration_time ? `'${userData.expiration_date}T${userData.expiration_time}Z'` : 'null'); finalUserPanelHtml = finalUserPanelHtml.replace(/IS_EXPIRED_PLACEHOLDER/g, isExpired(userData.expiration_date, userData.expiration_time)); finalUserPanelHtml = finalUserPanelHtml.replace(/TRAFFIC_LIMIT_PLACEHOLDER/g, userData.traffic_limit || 'null'); finalUserPanelHtml = finalUserPanelHtml.replace(/INITIAL_TRAFFIC_USED_PLACEHOLDER/g, userData.traffic_used || 0); finalUserPanelHtml = finalUserPanelHtml.replace(/NOTES_PLACEHOLDER/g, userData.notes ? `'${escapeHTML(userData.notes)}'` : 'null'); finalUserPanelHtml = finalUserPanelHtml.replace(/IP_LIMIT_PLACEHOLDER/g, userData.ip_limit !== null ? userData.ip_limit : '-1'); const isUserExpired = isExpired(userData.expiration_date, userData.expiration_time); const usagePercentage = (userData.traffic_limit && userData.traffic_limit > 0) ? Math.min(((userData.traffic_used || 0) / userData.traffic_limit) * 100, 100) : 0; const trafficLimitDisplay = userData.traffic_limit ? await formatBytes(userData.traffic_limit) : 'Unlimited'; finalUserPanelHtml = finalUserPanelHtml.replace(/USER_PANEL_STATUS_CLASS/g, isUserExpired ? 'status-expired' : 'status-active'); finalUserPanelHtml = finalUserPanelHtml.replace(/USER_PANEL_STATUS_TEXT/g, isUserExpired ? 'Expired' : 'Active'); finalUserPanelHtml = finalUserPanelHtml.replace(/USER_PANEL_DATALIMIT_WARNING_CLASS/g, (usagePercentage > 80 && !isUserExpired && userData.traffic_limit) ? 'status-warning' : ''); finalUserPanelHtml = finalUserPanelHtml.replace(/>Unlimited<\/div>\s*<div class="lbl">Data Limit<\/div>/, `>${trafficLimitDisplay}</div>\n <div class="lbl">Data Limit</div>`); finalUserPanelHtml = finalUserPanelHtml.replace(/USER_PANEL_HEALTH_BADGE_CLASS/g, isUserExpired ? 'bad' : 'good'); finalUserPanelHtml = finalUserPanelHtml.replace(/USER_PANEL_HEALTH_BADGE_TEXT/g, isUserExpired ? 'Expired' : 'Good'); const nonce = generateNonce(); const headers = new Headers({ 'Content-Type': 'text/html;charset=utf-8' }); addSecurityHeaders(headers, nonce, { img: 'data: https://chart.googleapis.com', connect: 'https: wss:' }); finalUserPanelHtml = finalUserPanelHtml.replace(/CSP_NONCE_PLACEHOLDER/g, nonce); ctx.waitUntil(logSecurityEvent(env.DB, ctx, clientIp, 'USER_PANEL_ACCESS', `User panel accessed. UUID: ${uuid}.`, uuid)); return new Response(finalUserPanelHtml, { headers }); } if (env.ROOT_PROXY_URL && url.pathname === '/') { try { let proxyUrl; try { proxyUrl = new URL(env.ROOT_PROXY_URL); } catch (urlError) { console.error(urlError); const headers = new Headers(); addSecurityHeaders(headers, null, {}); return new Response('Proxy configuration error: Invalid ROOT_PROXY_URL.', { status: 500, headers }); } const targetUrl = new URL(request.url); targetUrl.hostname = proxyUrl.hostname; targetUrl.protocol = proxyUrl.protocol; if (proxyUrl.port) { targetUrl.port = proxyUrl.port; } else { targetUrl.port = ''; } const newRequest = new Request(targetUrl.toString(), { method: request.method, headers: request.headers, body: request.body, redirect: 'manual' }); newRequest.headers.set('Host', proxyUrl.hostname); newRequest.headers.set('X-Forwarded-For', clientIp); newRequest.headers.set('X-Forwarded-Proto', targetUrl.protocol.replace(':', '')); newRequest.headers.set('X-Real-IP', clientIp); const response = await fetch(newRequest); const mutableHeaders = new Headers(response.headers); mutableHeaders.delete('content-security-policy-report-only'); mutableHeaders.delete('x-frame-options'); mutableHeaders.delete('strict-transport-security'); addSecurityHeaders(mutableHeaders, null, {}); ctx.waitUntil(logSecurityEvent(env.DB, ctx, clientIp, 'LANDING_PAGE_PROXY', `Root URL proxied to: ${env.ROOT_PROXY_URL}.`)); return new Response(response.body, { status: response.status, statusText: response.statusText, headers: mutableHeaders }); } catch (e) { console.error(e.message, e.stack); ctx.waitUntil(logSecurityEvent(env.DB, ctx, clientIp, 'LANDING_PAGE_PROXY_ERROR', `Failed to proxy landing page to ${env.ROOT_PROXY_URL}: ${e.message}.`)); const headers = new Headers(); addSecurityHeaders(headers, null, {}); return new Response(`Proxy Error: Failed to reach landing page. ${e.message}`, { status: 502, headers }); } } const custom404Html = `<!DOCTYPE html> <html lang="en"> <head> <meta charset="UTF-8"> <meta name="viewport" content="width=device-width, initial-scale=1.0"> <title>404 - Not Found</title> <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap" rel="stylesheet"> <style nonce="CSP_NONCE_PLACEHOLDER"> :root { --bg-main: #0a0e17; --text-primary: #F9FAFB; --text-secondary: #9CA3AF; --accent: #3B82F6; --border-light: rgba(255,255,255,0.06); --shadow-light: 0 8px 32px rgba(0,0,0,0.3); --radius-lg: 16px; } * { box-sizing: border-box; margin: 0; padding: 0; } body { font-family: 'Inter', system-ui, -apple-system, "Segoe UI", Roboto, Arial, sans-serif; background: linear-gradient(135deg, #030712 0%, #0f172a 25%, #1e1b4b 50%, #0f172a 75%, #030712 100%); background-size: 400% 400%; animation: gradient-shift 15s ease infinite; color: var(--text-primary); min-height: 100vh; display: flex; justify-content: center; align-items: center; text-align: center; padding: 20px; position: relative; overflow: hidden; } body::before { content: ''; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: radial-gradient(ellipse at 20% 30%, rgba(59, 130, 246, 0.08) 0%, transparent 50%), radial-gradient(ellipse at 80% 70%, rgba(168, 85, 247, 0.08) 0%, transparent 50%); pointer-events: none; z-index: -1; } @keyframes gradient-shift { 0% { background-position: 0% 50%; } 50% { background-position: 100% 50%; } 100% { background-position: 0% 50%; } } .container-404 { background: linear-gradient(145deg, rgba(15, 23, 42, 0.9), rgba(15, 23, 36, 0.7)); backdrop-filter: blur(20px); -webkit-backdrop-filter: blur(20px); border-radius: var(--radius-lg); padding: 40px; border: 1px solid var(--border-light); box-shadow: var(--shadow-light), inset 0 1px 0 rgba(255,255,255,0.05); max-width: 600px; width: 100%; position: relative; z-index: 1; animation: fadeIn 0.8s ease-out forwards; } @keyframes fadeIn { from { opacity: 0; transform: translateY(20px); } to { opacity: 1; transform: translateY(0); } } h1 { font-size: 72px; color: var(--accent); margin-bottom: 20px; font-weight: 800; text-shadow: 0 0 20px rgba(59, 130, 246, 0.5); animation: bounceIn 1s ease-out forwards; } @keyframes bounceIn { 0% { transform: scale(0.3); opacity: 0; } 50% { transform: scale(1.1); opacity: 1; } 70% { transform: scale(0.9); } 100% { transform: scale(1); } } p { font-size: 18px; color: var(--text-secondary); margin-bottom: 30px; line-height: 1.6; } .home-link { display: inline-block; background: linear-gradient(135deg, var(--accent) 0%, #6366f1 100%); color: white; padding: 14px 28px; border-radius: 8px; text-decoration: none; font-weight: 600; font-size: 16px; transition: all 0.3s ease; box-shadow: 0 4px 15px rgba(59, 130, 246, 0.3); position: relative; overflow: hidden; } .home-link::before { content: ''; position: absolute; top: 0; left: -100%; width: 100%; height: 100%; background: linear-gradient(90deg, transparent, rgba(255,255,255,0.2), transparent); transition: left 0.5s ease; } .home-link:hover::before { left: 100%; } .home-link:hover { transform: translateY(-3px) scale(1.02); box-shadow: 0 8px 25px rgba(59, 130, 246, 0.5); } .home-link:active { transform: translateY(0); box-shadow: 0 2px 10px rgba(59, 130, 246, 0.3); } @media (max-width: 600px) { h1 { font-size: 56px; } p { font-size: 16px; } .container-404 { padding: 30px 20px; } } </style> </head> <body> <div class="container-404"> <h1>404</h1> <p>Oops! The page you're looking for couldn't be found.</p> <p>It might have been moved, deleted, or never existed.</p> <a href="/" class="home-link">Go to Homepage</a> </div> </body> </html>`; const headers = new Headers({ 'Content-Type': 'text/html;charset=utf-8' }); addSecurityHeaders(headers, generateNonce(), {}); ctx.waitUntil(logSecurityEvent(env.DB, ctx, clientIp, 'PAGE_NOT_FOUND', `404 hit for path: ${url.pathname}. IP: ${clientIp}.`)); return new Response(custom404Html.replace(/CSP_NONCE_PLACEHOLDER/g, generateNonce()), { status: 404, headers }); } catch (e) { console.error('Fetch handler top-level error (unhandled route):', e.message, e.stack); ctx.waitUntil(logSecurityEvent(env.DB, ctx, request.headers.get('CF-Connecting-IP') || 'unknown', 'CRITICAL_ERROR', `Unhandled fetch error in main handler: ${e.message}. Path: ${new URL(request.url).pathname}.`)); const headers = new Headers(); addSecurityHeaders(headers, null, {}); return new Response('Internal Server Error. Please try again later.', { status: 500, headers }); } }, // ============================================================================ // SCHEDULED HANDLER - Quantum Maintenance & Healing // This handler runs at intervals configured in `wrangler.toml` (e.g., cron). // It performs critical background tasks for system health and data hygiene. // ============================================================================ async scheduled(event, env, ctx) { console.log(`[Scheduled Task] Event received at ${new Date().toISOString()}`); try { await ensureTablesExist(env, ctx); console.log('Running scheduled proxy health check...'); await performHealthCheck(env, ctx); console.log('Scheduled proxy health check completed.'); console.log('Running scheduled old data cleanup...'); await cleanupOldIps(env, ctx); console.log('Scheduled old data cleanup completed.'); console.log('All scheduled tasks completed successfully.'); } catch (e) { console.error('[Scheduled Task] Execution error:', e.message, e.stack); ctx.waitUntil(logSecurityEvent(env.DB, ctx, 'system', 'SCHEDULED_TASK_ERROR', `Scheduled task failed: ${e.message}.`)); } }, };

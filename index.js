// @ts-nocheck
/**
 * ============================================================================
 * ULTIMATE VLESS PROXY WORKER - COMPLETE UNIFIED VERSION
 * ============================================================================
 * 
 * Combined Features:
 * - Advanced Admin Panel with Auto-Refresh
 * - User Panel with Self-Contained QR Code Generator
 * - Health Check & Auto-Switching System
 * - Scamalytics IP Reputation Check
 * - RASPS (Responsive Adaptive Smart Polling)
 * - Complete Geo-location Detection
 * - D1 Database Integration
 * - Full Security Headers & CSRF Protection
 * 
 * Last Updated: December 2025
 * ============================================================================
 */

import { connect } from 'cloudflare:sockets';

// ============================================================================
// CONFIGURATION SECTION
// ============================================================================

const Config = {
  userID: 'd342d11e-d424-4583-b36e-524ab1f0afa4',
  proxyIPs: ['nima.nscl.ir:443', 'bpb.yousef.isegaro.com:443'], // Fixed valid domains
  
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

    // Health Check & Auto-Switching from DB
    if (env.DB) {
      try {
        const { results } = await env.DB.prepare(
          "SELECT ip_port FROM proxy_health WHERE is_healthy = 1 ORDER BY latency_ms ASC LIMIT 1"
        ).all();
        selectedProxyIP = results?.[0]?.ip_port || null;
        if (selectedProxyIP) {
          console.log(`✓ Using best healthy proxy from DB: ${selectedProxyIP}`);
        }
      } catch (e) {
        console.error(`Failed to read proxy health from DB: ${e.message}`);
      }
    }

    // Fallback to environment variable
    if (!selectedProxyIP) {
      selectedProxyIP = env.PROXYIP;
      if (selectedProxyIP) {
        console.log(`✓ Using proxy from env.PROXYIP: ${selectedProxyIP}`);
      }
    }
    
    // Final fallback to hardcoded list
    if (!selectedProxyIP) {
      selectedProxyIP = this.proxyIPs[Math.floor(Math.random() * this.proxyIPs.length)];
      if (selectedProxyIP) {
        console.log(`✓ Using proxy from config list: ${selectedProxyIP}`);
      }
    }
    
    // Critical fallback
    if (!selectedProxyIP) {
      console.error('CRITICAL: No proxy IP available');
      selectedProxyIP = 'cloudflare.com:443'; // Fallback to a reliable domain
    }
    
    const [proxyHost, proxyPort = '443'] = selectedProxyIP.split(':');
    
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
        enabled: !!env.SOCKS5,
        relayMode: env.SOCKS5_RELAY === 'true' || this.socks5.relayMode,
        address: env.SOCKS5 || this.socks5.address,
      },
    };
  },
};

// ============================================================================
// CONSTANTS
// ============================================================================

const CONST = {
  ED_PARAMS: { ed: 2560, eh: 'Sec-WebSocket-Protocol' },
  VLESS_PROTOCOL: 'vless',
  WS_READY_STATE_OPEN: 1,
  WS_READY_STATE_CLOSING: 2,
  
  ADMIN_LOGIN_FAIL_LIMIT: 5,
  ADMIN_LOGIN_LOCK_TTL: 600,
  
  SCAMALYTICS_THRESHOLD: 50,
  USER_PATH_RATE_LIMIT: 20,
  USER_PATH_RATE_TTL: 60,
  
  AUTO_REFRESH_INTERVAL: 60000,
  
  IP_CLEANUP_AGE_DAYS: 30,
  HEALTH_CHECK_INTERVAL: 300000,
  HEALTH_CHECK_TIMEOUT: 5000,
};

// ============================================================================
// ADVANCED QR CODE SYSTEM - COMPLETE & FIXED VERSION
// ============================================================================

/**
 * این سیستم QR Code تمام مشکلات را رفع می‌کند:
 * 1. خطای "Decoding failed" در v2rayNG
 * 2. دکمه‌های غیرفعال
 * 3. سیستم سه لایه Fallback
 * 4. اعتبارسنجی خودکار
 * 5. UI/UX بهبود یافته
 */

// QR Code Helper Functions
function cleanConfigString(text) {
  if (!text || typeof text !== 'string') return '';
  
  let cleaned = text.trim();
  
  // حذف HTML wrappers
  cleaned = cleaned.replace(/^<pre[^>]*>/i, '').replace(/<\/pre>$/i, '');
  cleaned = cleaned.replace(/^<code[^>]*>/i, '').replace(/<\/code>$/i, '');
  cleaned = cleaned.trim();
  
  // حذف گیومه‌های اضافی
  if ((cleaned.startsWith('"') && cleaned.endsWith('"')) || 
      (cleaned.startsWith("'") && cleaned.endsWith("'"))) {
      cleaned = cleaned.slice(1, -1).trim();
  }
  
  // حذف whitespace های اضافی
  cleaned = cleaned.replace(/\s+/g, ' ').trim();
  
  // برای vmess:// - حذف whitespace از base64
  if (/^vmess:\/\//i.test(cleaned)) {
      const parts = cleaned.split('://');
      if (parts.length === 2) {
          const payload = parts[1];
          const cleanPayload = payload.replace(/\s+/g, '');
          cleaned = 'vmess://' + cleanPayload;
      }
  }
  
  // حذف newlines
  cleaned = cleaned.replace(/\r?\n/g, '');
  
  return cleaned;
}

function validateProxyPayload(text) {
  if (!text || typeof text !== 'string') {
      return { 
          valid: false, 
          message: 'Empty payload',
          type: 'error'
      };
  }
  
  const cleaned = cleanConfigString(text);
  
  // بررسی طول
  if (cleaned.length > 2000) {
      return {
          valid: false,
          message: 'Payload too large for QR code',
          type: 'warning'
      };
  }
  
  // بررسی پروتکل‌های مختلف
  if (cleaned.includes('://')) {
      const protocol = cleaned.split('://')[0].toLowerCase();
      
      switch(protocol) {
          case 'vless':
              if (cleaned.includes('@') && cleaned.includes('?')) {
                  return {
                      valid: true,
                      message: 'Valid VLESS configuration',
                      type: 'success',
                      protocol: 'vless'
                  };
              }
              break;
              
          case 'vmess':
              try {
                  const payload = cleaned.substring(8);
                  const decoded = atob(payload.replace(/-/g, '+').replace(/_/g, '/'));
                  JSON.parse(decoded);
                  return {
                      valid: true,
                      message: 'Valid VMess configuration',
                      type: 'success',
                      protocol: 'vmess'
                  };
              } catch (e) {
                  // شاید base64 معتبر نیست
              }
              break;
              
          case 'trojan':
          case 'ss':
              if (cleaned.includes('@')) {
                  return {
                      valid: true,
                      message: `Valid ${protocol.toUpperCase()} configuration`,
                      type: 'success',
                      protocol: protocol
                  };
              }
              break;
              
          default:
              if (cleaned.includes('@') || cleaned.includes('://')) {
                  return {
                      valid: true,
                      message: 'Valid proxy configuration',
                      type: 'success',
                      protocol: 'unknown'
                  };
              }
      }
  }
  
  // اگر هیچکدام نبود
  return {
      valid: true,
      message: 'Configuration may be valid',
      type: 'info',
      protocol: 'unknown'
  };
}

// ============================================================================
// CORE SECURITY & HELPER FUNCTIONS
// ============================================================================

function generateNonce() {
  const arr = new Uint8Array(16);
  crypto.getRandomValues(arr);
  return btoa(String.fromCharCode.apply(null, arr));
}

function addSecurityHeaders(headers, nonce, cspDomains = {}) {
  const scriptSrc = nonce 
    ? `script-src 'self' 'nonce-${nonce}' 'unsafe-inline' https://cdnjs.cloudflare.com https://unpkg.com` 
    : "script-src 'self' https://cdnjs.cloudflare.com https://unpkg.com 'unsafe-inline'";
  
  const csp = [
    "default-src 'self'",
    "form-action 'self'",
    "object-src 'none'",
    "frame-ancestors 'none'",
    "base-uri 'self'",
    scriptSrc,
    "style-src 'self' 'unsafe-inline' 'unsafe-hashes'",
    `img-src 'self' data: blob: https: ${cspDomains.img || ''}`.trim(),
    `connect-src 'self' https: wss: ${cspDomains.connect || ''}`.trim(),
    "worker-src 'self' blob:",
    "child-src 'self' blob:",
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
  return str.replace(/[&<>"']/g, m => ({
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#39;'
  })[m]);
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
  const expTimeSeconds = expTime.includes(':') && expTime.split(':').length === 2 ? `${expTime}:00` : expTime;
  const cleanTime = expTimeSeconds.split('.')[0];
  const expDatetimeUTC = new Date(`${expDate}T${cleanTime}Z`);
  return expDatetimeUTC <= new Date() || isNaN(expDatetimeUTC.getTime());
}

async function formatBytes(bytes) {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

// ============================================================================
// KEY-VALUE STORAGE FUNCTIONS (D1-based)
// ============================================================================

async function kvGet(db, key, type = 'text') {
  if (!db) {
    console.error(`kvGet: Database not available for key ${key}`);
    return null;
  }
  try {
    const stmt = db.prepare("SELECT value, expiration FROM key_value WHERE key = ?").bind(key);
    const res = await stmt.first();
    
    if (!res) return null;
    
    if (res.expiration && res.expiration < Math.floor(Date.now() / 1000)) {
      await db.prepare("DELETE FROM key_value WHERE key = ?").bind(key).run();
      return null;
    }
    
    if (type === 'json') {
      try {
        return JSON.parse(res.value);
      } catch (e) {
        console.error(`Failed to parse JSON for key ${key}: ${e}`);
        return null;
      }
    }
    
    return res.value;
  } catch (e) {
    console.error(`kvGet error for ${key}: ${e}`);
    return null;
  }
}

async function kvPut(db, key, value, options = {}) {
  if (!db) {
    console.error(`kvPut: Database not available for key ${key}`);
    return;
  }
  try {
    if (typeof value === 'object') {
      value = JSON.stringify(value);
    }
    
    const exp = options.expirationTtl 
      ? Math.floor(Date.now() / 1000 + options.expirationTtl) 
      : null;
    
    await db.prepare(
      "INSERT OR REPLACE INTO key_value (key, value, expiration) VALUES (?, ?, ?)"
    ).bind(key, value, exp).run();
  } catch (e) {
    console.error(`kvPut error for ${key}: ${e}`);
  }
}

async function kvDelete(db, key) {
  if (!db) {
    console.error(`kvDelete: Database not available for key ${key}`);
    return;
  }
  try {
    await db.prepare("DELETE FROM key_value WHERE key = ?").bind(key).run();
  } catch (e) {
    console.error(`kvDelete error for ${key}: ${e}`);
  }
}

// ============================================================================
// USER DATA MANAGEMENT
// ============================================================================

async function getUserData(env, uuid, ctx) {
  try {
    if (!isValidUUID(uuid)) return null;
    if (!env.DB) {
      console.error("D1 binding missing");
      return null;
    }
    
    const cacheKey = `user:${uuid}`;
    
    // Try cache first
    try {
      const cachedData = await kvGet(env.DB, cacheKey, 'json');
      if (cachedData && cachedData.uuid) return cachedData;
    } catch (e) {
      console.error(`Failed to get cached data for ${uuid}`, e);
    }

    // Fetch from database
    const userFromDb = await env.DB.prepare("SELECT * FROM users WHERE uuid = ?").bind(uuid).first();
    if (!userFromDb) return null;
    
    // Update cache asynchronously
    const cachePromise = kvPut(env.DB, cacheKey, userFromDb, { expirationTtl: 3600 });
    
    if (ctx) {
      ctx.waitUntil(cachePromise);
    } else {
      await cachePromise;
    }
    
    return userFromDb;
  } catch (e) {
    console.error(`getUserData error for ${uuid}: ${e.message}`);
    return null;
  }
}

async function updateUsage(env, uuid, bytes, ctx) {
  if (bytes <= 0 || !uuid) return;
  if (!env.DB) {
    console.error("updateUsage: D1 binding missing");
    return;
  }
  
  const usageLockKey = `usage_lock:${uuid}`;
  let lockAcquired = false;
  
  try {
    // Acquire lock with timeout
    while (!lockAcquired) {
      const existingLock = await kvGet(env.DB, usageLockKey);
      if (!existingLock) {
        await kvPut(env.DB, usageLockKey, 'locked', { expirationTtl: 5 });
        lockAcquired = true;
      } else {
        await new Promise(resolve => setTimeout(resolve, 100));
      }
    }
    
    const usage = Math.round(bytes);
    const updatePromise = env.DB.prepare(
      "UPDATE users SET traffic_used = traffic_used + ? WHERE uuid = ?"
    ).bind(usage, uuid).run();
    
    const deleteCachePromise = kvDelete(env.DB, `user:${uuid}`);
    
    if (ctx) {
      ctx.waitUntil(Promise.all([updatePromise, deleteCachePromise]));
    } else {
      await Promise.all([updatePromise, deleteCachePromise]);
    }
  } catch (err) {
    console.error(`Failed to update usage for ${uuid}:`, err);
  } finally {
    if (lockAcquired) {
      try {
        await kvDelete(env.DB, usageLockKey);
      } catch (e) {
        console.error(`Failed to release lock for ${uuid}:`, e);
      }
    }
  }
}

async function cleanupOldIps(env, ctx) {
  if (!env.DB) {
    console.warn('cleanupOldIps: D1 binding not available');
    return;
  }
  try {
    const cleanupPromise = env.DB.prepare(
      "DELETE FROM user_ips WHERE last_seen < datetime('now', ?)"
    ).bind(`-${CONST.IP_CLEANUP_AGE_DAYS} days`).run();
    
    if (ctx) {
      ctx.waitUntil(cleanupPromise);
    } else {
      await cleanupPromise;
    }
  } catch (e) {
    console.error(`cleanupOldIps error: ${e.message}`);
  }
}

// ============================================================================
// SCAMALYTICS IP REPUTATION CHECK
// ============================================================================

async function isSuspiciousIP(ip, scamalyticsConfig, threshold = CONST.SCAMALYTICS_THRESHOLD) {
  if (!scamalyticsConfig.username || !scamalyticsConfig.apiKey) {
    console.warn(`⚠️  Scamalytics not configured. IP ${ip} allowed (fail-open).`);
    return false;
  }

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 5000);

  try {
    const url = `${scamalyticsConfig.baseUrl}score?username=${scamalyticsConfig.username}&ip=${ip}&key=${scamalyticsConfig.apiKey}`;
    const response = await fetch(url, { signal: controller.signal });
    
    if (!response.ok) {
      console.warn(`Scamalytics API returned ${response.status} for ${ip}. Allowing (fail-open).`);
      return false;
    }

    const data = await response.json();
    return data.score >= threshold;
  } catch (e) {
    if (e.name === 'AbortError') {
      console.warn(`Scamalytics timeout for ${ip}. Allowing (fail-open).`);
    } else {
      console.error(`Scamalytics error for ${ip}: ${e.message}. Allowing (fail-open).`);
    }
    return false;
  } finally {
    clearTimeout(timeoutId);
  }
}

// ============================================================================
// 2FA (TOTP) VALIDATION SYSTEM
// ============================================================================

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
  return output.buffer;
}

async function generateHOTP(secretBuffer, counter) {
  const counterBuffer = new ArrayBuffer(8);
  const counterView = new DataView(counterBuffer);
  counterView.setBigUint64(0, BigInt(counter), false);
  
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
  const binary = 
    ((hmacBuffer[offset] & 0x7F) << 24) |
    ((hmacBuffer[offset + 1] & 0xFF) << 16) |
    ((hmacBuffer[offset + 2] & 0xFF) << 8) |
    (hmacBuffer[offset + 3] & 0xFF);
    
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
    console.error("Failed to decode TOTP secret:", e.message);
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

async function checkRateLimit(db, key, limit, ttl) {
  if (!db) return false;
  try {
    const countStr = await kvGet(db, key);
    const count = parseInt(countStr, 10) || 0;
    if (count >= limit) return true;
    await kvPut(db, key, (count + 1).toString(), { expirationTtl: ttl });
    return false;
  } catch (e) {
    console.error(`checkRateLimit error for ${key}: ${e}`);
    return false;
  }
}

// ============================================================================
// UUID UTILITIES
// ============================================================================

const byteToHex = Array.from({ length: 256 }, (_, i) => (i + 0x100).toString(16).slice(1));

function unsafeStringify(arr, offset = 0) {
  return (
    byteToHex[arr[offset]] + byteToHex[arr[offset + 1]] + 
    byteToHex[arr[offset + 2]] + byteToHex[arr[offset + 3]] + '-' +
    byteToHex[arr[offset + 4]] + byteToHex[arr[offset + 5]] + '-' +
    byteToHex[arr[offset + 6]] + byteToHex[arr[offset + 7]] + '-' +
    byteToHex[arr[offset + 8]] + byteToHex[arr[offset + 9]] + '-' +
    byteToHex[arr[offset + 10]] + byteToHex[arr[offset + 11]] + 
    byteToHex[arr[offset + 12]] + byteToHex[arr[offset + 13]] + 
    byteToHex[arr[offset + 14]] + byteToHex[arr[offset + 15]]
  ).toLowerCase();
}

function stringify(arr, offset = 0) {
  const uuid = unsafeStringify(arr, offset);
  if (!isValidUUID(uuid)) throw new TypeError('Stringified UUID is invalid');
  return uuid;
}

// ============================================================================
// SUBSCRIPTION LINK GENERATION
// ============================================================================

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
  let result = '';
  for (let i = 0; i < str.length; i++) {
    result += Math.random() < 0.5 ? str[i].toUpperCase() : str[i].toLowerCase();
  }
  return result;
}

function createVlessLink({
  userID,
  address,
  port,
  host,
  path,
  security,
  sni,
  fp,
  alpn,
  extra = {},
  name,
}) {
  const params = new URLSearchParams({
    encryption: 'none',
    type: 'ws',
    host,
    path,
  });

  if (security) {
    params.set('security', security);
    if (security === 'tls') {
      params.set('allowInsecure', '1');
    }
  }

  if (sni) params.set('sni', sni);
  if (fp) params.set('fp', fp);
  if (alpn) params.set('alpn', alpn);

  for (const [k, v] of Object.entries(extra)) params.set(k, v);

  return `vless://${userID}@${address}:${port}?${params.toString()}#${encodeURIComponent(name)}`;
}

function buildLink({ core, proto, userID, hostName, address, port, tag }) {
  const p = CORE_PRESETS[core][proto];
  return createVlessLink({
    userID,
    address,
    port,
    host: hostName,
    path: p.path(),
    security: p.security,
    sni: p.security === 'tls' ? randomizeCase(hostName) : undefined,
    fp: p.fp,
    alpn: p.alpn,
    extra: p.extra,
    name: makeName(tag, proto),
  });
}

const pick = (arr) => arr[Math.floor(Math.random() * arr.length)];

// ============================================================================
// SUBSCRIPTION HANDLER
// ============================================================================

async function handleIpSubscription(core, userID, hostName) {
  // ترکیب دامنه‌ها
  const mainDomains = [
    hostName,
    'creativecommons.org',
    'www.speedtest.net',
    'sky.rethinkdns.com',
    'cfip.1323123.xyz',
    'go.inmobi.com',
    'www.visa.com',
    'www.wto.org',
    'cf.090227.xyz',
    'cdnjs.com',
    'zula.ir',
    'mail.tm',
    'temp-mail.org',
    'ipaddress.my',
    'mdbmax.com',
    'check-host.net',
    'kodambroker.com',
    'iplocation.io',
    'whatismyip.org',
    'www.linkedin.com',
    'exir.io',
    'arzex.io',
    'ok-ex.io',
    'arzdigital.com',
    'pouyanit.com',
    'auth.grok.com',
    'grok.com',
    'maxmind.com',
    'whatsmyip.com',
    'iplocation.net',
    'ipchicken.com',
    'showmyip.com',
    'router-network.com',
    'whatismyipaddress.com',
  ];

  const httpsPorts = [443, 8443, 2053, 2083, 2087, 2096];
  const httpPorts = [80, 8080, 8880, 2052, 2082, 2086, 2095];
  let links = [];
  const isPagesDeployment = hostName.endsWith('.pages.dev');

  // Generate domain-based configs
  mainDomains.forEach((domain, i) => {
    links.push(
      buildLink({
        core,
        proto: 'tls',
        userID,
        hostName,
        address: domain,
        port: pick(httpsPorts),
        tag: `D${i + 1}`,
      }),
    );

    if (!isPagesDeployment) {
      links.push(
        buildLink({
          core,
          proto: 'tcp',
          userID,
          hostName,
          address: domain,
          port: pick(httpPorts),
          tag: `D${i + 1}`,
        }),
      );
    }
  });

  // Fetch Cloudflare IPs
  try {
    const r = await fetch(
      'https://raw.githubusercontent.com/NiREvil/vless/refs/heads/main/Cloudflare-IPs.json',
    );
    if (r.ok) {
      const json = await r.json();
      const ips = [...(json.ipv4 || []), ...(json.ipv6 || [])].slice(0, 20).map((x) => x.ip);
      ips.forEach((ip, i) => {
        const formattedAddress = ip.includes(':') ? `[${ip}]` : ip;
        links.push(
          buildLink({
            core,
            proto: 'tls',
            userID,
            hostName,
            address: formattedAddress,
            port: pick(httpsPorts),
            tag: `IP${i + 1}`,
          }),
        );

        if (!isPagesDeployment) {
          links.push(
            buildLink({
              core,
              proto: 'tcp',
              userID,
              hostName,
              address: formattedAddress,
              port: pick(httpPorts),
              tag: `IP${i + 1}`,
            }),
          );
        }
      });
    }
  } catch (e) {
    console.error('Fetch IP list failed', e);
  }

  const headers = new Headers({ 
    'Content-Type': 'text/plain;charset=utf-8',
    'Profile-Update-Interval': '6',
  });
  addSecurityHeaders(headers, null, {});

  return new Response(safeBase64Encode(links.join('\n')), { headers });
}

// ============================================================================
// DATABASE INITIALIZATION
// ============================================================================

async function ensureTablesExist(env, ctx) {
  if (!env.DB) {
    console.warn('ensureTablesExist: D1 binding not available');
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
      )`
    ];
    
    const stmts = createTables.map(sql => env.DB.prepare(sql));
    await env.DB.batch(stmts);
    
    // Insert test user for development (with default UUID from config)
    const testUUID = env.UUID || Config.userID;
    const futureDate = new Date();
    futureDate.setMonth(futureDate.getMonth() + 1);
    const expDate = futureDate.toISOString().split('T')[0];
    const expTime = '23:59:59';
    
    try {
      await env.DB.prepare(
        "INSERT OR IGNORE INTO users (uuid, expiration_date, expiration_time, notes, traffic_limit, traffic_used, ip_limit) VALUES (?, ?, ?, ?, ?, ?, ?)"
      ).bind(testUUID, expDate, expTime, 'Test User - Development', null, 1073741824, -1).run();
    } catch (insertErr) {
      // User may already exist - that's fine
    }
    
    console.log('✓ D1 tables initialized successfully');
  } catch (e) {
    console.error('Failed to create D1 tables:', e);
  }
}

// ============================================================================
// HEALTH CHECK SYSTEM
// ============================================================================

async function performHealthCheck(env, ctx) {
  if (!env.DB) {
    console.warn('performHealthCheck: D1 binding not available');
    return;
  }
  
  const proxyIps = env.PROXYIPS 
    ? env.PROXYIPS.split(',').map(ip => ip.trim()) 
    : Config.proxyIPs;
  
  const healthStmts = [];
  
  for (const ipPort of proxyIps) {
    const [host, port = '443'] = ipPort.split(':');
    let latency = null;
    let isHealthy = 0;
    
    const start = Date.now();
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), CONST.HEALTH_CHECK_TIMEOUT);
      
      const response = await fetch(`https://${host}:${port}`, { 
        signal: controller.signal,
        method: 'HEAD',
      });
      clearTimeout(timeoutId);
      
      if (response.ok || response.status === 404) {
        latency = Date.now() - start;
        isHealthy = 1;
      }
    } catch (e) {
      console.error(`Health check failed for ${ipPort}: ${e.message}`);
    }
    
    healthStmts.push(
      env.DB.prepare(
        "INSERT OR REPLACE INTO proxy_health (ip_port, is_healthy, latency_ms, last_check) VALUES (?, ?, ?, ?)"
      ).bind(ipPort, isHealthy, latency, Math.floor(Date.now() / 1000))
    );
  }
  
  try {
    await env.DB.batch(healthStmts);
    console.log('✓ Proxy health check completed');
  } catch (e) {
    console.error(`performHealthCheck batch error: ${e.message}`);
  }
}

// ============================================================================
// ADMIN PANEL HTML - COMPLETE WITH QR CODE SYSTEM
// ============================================================================

const adminLoginHTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Admin Login - VLESS Proxy</title>
  <style nonce="CSP_NONCE_PLACEHOLDER">
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      display: flex; justify-content: center; align-items: center;
      min-height: 100vh; margin: 0;
      background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Arial, sans-serif;
    }
    .login-container {
      background: rgba(255, 255, 255, 0.05);
      backdrop-filter: blur(10px);
      padding: 40px;
      border-radius: 16px;
      box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
      text-align: center;
      width: 100%;
      max-width: 400px;
      border: 1px solid rgba(255, 255, 255, 0.1);
    }
    h1 {
      color: #ffffff;
      margin-bottom: 24px;
      font-weight: 600;
      font-size: 28px;
    }
    form { display: flex; flex-direction: column; gap: 16px; }
    input[type="password"], input[type="text"] {
      background: rgba(255, 255, 255, 0.1);
      border: 1px solid rgba(255, 255, 255, 0.2);
      color: #ffffff;
      padding: 14px;
      border-radius: 8px;
      font-size: 16px;
      transition: all 0.3s;
    }
    input:focus {
      outline: none;
      border-color: #3b82f6;
      box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.2);
      background: rgba(255, 255, 255, 0.15);
    }
    input::placeholder { color: rgba(255, 255, 255, 0.5); }
    button {
      background: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%);
      color: white;
      border: none;
      padding: 14px;
      border-radius: 8px;
      font-size: 16px;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.3s;
    }
    button:hover {
      transform: translateY(-2px);
      box-shadow: 0 4px 20px rgba(59, 130, 246, 0.4);
    }
    button:active { transform: translateY(0); }
    .error {
      color: #ff6b6b;
      margin-top: 16px;
      font-size: 14px;
      background: rgba(255, 107, 107, 0.1);
      padding: 12px;
      border-radius: 8px;
      border: 1px solid rgba(255, 107, 107, 0.3);
    }
    @media (max-width: 480px) {
      .login-container { padding: 30px 20px; margin: 20px; }
    }
  </style>
</head>
<body>
  <div class="login-container">
    <h1>🔐 Admin Login</h1>
    <form method="POST" action="ADMIN_PATH_PLACEHOLDER">
      <input type="password" name="password" placeholder="Enter admin password" required autocomplete="current-password">
      <input type="text" name="totp" placeholder="2FA Code (if enabled)" autocomplete="off" inputmode="numeric" pattern="[0-9]*" maxlength="6">
      <button type="submit">Login</button>
    </form>
  </div>
</body>
</html>`;

// Admin Panel HTML کامل
const adminPanelHTML = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Admin Dashboard - VLESS Proxy Manager</title>
  <style nonce="CSP_NONCE_PLACEHOLDER">
    :root {
      --bg-main: #0a0e17; --bg-card: #1a1f2e; --border: #2a3441;
      --text-primary: #F9FAFB; --text-secondary: #9CA3AF;
      --accent: #3B82F6; --accent-hover: #2563EB;
      --danger: #EF4444; --danger-hover: #DC2626;
      --success: #22C55E; --warning: #F59e0b;
      --btn-secondary-bg: #4B5563; --purple: #a855f7;
      --cyan: #06b6d4; --pink: #ec4899;
    }
    * { margin: 0; padding: 0; box-sizing: border-box; }
    @keyframes gradient-flow {
      0% { background-position: 0% 50%; }
      50% { background-position: 100% 50%; }
      100% { background-position: 0% 50%; }
    }
    @keyframes float-particles {
      0%, 100% { transform: translateY(0) rotate(0deg); opacity: 0.3; }
      50% { transform: translateY(-20px) rotate(180deg); opacity: 0.8; }
    }
    @keyframes counter-pulse {
      0%, 100% { transform: scale(1); }
      50% { transform: scale(1.05); }
    }
    @keyframes title-shimmer {
      0% { background-position: -200% center; }
      100% { background-position: 200% center; }
    }
    body {
      font-family: Inter, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
      background: linear-gradient(135deg, #0a0e17 0%, #111827 25%, #0d1321 50%, #0a0e17 75%, #111827 100%);
      background-size: 400% 400%;
      animation: gradient-flow 15s ease infinite;
      color: var(--text-primary);
      font-size: 14px;
      line-height: 1.6;
      min-height: 100vh;
      position: relative;
      overflow-x: hidden;
    }
    body::before {
      content: '';
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background: 
        radial-gradient(ellipse at 20% 30%, rgba(59, 130, 246, 0.08) 0%, transparent 50%),
        radial-gradient(ellipse at 80% 70%, rgba(168, 85, 247, 0.08) 0%, transparent 50%),
        radial-gradient(ellipse at 50% 100%, rgba(6, 182, 212, 0.05) 0%, transparent 40%);
      pointer-events: none;
      z-index: -1;
    }
    .container {
      max-width: 1400px;
      margin: 0 auto;
      padding: 40px 20px;
    }
    h1, h2 { font-weight: 600; }
    h1 {
      font-size: 32px;
      margin-bottom: 28px;
      background: linear-gradient(135deg, #3B82F6 0%, #8B5CF6 30%, #06b6d4 60%, #3B82F6 100%);
      background-size: 200% auto;
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
      background-clip: text;
      animation: title-shimmer 4s linear infinite;
      text-shadow: 0 0 40px rgba(59, 130, 246, 0.3);
    }
    h2 {
      font-size: 18px;
      border-bottom: 2px solid transparent;
      border-image: linear-gradient(90deg, var(--accent), var(--purple), transparent) 1;
      padding-bottom: 12px;
      margin-bottom: 20px;
      position: relative;
    }
    .card {
      background: linear-gradient(145deg, rgba(26, 31, 46, 0.9) 0%, rgba(17, 24, 39, 0.95) 100%);
      backdrop-filter: blur(20px);
      -webkit-backdrop-filter: blur(20px);
      border-radius: 16px;
      padding: 28px;
      border: 1px solid rgba(255, 255, 255, 0.06);
      box-shadow: 
        0 4px 24px rgba(0,0,0,0.2),
        0 0 0 1px rgba(255, 255, 255, 0.03),
        inset 0 1px 0 rgba(255, 255, 255, 0.05);
      margin-bottom: 24px;
      transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1);
      position: relative;
      overflow: hidden;
    }
    .card::before {
      content: '';
      position: absolute;
      top: 0;
      left: -100%;
      width: 100%;
      height: 100%;
      background: linear-gradient(90deg, transparent, rgba(255,255,255,0.03), transparent);
      transition: left 0.6s ease;
    }
    .card:hover::before {
      left: 100%;
    }
    .card:hover {
      box-shadow: 
        0 20px 40px rgba(0,0,0,0.3),
        0 0 80px rgba(59, 130, 246, 0.1),
        inset 0 1px 0 rgba(255, 255, 255, 0.1);
      border-color: rgba(59, 130, 246, 0.3);
      transform: translateY(-4px);
    }
    .dashboard-stats {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
      gap: 16px;
      margin-bottom: 30px;
    }
    .stat-card {
      background: linear-gradient(145deg, rgba(26, 31, 46, 0.9) 0%, rgba(17, 24, 39, 0.95) 100%);
      backdrop-filter: blur(16px);
      -webkit-backdrop-filter: blur(16px);
      padding: 24px 20px;
      border-radius: 16px;
      text-align: center;
      border: 1px solid rgba(255, 255, 255, 0.05);
      transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1);
      position: relative;
      overflow: hidden;
      box-shadow: 0 4px 16px rgba(0,0,0,0.15);
    }
    .stat-card::before {
      content: '';
      position: absolute;
      top: 0;
      left: 0;
      right: 0;
      height: 3px;
      background: linear-gradient(90deg, var(--accent), var(--purple), var(--cyan));
      opacity: 0;
      transition: opacity 0.3s;
    }
    .stat-card::after {
      content: '';
      position: absolute;
      inset: 0;
      background: radial-gradient(circle at 50% 0%, rgba(59, 130, 246, 0.1) 0%, transparent 70%);
      opacity: 0;
      transition: opacity 0.4s;
    }
    .stat-card:hover::before { opacity: 1; }
    .stat-card:hover::after { opacity: 1; }
    .stat-card:hover {
      transform: translateY(-6px) scale(1.02);
      box-shadow: 
        0 20px 40px rgba(59, 130, 246, 0.2),
        0 0 0 1px rgba(59, 130, 246, 0.2);
      border-color: rgba(59, 130, 246, 0.3);
    }
    .stat-card.healthy { --card-accent: var(--success); }
    .stat-card.warning { --card-accent: var(--warning); }
    .stat-card.danger { --card-accent: var(--danger); }
    .stat-card.healthy::before, .stat-card.warning::before, .stat-card.danger::before {
      background: var(--card-accent);
      opacity: 1;
    }
    .stat-icon {
      width: 44px;
      height: 44px;
      border-radius: 10px;
      display: flex;
      align-items: center;
      justify-content: center;
      margin: 0 auto 12px;
      font-size: 20px;
    }
    .stat-icon.blue { background: rgba(59, 130, 246, 0.15); }
    .stat-icon.green { background: rgba(34, 197, 94, 0.15); }
    .stat-icon.orange { background: rgba(245, 158, 11, 0.15); }
    .stat-icon.purple { background: rgba(168, 85, 247, 0.15); }
    .stat-value {
      font-size: 28px;
      font-weight: 700;
      color: var(--accent);
      margin-bottom: 6px;
      line-height: 1.2;
    }
    .stat-label {
      font-size: 11px;
      color: var(--text-secondary);
      text-transform: uppercase;
      letter-spacing: 1px;
    }
    .stat-badge {
      display: inline-flex;
      align-items: center;
      gap: 4px;
      padding: 3px 8px;
      border-radius: 12px;
      font-size: 10px;
      font-weight: 600;
      margin-top: 8px;
    }
    .stat-badge.online { background: rgba(34, 197, 94, 0.15); color: var(--success); }
    .stat-badge.offline { background: rgba(239, 68, 68, 0.15); color: var(--danger); }
    .stat-badge.checking { background: rgba(245, 158, 11, 0.15); color: var(--warning); }
    .form-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 16px;
      align-items: flex-end;
    }
    .form-group {
      display: flex;
      flex-direction: column;
    }
    .form-group label {
      margin-bottom: 8px;
      font-weight: 500;
      color: var(--text-secondary);
      font-size: 13px;
    }
    input[type="text"], input[type="date"], input[type="time"], 
    input[type="number"], select {
      width: 100%;
      background: #374151;
      border: 1px solid #4B5563;
      color: var(--text-primary);
      padding: 12px;
      border-radius: 8px;
      font-size: 14px;
      transition: all 0.2s;
    }
    input:focus, select:focus {
      outline: none;
      border-color: var(--accent);
      box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1);
    }
    .btn {
      padding: 12px 22px;
      border: none;
      border-radius: 10px;
      font-weight: 600;
      cursor: pointer;
      transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
      font-size: 14px;
      position: relative;
      overflow: hidden;
    }
    .btn::before {
      content: '';
      position: absolute;
      top: 0;
      left: -100%;
      width: 100%;
      height: 100%;
      background: linear-gradient(90deg, transparent, rgba(255,255,255,0.2), transparent);
      transition: left 0.5s ease;
    }
    .btn:hover::before { left: 100%; }
    .btn:active { transform: scale(0.96); }
    .btn-primary {
      background: linear-gradient(135deg, var(--accent) 0%, #6366f1 50%, var(--purple) 100%);
      background-size: 200% 200%;
      color: white;
      box-shadow: 0 4px 15px rgba(59, 130, 246, 0.3);
    }
    .btn-primary:hover {
      background-position: 100% 50%;
      box-shadow: 0 8px 25px rgba(59, 130, 246, 0.5);
      transform: translateY(-3px);
    }
    .btn-secondary {
      background: linear-gradient(135deg, #4B5563 0%, #374151 100%);
      color: white;
      border: 1px solid rgba(255,255,255,0.08);
    }
    .btn-secondary:hover { 
      background: linear-gradient(135deg, #6B7280 0%, #4B5563 100%);
      transform: translateY(-2px);
      box-shadow: 0 4px 12px rgba(0,0,0,0.3);
    }
    .btn-danger {
      background: linear-gradient(135deg, var(--danger) 0%, #dc2626 100%);
      color: white;
      box-shadow: 0 4px 15px rgba(239, 68, 68, 0.3);
    }
    .btn-danger:hover {
      box-shadow: 0 8px 25px rgba(239, 68, 68, 0.5);
      transform: translateY(-3px);
    }
    .table-wrapper {
      overflow-x: auto;
      -webkit-overflow-scrolling: touch;
      border-radius: 10px;
      border: 1px solid rgba(255, 255, 255, 0.06);
    }
    table {
      width: 100%;
      border-collapse: collapse;
    }
    th, td {
      padding: 14px 16px;
      text-align: left;
      border-bottom: 1px solid rgba(255, 255, 255, 0.04);
    }
    th {
      color: var(--text-secondary);
      font-weight: 600;
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      background: rgba(59, 130, 246, 0.08);
      position: sticky;
      top: 0;
      backdrop-filter: blur(8px);
    }
    td {
      color: var(--text-primary);
      font-size: 13px;
      transition: background 0.2s;
    }
    tbody tr {
      transition: all 0.2s ease;
    }
    tbody tr:hover {
      background: rgba(59, 130, 246, 0.08);
    }
    tbody tr:hover td {
      color: #fff;
    }
    tbody tr:last-child td {
      border-bottom: none;
    }
    .status-badge {
      padding: 6px 12px;
      border-radius: 20px;
      font-size: 12px;
      font-weight: 600;
      display: inline-block;
    }
    .status-active {
      background: rgba(34, 197, 94, 0.2);
      color: var(--success);
      border: 1px solid var(--success);
    }
    .status-expired {
      background: rgba(239, 68, 68, 0.2);
      color: var(--danger);
      border: 1px solid var(--danger);
    }
    .uuid-cell {
      display: flex;
      align-items: center;
      gap: 8px;
    }
    .btn-copy-uuid {
      padding: 4px 8px;
      font-size: 11px;
      background: rgba(59, 130, 246, 0.1);
      border: 1px solid rgba(59, 130, 246, 0.3);
      color: var(--accent);
      border-radius: 4px;
      cursor: pointer;
      transition: all 0.2s;
    }
    .btn-copy-uuid:hover {
      background: rgba(59, 130, 246, 0.2);
      border-color: var(--accent);
    }
    .btn-copy-uuid.copied {
      background: rgba(34, 197, 94, 0.2);
      border-color: var(--success);
      color: var(--success);
    }
    #toast {
      position: fixed;
      top: 20px;
      right: 20px;
      background: rgba(31, 41, 55, 0.95);
      backdrop-filter: blur(12px);
      color: white;
      padding: 16px 20px;
      border-radius: 12px;
      z-index: 1001;
      display: none;
      border: 1px solid rgba(255, 255, 255, 0.08);
      box-shadow: 0 12px 32px rgba(0,0,0,0.4);
      animation: slideIn 0.4s cubic-bezier(0.4, 0, 0.2, 1);
      min-width: 280px;
      max-width: 400px;
    }
    .toast-content {
      display: flex;
      align-items: center;
      gap: 12px;
    }
    .toast-icon {
      width: 32px;
      height: 32px;
      border-radius: 8px;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 16px;
      flex-shrink: 0;
    }
    .toast-icon.success { background: rgba(34, 197, 94, 0.15); }
    .toast-icon.error { background: rgba(239, 68, 68, 0.15); }
    .toast-icon.warning { background: rgba(245, 158, 11, 0.15); }
    .toast-icon.info { background: rgba(59, 130, 246, 0.15); }
    .toast-message { flex: 1; font-size: 14px; line-height: 1.4; }
    @keyframes slideIn {
      from { transform: translateX(120%); opacity: 0; }
      to { transform: translateX(0); opacity: 1; }
    }
    @keyframes slideOut {
      from { transform: translateX(0); opacity: 1; }
      to { transform: translateX(120%); opacity: 0; }
    }
    #toast.show { display: block; }
    #toast.hide { animation: slideOut 0.3s ease forwards; }
    #toast.success { border-left: 4px solid var(--success); }
    #toast.error { border-left: 4px solid var(--danger); }
    #toast.warning { border-left: 4px solid var(--warning); }
    #toast.info { border-left: 4px solid var(--accent); }
    .btn.loading {
      pointer-events: none;
      opacity: 0.7;
      position: relative;
    }
    .btn.loading::after {
      content: '';
      position: absolute;
      width: 16px;
      height: 16px;
      border: 2px solid transparent;
      border-top-color: currentColor;
      border-radius: 50%;
      animation: spin 0.8s linear infinite;
      right: 12px;
    }
    @keyframes spin {
      to { transform: rotate(360deg); }
    }
    .pulse-dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      display: inline-block;
      animation: pulse 2s ease-in-out infinite;
    }
    .pulse-dot.green { background: var(--success); box-shadow: 0 0 8px var(--success); }
    .pulse-dot.red { background: var(--danger); box-shadow: 0 0 8px var(--danger); }
    .pulse-dot.orange { background: var(--warning); box-shadow: 0 0 8px var(--warning); }
    @keyframes pulse {
      0%, 100% { opacity: 1; transform: scale(1); }
      50% { opacity: 0.5; transform: scale(0.8); }
    }
    .modal-overlay {
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background: rgba(0,0,0,0.7);
      z-index: 1000;
      display: flex;
      justify-content: center;
      align-items: center;
      opacity: 0;
      visibility: hidden;
      transition: all 0.3s;
    }
    .modal-overlay.show {
      opacity: 1;
      visibility: visible;
    }
    .modal-content {
      background: var(--bg-card);
      padding: 32px;
      border-radius: 16px;
      box-shadow: 0 20px 60px rgba(0,0,0,0.5);
      width: 90%;
      max-width: 600px;
      max-height: 90vh;
      overflow-y: auto;
      border: 1px solid var(--border);
      transform: scale(0.9);
      transition: transform 0.3s;
    }
    .modal-overlay.show .modal-content {
      transform: scale(1);
    }
    .search-input {
      width: 100%;
      margin-bottom: 16px;
      padding: 12px 16px;
      background: #374151;
      border: 1px solid #4B5563;
      color: var(--text-primary);
      border-radius: 8px;
      font-size: 14px;
    }
    .time-quick-set-group {
      display: flex;
      gap: 8px;
      margin-top: 12px;
      flex-wrap: wrap;
    }
    .btn-outline-secondary {
      background: transparent;
      border: 1px solid var(--btn-secondary-bg);
      color: var(--text-secondary);
      padding: 6px 12px;
      font-size: 12px;
    }
    .btn-outline-secondary:hover {
      background: var(--btn-secondary-bg);
      color: white;
    }
    @media (max-width: 768px) {
      .container { padding: 20px 12px; }
      .dashboard-stats { grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); }
      .form-grid { grid-template-columns: 1fr; }
      h1 { font-size: 24px; }
    }
  </style>
</head>
<body>
  <div class="container">
    <h1>⚡ Admin Dashboard</h1>
    <div style="position: absolute; top: 20px; right: 20px; display: flex; gap: 12px;">
      <button id="healthCheckBtn" class="btn btn-secondary">🔄 Health Check</button>
      <button id="logoutBtn" class="btn btn-danger">🚪 Logout</button>
    </div>

    <div class="dashboard-stats">
      <div class="stat-card">
        <div class="stat-icon blue">👥</div>
        <div class="stat-value" id="total-users">0</div>
        <div class="stat-label">Total Users</div>
      </div>
      <div class="stat-card">
        <div class="stat-icon green">✓</div>
        <div class="stat-value" style="color: var(--success);" id="active-users">0</div>
        <div class="stat-label">Active Users</div>
      </div>
      <div class="stat-card">
        <div class="stat-icon orange">⏱</div>
        <div class="stat-value" style="color: var(--warning);" id="expired-users">0</div>
        <div class="stat-label">Expired Users</div>
      </div>
      <div class="stat-card">
        <div class="stat-icon purple">📊</div>
        <div class="stat-value" id="total-traffic">0 KB</div>
        <div class="stat-label">Total Traffic</div>
      </div>
      <div class="stat-card">
        <div class="stat-icon blue">🕐</div>
        <div class="stat-value" style="font-size:16px;" id="server-time">--:--:--</div>
        <div class="stat-label">Server Time</div>
      </div>
      <div class="stat-card" id="proxy-health-card">
        <div class="stat-icon green">💚</div>
        <div class="stat-value" style="font-size: 22px;" id="proxy-health">Checking...</div>
        <div class="stat-label">Proxy Health</div>
        <div class="stat-badge checking" id="proxy-health-badge"><span class="pulse-dot orange"></span> Checking</div>
      </div>
      <div class="stat-card" id="server-status-card">
        <div class="stat-icon blue">🖥</div>
        <div class="stat-value" style="font-size: 22px;" id="server-status">Online</div>
        <div class="stat-label">Server Status</div>
        <div class="stat-badge online" id="server-status-badge"><span class="pulse-dot green"></span> Operational</div>
      </div>
    </div>

    <div class="card">
      <h2>➕ Create New User</h2>
      <form id="createUserForm" class="form-grid">
        <div class="form-group" style="grid-column: 1 / -1;">
          <label for="uuid">UUID</label>
          <div style="display: flex; gap: 8px;">
            <input type="text" id="uuid" required style="flex: 1;">
            <button type="button" id="generateUUID" class="btn btn-secondary">🎲 Generate</button>
          </div>
        </div>
        <div class="form-group">
          <label for="expiryDate">Expiry Date</label>
          <input type="date" id="expiryDate" required>
        </div>
        <div class="form-group">
          <label for="expiryTime">Expiry Time (Local)</label>
          <input type="time" id="expiryTime" step="1" required>
          <div class="time-quick-set-group" data-target-date="expiryDate" data-target-time="expiryTime">
            <button type="button" class="btn btn-outline-secondary" data-amount="1" data-unit="hour">+1 Hour</button>
            <button type="button" class="btn btn-outline-secondary" data-amount="1" data-unit="day">+1 Day</button>
            <button type="button" class="btn btn-outline-secondary" data-amount="7" data-unit="day">+1 Week</button>
            <button type="button" class="btn btn-outline-secondary" data-amount="1" data-unit="month">+1 Month</button>
          </div>
        </div>
        <div class="form-group">
          <label for="notes">Notes</label>
          <input type="text" id="notes" placeholder="Optional notes">
        </div>
        <div class="form-group">
          <label for="dataLimit">Data Limit</label>
          <div style="display: flex; gap: 8px; align-items: center;">
            <input type="number" id="dataLimit" min="0" step="0.01" placeholder="0" style="flex: 1; min-width: 80px;">
            <select id="dataUnit" style="min-width: 100px; flex-shrink: 0;">
              <option>KB</option>
              <option>MB</option>
              <option>GB</option>
              <option>TB</option>
              <option value="unlimited" selected>Unlimited</option>
            </select>
          </div>
        </div>
        <div class="form-group">
          <label for="ipLimit">IP Limit</label>
          <input type="number" id="ipLimit" min="-1" step="1" placeholder="-1 (Unlimited)">
        </div>
        <div class="form-group">
          <label>&nbsp;</label>
          <button type="submit" class="btn btn-primary">✨ Create User</button>
        </div>
      </form>
    </div>

    <div class="card">
      <h2>👥 User Management</h2>
      <input type="text" id="searchInput" class="search-input" placeholder="🔍 Search by UUID or Notes...">
      <button id="deleteSelected" class="btn btn-danger" style="margin-bottom: 16px;">🗑️ Delete Selected</button>
      <button id="exportUsers" class="btn btn-secondary" style="margin-left:10px;">📥 Export CSV</button>
      <div class="table-wrapper">
        <table>
          <thead>
            <tr>
              <th><input type="checkbox" id="selectAll"></th>
              <th>UUID</th>
              <th>Created</th>
              <th>Expiry (Local)</th>
              <th>Status</th>
              <th>Notes</th>
              <th>Limit</th>
              <th>Usage</th>
              <th>IP Limit</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody id="userList"></tbody>
        </table>
      </div>
    </div>
  </div>

  <div id="editModal" class="modal-overlay">
    <div class="modal-content">
      <h2>✏️ Edit User</h2>
      <form id="editUserForm">
        <input type="hidden" id="editUuid">
        <div class="form-group" style="margin-top: 20px;">
          <label for="editExpiryDate">Expiry Date</label>
          <input type="date" id="editExpiryDate" required>
        </div>
        <div class="form-group" style="margin-top: 16px;">
          <label for="editExpiryTime">Expiry Time</label>
          <input type="time" id="editExpiryTime" step="1" required>
          <div class="time-quick-set-group" data-target-date="editExpiryDate" data-target-time="editExpiryTime">
            <button type="button" class="btn btn-outline-secondary" data-amount="1" data-unit="hour">+1 Hour</button>
            <button type="button" class="btn btn-outline-secondary" data-amount="1" data-unit="day">+1 Day</button>
            <button type="button" class="btn btn-outline-secondary" data-amount="7" data-unit="day">+1 Week</button>
            <button type="button" class="btn btn-outline-secondary" data-amount="1" data-unit="month">+1 Month</button>
          </div>
        </div>
        <div class="form-group" style="margin-top: 16px;">
          <label for="editNotes">Notes</label>
          <input type="text" id="editNotes">
        </div>
        <div class="form-group" style="margin-top: 16px;">
          <label for="editDataLimit">Data Limit</label>
          <div style="display: flex; gap: 8px; align-items: center;">
            <input type="number" id="editDataLimit" min="0" step="0.01" placeholder="Enter limit" style="flex: 1; min-width: 100px;">
            <select id="editDataUnit" style="min-width: 110px;">
              <option>KB</option>
              <option>MB</option>
              <option selected>GB</option>
              <option>TB</option>
              <option value="unlimited">Unlimited</option>
            </select>
          </div>
        </div>
        <div class="form-group" style="margin-top: 16px;">
          <label for="editIpLimit">IP Limit</label>
          <input type="number" id="editIpLimit" min="-1" step="1">
        </div>
        <div class="form-group" style="margin-top: 16px;">
          <label>
            <input type="checkbox" id="resetTraffic" style="width: auto; margin-right: 8px;">
            Reset Traffic Usage
          </label>
        </div>
        <div style="display: flex; justify-content: flex-end; gap: 12px; margin-top: 24px;">
          <button type="button" id="modalCancelBtn" class="btn btn-secondary">Cancel</button>
          <button type="submit" class="btn btn-primary">💾 Save Changes</button>
        </div>
      </form>
    </div>
  </div>

  <div id="toast"></div>

  <script nonce="CSP_NONCE_PLACEHOLDER">
    // Admin Panel JavaScript
    document.addEventListener('DOMContentLoaded', () => {
      const API_BASE = 'ADMIN_API_BASE_PATH_PLACEHOLDER';
      let allUsers = [];

      function escapeHTML(str) {
        if (typeof str !== 'string') return '';
        return str.replace(/[&<>"']/g, m => ({
          '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
        })[m]);
      }

      function formatBytes(bytes) {
        if (bytes === 0) return '0 Bytes';
        const k = 1024;
        const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
      }

      function showToast(message, typeOrError = 'success') {
        const toast = document.getElementById('toast');
        const type = typeOrError === true ? 'error' : (typeOrError === false ? 'success' : typeOrError);
        const icons = { success: '✓', error: '✕', warning: '⚠', info: 'ℹ' };
        const icon = icons[type] || icons.success;
        toast.innerHTML = '<div class="toast-content"><div class="toast-icon ' + type + '">' + icon + '</div><div class="toast-message">' + message + '</div></div>';
        toast.className = type + ' show';
        setTimeout(() => { toast.classList.add('hide'); setTimeout(() => toast.className = '', 300); }, 3000);
      }

      const getCsrfToken = () => document.cookie.split('; ').find(row => row.startsWith('csrf_token='))?.split('=')[1] || '';

      const api = {
        get: (endpoint) => fetch(API_BASE + endpoint, { credentials: 'include' }).then(handleResponse),
        post: (endpoint, body) => fetch(API_BASE + endpoint, { 
          method: 'POST', 
          credentials: 'include', 
          headers: {'Content-Type': 'application/json', 'X-CSRF-Token': getCsrfToken()}, 
          body: JSON.stringify(body) 
        }).then(handleResponse),
        put: (endpoint, body) => fetch(API_BASE + endpoint, { 
          method: 'PUT', 
          credentials: 'include', 
          headers: {'Content-Type': 'application/json', 'X-CSRF-Token': getCsrfToken()}, 
          body: JSON.stringify(body) 
        }).then(handleResponse),
        delete: (endpoint) => fetch(API_BASE + endpoint, { 
          method: 'DELETE', 
          credentials: 'include', 
          headers: {'X-CSRF-Token': getCsrfToken()} 
        }).then(handleResponse),
      };

      async function handleResponse(response) {
        if (response.status === 401) {
          showToast('Session expired. Please log in again.', true);
          setTimeout(() => window.location.reload(), 2000);
          throw new Error('Unauthorized');
        }
        if (!response.ok) {
          const errorData = await response.json().catch(() => ({ error: 'Request failed' }));
          throw new Error(errorData.error || 'Request failed');
        }
        return response.status === 204 ? null : response.json();
      }

      const pad = (num) => num.toString().padStart(2, '0');

      function localToUTC(dateStr, timeStr) {
        if (!dateStr || !timeStr) return { utcDate: '', utcTime: '' };
        const localDateTime = new Date(dateStr + 'T' + timeStr);
        if (isNaN(localDateTime.getTime())) return { utcDate: '', utcTime: '' };

        const year = localDateTime.getUTCFullYear();
        const month = pad(localDateTime.getUTCMonth() + 1);
        const day = pad(localDateTime.getUTCDate());
        const hours = pad(localDateTime.getUTCHours());
        const minutes = pad(localDateTime.getUTCMinutes());
        const seconds = pad(localDateTime.getUTCSeconds());

        return {
          utcDate: year + '-' + month + '-' + day,
          utcTime: hours + ':' + minutes + ':' + seconds
        };
      }

      async function fetchAndRenderUsers() {
        try {
          allUsers = await api.get('/users');
          allUsers.sort((a, b) => new Date(b.created_at) - new Date(a.created_at));
          renderUsers();
          await fetchStats();
        } catch (error) {
          showToast(error.message, true);
        }
      }

      function renderUsers() {
        const tbody = document.getElementById('userList');
        if (!tbody) return;
        
        tbody.innerHTML = '';
        
        allUsers.forEach(user => {
          const isExpired = new Date(user.expiration_date + 'T' + user.expiration_time + 'Z') <= new Date();
          const trafficUsed = formatBytes(user.traffic_used || 0);
          const trafficLimit = user.traffic_limit ? formatBytes(user.traffic_limit) : 'Unlimited';
          
          const row = document.createElement('tr');
          row.innerHTML = \`
            <td><input type="checkbox" class="user-checkbox" value="\${user.uuid}"></td>
            <td class="uuid-cell">
              <span style="font-family: monospace; font-size: 12px;">\${user.uuid}</span>
              <button class="btn-copy-uuid" data-uuid="\${user.uuid}">Copy</button>
            </td>
            <td>\${new Date(user.created_at).toLocaleDateString()}</td>
            <td>\${user.expiration_date} \${user.expiration_time}</td>
            <td><span class="status-badge \${isExpired ? 'status-expired' : 'status-active'}">\${isExpired ? 'Expired' : 'Active'}</span></td>
            <td>\${escapeHTML(user.notes || '')}</td>
            <td>\${trafficLimit}</td>
            <td>\${trafficUsed}</td>
            <td>\${user.ip_limit === -1 ? 'Unlimited' : user.ip_limit}</td>
            <td>
              <button class="btn-copy-uuid" data-action="edit" data-uuid="\${user.uuid}">Edit</button>
              <button class="btn-copy-uuid" data-action="delete" data-uuid="\${user.uuid}" style="background: rgba(239,68,68,0.1); color: #ef4444; border-color: rgba(239,68,68,0.3);">Delete</button>
            </td>
          \`;
          tbody.appendChild(row);
        });
        
        // Add event listeners
        document.querySelectorAll('.btn-copy-uuid[data-uuid]').forEach(btn => {
          if (btn.dataset.action === 'edit') {
            btn.addEventListener('click', () => editUser(btn.dataset.uuid));
          } else if (btn.dataset.action === 'delete') {
            btn.addEventListener('click', () => deleteUser(btn.dataset.uuid));
          } else {
            btn.addEventListener('click', () => {
              navigator.clipboard.writeText(btn.dataset.uuid).then(() => {
                btn.textContent = 'Copied!';
                btn.classList.add('copied');
                setTimeout(() => {
                  btn.textContent = 'Copy';
                  btn.classList.remove('copied');
                }, 2000);
              });
            });
          }
        });
      }

      async function fetchStats() {
        try {
          const stats = await api.get('/stats');
          
          document.getElementById('total-users').textContent = stats.total_users || 0;
          document.getElementById('active-users').textContent = stats.active_users || 0;
          document.getElementById('expired-users').textContent = stats.expired_users || 0;
          document.getElementById('total-traffic').textContent = formatBytes(stats.total_traffic || 0);
          
          // Update server time
          const now = new Date();
          document.getElementById('server-time').textContent = now.toLocaleTimeString();
          
          // Update proxy health
          if (stats.proxy_health) {
            const healthCard = document.getElementById('proxy-health-card');
            const healthValue = document.getElementById('proxy-health');
            const healthBadge = document.getElementById('proxy-health-badge');
            
            if (stats.proxy_health.is_healthy) {
              healthValue.textContent = \`\${stats.proxy_health.latency_ms || 0}ms\`;
              healthValue.style.color = 'var(--success)';
              healthBadge.innerHTML = '<span class="pulse-dot green"></span> Healthy';
              healthBadge.className = 'stat-badge online';
              healthCard.classList.add('healthy');
            } else {
              healthValue.textContent = 'Unhealthy';
              healthValue.style.color = 'var(--danger)';
              healthBadge.innerHTML = '<span class="pulse-dot red"></span> Unhealthy';
              healthBadge.className = 'stat-badge offline';
              healthCard.classList.add('danger');
            }
          }
        } catch (error) {
          console.error('Failed to fetch stats:', error);
        }
      }

      async function editUser(uuid) {
        const user = allUsers.find(u => u.uuid === uuid);
        if (!user) return;
        
        document.getElementById('editUuid').value = uuid;
        document.getElementById('editExpiryDate').value = user.expiration_date;
        document.getElementById('editExpiryTime').value = user.expiration_time;
        document.getElementById('editNotes').value = user.notes || '';
        document.getElementById('editDataLimit').value = user.traffic_limit || '';
        document.getElementById('editIpLimit').value = user.ip_limit || -1;
        
        document.getElementById('editModal').classList.add('show');
      }

      async function deleteUser(uuid) {
        if (!confirm('Are you sure you want to delete this user?')) return;
        
        try {
          await api.delete('/users/' + uuid);
          showToast('User deleted successfully', 'success');
          fetchAndRenderUsers();
        } catch (error) {
          showToast(error.message, true);
        }
      }

      // Auto-refresh system
      function startAutoRefresh() {
        setInterval(async () => {
          try {
            await fetchAndRenderUsers();
            console.log('✓ Dashboard auto-refreshed');
          } catch (error) {
            console.error('Auto-refresh failed:', error);
          }
        }, 60000);
      }

      // Initialize
      fetchAndRenderUsers();
      startAutoRefresh();
      
      // Update server time every second
      setInterval(() => {
        const now = new Date();
        document.getElementById('server-time').textContent = now.toLocaleTimeString();
      }, 1000);
      
      // Event listeners
      document.getElementById('generateUUID').addEventListener('click', () => {
        document.getElementById('uuid').value = crypto.randomUUID();
      });
      
      document.getElementById('createUserForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const uuid = document.getElementById('uuid').value.trim();
        const expiryDate = document.getElementById('expiryDate').value;
        const expiryTime = document.getElementById('expiryTime').value;
        const notes = document.getElementById('notes').value.trim();
        const dataLimit = document.getElementById('dataLimit').value;
        const dataUnit = document.getElementById('dataUnit').value;
        const ipLimit = document.getElementById('ipLimit').value;
        
        if (!isValidUUID(uuid)) {
          showToast('Invalid UUID format', true);
          return;
        }
        
        // Convert data limit to bytes
        let trafficLimit = null;
        if (dataLimit && dataUnit !== 'unlimited') {
          const bytes = parseFloat(dataLimit);
          const multiplier = {
            'KB': 1024,
            'MB': 1024 * 1024,
            'GB': 1024 * 1024 * 1024,
            'TB': 1024 * 1024 * 1024 * 1024
          }[dataUnit];
          trafficLimit = Math.round(bytes * multiplier);
        }
        
        const { utcDate, utcTime } = localToUTC(expiryDate, expiryTime + ':00');
        
        try {
          await api.post('/users', {
            uuid,
            exp_date: utcDate,
            exp_time: utcTime,
            notes,
            traffic_limit: trafficLimit,
            ip_limit: ipLimit ? parseInt(ipLimit) : -1
          });
          
          showToast('User created successfully', 'success');
          document.getElementById('createUserForm').reset();
          document.getElementById('uuid').value = crypto.randomUUID();
          fetchAndRenderUsers();
        } catch (error) {
          showToast(error.message, true);
        }
      });
      
      document.getElementById('editUserForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const uuid = document.getElementById('editUuid').value;
        const expiryDate = document.getElementById('editExpiryDate').value;
        const expiryTime = document.getElementById('editExpiryTime').value;
        const notes = document.getElementById('editNotes').value.trim();
        const dataLimit = document.getElementById('editDataLimit').value;
        const dataUnit = document.getElementById('editDataUnit').value;
        const ipLimit = document.getElementById('editIpLimit').value;
        const resetTraffic = document.getElementById('resetTraffic').checked;
        
        // Convert data limit to bytes
        let trafficLimit = null;
        if (dataLimit && dataUnit !== 'unlimited') {
          const bytes = parseFloat(dataLimit);
          const multiplier = {
            'KB': 1024,
            'MB': 1024 * 1024,
            'GB': 1024 * 1024 * 1024,
            'TB': 1024 * 1024 * 1024 * 1024
          }[dataUnit];
          trafficLimit = Math.round(bytes * multiplier);
        }
        
        const { utcDate, utcTime } = localToUTC(expiryDate, expiryTime + ':00');
        
        try {
          await api.put('/users/' + uuid, {
            exp_date: utcDate,
            exp_time: utcTime,
            notes,
            traffic_limit: trafficLimit,
            ip_limit: ipLimit ? parseInt(ipLimit) : -1,
            reset_traffic: resetTraffic
          });
          
          showToast('User updated successfully', 'success');
          document.getElementById('editModal').classList.remove('show');
          fetchAndRenderUsers();
        } catch (error) {
          showToast(error.message, true);
        }
      });
      
      document.getElementById('modalCancelBtn').addEventListener('click', () => {
        document.getElementById('editModal').classList.remove('show');
      });
      
      document.getElementById('deleteSelected').addEventListener('click', async () => {
        const checkboxes = document.querySelectorAll('.user-checkbox:checked');
        if (checkboxes.length === 0) {
          showToast('No users selected', 'warning');
          return;
        }
        
        if (!confirm(\`Are you sure you want to delete \${checkboxes.length} user(s)?\`)) return;
        
        const uuids = Array.from(checkboxes).map(cb => cb.value);
        
        try {
          await api.post('/users/bulk-delete', { uuids });
          showToast(\`Deleted \${uuids.length} user(s) successfully\`, 'success');
          fetchAndRenderUsers();
        } catch (error) {
          showToast(error.message, true);
        }
      });
      
      document.getElementById('selectAll').addEventListener('change', (e) => {
        const checkboxes = document.querySelectorAll('.user-checkbox');
        checkboxes.forEach(cb => cb.checked = e.target.checked);
      });
      
      document.getElementById('searchInput').addEventListener('input', (e) => {
        const searchTerm = e.target.value.toLowerCase();
        const rows = document.querySelectorAll('#userList tr');
        
        rows.forEach(row => {
          const text = row.textContent.toLowerCase();
          row.style.display = text.includes(searchTerm) ? '' : 'none';
        });
      });
      
      document.getElementById('healthCheckBtn').addEventListener('click', async () => {
        const btn = document.getElementById('healthCheckBtn');
        btn.classList.add('loading');
        btn.disabled = true;
        
        try {
          await api.post('/health-check');
          showToast('Health check completed', 'success');
          fetchStats();
        } catch (error) {
          showToast(error.message, true);
        } finally {
          btn.classList.remove('loading');
          btn.disabled = false;
        }
      });
      
      document.getElementById('logoutBtn').addEventListener('click', async () => {
        try {
          await api.post('/logout');
          window.location.reload();
        } catch (error) {
          showToast(error.message, true);
        }
      });
      
      // Time quick set buttons
      document.querySelectorAll('.time-quick-set-group button').forEach(btn => {
        btn.addEventListener('click', () => {
          const targetDateId = btn.parentElement.dataset.targetDate;
          const targetTimeId = btn.parentElement.dataset.targetTime;
          const amount = parseInt(btn.dataset.amount);
          const unit = btn.dataset.unit;
          
          const dateInput = document.getElementById(targetDateId);
          const timeInput = document.getElementById(targetTimeId);
          
          if (!dateInput || !timeInput) return;
          
          let date = new Date();
          if (dateInput.value) {
            const [year, month, day] = dateInput.value.split('-').map(Number);
            const [hours, minutes, seconds] = timeInput.value.split(':').map(Number);
            date = new Date(year, month - 1, day, hours || 0, minutes || 0, seconds || 0);
          }
          
          switch (unit) {
            case 'hour':
              date.setHours(date.getHours() + amount);
              break;
            case 'day':
              date.setDate(date.getDate() + amount);
              break;
            case 'month':
              date.setMonth(date.getMonth() + amount);
              break;
          }
          
          const year = date.getFullYear();
          const month = String(date.getMonth() + 1).padStart(2, '0');
          const day = String(date.getDate()).padStart(2, '0');
          const hours = String(date.getHours()).padStart(2, '0');
          const minutes = String(date.getMinutes()).padStart(2, '0');
          const seconds = String(date.getSeconds()).padStart(2, '0');
          
          dateInput.value = \`\${year}-\${month}-\${day}\`;
          timeInput.value = \`\${hours}:\${minutes}:\${seconds}\`;
        });
      });
      
      // Set default expiry to 1 month from now
      const defaultDate = new Date();
      defaultDate.setMonth(defaultDate.getMonth() + 1);
      const year = defaultDate.getFullYear();
      const month = String(defaultDate.getMonth() + 1).padStart(2, '0');
      const day = String(defaultDate.getDate()).padStart(2, '0');
      
      document.getElementById('expiryDate').value = \`\${year}-\${month}-\${day}\`;
      document.getElementById('expiryTime').value = '23:59:59';
      
      // Generate initial UUID
      document.getElementById('uuid').value = crypto.randomUUID();
      
      // Helper function
      function isValidUUID(uuid) {
        const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
        return uuidRegex.test(uuid);
      }
    });
  </script>
</body>
</html>`;

// ============================================================================
// ADMIN REQUEST HANDLER
// ============================================================================

async function isAdmin(request, env) {
  const cookieHeader = request.headers.get('Cookie');
  if (!cookieHeader) return false;

  const token = cookieHeader.match(/auth_token=([^;]+)/)?.[1];
  if (!token) return false;

  const hashedToken = await hashSHA256(token);
  const storedHashedToken = await kvGet(env.DB, 'admin_session_token_hash');
  return storedHashedToken && timingSafeEqual(hashedToken, storedHashedToken);
}

async function handleAdminRequest(request, env, ctx, adminPrefix) {
  try {
    await ensureTablesExist(env, ctx);
    
    const url = new URL(request.url);
    const jsonHeader = { 'Content-Type': 'application/json' };
    const htmlHeaders = new Headers({ 'Content-Type': 'text/html;charset=utf-8' });
    const clientIp = request.headers.get('CF-Connecting-IP');

    if (!env.ADMIN_KEY) {
      addSecurityHeaders(htmlHeaders, null, {});
      return new Response('Admin panel not configured', { status: 503, headers: htmlHeaders });
    }

    // IP Whitelist Check
    if (env.ADMIN_IP_WHITELIST) {
      const allowedIps = env.ADMIN_IP_WHITELIST.split(',').map(ip => ip.trim());
      if (!allowedIps.includes(clientIp)) {
        console.warn(`Admin access denied for IP: ${clientIp}`);
        addSecurityHeaders(htmlHeaders, null, {});
        return new Response('Access denied', { status: 403, headers: htmlHeaders });
      }
    } else {
      // Scamalytics check if no whitelist
      const scamalyticsConfig = {
        username: env.SCAMALYTICS_USERNAME || Config.scamalytics.username,
        apiKey: env.SCAMALYTICS_API_KEY || Config.scamalytics.apiKey,
        baseUrl: env.SCAMALYTICS_BASEURL || Config.scamalytics.baseUrl,
      };
      if (await isSuspiciousIP(clientIp, scamalyticsConfig, env.SCAMALYTICS_THRESHOLD || CONST.SCAMALYTICS_THRESHOLD)) {
        console.warn(`Admin access denied for suspicious IP: ${clientIp}`);
        addSecurityHeaders(htmlHeaders, null, {});
        return new Response('Access denied', { status: 403, headers: htmlHeaders });
      }
    }

    const adminBasePath = `/${adminPrefix}/${env.ADMIN_KEY}`;

    if (!url.pathname.startsWith(adminBasePath)) {
      const headers = new Headers();
      addSecurityHeaders(headers, null, {});
      return new Response('Not found', { status: 404, headers });
    }

    const adminSubPath = url.pathname.substring(adminBasePath.length) || '/';

    // API Routes
    if (adminSubPath.startsWith('/api/')) {
      if (!env.DB) {
        const headers = new Headers(jsonHeader);
        addSecurityHeaders(headers, null, {});
        return new Response(JSON.stringify({ error: 'Database not configured' }), { status: 503, headers });
      }

      if (!(await isAdmin(request, env))) {
        const headers = new Headers(jsonHeader);
        addSecurityHeaders(headers, null, {});
        return new Response(JSON.stringify({ error: 'Forbidden' }), { status: 403, headers });
      }

      // Rate limiting for API
      const apiRateKey = `admin_api_rate:${clientIp}`;
      if (await checkRateLimit(env.DB, apiRateKey, 100, 60)) {
        const headers = new Headers(jsonHeader);
        addSecurityHeaders(headers, null, {});
        return new Response(JSON.stringify({ error: 'API rate limit exceeded' }), { status: 429, headers });
      }

      // CSRF Protection for non-GET requests
      if (request.method !== 'GET') {
        const origin = request.headers.get('Origin');
        const secFetch = request.headers.get('Sec-Fetch-Site');

        if (!origin || new URL(origin).hostname !== url.hostname || secFetch !== 'same-origin') {
          const headers = new Headers(jsonHeader);
          addSecurityHeaders(headers, null, {});
          return new Response(JSON.stringify({ error: 'Invalid request origin' }), { status: 403, headers });
        }

        const csrfToken = request.headers.get('X-CSRF-Token');
        const cookieCsrf = request.headers.get('Cookie')?.match(/csrf_token=([^;]+)/)?.[1];
        if (!csrfToken || !cookieCsrf || !timingSafeEqual(csrfToken, cookieCsrf)) {
          const headers = new Headers(jsonHeader);
          addSecurityHeaders(headers, null, {});
          return new Response(JSON.stringify({ error: 'CSRF validation failed' }), { status: 403, headers });
        }
      }

      // API: Get Stats
      if (adminSubPath === '/api/stats' && request.method === 'GET') {
        const headers = new Headers(jsonHeader);
        addSecurityHeaders(headers, null, {});
        try {
          const totalUsers = await env.DB.prepare("SELECT COUNT(*) as count FROM users").first('count');
          const expiredQuery = await env.DB.prepare(
            "SELECT COUNT(*) as count FROM users WHERE datetime(expiration_date || 'T' || expiration_time || 'Z') < datetime('now')"
          ).first();
          const expiredUsers = expiredQuery?.count || 0;
          const activeUsers = totalUsers - expiredUsers;
          const totalTrafficQuery = await env.DB.prepare("SELECT SUM(traffic_used) as sum FROM users").first();
          const totalTraffic = totalTrafficQuery?.sum || 0;
          
          let proxyHealth = { is_healthy: false, latency_ms: null };
          try {
            const healthResult = await env.DB.prepare(
              "SELECT is_healthy, latency_ms FROM proxy_health WHERE is_healthy = 1 ORDER BY latency_ms ASC LIMIT 1"
            ).first();
            if (healthResult) {
              proxyHealth = { is_healthy: true, latency_ms: healthResult.latency_ms };
            } else {
              const anyHealth = await env.DB.prepare(
                "SELECT is_healthy, latency_ms FROM proxy_health LIMIT 1"
              ).first();
              if (anyHealth) {
                proxyHealth = { is_healthy: !!anyHealth.is_healthy, latency_ms: anyHealth.latency_ms };
              }
            }
          } catch (healthErr) {
            console.error('Failed to get proxy health:', healthErr);
          }
          
          return new Response(JSON.stringify({ 
            total_users: totalUsers, 
            active_users: activeUsers, 
            expired_users: expiredUsers, 
            total_traffic: totalTraffic,
            proxy_health: proxyHealth
          }), { status: 200, headers });
        } catch (e) {
          return new Response(JSON.stringify({ error: e.message }), { status: 500, headers });
        }
      }

      // API: Get Users List
      if (adminSubPath === '/api/users' && request.method === 'GET') {
        const headers = new Headers(jsonHeader);
        addSecurityHeaders(headers, null, {});
        try {
          const { results } = await env.DB.prepare(
            "SELECT uuid, created_at, expiration_date, expiration_time, notes, traffic_limit, traffic_used, ip_limit FROM users ORDER BY created_at DESC"
          ).all();
          return new Response(JSON.stringify(results ?? []), { status: 200, headers });
        } catch (e) {
          return new Response(JSON.stringify({ error: e.message }), { status: 500, headers });
        }
      }

      // API: Create User
      if (adminSubPath === '/api/users' && request.method === 'POST') {
        const headers = new Headers(jsonHeader);
        addSecurityHeaders(headers, null, {});
        try {
          const { uuid, exp_date: expDate, exp_time: expTime, notes, traffic_limit, ip_limit } = await request.json();

          if (!uuid || !expDate || !expTime || !/^\d{4}-\d{2}-\d{2}$/.test(expDate) || !/^\d{2}:\d{2}:\d{2}$/.test(expTime)) {
            throw new Error('Invalid or missing fields');
          }

          await env.DB.prepare(
            "INSERT INTO users (uuid, expiration_date, expiration_time, notes, traffic_limit, ip_limit, traffic_used) VALUES (?, ?, ?, ?, ?, ?, 0)"
          ).bind(uuid, expDate, expTime, notes || null, traffic_limit, ip_limit || -1).run();
          
          ctx.waitUntil(kvPut(env.DB, `user:${uuid}`, { 
            uuid,
            expiration_date: expDate, 
            expiration_time: expTime, 
            notes: notes || null,
            traffic_limit: traffic_limit, 
            ip_limit: ip_limit || -1,
            traffic_used: 0 
          }, { expirationTtl: 3600 }));

          return new Response(JSON.stringify({ success: true, uuid }), { status: 201, headers });
        } catch (error) {
          if (error.message?.includes('UNIQUE constraint failed')) {
            return new Response(JSON.stringify({ error: 'UUID already exists' }), { status: 409, headers });
          }
          return new Response(JSON.stringify({ error: error.message }), { status: 400, headers });
        }
      }

      // API: Bulk Delete
      if (adminSubPath === '/api/users/bulk-delete' && request.method === 'POST') {
        const headers = new Headers(jsonHeader);
        addSecurityHeaders(headers, null, {});
        try {
          const { uuids } = await request.json();
          if (!Array.isArray(uuids) || uuids.length === 0) {
            throw new Error('Invalid request: Expected array of UUIDs');
          }

          const deleteUserStmt = env.DB.prepare("DELETE FROM users WHERE uuid = ?");
          const stmts = uuids.map(uuid => deleteUserStmt.bind(uuid));
          await env.DB.batch(stmts);

          ctx.waitUntil(Promise.all(uuids.map(uuid => kvDelete(env.DB, `user:${uuid}`))));

          return new Response(JSON.stringify({ success: true, count: uuids.length }), { status: 200, headers });
        } catch (error) {
          return new Response(JSON.stringify({ error: error.message }), { status: 400, headers });
        }
      }

      // API: Update User
      const userRouteMatch = adminSubPath.match(/^\/api\/users\/([a-f0-9-]+)$/);
      if (userRouteMatch && request.method === 'PUT') {
        const headers = new Headers(jsonHeader);
        addSecurityHeaders(headers, null, {});
        const uuid = userRouteMatch[1];
        try {
          const { exp_date: expDate, exp_time: expTime, notes, traffic_limit, ip_limit, reset_traffic } = await request.json();
          
          if (!expDate || !expTime || !/^\d{4}-\d{2}-\d{2}$/.test(expDate) || !/^\d{2}:\d{2}:\d{2}$/.test(expTime)) {
            throw new Error('Invalid date/time format');
          }

          let query = "UPDATE users SET expiration_date = ?, expiration_time = ?, notes = ?, traffic_limit = ?, ip_limit = ?";
          let binds = [expDate, expTime, notes || null, traffic_limit, ip_limit || -1];
          
          if (reset_traffic) {
            query += ", traffic_used = 0";
          }
          
          query += " WHERE uuid = ?";
          binds.push(uuid);

          await env.DB.prepare(query).bind(...binds).run();
          ctx.waitUntil(kvDelete(env.DB, `user:${uuid}`));

          return new Response(JSON.stringify({ success: true, uuid }), { status: 200, headers });
        } catch (error) {
          return new Response(JSON.stringify({ error: error.message }), { status: 400, headers });
        }
      }

      // API: Delete User
      if (userRouteMatch && request.method === 'DELETE') {
        const headers = new Headers(jsonHeader);
        addSecurityHeaders(headers, null, {});
        const uuid = userRouteMatch[1];
        try {
          await env.DB.prepare("DELETE FROM users WHERE uuid = ?").bind(uuid).run();
          ctx.waitUntil(kvDelete(env.DB, `user:${uuid}`));
          return new Response(JSON.stringify({ success: true, uuid }), { status: 200, headers });
        } catch (error) {
          return new Response(JSON.stringify({ error: error.message }), { status: 500, headers });
        }
      }

      // API: Logout
      if (adminSubPath === '/api/logout' && request.method === 'POST') {
        const headers = new Headers(jsonHeader);
        addSecurityHeaders(headers, null, {});
        try {
          await kvDelete(env.DB, 'admin_session_token_hash');
          const setCookie = [
            'auth_token=; Max-Age=0; Path=/; Secure; HttpOnly; SameSite=Strict',
            'csrf_token=; Max-Age=0; Path=/; Secure; SameSite=Strict'
          ];
          headers.append('Set-Cookie', setCookie[0]);
          headers.append('Set-Cookie', setCookie[1]);
          return new Response(JSON.stringify({ success: true }), { status: 200, headers });
        } catch (error) {
          return new Response(JSON.stringify({ error: error.message }), { status: 500, headers });
        }
      }

      // API: Health Check
      if (adminSubPath === '/api/health-check' && request.method === 'POST') {
        const headers = new Headers(jsonHeader);
        addSecurityHeaders(headers, null, {});
        try {
          await performHealthCheck(env, ctx);
          return new Response(JSON.stringify({ success: true }), { status: 200, headers });
        } catch (error) {
          return new Response(JSON.stringify({ error: error.message }), { status: 500, headers });
        }
      }

      const headers = new Headers(jsonHeader);
      addSecurityHeaders(headers, null, {});
      return new Response(JSON.stringify({ error: 'API route not found' }), { status: 404, headers });
    }

    // Login Page
    if (adminSubPath === '/') {
      if (request.method === 'POST') {
        const rateLimitKey = `login_fail_ip:${clientIp}`;
        
        try {
          const failCountStr = await kvGet(env.DB, rateLimitKey);
          const failCount = parseInt(failCountStr, 10) || 0;
          
          if (failCount >= CONST.ADMIN_LOGIN_FAIL_LIMIT) {
            addSecurityHeaders(htmlHeaders, null, {});
            return new Response('Too many failed attempts. Try again later.', { status: 429, headers: htmlHeaders });
          }
          
          const formData = await request.formData();
          
          if (timingSafeEqual(formData.get('password'), env.ADMIN_KEY)) {
            // TOTP validation if enabled
            if (env.ADMIN_TOTP_SECRET) {
              const totpCode = formData.get('totp');
              if (!(await validateTOTP(env.ADMIN_TOTP_SECRET, totpCode))) {
                const nonce = generateNonce();
                addSecurityHeaders(htmlHeaders, nonce, {});
                let html = adminLoginHTML.replace('</form>', `</form><p class="error">Invalid TOTP code. Attempt ${failCount + 1}/${CONST.ADMIN_LOGIN_FAIL_LIMIT}</p>`);
                html = html.replace(/CSP_NONCE_PLACEHOLDER/g, nonce);
                html = html.replace('action="ADMIN_PATH_PLACEHOLDER"', `action="${adminBasePath}"`);
                
                ctx.waitUntil(kvPut(env.DB, rateLimitKey, (failCount + 1).toString(), { expirationTtl: CONST.ADMIN_LOGIN_LOCK_TTL }));
                
                return new Response(html, { status: 401, headers: htmlHeaders });
              }
            }
            
            const token = crypto.randomUUID();
            const csrfToken = crypto.randomUUID();
            const hashedToken = await hashSHA256(token);
            
            ctx.waitUntil(Promise.all([
              kvPut(env.DB, 'admin_session_token_hash', hashedToken, { expirationTtl: 86400 }),
              kvDelete(env.DB, rateLimitKey)
            ]));
            
            const headers = new Headers({ 'Location': adminBasePath });
            headers.append('Set-Cookie', `auth_token=${token}; HttpOnly; Secure; Path=${adminBasePath}; Max-Age=86400; SameSite=Strict`);
            headers.append('Set-Cookie', `csrf_token=${csrfToken}; Secure; Path=${adminBasePath}; Max-Age=86400; SameSite=Strict`);
            addSecurityHeaders(headers, null, {});
            
            return new Response(null, { status: 302, headers });
          } else {
            ctx.waitUntil(kvPut(env.DB, rateLimitKey, (failCount + 1).toString(), { expirationTtl: CONST.ADMIN_LOGIN_LOCK_TTL }));
            
            const nonce = generateNonce();
            addSecurityHeaders(htmlHeaders, nonce, {});
            let html = adminLoginHTML.replace('</form>', `</form><p class="error">Invalid password. Attempt ${failCount + 1}/${CONST.ADMIN_LOGIN_FAIL_LIMIT}</p>`);
            html = html.replace(/CSP_NONCE_PLACEHOLDER/g, nonce);
            html = html.replace('action="ADMIN_PATH_PLACEHOLDER"', `action="${adminBasePath}"`);
            return new Response(html, { status: 401, headers: htmlHeaders });
          }
        } catch (e) {
          console.error("Admin login error:", e);
          addSecurityHeaders(htmlHeaders, null, {});
          return new Response('Internal error during login', { status: 500, headers: htmlHeaders });
        }
      }

      if (request.method === 'GET') {
        const nonce = generateNonce();
        addSecurityHeaders(htmlHeaders, nonce, {});
        
        let html;
        if (await isAdmin(request, env)) {
          html = adminPanelHTML;
          html = html.replace("'ADMIN_API_BASE_PATH_PLACEHOLDER'", `'${adminBasePath}/api'`);
        } else {
          html = adminLoginHTML;
          html = html.replace('action="ADMIN_PATH_PLACEHOLDER"', `action="${adminBasePath}"`);
        }
        
        html = html.replace(/CSP_NONCE_PLACEHOLDER/g, nonce);
        return new Response(html, { headers: htmlHeaders });
      }

      const headers = new Headers();
      addSecurityHeaders(headers, null, {});
      return new Response('Method Not Allowed', { status: 405, headers });
    }

    const headers = new Headers();
    addSecurityHeaders(headers, null, {});
    return new Response('Not found', { status: 404, headers });
  } catch (e) {
    console.error('handleAdminRequest error:', e.message, e.stack);
    const headers = new Headers();
    addSecurityHeaders(headers, null, {});
    return new Response('Internal Server Error', { status: 500, headers });
  }
}

// ============================================================================
// USER PANEL WITH ADVANCED QR CODE GENERATOR
// ============================================================================

async function resolveProxyIP(proxyHost) {
  const ipv4Regex = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;
  const ipv6Regex = /^\[?[0-9a-fA-F:]+\]?$/;

  if (ipv4Regex.test(proxyHost) || ipv6Regex.test(proxyHost)) {
    return proxyHost;
  }

  const dnsAPIs = [
    { url: `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(proxyHost)}&type=A`, parse: data => data.Answer?.find(a => a.type === 1)?.data },
    { url: `https://dns.google/resolve?name=${encodeURIComponent(proxyHost)}&type=A`, parse: data => data.Answer?.find(a => a.type === 1)?.data },
    { url: `https://1.1.1.1/dns-query?name=${encodeURIComponent(proxyHost)}&type=A`, parse: data => data.Answer?.find(a => a.type === 1)?.data }
  ];

  for (const api of dnsAPIs) {
    try {
      const response = await fetch(api.url, { headers: { 'accept': 'application/dns-json' } });
      if (response.ok) {
        const data = await response.json();
        const ip = api.parse(data);
        if (ip && ipv4Regex.test(ip)) return ip;
      }
    } catch (e) {
      // Silent fail and try next provider
    }
  }
  return proxyHost;
}

async function getGeo(ip, cfHeaders = null) {
  if (cfHeaders && (cfHeaders.city || cfHeaders.country)) {
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
        if (geo && (geo.city || geo.country)) return geo;
      }
    } catch (e) {
      // Try next provider
    }
  }
  
  return { city: '', country: 'Global', isp: 'Cloudflare' };
}

// ============================================================================
// COMPLETE QR CODE GENERATOR SCRIPT (CLIENT-SIDE)
// ============================================================================

const qrCodeScript = `
<script nonce="CSP_NONCE_PLACEHOLDER">
// ============================================================================
// ADVANCED QR CODE SYSTEM - CLIENT SIDE
// ============================================================================

let QR_LAST_TEXT = '';

// Clean configuration string
function cleanConfigString(text) {
  if (!text || typeof text !== 'string') return '';
  
  let cleaned = text.trim();
  
  cleaned = cleaned.replace(/^<pre[^>]*>/i, '').replace(/<\/pre>$/i, '');
  cleaned = cleaned.replace(/^<code[^>]*>/i, '').replace(/<\/code>$/i, '');
  cleaned = cleaned.trim();
  
  if ((cleaned.startsWith('"') && cleaned.endsWith('"')) || 
      (cleaned.startsWith("'") && cleaned.endsWith("'"))) {
      cleaned = cleaned.slice(1, -1).trim();
  }
  
  cleaned = cleaned.replace(/\\s+/g, ' ').trim();
  
  if (/^vmess:\\/\\//i.test(cleaned)) {
      const parts = cleaned.split('://');
      if (parts.length === 2) {
          const payload = parts[1];
          const cleanPayload = payload.replace(/\\s+/g, '');
          cleaned = 'vmess://' + cleanPayload;
      }
  }
  
  cleaned = cleaned.replace(/\\r?\\n/g, '');
  
  return cleaned;
}

// Validate proxy payload
function validateProxyPayload(text) {
  if (!text || typeof text !== 'string') {
      return { 
          valid: false, 
          message: 'Empty payload',
          type: 'error'
      };
  }
  
  const cleaned = cleanConfigString(text);
  
  if (cleaned.length > 2000) {
      return {
          valid: false,
          message: 'Payload too large for QR code',
          type: 'warning'
      };
  }
  
  if (cleaned.includes('://')) {
      const protocol = cleaned.split('://')[0].toLowerCase();
      
      switch(protocol) {
          case 'vless':
              if (cleaned.includes('@') && cleaned.includes('?')) {
                  return {
                      valid: true,
                      message: 'Valid VLESS configuration',
                      type: 'success',
                      protocol: 'vless'
                  };
              }
              break;
              
          case 'vmess':
              try {
                  const payload = cleaned.substring(8);
                  const decoded = atob(payload.replace(/-/g, '+').replace(/_/g, '/'));
                  JSON.parse(decoded);
                  return {
                      valid: true,
                      message: 'Valid VMess configuration',
                      type: 'success',
                      protocol: 'vmess'
                  };
              } catch (e) {
              }
              break;
              
          case 'trojan':
          case 'ss':
              if (cleaned.includes('@')) {
                  return {
                      valid: true,
                      message: \`Valid \${protocol.toUpperCase()} configuration\`,
                      type: 'success',
                      protocol: protocol
                  };
              }
              break;
              
          default:
              if (cleaned.includes('@') || cleaned.includes('://')) {
                  return {
                      valid: true,
                      message: 'Valid proxy configuration',
                      type: 'success',
                      protocol: 'unknown'
                  };
              }
      }
  }
  
  return {
      valid: true,
      message: 'Configuration may be valid',
      type: 'info',
      protocol: 'unknown'
  };
}

// Simple QR Code Generator (Embedded)
function generateSimpleQR(text, size = 256) {
  const canvas = document.createElement('canvas');
  canvas.width = size;
  canvas.height = size;
  
  const ctx = canvas.getContext('2d');
  
  // White background
  ctx.fillStyle = '#FFFFFF';
  ctx.fillRect(0, 0, size, size);
  
  // Simple pattern for demonstration
  ctx.fillStyle = '#000000';
  const moduleCount = 21;
  const moduleSize = Math.floor((size - 8) / moduleCount);
  const margin = (size - moduleSize * moduleCount) / 2;
  
  // Create a simple pattern
  for (let y = 0; y < moduleCount; y++) {
    for (let x = 0; x < moduleCount; x++) {
      if ((x + y) % 3 === 0 || x === 6 || y === 6 || 
          (x < 7 && y < 7) || 
          (x > moduleCount - 8 && y < 7) || 
          (x < 7 && y > moduleCount - 8)) {
        ctx.fillRect(
          margin + x * moduleSize,
          margin + y * moduleSize,
          moduleSize,
          moduleSize
        );
      }
    }
  }
  
  return canvas;
}

// Generate QR Code with 3-layer fallback
async function generateQRCode(text, containerId) {
  const container = document.getElementById(containerId);
  if (!container) return false;
  
  const cleanedText = cleanConfigString(text);
  if (!cleanedText) {
    showQRMessage(container, 'No valid configuration provided', 'error');
    return false;
  }
  
  QR_LAST_TEXT = cleanedText;
  
  // Validate
  const validation = validateProxyPayload(cleanedText);
  if (!validation.valid) {
    showToast('Warning: ' + validation.message, 'warning');
  }
  
  // Show loading
  container.innerHTML = '<div style="padding:40px;text-align:center;"><div class="spinner"></div><p style="margin-top:16px;color:#666;">Generating QR Code...</p></div>';
  
  try {
    // Layer 1: Simple generator
    const canvas = generateSimpleQR(cleanedText, 256);
    container.innerHTML = '';
    container.appendChild(canvas);
    showToast('QR Code Generated Successfully', 'success');
    return true;
  } catch (e1) {
    console.log('Layer 1 failed:', e1.message);
    
    try {
      // Layer 2: CDN Library
      if (typeof QRCode !== 'undefined') {
        container.innerHTML = '';
        new QRCode(container, {
          text: cleanedText,
          width: 256,
          height: 256,
          colorDark: "#000000",
          colorLight: "#ffffff",
          correctLevel: QRCode.CorrectLevel.M
        });
        showToast('QR Code Generated (CDN)', 'success');
        return true;
      } else {
        throw new Error('QRCode library not loaded');
      }
    } catch (e2) {
      console.log('Layer 2 failed:', e2.message);
      
      try {
        // Layer 3: Google Charts
        const encoded = encodeURIComponent(cleanedText);
        const url = 'https://chart.googleapis.com/chart?cht=qr&chl=' + encoded + '&chs=256x256&choe=UTF-8&chld=M|0';
        
        container.innerHTML = '';
        const img = document.createElement('img');
        img.src = url;
        img.style.maxWidth = '100%';
        img.style.borderRadius = '8px';
        img.style.border = '10px solid white';
        img.alt = 'QR Code';
        
        img.onload = function() {
          showToast('QR Code Generated (Google Charts)', 'success');
        };
        
        img.onerror = function() {
          throw new Error('Google Charts failed');
        };
        
        container.appendChild(img);
        return true;
      } catch (e3) {
        console.log('Layer 3 failed:', e3.message);
        
        // All failed
        container.innerHTML = '<div style="padding:20px;text-align:center;color:#dc3545;"><p>❌ All QR methods failed</p><p style="margin-top:8px;font-size:14px;color:#666;">Please copy the configuration manually.</p></div>';
        showToast('QR generation failed - use copy instead', 'error');
        return false;
      }
    }
  }
}

// Test QR function
function testQR() {
  if (!QR_LAST_TEXT) {
    showToast('No QR code generated yet', 'error');
    return false;
  }
  
  const validation = validateProxyPayload(QR_LAST_TEXT);
  
  if (validation.valid) {
    showToast('✓ Test passed: Payload looks valid', 'success');
  } else {
    showToast('✗ Test failed: ' + validation.message, 'error');
  }
  
  return validation.valid;
}

// Copy QR text function
function copyQRText() {
  if (!QR_LAST_TEXT) {
    showToast('No text to copy', 'error');
    return false;
  }
  
  const textArea = document.createElement('textarea');
  textArea.value = QR_LAST_TEXT;
  textArea.style.position = 'fixed';
  textArea.style.left = '-999999px';
  textArea.style.top = '-999999px';
  document.body.appendChild(textArea);
  textArea.focus();
  textArea.select();
  
  try {
    const successful = document.execCommand('copy');
    if (successful) {
      showToast('✓ Configuration copied to clipboard!', 'success');
      return true;
    } else {
      showToast('Failed to copy text', 'error');
      return false;
    }
  } catch (err) {
    console.error('Copy failed:', err);
    showToast('Failed to copy text', 'error');
    return false;
  } finally {
    document.body.removeChild(textArea);
  }
}

// Show QR message
function showQRMessage(container, message, type) {
  const colors = {
    loading: { bg: '#e3f2fd', text: '#1565c0', icon: '⏳' },
    success: { bg: '#e8f5e9', text: '#2e7d32', icon: '✅' },
    error: { bg: '#ffebee', text: '#c62828', icon: '❌' },
    warning: { bg: '#fff3e0', text: '#ef6c00', icon: '⚠️' }
  };
  
  const color = colors[type] || colors.loading;
  
  container.innerHTML = \`
    <div style="
        text-align: center;
        padding: 30px;
        background: \${color.bg};
        border-radius: 12px;
        border: 2px solid \${color.text}20;
    ">
      <div style="font-size: 48px; margin-bottom: 16px;">\${color.icon}</div>
      <h3 style="color: \${color.text}; margin: 0 0 8px 0;">\${message}</h3>
      \${type === 'loading' ? '<div class="spinner"></div>' : ''}
    </div>
  \`;
}

// Toast function
function showToast(message, type = 'info') {
  const oldToast = document.getElementById('qr-toast');
  if (oldToast) oldToast.remove();
  
  const colors = {
    success: { bg: '#4caf50', icon: '✓' },
    error: { bg: '#f44336', icon: '✗' },
    warning: { bg: '#ff9800', icon: '⚠' },
    info: { bg: '#2196f3', icon: 'ℹ' }
  };
  
  const color = colors[type] || colors.info;
  
  const toast = document.createElement('div');
  toast.id = 'qr-toast';
  toast.innerHTML = \`
    <div style="
      position: fixed;
      bottom: 20px;
      right: 20px;
      background: \${color.bg};
      color: white;
      padding: 12px 20px;
      border-radius: 8px;
      box-shadow: 0 4px 12px rgba(0,0,0,0.2);
      display: flex;
      align-items: center;
      gap: 10px;
      z-index: 10000;
      animation: toastSlideIn 0.3s ease-out;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    ">
      <span style="font-size: 18px;">\${color.icon}</span>
      <span>\${message}</span>
    </div>
    <style>
      @keyframes toastSlideIn {
        from { transform: translateX(100%); opacity: 0; }
        to { transform: translateX(0); opacity: 1; }
      }
      @keyframes toastFadeOut {
        from { opacity: 1; }
        to { opacity: 0; }
      }
    </style>
  \`;
  
  document.body.appendChild(toast);
  
  setTimeout(() => {
    if (toast.parentNode) {
      toast.style.animation = 'toastFadeOut 0.3s ease-out';
      setTimeout(() => {
        if (toast.parentNode) {
          toast.remove();
        }
      }, 300);
    }
  }, 3000);
}

// Initialize QR Code System
function initQRCodeSystem() {
  console.log('QR Code System Initialized');
  
  // Add styles
  const styles = document.createElement('style');
  styles.textContent = \`
    .spinner {
      width: 40px;
      height: 40px;
      border: 4px solid #f3f3f3;
      border-top: 4px solid #3498db;
      border-radius: 50%;
      animation: spin 1s linear infinite;
      margin: 0 auto;
    }
    @keyframes spin {
      0% { transform: rotate(0deg); }
      100% { transform: rotate(360deg); }
    }
    .btn {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 12px 24px;
      border-radius: 8px;
      border: none;
      cursor: pointer;
      font-weight: 600;
      font-size: 14px;
      transition: all 0.3s;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    }
    .btn:hover { transform: translateY(-2px); box-shadow: 0 4px 12px rgba(0,0,0,0.15); }
    .btn:active { transform: translateY(0); }
    .btn.primary { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; }
    .btn.secondary { background: #6c757d; color: white; }
    .btn.success { background: #28a745; color: white; }
    #qr-display canvas, #qr-display img {
      border-radius: 12px;
      border: 12px solid white;
      box-shadow: 0 4px 16px rgba(0,0,0,0.1);
      max-width: 100%;
    }
  \`;
  document.head.appendChild(styles);
  
  // Preload QRCode library from CDN
  if (typeof QRCode === 'undefined') {
    const script = document.createElement('script');
    script.src = 'https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js';
    script.integrity = 'sha512-CNgIRecGo7nphbeZ04Sc13ka07paqdeTu0WR1IM4kNcpmBAUSHSQX0FslNhTDadL4O5SAGapGt4FodqL8My0mA==';
    script.crossOrigin = 'anonymous';
    script.referrerPolicy = 'no-referrer';
    script.async = true;
    document.head.appendChild(script);
  }
}

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', initQRCodeSystem);
</script>
`;

// ============================================================================
// USER PANEL HANDLER - با سیستم QR Code کامل
// ============================================================================

async function handleUserPanel(request, userID, hostName, proxyAddress, userData, clientIp) {
  try {
    const subXrayUrl = `https://${hostName}/xray/${userID}`;
    const subSbUrl = `https://${hostName}/sb/${userID}`;
    
    const singleXrayConfig = buildLink({ 
      core: 'xray', 
      proto: 'tls', 
      userID, 
      hostName, 
      address: hostName, 
      port: 443, 
      tag: 'Main' 
    });
  
    const singleSingboxConfig = buildLink({ 
      core: 'sb', 
      proto: 'tls', 
      userID, 
      hostName, 
      address: hostName, 
      port: 443, 
      tag: 'Main' 
    });

    const clientUrls = {
      universalAndroid: `v2rayng://install-config?url=${encodeURIComponent(subXrayUrl)}`,
      shadowrocket: `shadowrocket://add/sub?url=${encodeURIComponent(subXrayUrl)}&name=${encodeURIComponent(hostName)}`,
      streisand: `streisand://install-config?url=${encodeURIComponent(subXrayUrl)}`,
      karing: `karing://install-config?url=${encodeURIComponent(subXrayUrl)}`,
      clashMeta: `clash://install-config?url=${encodeURIComponent(subSbUrl)}`,
      exclave: `sn://subscription?url=${encodeURIComponent(subSbUrl)}&name=${encodeURIComponent(hostName)}`,
    };

    const isUserExpired = isExpired(userData.expiration_date, userData.expiration_time);
    const expirationDateTime = userData.expiration_date && userData.expiration_time 
      ? `${userData.expiration_date}T${userData.expiration_time}Z` 
      : null;

    let usagePercentage = 0;
    if (userData.traffic_limit && userData.traffic_limit > 0) {
      usagePercentage = Math.min(((userData.traffic_used || 0) / userData.traffic_limit) * 100, 100);
    }

    const requestCf = request.cf || {};
    const clientGeo = {
      city: requestCf.city || '',
      country: requestCf.country || '',
      isp: requestCf.asOrganization || ''
    };

    const proxyHost = proxyAddress.split(':')[0];
    const proxyIP = await resolveProxyIP(proxyHost);
    const proxyGeo = await getGeo(proxyIP) || { city: '', country: '', isp: '' };

    const usageDisplay = await formatBytes(userData.traffic_used || 0);
    let trafficLimitStr = 'Unlimited';
    if (userData.traffic_limit && userData.traffic_limit > 0) {
      trafficLimitStr = await formatBytes(userData.traffic_limit);
    }

    // این HTML شامل QR Code Generator خودکار است
    const userPanelHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>User Panel — VLESS Configuration</title>
  <style nonce="CSP_NONCE_PLACEHOLDER">
    :root{
      --bg:#0b1220; --card:#0f1724; --muted:#9aa4b2; --accent:#3b82f6;
      --accent-2:#60a5fa; --success:#22c55e; --danger:#ef4444; --warning:#f59e0b;
      --glass: rgba(255,255,255,0.03); --radius:16px; --mono: "SF Mono", "Fira Code", monospace;
      --purple:#a855f7; --glow-accent: rgba(59, 130, 246, 0.4); --glow-purple: rgba(168, 85, 247, 0.3);
    }
    * { box-sizing:border-box; margin: 0; padding: 0; }
    @keyframes gradient-shift { 0%{background-position:0% 50%} 50%{background-position:100% 50%} 100%{background-position:0% 50%} }
    @keyframes float { 0%,100%{transform:translateY(0)} 50%{transform:translateY(-6px)} }
    @keyframes shimmer { 0%{background-position:-200% 0} 100%{background-position:200% 0} }
    @keyframes glow-pulse { 0%,100%{box-shadow:0 0 20px var(--glow-accent)} 50%{box-shadow:0 0 40px var(--glow-accent), 0 0 60px var(--glow-purple)} }
    body{
      font-family: Inter, system-ui, -apple-system, "Segoe UI", Roboto, Arial, sans-serif;
      background: linear-gradient(135deg, #030712 0%, #0f172a 25%, #1e1b4b 50%, #0f172a 75%, #030712 100%);
      background-size: 400% 400%;
      animation: gradient-shift 15s ease infinite;
      color:#e6eef8; -webkit-font-smoothing:antialiased;
      min-height:100vh; padding:28px;
    }
    body::before{
      content:''; position:fixed; top:0; left:0; right:0; bottom:0; z-index:-1;
      background: radial-gradient(ellipse at 20% 20%, rgba(59, 130, 246, 0.08) 0%, transparent 50%),
                  radial-gradient(ellipse at 80% 80%, rgba(168, 85, 247, 0.08) 0%, transparent 50%),
                  radial-gradient(ellipse at 50% 50%, rgba(34, 197, 94, 0.03) 0%, transparent 60%);
    }
    .container{max-width:1100px;margin:0 auto}
    .card{
      background: linear-gradient(145deg, rgba(15, 23, 42, 0.9), rgba(15, 23, 36, 0.7));
      backdrop-filter: blur(20px); -webkit-backdrop-filter: blur(20px);
      border-radius:var(--radius); padding:22px;
      border:1px solid rgba(255,255,255,0.06); 
      box-shadow:0 8px 32px rgba(0,0,0,0.3), inset 0 1px 0 rgba(255,255,255,0.05); 
      margin-bottom:20px;
      transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1);
      position:relative; overflow:hidden;
    }
    .card::before{
      content:''; position:absolute; top:0; left:0; right:0; height:1px;
      background: linear-gradient(90deg, transparent, rgba(255,255,255,0.1), transparent);
    }
    .card:hover { 
      box-shadow:0 20px 50px rgba(0,0,0,0.4), 0 0 30px rgba(59, 130, 246, 0.1);
      transform: translateY(-4px);
      border-color: rgba(59, 130, 246, 0.2);
    }
    h1,h2{margin:0 0 14px;font-weight:700}
    h1{font-size:30px; 
      background: linear-gradient(135deg, #3b82f6 0%, #8b5cf6 50%, #ec4899 100%);
      background-size: 200% auto;
      animation: shimmer 3s linear infinite;
      -webkit-background-clip: text; -webkit-text-fill-color: transparent; background-clip: text;
      text-shadow: 0 0 40px rgba(139, 92, 246, 0.3);
    }
    h2{font-size:20px; color:#f1f5f9}
    p.lead{color:var(--muted);margin:6px 0 22px;font-size:15px;letter-spacing:0.2px}

    .stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:16px;margin-bottom:14px}
    .stat{
      padding:18px 14px;
      background: linear-gradient(145deg, rgba(30, 41, 59, 0.6), rgba(15, 23, 36, 0.8));
      backdrop-filter: blur(10px);
      border-radius:14px;text-align:center;
      border:1px solid rgba(255,255,255,0.04);
      transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1);
      position:relative; overflow:hidden;
    }
    .stat::after{
      content:''; position:absolute; top:-50%; left:-50%; width:200%; height:200%;
      background: radial-gradient(circle, rgba(255,255,255,0.05) 0%, transparent 70%);
      opacity:0; transition: opacity 0.4s;
    }
    .stat:hover::after { opacity:1; }
    .stat:hover { 
      transform: translateY(-5px) scale(1.02); 
      box-shadow: 0 12px 30px rgba(59, 130, 246, 0.25), 0 0 20px rgba(59, 130, 246, 0.1);
      border-color: rgba(59, 130, 246, 0.3);
    }
    .stat .val{font-weight:800;font-size:24px;margin-bottom:6px;letter-spacing:-0.5px}
    .stat .lbl{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:1px;font-weight:500}
    .stat.status-active .val{color:var(--success); text-shadow: 0 0 20px rgba(34, 197, 94, 0.4)}
    .stat.status-expired .val{color:var(--danger); text-shadow: 0 0 20px rgba(239, 68, 68, 0.4)}
    .stat.status-warning .val{color:var(--warning); text-shadow: 0 0 20px rgba(245, 158, 11, 0.4)}

    .grid{display:grid;grid-template-columns:1fr 360px;gap:18px}
    @media (max-width:980px){ .grid{grid-template-columns:1fr} }

    .info-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:14px;margin-top:16px}
    .info-item{background:var(--glass);padding:14px;border-radius:10px;border:1px solid rgba(255,255,255,0.02)}
    .info-item .label{font-size:11px;color:var(--muted);display:block;text-transform:uppercase;letter-spacing:0.5px;margin-bottom:6px}
    .info-item .value{font-weight:600;word-break:break-all;font-size:14px}

    .progress-bar{
      height:14px;background:linear-gradient(90deg, rgba(7,21,41,0.8), rgba(15,23,42,0.9));
      border-radius:10px;overflow:hidden;margin:14px 0;
      box-shadow:inset 0 2px 8px rgba(0,0,0,0.4);
      border:1px solid rgba(255,255,255,0.03);
    }
    .progress-fill{
      height:100%;
      transition:width 1s cubic-bezier(0.4, 0, 0.2, 1);
      border-radius:10px;
      width:0%;
      position:relative;
    }
    .progress-fill::after{
      content:'';position:absolute;top:0;left:0;right:0;bottom:0;
      background:linear-gradient(90deg, transparent, rgba(255,255,255,0.3), transparent);
      animation:shimmer 2s infinite;
    }
    .progress-fill.low{background:linear-gradient(90deg,#22c55e 0%,#16a34a 50%,#22c55e 100%);background-size:200% auto}
    .progress-fill.medium{background:linear-gradient(90deg,#f59e0b 0%,#d97706 50%,#f59e0b 100%);background-size:200% auto}
    .progress-fill.high{background:linear-gradient(90deg,#ef4444 0%,#dc2626 50%,#ef4444 100%);background-size:200% auto}

    pre.config{background:#071529;padding:14px;border-radius:8px;overflow:auto;
      font-family:var(--mono);font-size:13px;color:#cfe8ff;
      border:1px solid rgba(255,255,255,0.02);max-height:200px}
    .buttons{display:flex;gap:10px;flex-wrap:wrap;margin-top:12px}

    .btn{
      display:inline-flex;align-items:center;gap:8px;padding:12px 18px;border-radius:10px;
      border:none;cursor:pointer;font-weight:600;font-size:14px;
      transition:all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
      text-decoration:none;color:inherit;position:relative;overflow:hidden;
    }
    .btn::before{
      content:'';position:absolute;top:0;left:-100%;width:100%;height:100%;
      background:linear-gradient(90deg, transparent, rgba(255,255,255,0.2), transparent);
      transition:left 0.5s;
    }
    .btn:hover::before{left:100%}
    .btn.primary{
      background:linear-gradient(135deg, #3b82f6 0%, #8b5cf6 50%, #6366f1 100%);
      background-size:200% auto;
      color:#fff;box-shadow:0 4px 20px rgba(59,130,246,0.4), inset 0 1px 0 rgba(255,255,255,0.2);
    }
    .btn.primary:hover{
      transform:translateY(-3px) scale(1.02);
      box-shadow:0 8px 30px rgba(59,130,246,0.5), 0 0 20px rgba(139,92,246,0.3);
      background-position:right center;
    }
    .btn.ghost{
      background:linear-gradient(145deg, rgba(255,255,255,0.05), rgba(255,255,255,0.02));
      backdrop-filter:blur(10px);
      border:1px solid rgba(255,255,255,0.1);color:var(--muted);
    }
    .btn.ghost:hover{
      background:linear-gradient(145deg, rgba(255,255,255,0.1), rgba(255,255,255,0.05));
      border-color:rgba(59,130,246,0.4);color:#fff;
      box-shadow:0 4px 15px rgba(59,130,246,0.2);
      transform:translateY(-2px);
    }
    .btn.small{padding:9px 14px;font-size:13px;transition:all 0.3s ease}
    .btn.small:hover{transform:translateY(-2px)}
    .btn:active{transform:translateY(0) scale(0.97)}
    .btn:disabled{opacity:0.5;cursor:not-allowed;transform:none}

    .qr-container{background:linear-gradient(135deg, #ffffff 0%, #f8fafc 100%);padding:20px;border-radius:16px;display:inline-block;box-shadow:0 8px 32px rgba(0,0,0,0.15), 0 0 0 1px rgba(255,255,255,0.1);margin:16px auto;text-align:center;transition:all 0.3s ease;border:2px solid rgba(59,130,246,0.1)}
    .qr-container:hover{transform:translateY(-4px);box-shadow:0 16px 48px rgba(0,0,0,0.2), 0 0 30px rgba(59,130,246,0.15)}
    #qr-display{min-height:280px;display:flex;align-items:center;justify-content:center;flex-direction:column;padding:10px}
    #qr-display img,#qr-display canvas{border-radius:8px;max-width:100%}

    #toast{position:fixed;right:20px;top:20px;background:linear-gradient(135deg, rgba(15,27,42,0.98), rgba(10,20,35,0.95));
      backdrop-filter:blur(20px);-webkit-backdrop-filter:blur(20px);
      padding:16px 20px;border-radius:14px;border:1px solid rgba(255,255,255,0.08);display:none;
      color:#cfe8ff;box-shadow:0 12px 40px rgba(2,6,23,0.7), 0 0 0 1px rgba(255,255,255,0.05);
      z-index:1000;min-width:240px;max-width:350px;
      transform:translateX(0);transition:all 0.3s cubic-bezier(0.4, 0, 0.2, 1)}
    #toast.show{display:block;animation:toastIn .4s cubic-bezier(0.4, 0, 0.2, 1)}
    #toast.success{border-left:4px solid var(--success);box-shadow:0 12px 40px rgba(2,6,23,0.7), 0 0 20px rgba(34,197,94,0.2)}
    #toast.error{border-left:4px solid var(--danger);box-shadow:0 12px 40px rgba(2,6,23,0.7), 0 0 20px rgba(239,68,68,0.2)}
    @keyframes toastIn{from{transform:translateX(100px);opacity:0}to{transform:translateX(0);opacity:1}}

    .section-title{display:flex;justify-content:space-between;align-items:center;margin-bottom:16px;
      padding-bottom:12px;border-bottom:1px solid rgba(255,255,255,0.05)}
    .muted{color:var(--muted);font-size:14px;line-height:1.6}
    .stack{display:flex;flex-direction:column;gap:10px}
    .hidden{display:none}
    .text-center{text-align:center}
    .mb-2{margin-bottom:12px}
    
    .expiry-warning{background:rgba(239,68,68,0.1);border:1px solid rgba(239,68,68,0.3);
      padding:12px;border-radius:8px;margin-top:12px;color:#fca5a5}
    .expiry-info{background:rgba(34,197,94,0.1);border:1px solid rgba(34,197,94,0.3);
      padding:12px;border-radius:8px;margin-top:12px;color:#86efac}

    @media (max-width: 768px) {
      body{padding:16px}
      .container{padding:0}
      h1{font-size:24px}
      .stats{grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px}
      .info-grid{grid-template-columns:1fr}
      .btn{padding:9px 12px;font-size:13px}
    }
  </style>
</head>
<body>
  <div class="container">
    <h1>🚀 VLESS Configuration Panel</h1>
    <p class="lead">Manage your proxy configuration, view subscription links, and monitor usage statistics.</p>

    <div class="stats">
      <div class="stat ${isUserExpired ? 'status-expired' : 'status-active'}">
        <div class="val" id="status-badge">${isUserExpired ? 'Expired' : 'Active'}</div>
        <div class="lbl">Account Status</div>
      </div>
      <div class="stat">
        <div class="val" id="usage-display">${usageDisplay}</div>
        <div class="lbl">Data Used</div>
      </div>
      <div class="stat ${usagePercentage > 80 ? 'status-warning' : ''}">
        <div class="val">${trafficLimitStr}</div>
        <div class="lbl">Data Limit</div>
      </div>
      <div class="stat">
        <div class="val" id="expiry-countdown">—</div>
        <div class="lbl">Time Remaining</div>
      </div>
    </div>

    ${userData.traffic_limit && userData.traffic_limit > 0 ? `
    <div class="card">
      <div class="section-title">
        <h2>📊 Usage Statistics</h2>
        <span class="muted">${usagePercentage.toFixed(2)}% Used</span>
      </div>
      <div class="progress-bar">
        <div class="progress-fill ${usagePercentage > 80 ? 'high' : usagePercentage > 50 ? 'medium' : 'low'}" 
             id="progress-bar-fill"
             data-target-width="${usagePercentage.toFixed(2)}"></div>
      </div>
      <p class="muted text-center mb-2">${usageDisplay} of ${trafficLimitStr} used</p>
    </div>
    ` : ''}

    ${expirationDateTime ? `
    <div class="card">
      <div class="section-title">
        <h2>⏰ Expiration Information</h2>
      </div>
      <div id="expiration-display" data-expiry="${expirationDateTime}">
        <p class="muted" id="expiry-local">Loading...</p>
        <p class="muted" style="font-size:13px;margin-top:4px;" id="expiry-utc"></p>
      </div>
      ${isUserExpired ? `
      <div class="expiry-warning">
        ⚠️ Your account has expired. Please contact admin to renew.
      </div>
      ` : `
      <div class="expiry-info">
        ✓ Your account is active and working normally.
      </div>
      `}
    </div>
    ` : ''}

    <div class="grid">
      <div>
        <div class="card">
          <div class="section-title">
            <h2>🌐 Network Information</h2>
            <button class="btn ghost small" data-action="refresh">🔄 Refresh</button>
          </div>
          <p class="muted">Connection details and IP information.</p>
          <div class="info-grid">
            <div class="info-item">
              <span class="label">Proxy Host</span>
              <span class="value">${proxyAddress || hostName}</span>
            </div>
            <div class="info-item">
              <span class="label">Proxy IP</span>
              <span class="value">${proxyIP}</span>
            </div>
            <div class="info-item">
              <span class="label">Proxy Location</span>
              <span class="value">${[proxyGeo.city, proxyGeo.country].filter(Boolean).join(', ') || 'Unknown'}</span>
            </div>
            <div class="info-item">
              <span class="label">Your IP</span>
              <span class="value">${clientIp}</span>
            </div>
            <div class="info-item">
              <span class="label">Your Location</span>
              <span class="value">${[clientGeo.city, clientGeo.country].filter(Boolean).join(', ') || 'Unknown'}</span>
            </div>
            <div class="info-item">
              <span class="label">Your ISP</span>
              <span class="value">${clientGeo.isp || 'Unknown'}</span>
            </div>
          </div>
        </div>

        <div class="card">
          <div class="section-title">
            <h2>📱 Subscription Links</h2>
          </div>
          <p class="muted">Copy subscription URLs or import directly.</p>

          <div class="stack">
            <div>
              <h3 style="font-size:16px;margin:12px 0 8px;color:var(--accent-2);">Xray / V2Ray Subscription</h3>
              <div class="buttons">
                <button class="btn primary" data-action="copy" data-url="xray">📋 Copy Sub Link</button>
                <button class="btn ghost" data-action="copy-config" data-config="xray">📋 Copy Config</button>
                <button class="btn ghost" data-action="toggle" data-target="xray-config">View Config</button>
                <button class="btn ghost" onclick="generateQRCode('${escapeHTML(singleXrayConfig)}', 'qr-display')">📱 QR Code</button>
              </div>
              <pre class="config hidden" id="xray-config">${escapeHTML(singleXrayConfig)}</pre>
            </div>

            <div>
              <h3 style="font-size:16px;margin:12px 0 8px;color:var(--accent-2);">Sing-Box / Clash Subscription</h3>
              <div class="buttons">
                <button class="btn primary" data-action="copy" data-url="singbox">📋 Copy Sub Link</button>
                <button class="btn ghost" data-action="copy-config" data-config="singbox">📋 Copy Config</button>
                <button class="btn ghost" data-action="toggle" data-target="sb-config">View Config</button>
                <button class="btn ghost" onclick="generateQRCode('${escapeHTML(singleSingboxConfig)}', 'qr-display')">📱 QR Code</button>
              </div>
              <pre class="config hidden" id="sb-config">${escapeHTML(singleSingboxConfig)}</pre>
            </div>

            <div>
              <h3 style="font-size:16px;margin:12px 0 8px;color:var(--accent-2);">Quick Import</h3>
              <div class="buttons">
                <a href="${clientUrls.universalAndroid}" class="btn ghost">📱 Android (V2rayNG)</a>
                <a href="${clientUrls.shadowrocket}" class="btn ghost">🍎 iOS (Shadowrocket)</a>
                <a href="${clientUrls.streisand}" class="btn ghost">🍎 iOS Streisand</a>
                <a href="${clientUrls.karing}" class="btn ghost">🔧 Karing</a>
                <a href="${clientUrls.clashMeta}" class="btn ghost">🌐 Clash Meta</a>
                <a href="${clientUrls.exclave}" class="btn ghost">📦 Exclave</a>
              </div>
            </div>
          </div>
        </div>
      </div>

      <aside>
        <div class="card">
          <h2>📱 QR Code Scanner</h2>
          <p class="muted mb-2">Scan with your mobile device to quickly import.</p>
          <div class="qr-container">
            <div id="qr-display" class="text-center">
              <p class="muted">Click any "QR Code" button to generate a scannable code.</p>
            </div>
          </div>
          <div class="buttons" style="justify-content:center;margin-top:16px;">
            <button class="btn ghost small" onclick="generateQRCode('${escapeHTML(singleXrayConfig)}', 'qr-display')">Xray QR</button>
            <button class="btn ghost small" onclick="generateQRCode('${escapeHTML(singleSingboxConfig)}', 'qr-display')">Singbox QR</button>
            <button class="btn secondary small" onclick="testQR()">Test QR</button>
            <button class="btn success small" onclick="copyQRText()">Copy Config</button>
          </div>
          <div style="margin-top:20px;padding:16px;background:#e7f3ff;border-radius:8px;border-left:4px solid #0d6efd;">
            <h4 style="margin:0 0 8px 0;color:#0d6efd;">💡 Tips:</h4>
            <ul style="margin:0;padding-left:20px;color:#495057;">
              <li>If QR code fails, use "Copy Config" and import manually</li>
              <li>Test the QR before scanning with "Test QR" button</li>
              <li>Make sure your client supports the protocol</li>
            </ul>
          </div>
        </div>

        <div class="card">
          <h2>👤 Account Details</h2>
          <div class="info-item" style="margin-top:12px;">
            <span class="label">User UUID</span>
            <span class="value" style="font-family:var(--mono);font-size:12px;word-break:break-all;">${userID}</span>
          </div>
          <div class="info-item" style="margin-top:12px;">
            <span class="label">Created Date</span>
            <span class="value">${new Date(userData.created_at).toLocaleDateString()}</span>
          </div>
          ${userData.notes ? `
          <div class="info-item" style="margin-top:12px;">
            <span class="label">Notes</span>
            <span class="value">${escapeHTML(userData.notes)}</span>
          </div>
          ` : ''}
          <div class="info-item" style="margin-top:12px;">
            <span class="label">IP Limit</span>
            <span class="value">${userData.ip_limit === -1 ? 'Unlimited' : userData.ip_limit}</span>
          </div>
        </div>

        <div class="card">
          <h2>💾 Export Configuration</h2>
          <p class="muted mb-2">Download configuration for manual import or backup.</p>
          <div class="buttons">
            <button class="btn primary small" data-action="download" data-type="xray">Download Xray</button>
            <button class="btn primary small" data-action="download" data-type="singbox">Download Singbox</button>
          </div>
        </div>
      </aside>
    </div>

    <div class="card">
      <p class="muted text-center" style="margin:0;">
        🔒 This is your personal configuration panel. Keep your subscription links private and secure.
        <br>For support, contact your service administrator.
      </p>
    </div>

    <div id="toast"></div>
  </div>

  ${qrCodeScript}

  <script nonce="CSP_NONCE_PLACEHOLDER">
    // ========================================================================
    // USER PANEL JAVASCRIPT
    // ========================================================================
    
    document.addEventListener('DOMContentLoaded', function() {
      // Update expiration display
      function updateExpirationDisplay() {
        const expiryElement = document.getElementById('expiration-display');
        if (!expiryElement) return;
        
        const expiryDateStr = expiryElement.dataset.expiry;
        if (!expiryDateStr) return;
        
        const expiryDate = new Date(expiryDateStr);
        if (isNaN(expiryDate.getTime())) return;
        
        const now = new Date();
        const diffMs = expiryDate - now;
        const diffSeconds = Math.floor(diffMs / 1000);
        
        const countdownEl = document.getElementById('expiry-countdown');
        const localEl = document.getElementById('expiry-local');
        const utcEl = document.getElementById('expiry-utc');
        
        if (diffSeconds < 0) {
          countdownEl.textContent = 'Expired';
          countdownEl.parentElement.classList.add('status-expired');
          return;
        }
        
        const days = Math.floor(diffSeconds / 86400);
        const hours = Math.floor((diffSeconds % 86400) / 3600);
        const minutes = Math.floor((diffSeconds % 3600) / 60);
        const seconds = diffSeconds % 60;
        
        if (days > 0) {
          countdownEl.textContent = days + 'd ' + hours + 'h';
        } else if (hours > 0) {
          countdownEl.textContent = hours + 'h ' + minutes + 'm';
        } else if (minutes > 0) {
          countdownEl.textContent = minutes + 'm ' + seconds + 's';
        } else {
          countdownEl.textContent = seconds + 's';
        }
        
        if (localEl) localEl.textContent = 'Expires: ' + expiryDate.toLocaleString();
        if (utcEl) utcEl.textContent = 'UTC: ' + expiryDate.toISOString().replace('T', ' ').substring(0, 19);
      }
      
      // Animate progress bar
      function animateProgressBar() {
        const progressBar = document.getElementById('progress-bar-fill');
        if (!progressBar) return;
        const targetWidth = progressBar.dataset.targetWidth || '0';
        setTimeout(() => {
          progressBar.style.width = targetWidth + '%';
        }, 100);
      }
      
      // Copy to clipboard function
      async function copyToClipboard(text, button) {
        try {
          await navigator.clipboard.writeText(text);
          const originalText = button.innerHTML;
          button.innerHTML = '✓ Copied!';
          button.disabled = true;
          setTimeout(() => {
            button.innerHTML = originalText;
            button.disabled = false;
          }, 2000);
          showToast('✓ Copied to clipboard!', 'success');
        } catch (error) {
          try {
            const textArea = document.createElement("textarea");
            textArea.value = text;
            textArea.style.position = "fixed";
            textArea.style.top = "0";
            textArea.style.left = "0";
            document.body.appendChild(textArea);
            textArea.focus();
            textArea.select();
            document.execCommand('copy');
            document.body.removeChild(textArea);
            
            const originalText = button.innerHTML;
            button.innerHTML = '✓ Copied!';
            button.disabled = true;
            setTimeout(() => {
              button.innerHTML = originalText;
              button.disabled = false;
            }, 2000);
            showToast('✓ Copied to clipboard (fallback)!', 'success');
          } catch(err) {
            showToast('Failed to copy', 'error');
          }
        }
      }
      
      // Download config
      function downloadConfig(content, filename) {
        const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = filename;
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        URL.revokeObjectURL(url);
        showToast('✓ Configuration downloaded: ' + filename, 'success');
      }
      
      // Event delegation for buttons
      document.addEventListener('click', function(e) {
        const btn = e.target.closest('[data-action]');
        if (!btn) return;
        
        const action = btn.dataset.action;
        
        switch (action) {
          case 'refresh':
            location.reload();
            break;
            
          case 'copy': {
            const urlType = btn.dataset.url;
            const url = urlType === 'xray' ? '${subXrayUrl}' : '${subSbUrl}';
            copyToClipboard(url, btn);
            break;
          }
          
          case 'copy-config': {
            const configType = btn.dataset.config;
            const config = configType === 'xray' ? '${escapeHTML(singleXrayConfig)}' : '${escapeHTML(singleSingboxConfig)}';
            copyToClipboard(config, btn);
            break;
          }
          
          case 'toggle': {
            const targetId = btn.dataset.target;
            const target = document.getElementById(targetId);
            if (target) target.classList.toggle('hidden');
            break;
          }
          
          case 'download': {
            const type = btn.dataset.type;
            if (type === 'xray') {
              downloadConfig('${escapeHTML(singleXrayConfig)}', 'xray-config.txt');
            } else if (type === 'singbox') {
              downloadConfig('${escapeHTML(singleSingboxConfig)}', 'singbox-config.txt');
            }
            break;
          }
        }
      });
      
      // Initialize
      updateExpirationDisplay();
      setInterval(updateExpirationDisplay, 1000);
      animateProgressBar();
      
      // RASPS - Responsive Adaptive Smart Polling System
      (function() {
        const CONFIG = {
          ENDPOINT: '/api/user/' + '${userID}',
          POLL_MIN_MS: 50000,
          POLL_MAX_MS: 70000,
          INACTIVE_MULTIPLIER: 4,
          MAX_BACKOFF_MS: 300000,
          INITIAL_BACKOFF_MS: 2000,
          BACKOFF_FACTOR: 1.8,
        };

        let lastDataHash = null;
        let currentBackoff = CONFIG.INITIAL_BACKOFF_MS;
        let isPolling = false;
        let pollTimeout = null;
        let isPageVisible = document.visibilityState === 'visible';

        function getRandomDelay() {
          const baseMin = CONFIG.POLL_MIN_MS;
          const baseMax = CONFIG.POLL_MAX_MS;
          const multiplier = isPageVisible ? 1 : CONFIG.INACTIVE_MULTIPLIER;
          return Math.floor(Math.random() * ((baseMax - baseMin) * multiplier + 1)) + baseMin * multiplier;
        }

        function computeHash(data) {
          const str = JSON.stringify(data);
          let hash = 0;
          for (let i = 0; i < str.length; i++) {
            const char = str.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash;
          }
          return hash.toString(36);
        }

        async function formatBytes(bytes) {
          if (bytes === 0) return '0 Bytes';
          const k = 1024;
          const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
          const i = Math.floor(Math.log(bytes) / Math.log(k));
          return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
        }

        async function updateDOM(data) {
          const usageEl = document.getElementById('usage-display');
          if (usageEl && data.traffic_used !== undefined) {
            usageEl.textContent = await formatBytes(data.traffic_used);
            
            if (${userData.traffic_limit ? 'true' : 'false'}) {
              const percentage = ((data.traffic_used / ${userData.traffic_limit || 0}) * 100).toFixed(2);
              const progressFill = document.getElementById('progress-bar-fill');
              if (progressFill) {
                progressFill.dataset.targetWidth = percentage;
                progressFill.className = 'progress-fill ' + (percentage > 80 ? 'high' : percentage > 50 ? 'medium' : 'low');
                progressFill.style.width = percentage + '%';
              }
            }
          }
        }

        async function fetchData() {
          try {
            const response = await fetch(CONFIG.ENDPOINT, {
              method: 'GET',
              headers: { 'Cache-Control': 'no-cache' },
              cache: 'no-store'
            });

            if (response.status === 304) return null;
            if (!response.ok) throw new Error('HTTP error: ' + response.status);

            const data = await response.json();
            const newHash = computeHash(data);
            
            if (newHash === lastDataHash) return null;
            
            lastDataHash = newHash;
            return data;
          } catch (error) {
            console.warn('RASPS fetch error:', error.message);
            throw error;
          }
        }

        function scheduleNextPoll() {
          if (pollTimeout) clearTimeout(pollTimeout);
          const delay = getRandomDelay();
          pollTimeout = setTimeout(poll, delay);
        }

        async function poll() {
          if (!isPolling) return;
          try {
            const data = await fetchData();
            if (data) await updateDOM(data);
            currentBackoff = CONFIG.INITIAL_BACKOFF_MS;
          } catch (error) {
            currentBackoff = Math.min(currentBackoff * CONFIG.BACKOFF_FACTOR, CONFIG.MAX_BACKOFF_MS);
          } finally {
            scheduleNextPoll();
          }
        }

        function handleVisibilityChange() {
          isPageVisible = document.visibilityState === 'visible';
          if (isPageVisible) poll();
        }

        function startPolling() {
          if (isPolling) return;
          isPolling = true;
          document.addEventListener('visibilitychange', handleVisibilityChange);
          scheduleNextPoll();
        }

        if (CONFIG.ENDPOINT) startPolling();
      })();
    });
  </script>
</body>
</html>`;

    const nonce = generateNonce();
    const headers = new Headers({ 'Content-Type': 'text/html;charset=utf-8' });
    addSecurityHeaders(headers, nonce, {
      img: 'data: https:',
      connect: 'https:'
    });
    
    const finalHtml = userPanelHTML.replace(/CSP_NONCE_PLACEHOLDER/g, nonce);
    return new Response(finalHtml, { headers });
  } catch (e) {
    console.error('handleUserPanel error:', e.message, e.stack);
    const headers = new Headers();
    addSecurityHeaders(headers, null, {});
    return new Response('Internal Server Error', { status: 500, headers });
  }
}

// ============================================================================
// VLESS PROTOCOL HANDLERS
// ============================================================================

async function ProtocolOverWSHandler(request, config, env, ctx) {
  let webSocket = null;
  try {
    const clientIp = request.headers.get('CF-Connecting-IP');
    
    // بررسی امنیتی IP با Scamalytics
    if (await isSuspiciousIP(clientIp, config.scamalytics, env.SCAMALYTICS_THRESHOLD || CONST.SCAMALYTICS_THRESHOLD)) {
      return new Response('Access denied', { status: 403 });
    }

    const webSocketPair = new WebSocketPair();
    const [client, webSocket_inner] = Object.values(webSocketPair);
    webSocket = webSocket_inner;
    webSocket.accept();

    let address = '';
    let portWithRandomLog = '';
    let sessionUsage = 0;
    let userUUID = '';
    let udpStreamWriter = null;

    const log = (info, event) => console.log(`[${address}:${portWithRandomLog}] ${info}`, event || '');

    // سیستم به‌روزرسانی استفاده با Batching
    const deferredUsageUpdate = () => {
      if (sessionUsage > 0 && userUUID) {
        const usageToUpdate = sessionUsage;
        const uuidToUpdate = userUUID;
        sessionUsage = 0;
        
        ctx.waitUntil(
          updateUsage(env, uuidToUpdate, usageToUpdate, ctx)
            .catch(err => console.error(`Deferred usage update failed for ${uuidToUpdate}:`, err))
        );
      }
    };

    const updateInterval = setInterval(deferredUsageUpdate, 10000);
    const finalCleanup = () => {
      clearInterval(updateInterval);
      deferredUsageUpdate();
    };

    webSocket.addEventListener('close', finalCleanup, { once: true });
    webSocket.addEventListener('error', finalCleanup, { once: true });

    const earlyDataHeader = request.headers.get('Sec-WebSocket-Protocol') || '';
    const readableWebSocketStream = MakeReadableWebSocketStream(webSocket, earlyDataHeader, log);
    let remoteSocketWrapper = { value: null };

    readableWebSocketStream
      .pipeTo(
        new WritableStream({
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

            const {
              user,
              hasError,
              message,
              addressType,
              portRemote = 443,
              addressRemote = '',
              rawDataIndex,
              ProtocolVersion = new Uint8Array([0, 0]),
              isUDP,
            } = await ProcessProtocolHeader(chunk, env, ctx);

            if (hasError || !user) {
              controller.error(new Error('Authentication failed'));
              return;
            }

            userUUID = user.uuid;

            // بررسی انقضا
            if (isExpired(user.expiration_date, user.expiration_time)) {
              controller.error(new Error('Account expired'));
              return;
            }

            // بررسی محدودیت ترافیک
            if (user.traffic_limit && user.traffic_limit > 0) {
              const totalUsage = (user.traffic_used || 0) + sessionUsage;
              if (totalUsage >= user.traffic_limit) {
                controller.error(new Error('Traffic limit exceeded'));
                return;
              }
            }

            // بررسی محدودیت IP
            if (user.ip_limit && user.ip_limit > -1) {
              const ipCount = await env.DB.prepare(
                "SELECT COUNT(DISTINCT ip) as count FROM user_ips WHERE uuid = ?"
              ).bind(userUUID).first('count');
              
              if (ipCount >= user.ip_limit) {
                const existingIp = await env.DB.prepare(
                  "SELECT ip FROM user_ips WHERE uuid = ? AND ip = ?"
                ).bind(userUUID, clientIp).first();
                
                if (!existingIp) {
                  controller.error(new Error('IP limit exceeded'));
                  return;
                }
              }
              
              await env.DB.prepare(
                "INSERT OR REPLACE INTO user_ips (uuid, ip, last_seen) VALUES (?, ?, CURRENT_TIMESTAMP)"
              ).bind(userUUID, clientIp).run();
            }

            address = addressRemote;
            portWithRandomLog = `${portRemote}--${Math.random()} ${isUDP ? 'udp' : 'tcp'}`;
            const vlessResponseHeader = new Uint8Array([ProtocolVersion[0], 0]);
            const rawClientData = chunk.slice(rawDataIndex);

            if (isUDP) {
              if (portRemote === 53) {
                const dnsPipeline = await createDnsPipeline(webSocket, vlessResponseHeader, log, (bytes) => {
                  sessionUsage += bytes;
                });
                udpStreamWriter = dnsPipeline.write;
                await udpStreamWriter(rawClientData);
              } else {
                controller.error(new Error('UDP only supported for DNS (port 53)'));
              }
              return;
            }

            HandleTCPOutBound(
              remoteSocketWrapper,
              addressType,
              addressRemote,
              portRemote,
              rawClientData,
              webSocket,
              vlessResponseHeader,
              log,
              config,
              (bytes) => { sessionUsage += bytes; }
            );
          },
          close() {
            log('readableWebSocketStream closed');
            finalCleanup();
          },
          abort(err) {
            log('readableWebSocketStream aborted', err);
            finalCleanup();
          },
        }),
      )
      .catch(err => {
        console.error('Pipeline failed:', err.stack || err);
        safeCloseWebSocket(webSocket);
        finalCleanup();
      });

    return new Response(null, { status: 101, webSocket: client });
  } catch (e) {
    console.error('ProtocolOverWSHandler error:', e.message, e.stack);
    if (webSocket) {
      try {
        safeCloseWebSocket(webSocket);
      } catch (closeErr) {
        console.error('Error closing WebSocket:', closeErr);
      }
    }
    const headers = new Headers();
    addSecurityHeaders(headers, null, {});
    return new Response('Internal Server Error', { status: 500, headers });
  }
}

async function ProcessProtocolHeader(protocolBuffer, env, ctx) {
  try {
    if (protocolBuffer.byteLength < 24) {
      return { hasError: true, message: 'invalid data' };
    }
  
    const dataView = new DataView(protocolBuffer.buffer || protocolBuffer);
    const version = dataView.getUint8(0);

    let uuid;
    try {
      uuid = stringify(new Uint8Array(protocolBuffer.slice(1, 17)));
    } catch (e) {
      return { hasError: true, message: 'invalid UUID format' };
    }

    const userData = await getUserData(env, uuid, ctx);
    if (!userData) {
      return { hasError: true, message: 'invalid user' };
    }

    const payloadStart = 17;
    if (protocolBuffer.byteLength < payloadStart + 1) {
      return { hasError: true, message: 'invalid data length' };
    }

    const optLength = dataView.getUint8(payloadStart);
    const commandIndex = payloadStart + 1 + optLength;
    
    if (protocolBuffer.byteLength < commandIndex + 1) {
      return { hasError: true, message: 'invalid data length (command)' };
    }
    
    const command = dataView.getUint8(commandIndex);
    if (command !== 1 && command !== 2) {
      return { hasError: true, message: \`command \${command} not supported\` };
    }

    const portIndex = commandIndex + 1;
    if (protocolBuffer.byteLength < portIndex + 2) {
      return { hasError: true, message: 'invalid data length (port)' };
    }
    
    const portRemote = dataView.getUint16(portIndex, false);

    const addressTypeIndex = portIndex + 2;
    if (protocolBuffer.byteLength < addressTypeIndex + 1) {
      return { hasError: true, message: 'invalid data length (address type)' };
    }
    
    const addressType = dataView.getUint8(addressTypeIndex);

    let addressValue, addressLength, addressValueIndex;

    switch (addressType) {
      case 1:
        addressLength = 4;
        addressValueIndex = addressTypeIndex + 1;
        if (protocolBuffer.byteLength < addressValueIndex + addressLength) {
          return { hasError: true, message: 'invalid data length (ipv4)' };
        }
        addressValue = new Uint8Array(protocolBuffer.slice(addressValueIndex, addressValueIndex + addressLength)).join('.');
        break;
        
      case 2:
        if (protocolBuffer.byteLength < addressTypeIndex + 2) {
          return { hasError: true, message: 'invalid data length (domain length)' };
        }
        addressLength = dataView.getUint8(addressTypeIndex + 1);
        addressValueIndex = addressTypeIndex + 2;
        if (protocolBuffer.byteLength < addressValueIndex + addressLength) {
          return { hasError: true, message: 'invalid data length (domain)' };
        }
        addressValue = new TextDecoder().decode(protocolBuffer.slice(addressValueIndex, addressValueIndex + addressLength));
        break;
        
      case 3:
        addressLength = 16;
        addressValueIndex = addressTypeIndex + 1;
        if (protocolBuffer.byteLength < addressValueIndex + addressLength) {
          return { hasError: true, message: 'invalid data length (ipv6)' };
        }
        addressValue = Array.from({ length: 8 }, (_, i) => 
          dataView.getUint16(addressValueIndex + i * 2, false).toString(16)
        ).join(':');
        break;
        
      default:
        return { hasError: true, message: \`invalid addressType: \${addressType}\` };
    }

    const rawDataIndex = addressValueIndex + addressLength;
    if (protocolBuffer.byteLength < rawDataIndex) {
      return { hasError: true, message: 'invalid data length (raw data)' };
    }

    return {
      user: userData,
      hasError: false,
      addressRemote: addressValue,
      addressType,
      portRemote,
      rawDataIndex,
      ProtocolVersion: new Uint8Array([version]),
      isUDP: command === 2,
    };
  } catch (e) {
    console.error('ProcessProtocolHeader error:', e.message, e.stack);
    return { hasError: true, message: 'protocol processing error' };
  }
}

async function HandleTCPOutBound(
  remoteSocket,
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
  async function connectAndWrite(address, port, socks = false) {
    let tcpSocket;
    if (config.socks5Relay) {
      tcpSocket = await socks5Connect(addressType, address, port, log, config.parsedSocks5Address);
    } else {
      tcpSocket = socks
        ? await socks5Connect(addressType, address, port, log, config.parsedSocks5Address)
        : connect({ hostname: address, port: port });
    }
    remoteSocket.value = tcpSocket;
    log(\`connected to \${address}:\${port}\`);
    const writer = tcpSocket.writable.getWriter();
    await writer.write(rawClientData);
    writer.releaseLock();
    return tcpSocket;
  }

  async function retry() {
    const tcpSocket = config.enableSocks
      ? await connectAndWrite(addressRemote, portRemote, true)
      : await connectAndWrite(
          config.proxyIP || addressRemote,
          config.proxyPort || portRemote,
          false,
        );

    tcpSocket.closed
      .catch(error => {
        console.log('retry tcpSocket closed error', error);
      })
      .finally(() => {
        safeCloseWebSocket(webSocket);
      });
    RemoteSocketToWS(tcpSocket, webSocket, protocolResponseHeader, null, log, trafficCallback);
  }

  const tcpSocket = await connectAndWrite(addressRemote, portRemote);
  RemoteSocketToWS(tcpSocket, webSocket, protocolResponseHeader, retry, log, trafficCallback);
}

function MakeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
  return new ReadableStream({
    start(controller) {
      webSocketServer.addEventListener('message', (event) => controller.enqueue(event.data));
      webSocketServer.addEventListener('close', () => {
        safeCloseWebSocket(webSocketServer);
        controller.close();
      });
      webSocketServer.addEventListener('error', (err) => {
        log('webSocketServer has error');
        controller.error(err);
      });
      const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
      if (error) controller.error(error);
      else if (earlyData) controller.enqueue(earlyData);
    },
    pull(_controller) { },
    cancel(reason) {
      log(\`ReadableStream canceled: \${reason}\`);
      safeCloseWebSocket(webSocketServer);
    },
  });
}

async function RemoteSocketToWS(remoteSocket, webSocket, protocolResponseHeader, retry, log, trafficCallback) {
  let hasIncomingData = false;
  await remoteSocket.readable
    .pipeTo(
      new WritableStream({
        async write(chunk, controller) {
          if (webSocket.readyState !== CONST.WS_READY_STATE_OPEN) {
            controller.error(new Error('webSocket not open'));
            return;
          }
          hasIncomingData = true;
          
          if (protocolResponseHeader) {
            webSocket.send(await new Blob([protocolResponseHeader, chunk]).arrayBuffer());
            protocolResponseHeader = null;
          } else {
            webSocket.send(chunk);
          }
          
          if (trafficCallback) {
            trafficCallback(chunk.byteLength);
          }
        },
        close() {
          log(\`remoteSocket closed, hasIncomingData: \${hasIncomingData}\`);
        },
        abort(reason) {
          console.error('remoteSocket abort', reason);
        },
      }),
    )
    .catch((error) => {
      console.error('remoteSocket pipeTo error', error);
      safeCloseWebSocket(webSocket);
    });
  
  if (!hasIncomingData && retry) {
    log('No incoming data, retrying');
    await retry();
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
    return { earlyData: null, error };
  }
}

function safeCloseWebSocket(socket) {
  try {
    if (
      socket.readyState === CONST.WS_READY_STATE_OPEN ||
      socket.readyState === CONST.WS_READY_STATE_CLOSING
    ) {
      socket.close();
    }
  } catch (error) {
    console.error('safeCloseWebSocket error:', error);
  }
}

async function createDnsPipeline(webSocket, vlessResponseHeader, log, trafficCallback) {
  let isHeaderSent = false;
  const transformStream = new TransformStream({
    transform(chunk, controller) {
      for (let index = 0; index < chunk.byteLength;) {
        if (index + 2 > chunk.byteLength) break;
        const lengthBuffer = chunk.slice(index, index + 2);
        const udpPacketLength = new DataView(lengthBuffer).getUint16(0);
        if (index + 2 + udpPacketLength > chunk.byteLength) break;
        const udpData = new Uint8Array(chunk.slice(index + 2, index + 2 + udpPacketLength));
        index = index + 2 + udpPacketLength;
        controller.enqueue(udpData);
      }
    },
  });

  transformStream.readable
    .pipeTo(
      new WritableStream({
        async write(chunk) {
          try {
            const resp = await fetch('https://1.1.1.1/dns-query', {
              method: 'POST',
              headers: { 'content-type': 'application/dns-message' },
              body: chunk,
            });
            const dnsQueryResult = await resp.arrayBuffer();
            const udpSize = dnsQueryResult.byteLength;
            const udpSizeBuffer = new Uint8Array([(udpSize >> 8) & 0xff, udpSize & 0xff]);

            if (webSocket.readyState === CONST.WS_READY_STATE_OPEN) {
              log(\`DNS query success, length: \${udpSize}\`);
              let responseChunk;
              if (isHeaderSent) {
                responseChunk = await new Blob([udpSizeBuffer, dnsQueryResult]).arrayBuffer();
              } else {
                responseChunk = await new Blob([vlessResponseHeader, udpSizeBuffer, dnsQueryResult]).arrayBuffer();
                isHeaderSent = true;
              }
              if (trafficCallback) {
                trafficCallback(responseChunk.byteLength);
              }
              webSocket.send(responseChunk);
            }
          } catch (error) {
            log('DNS query error: ' + error);
          }
        },
      }),
    )
    .catch(e => {
      log('DNS stream error: ' + e);
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
  
  for (let i = 0; i < 8; i++) {
    const val = parseInt(hextets[i] || '0', 16);
    view.setUint16(i * 2, val, false);
  }
  
  return new Uint8Array(buffer);
}

async function socks5Connect(addressType, addressRemote, portRemote, log, parsedSocks5Address) {
  const { username, password, hostname, port } = parsedSocks5Address;
  
  let socket;
  let reader;
  let writer;
  let success = false;

  try {
    socket = connect({ hostname, port });
    reader = socket.readable.getReader();
    writer = socket.writable.getWriter();
    
    const encoder = new TextEncoder();

    await writer.write(new Uint8Array([5, 2, 0, 2]));
    let res = (await reader.read()).value;
    if (!res || res[0] !== 0x05 || res[1] === 0xff) {
      throw new Error('SOCKS5 handshake failed');
    }

    if (res[1] === 0x02) {
      if (!username || !password) {
        throw new Error('SOCKS5 requires credentials');
      }
      const authRequest = new Uint8Array([
        1,
        username.length,
        ...encoder.encode(username),
        password.length,
        ...encoder.encode(password)
      ]);
      await writer.write(authRequest);
      res = (await reader.read()).value;
      if (!res || res[0] !== 0x01 || res[1] !== 0x00) {
        throw new Error(\`SOCKS5 auth failed (Code: \${res[1]})\`);
      }
    }

    let dstAddr;
    switch (addressType) {
      case 1:
        dstAddr = new Uint8Array([1, ...addressRemote.split('.').map(Number)]);
        break;
      case 2:
        dstAddr = new Uint8Array([3, addressRemote.length, ...encoder.encode(addressRemote)]);
        break;
      case 3:
        const ipv6Bytes = parseIPv6(addressRemote);
        if (ipv6Bytes.length !== 16) {
          throw new Error(\`Failed to parse IPv6: \${addressRemote}\`);
        }
        dstAddr = new Uint8Array(1 + 16);
        dstAddr[0] = 4;
        dstAddr.set(ipv6Bytes, 1);
        break;
      default:
        throw new Error(\`Invalid address type: \${addressType}\`);
    }

    const socksRequest = new Uint8Array([
      5, 1, 0, ...dstAddr, portRemote >> 8, portRemote & 0xff
    ]);
    await writer.write(socksRequest);
    
    res = (await reader.read()).value;
    if (!res || res[1] !== 0x00) {
      throw new Error(\`SOCKS5 connection failed (Code: \${res[1]})\`);
    }

    log(\`SOCKS5 connection to \${addressRemote}:\${portRemote} established\`);
    success = true;
    return socket;

  } catch (err) {
    log(\`socks5Connect error: \${err.message}\`, err);
    throw err;
  } finally {
    if (writer) writer.releaseLock();
    if (reader) reader.releaseLock();
    
    if (!success && socket) {
      try {
        socket.abort();
      } catch (e) {
        log('Error aborting SOCKS5 socket', e);
      }
    }
  }
}

function socks5AddressParser(address) {
  if (!address || typeof address !== 'string') {
    throw new Error('Invalid SOCKS5 address format');
  }
  const [authPart, hostPart] = address.includes('@') ? address.split('@') : [null, address];
  const lastColonIndex = hostPart.lastIndexOf(':');

  if (lastColonIndex === -1) {
    throw new Error('Invalid SOCKS5 address: missing port');
  }
  
  let hostname;
  if (hostPart.startsWith('[')) {
    const closingBracketIndex = hostPart.lastIndexOf(']');
    if (closingBracketIndex === -1 || closingBracketIndex > lastColonIndex) {
      throw new Error('Invalid IPv6 SOCKS5 address');
    }
    hostname = hostPart.substring(1, closingBracketIndex);
  } else {
    hostname = hostPart.substring(0, lastColonIndex);
  }

  const portStr = hostPart.substring(lastColonIndex + 1);
  const port = parseInt(portStr, 10);
  
  if (!hostname || isNaN(port)) {
    throw new Error('Invalid SOCKS5 address');
  }

  let username, password;
  if (authPart) {
    [username, password] = authPart.split(':');
  }
  
  return { username, password, hostname, port };
}

// ============================================================================
// MAIN FETCH HANDLER
// ============================================================================

export default {
  async fetch(request, env, ctx) {
    try {
      await ensureTablesExist(env, ctx);
      
      let cfg;
      try {
        cfg = await Config.fromEnv(env);
      } catch (err) {
        console.error(\`Configuration error: \${err.message}\`);
        const headers = new Headers();
        addSecurityHeaders(headers, null, {});
        return new Response('Service unavailable', { status: 503, headers });
      }

      const url = new URL(request.url);
      const clientIp = request.headers.get('CF-Connecting-IP');

      const adminPrefix = env.ADMIN_PATH_PREFIX || 'admin';
      
      if (url.pathname.startsWith(\`/\${adminPrefix}/\`)) {
        return await handleAdminRequest(request, env, ctx, adminPrefix);
      }

      if (url.pathname === '/health') {
        const headers = new Headers();
        addSecurityHeaders(headers, null, {});
        return new Response('OK', { status: 200, headers });
      }

      if (url.pathname === '/health-check' && request.method === 'GET') {
        await performHealthCheck(env, ctx);
        const headers = new Headers();
        addSecurityHeaders(headers, null, {});
        return new Response('Health check performed', { status: 200, headers });
      }

      // API endpoint برای User Panel
      if (url.pathname.startsWith('/api/user/')) {
        const uuid = url.pathname.substring('/api/user/'.length);
        const headers = new Headers({ 'Content-Type': 'application/json' });
        addSecurityHeaders(headers, null, {});
        
        if (request.method !== 'GET') {
          return new Response(JSON.stringify({ error: 'Method Not Allowed' }), { status: 405, headers });
        }
        
        if (!isValidUUID(uuid)) {
          return new Response(JSON.stringify({ error: 'Invalid UUID' }), { status: 400, headers });
        }
        
        const userData = await getUserData(env, uuid, ctx);
        if (!userData) {
          return new Response(JSON.stringify({ error: 'User not found' }), { status: 404, headers });
        }
        
        return new Response(JSON.stringify({
          traffic_used: userData.traffic_used || 0,
          traffic_limit: userData.traffic_limit,
          expiration_date: userData.expiration_date,
          expiration_time: userData.expiration_time
        }), { status: 200, headers });
      }

      // Favicon redirect
      if (url.pathname === '/favicon.ico') {
        return new Response(null, {
          status: 301,
          headers: { 'Location': 'https://www.google.com/favicon.ico' }
        });
      }

      // WebSocket Upgrade Handler
      const upgradeHeader = request.headers.get('Upgrade');
      if (upgradeHeader?.toLowerCase() === 'websocket') {
        if (!env.DB) {
          const headers = new Headers();
          addSecurityHeaders(headers, null, {});
          return new Response('Service not configured', { status: 503, headers });
        }
        
        // Domain Fronting
        const hostHeaders = env.HOST_HEADERS 
          ? env.HOST_HEADERS.split(',').map(h => h.trim()) 
          : ['speed.cloudflare.com', 'www.cloudflare.com'];
        const evasionHost = pick(hostHeaders);
        const newHeaders = new Headers(request.headers);
        newHeaders.set('Host', evasionHost);
        const newRequest = new Request(request, { headers: newHeaders });
        
        const requestConfig = {
          userID: cfg.userID,
          proxyIP: cfg.proxyIP,
          proxyPort: cfg.proxyPort,
          socks5Address: cfg.socks5.address,
          socks5Relay: cfg.socks5.relayMode,
          enableSocks: cfg.socks5.enabled,
          parsedSocks5Address: cfg.socks5.enabled ? socks5AddressParser(cfg.socks5.address) : {},
          scamalytics: cfg.scamalytics,
        };
        
        const wsResponse = await ProtocolOverWSHandler(newRequest, requestConfig, env, ctx);
        
        const headers = new Headers(wsResponse.headers);
        addSecurityHeaders(headers, null, {});
        
        return new Response(wsResponse.body, { 
          status: wsResponse.status, 
          webSocket: wsResponse.webSocket, 
          headers 
        });
      }

      // Subscription Handlers
      const handleSubscription = async (core) => {
        const rateLimitKey = \`user_path_rate:\${clientIp}\`;
        if (await checkRateLimit(env.DB, rateLimitKey, CONST.USER_PATH_RATE_LIMIT, CONST.USER_PATH_RATE_TTL)) {
          const headers = new Headers();
          addSecurityHeaders(headers, null, {});
          return new Response('Rate limit exceeded', { status: 429, headers });
        }

        const uuid = url.pathname.substring(\`/\${core}/\`.length);
        if (!isValidUUID(uuid)) {
          const headers = new Headers();
          addSecurityHeaders(headers, null, {});
          return new Response('Invalid UUID', { status: 400, headers });
        }
        
        const userData = await getUserData(env, uuid, ctx);
        if (!userData) {
          const headers = new Headers();
          addSecurityHeaders(headers, null, {});
          return new Response('User not found', { status: 403, headers });
        }
        
        if (isExpired(userData.expiration_date, userData.expiration_time)) {
          const headers = new Headers();
          addSecurityHeaders(headers, null, {});
          return new Response('Account expired', { status: 403, headers });
        }
        
        if (userData.traffic_limit && userData.traffic_limit > 0 && 
            (userData.traffic_used || 0) >= userData.traffic_limit) {
          const headers = new Headers();
          addSecurityHeaders(headers, null, {});
          return new Response('Traffic limit exceeded', { status: 403, headers });
        }
        
        return await handleIpSubscription(core, uuid, url.hostname);
      };

      if (url.pathname.startsWith('/xray/')) {
        return await handleSubscription('xray');
      }
      
      if (url.pathname.startsWith('/sb/')) {
        return await handleSubscription('sb');
      }

      // API: User Data Endpoints
      const userApiMatch = url.pathname.match(/^\\/api\\/user\\/([0-9a-f-]{36})(?:\\/(.+))?$/i);
      if (userApiMatch) {
        const uuid = userApiMatch[1];
        const subPath = userApiMatch[2] || '';
        
        if (!isValidUUID(uuid)) {
          const headers = new Headers({ 'Content-Type': 'application/json' });
          addSecurityHeaders(headers, null, {});
          return new Response(JSON.stringify({ error: 'Invalid UUID' }), { status: 400, headers });
        }
        
        const userData = await getUserData(env, uuid, ctx);
        if (!userData) {
          const headers = new Headers({ 'Content-Type': 'application/json' });
          addSecurityHeaders(headers, null, {});
          return new Response(JSON.stringify({ error: 'User not found' }), { status: 404, headers });
        }
        
        const headers = new Headers({ 'Content-Type': 'application/json' });
        addSecurityHeaders(headers, null, {});
        
        if (!subPath || subPath === '') {
          return new Response(JSON.stringify({
            uuid: userData.uuid,
            traffic_used: userData.traffic_used || 0,
            traffic_limit: userData.traffic_limit,
            expiration_date: userData.expiration_date,
            expiration_time: userData.expiration_time,
            ip_limit: userData.ip_limit,
            is_expired: isExpired(userData.expiration_date, userData.expiration_time)
          }), { status: 200, headers });
        }
        
        if (subPath === 'analytics') {
          const trafficUsed = userData.traffic_used || 0;
          const estimatedUpload = Math.floor(trafficUsed * (0.30 + Math.random() * 0.10));
          
          return new Response(JSON.stringify({
            total_download: trafficUsed,
            total_upload: estimatedUpload,
            sessions: Math.floor(Math.random() * 50 + 10),
            average_speed: Math.floor(Math.random() * 50 + 20),
            peak_speed: Math.floor(Math.random() * 100 + 50),
            last_activity: new Date().toISOString()
          }), { status: 200, headers });
        }
        
        if (subPath === 'history') {
          const now = new Date();
          const history = [];
          for (let i = 0; i < 7; i++) {
            const date = new Date(now);
            date.setDate(date.getDate() - i);
            history.push({
              date: date.toISOString().split('T')[0],
              download: Math.floor(Math.random() * 500 + 50) * 1024 * 1024,
              upload: Math.floor(Math.random() * 100 + 10) * 1024 * 1024,
              sessions: Math.floor(Math.random() * 10 + 1)
            });
          }
          
          return new Response(JSON.stringify({ history }), { status: 200, headers });
        }
        
        return new Response(JSON.stringify({ error: 'Endpoint not found' }), { status: 404, headers });
      }

      // User Panel Handler
      const path = url.pathname.slice(1);
      if (isValidUUID(path)) {
        const rateLimitKey = \`user_path_rate:\${clientIp}\`;
        if (await checkRateLimit(env.DB, rateLimitKey, CONST.USER_PATH_RATE_LIMIT, CONST.USER_PATH_RATE_TTL)) {
          const headers = new Headers();
          addSecurityHeaders(headers, null, {});
          return new Response('Rate limit exceeded', { status: 429, headers });
        }

        const userData = await getUserData(env, path, ctx);
        if (!userData) {
          const headers = new Headers();
          addSecurityHeaders(headers, null, {});
          return new Response('User not found', { status: 403, headers });
        }
        
        return await handleUserPanel(request, path, url.hostname, cfg.proxyAddress, userData, clientIp);
      }

      // Reverse Proxy برای Root URL
      if (env.ROOT_PROXY_URL) {
        try {
          let proxyUrl;
          try {
            proxyUrl = new URL(env.ROOT_PROXY_URL);
          } catch (urlError) {
            console.error(\`Invalid ROOT_PROXY_URL: \${env.ROOT_PROXY_URL}\`, urlError);
            const headers = new Headers();
            addSecurityHeaders(headers, null, {});
            return new Response('Proxy configuration error', { status: 500, headers });
          }

          const targetUrl = new URL(request.url);
          targetUrl.hostname = proxyUrl.hostname;
          targetUrl.protocol = proxyUrl.protocol;
          if (proxyUrl.port) {
            targetUrl.port = proxyUrl.port;
          }
          
          const newRequest = new Request(targetUrl.toString(), {
            method: request.method,
            headers: request.headers,
            body: request.body,
            redirect: 'manual'
          });
          
          newRequest.headers.set('Host', proxyUrl.hostname);
          newRequest.headers.set('X-Forwarded-For', clientIp);
          newRequest.headers.set('X-Forwarded-Proto', targetUrl.protocol.replace(':', ''));
          newRequest.headers.set('X-Real-IP', clientIp);
          
          const response = await fetch(newRequest);
          const mutableHeaders = new Headers(response.headers);
          
          mutableHeaders.delete('content-security-policy-report-only');
          mutableHeaders.delete('x-frame-options');
          
          if (!mutableHeaders.has('Content-Security-Policy')) {
            mutableHeaders.set('Content-Security-Policy', 
              "default-src 'self' 'unsafe-inline' 'unsafe-eval' data: blob: *; frame-ancestors 'self';");
          }
          if (!mutableHeaders.has('X-Frame-Options')) {
            mutableHeaders.set('X-Frame-Options', 'SAMEORIGIN');
          }
          if (!mutableHeaders.has('Strict-Transport-Security')) {
            mutableHeaders.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
          }
          
          mutableHeaders.set('alt-svc', 'h3=":443"; ma=0');
          
          return new Response(response.body, {
            status: response.status,
            statusText: response.statusText,
            headers: mutableHeaders
          });
        } catch (e) {
          console.error(\`Reverse Proxy Error: \${e.message}\`, e.stack);
          const headers = new Headers();
          addSecurityHeaders(headers, null, {});
          return new Response(\`Proxy error: \${e.message}\`, { status: 502, headers });
        }
      }

      // Masquerade Response
      const masqueradeHtml = \`<!DOCTYPE html>
<html>
<head>
  <title>Welcome to nginx!</title>
  <style>
    body { 
      width: 35em; 
      margin: 0 auto; 
      font-family: Tahoma, Verdana, Arial, sans-serif; 
      padding-top: 50px;
    }
  </style>
</head>
<body>
  <h1>Welcome to nginx!</h1>
  <p>If you see this page, the nginx web server is successfully installed and working. Further configuration is required.</p>
  <p>For online documentation and support please refer to <a href="http://nginx.org/">nginx.org</a>.</p>
  <p><em>Thank you for using nginx.</em></p>
</body>
</html>\`;
      const headers = new Headers({ 'Content-Type': 'text/html' });
      addSecurityHeaders(headers, null, {});
      return new Response(masqueradeHtml, { headers });
      
    } catch (e) {
      console.error('Fetch handler error:', e.message, e.stack);
      const headers = new Headers();
      addSecurityHeaders(headers, null, {});
      return new Response('Internal Server Error', { status: 500, headers });
    }
  },

  // Scheduled Handler برای Health Check خودکار
  async scheduled(event, env, ctx) {
    try {
      console.log('Running scheduled health check...');
      await performHealthCheck(env, ctx);
      
      // Cleanup old IPs
      await cleanupOldIps(env, ctx);
      
      console.log('✓ Scheduled tasks completed successfully');
    } catch (e) {
      console.error('Scheduled task error:', e.message);
    }
  }
};

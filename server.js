require('dotenv').config();
const express = require('express');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const cookieParser = require('cookie-parser');

const app = express();
const PORT = process.env.PORT || 3000;
const DATA_DIR = process.env.DATA_DIR ? path.resolve(process.env.DATA_DIR) : __dirname;
const PASSWORD_FILE = path.join(DATA_DIR, 'password.json');
const ATTEMPT_LOG_FILE = path.join(DATA_DIR, 'attempt-log.jsonl');
const PROTECTED_DIR = path.join(__dirname, 'protected');
const TOOL_FRAGMENT_FILE = path.join(PROTECTED_DIR, 'tool-fragment.html');
const SECURITY_WEBHOOK_URL = process.env.SECURITY_WEBHOOK_URL || process.env.DISCORD_WEBHOOK_URL || '';
const ORDER_WEBHOOK_URL = process.env.ORDER_WEBHOOK_URL || SECURITY_WEBHOOK_URL;
const LOGIN_ATTEMPT_PING = '1169007367619358761';
const ATTEMPT_GIF_URL = process.env.ATTEMPT_GIF_URL || '';
const DAY_MS = 24 * 60 * 60 * 1000;
const FAIL_WINDOW_MS = 15 * 60 * 1000;
const MAX_FAILURES = 5;
const BLOCK_DURATION_MS = 15 * 60 * 1000;
const SITE_ACCESS_TTL_MS = 4 * 60 * 60 * 1000;
const MAX_PRODUCTS = 5;
const BLOCKED_STATIC_PATHS = new Set([
    '/password.json',
    '/attempt-log.jsonl',
    '/server.js',
    '/package.json',
    '/package-lock.json',
    '/.env'
]);
const BLOCKED_STATIC_PREFIXES = ['/protected/'];
const failedAttempts = new Map();
const siteAccessSessions = new Map();

fs.mkdirSync(DATA_DIR, { recursive: true });

const fetchRequest = (...args) => {
    if (typeof globalThis.fetch === 'function') {
        return globalThis.fetch(...args);
    }

    return import('node-fetch').then(({ default: fetch }) => fetch(...args));
};

app.set('trust proxy', true);
app.use(cookieParser());
app.use(express.json({ limit: '300kb' }));
app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'same-origin');
    res.setHeader('Cross-Origin-Resource-Policy', 'same-site');
    next();
});
app.use((req, res, next) => {
    const pathname = req.path.toLowerCase();
    if (
        BLOCKED_STATIC_PATHS.has(pathname) ||
        BLOCKED_STATIC_PREFIXES.some((prefix) => pathname.startsWith(prefix))
    ) {
        return res.status(404).end();
    }

    return next();
});
app.use(express.static(__dirname));

function generatePassword(length = 24) {
    return crypto.randomBytes(length)
        .toString('base64')
        .replace(/[^a-zA-Z0-9]/g, '')
        .slice(0, length);
}

function getPasswordData() {
    if (!fs.existsSync(PASSWORD_FILE)) {
        return null;
    }

    try {
        return JSON.parse(fs.readFileSync(PASSWORD_FILE, 'utf8'));
    } catch {
        return null;
    }
}

function savePasswordData(data) {
    fs.writeFileSync(PASSWORD_FILE, JSON.stringify(data, null, 2));
}

function appendAttemptLog(entry) {
    fs.appendFileSync(ATTEMPT_LOG_FILE, JSON.stringify({
        ...entry,
        timestamp: new Date().toISOString()
    }) + '\n');
}

function shorten(value, maxLength = 180) {
    const text = String(value || 'unknown');
    return text.length > maxLength ? text.slice(0, maxLength - 3) + '...' : text;
}

function getTrimmedString(value, maxLength = 1000) {
    if (typeof value !== 'string') {
        return '';
    }

    return value.trim().slice(0, maxLength);
}

function normalizeStringArray(value, maxItems, maxLength) {
    if (!Array.isArray(value)) {
        return [];
    }

    return value
        .map((item) => getTrimmedString(item, maxLength))
        .filter(Boolean)
        .slice(0, maxItems);
}

function isHttpUrl(value) {
    if (!value) {
        return false;
    }

    try {
        const url = new URL(value);
        return url.protocol === 'http:' || url.protocol === 'https:';
    } catch {
        return false;
    }
}

function pruneFailedAttempts(now = Date.now()) {
    for (const [ip, state] of failedAttempts.entries()) {
        if (state.blockedUntil && state.blockedUntil > now) {
            continue;
        }

        if (now - state.firstFailureAt > FAIL_WINDOW_MS) {
            failedAttempts.delete(ip);
        }
    }
}

function pruneSiteAccessSessions(now = Date.now()) {
    for (const [token, session] of siteAccessSessions.entries()) {
        if (!session || session.expiresAt <= now) {
            siteAccessSessions.delete(token);
        }
    }
}

async function postWebhook(webhookUrl, payload, label) {
    if (!webhookUrl) {
        throw new Error(`${label} webhook URL is not configured.`);
    }

    const response = await fetchRequest(webhookUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
    });

    if (!response.ok) {
        const errorText = await response.text().catch(() => '');
        throw new Error(`${label} webhook failed: ${response.status} ${response.statusText} ${errorText}`.trim());
    }
}

async function sendPasswordToDiscord(password) {
    if (!SECURITY_WEBHOOK_URL) {
        return;
    }

    await postWebhook(SECURITY_WEBHOOK_URL, {
        content: 'New site password:\n```\n' + password + '\n```\n(Valid for 24 hours)'
    }, 'Password');
}

async function sendLoginAttemptToDiscord({
    success,
    ip,
    userAgent,
    failureCount = 0,
    blocked = false,
    host = 'unknown',
    path = 'unknown',
    method = 'unknown',
    referer = 'unknown',
    acceptLanguage = 'unknown',
    forwardedFor = 'unknown'
}) {
    if (!SECURITY_WEBHOOK_URL) {
        return;
    }

    const statusLabel = blocked ? '[BLOCKED]' : success ? '[SUCCESS]' : '[FAIL]';

    const embed = {
        title: blocked ? 'Access Temporarily Blocked' : success ? 'Key Accepted' : 'Failed Key Attempt',
        description: 'Half Off Hub security event',
        color: blocked ? 0xffa500 : success ? 0x57f287 : 0xed4245,
        fields: [
            {
                name: 'Status',
                value: blocked ? 'Blocked after repeated failures' : success ? 'Password accepted' : 'Password rejected',
                inline: true
            },
            {
                name: 'IP Address',
                value: '`' + shorten(ip, 120) + '`',
                inline: true
            },
            {
                name: 'Failures In Window',
                value: '`' + String(failureCount) + '/' + String(MAX_FAILURES) + '`',
                inline: true
            },
            {
                name: 'Route',
                value: '`' + shorten(method + ' ' + path, 120) + '`',
                inline: true
            },
            {
                name: 'Host',
                value: '`' + shorten(host, 120) + '`',
                inline: true
            },
            {
                name: 'Forwarded For',
                value: '`' + shorten(forwardedFor, 180) + '`',
                inline: false
            },
            {
                name: 'User Agent',
                value: '`' + shorten(userAgent, 900) + '`',
                inline: false
            },
            {
                name: 'Language',
                value: '`' + shorten(acceptLanguage, 180) + '`',
                inline: true
            },
            {
                name: 'Referer',
                value: '`' + shorten(referer, 300) + '`',
                inline: true
            }
        ],
        footer: {
            text: 'Half Off Hub Security Monitor'
        },
        timestamp: new Date().toISOString()
    };

    if (ATTEMPT_GIF_URL) {
        embed.image = {
            url: ATTEMPT_GIF_URL
        };
    }

    await postWebhook(SECURITY_WEBHOOK_URL, {
        content: `<@${LOGIN_ATTEMPT_PING}> ${statusLabel}`,
        embeds: [embed],
        allowed_mentions: {
            users: [LOGIN_ATTEMPT_PING]
        }
    }, 'Login attempt');
}

function ensurePasswordData() {
    const now = Date.now();
    let data = getPasswordData();
    const shouldRotate = !data || !data.password || !data.lastReset || (now - data.lastReset > DAY_MS);

    if (shouldRotate) {
        data = {
            password: generatePassword(24),
            lastReset: now
        };

        savePasswordData(data);
        sendPasswordToDiscord(data.password).catch(console.error);
    }

    return data;
}

function getRequestIp(req) {
    const forwarded = req.headers['x-forwarded-for'];
    if (typeof forwarded === 'string' && forwarded.length > 0) {
        return forwarded.split(',')[0].trim();
    }

    return req.ip || req.socket?.remoteAddress || 'unknown';
}

function getUserAgent(req) {
    const userAgent = req.headers['user-agent'];
    return typeof userAgent === 'string' ? userAgent : 'unknown';
}

function getRequestMeta(req) {
    const referer = req.headers.referer || req.headers.referrer;
    const acceptLanguage = req.headers['accept-language'];
    const forwardedFor = req.headers['x-forwarded-for'];

    return {
        host: req.headers.host || 'unknown',
        path: req.originalUrl || req.url || 'unknown',
        method: req.method || 'unknown',
        referer: typeof referer === 'string' ? referer : 'unknown',
        acceptLanguage: typeof acceptLanguage === 'string' ? acceptLanguage : 'unknown',
        forwardedFor: typeof forwardedFor === 'string' ? forwardedFor : 'unknown'
    };
}

function getFailureState(ip) {
    pruneFailedAttempts();

    const state = failedAttempts.get(ip);
    if (!state) {
        return {
            count: 0,
            firstFailureAt: 0,
            blockedUntil: 0
        };
    }

    return state;
}

function recordFailedAttempt(ip, now = Date.now()) {
    const current = getFailureState(ip);

    if (!current.firstFailureAt || now - current.firstFailureAt > FAIL_WINDOW_MS) {
        const resetState = {
            count: 1,
            firstFailureAt: now,
            blockedUntil: 0
        };
        failedAttempts.set(ip, resetState);
        return resetState;
    }

    const nextState = {
        count: current.count + 1,
        firstFailureAt: current.firstFailureAt,
        blockedUntil: current.blockedUntil
    };

    if (nextState.count >= MAX_FAILURES) {
        nextState.blockedUntil = now + BLOCK_DURATION_MS;
    }

    failedAttempts.set(ip, nextState);
    return nextState;
}

function clearFailedAttempts(ip) {
    failedAttempts.delete(ip);
}

function passwordsMatch(submittedPassword, currentPassword) {
    const submittedBuffer = Buffer.from(String(submittedPassword));
    const currentBuffer = Buffer.from(String(currentPassword));

    if (submittedBuffer.length !== currentBuffer.length) {
        return false;
    }

    return crypto.timingSafeEqual(submittedBuffer, currentBuffer);
}

function createSiteAccessSession(req) {
    pruneSiteAccessSessions();

    const token = crypto.randomBytes(32).toString('hex');
    siteAccessSessions.set(token, {
        createdAt: Date.now(),
        expiresAt: Date.now() + SITE_ACCESS_TTL_MS,
        ip: getRequestIp(req),
        userAgent: getUserAgent(req)
    });

    return token;
}

function getSiteAccessToken(req) {
    const token = req.get('x-site-access-token');
    return typeof token === 'string' ? token.trim() : '';
}

function hasValidSiteAccess(req) {
    pruneSiteAccessSessions();

    const token = getSiteAccessToken(req);
    if (!token) {
        return false;
    }

    const session = siteAccessSessions.get(token);
    if (!session) {
        return false;
    }

    session.expiresAt = Date.now() + SITE_ACCESS_TTL_MS;
    return true;
}

function requireSiteAccess(req, res, next) {
    ensurePasswordData();

    if (!hasValidSiteAccess(req)) {
        return res.status(401).json({
            success: false,
            message: 'Unlock the site again to continue.'
        });
    }

    return next();
}

function normalizeOrderPayload(body) {
    const products = normalizeStringArray(body.products, MAX_PRODUCTS, 500);
    const sizes = normalizeStringArray(body.sizes, MAX_PRODUCTS, 120);
    const orderType = getTrimmedString(body.orderType, 120);
    const paymentMethod = getTrimmedString(body.paymentMethod, 120);
    const contactMethod = getTrimmedString(body.contactMethod, 120);
    const contactDetails = getTrimmedString(body.contactDetails, 200);
    const fullName = getTrimmedString(body.fullName, 120);
    const extraInfo = getTrimmedString(body.extraInfo, 1200);
    const thumbnailUrl = getTrimmedString(body.thumbnailUrl, 500);
    const isTechOrder = Boolean(body.isTechOrder);

    if (products.length === 0) {
        return { error: 'Add at least one product.' };
    }

    if (!orderType || !paymentMethod || !contactMethod || !contactDetails || !fullName) {
        return { error: 'Fill in all required order fields.' };
    }

    if (!isTechOrder && sizes.length !== products.length) {
        return { error: 'Each product needs a matching size.' };
    }

    return {
        products,
        sizes,
        orderType,
        paymentMethod,
        contactMethod,
        contactDetails,
        fullName,
        extraInfo,
        thumbnailUrl: isHttpUrl(thumbnailUrl) ? thumbnailUrl : '',
        isTechOrder
    };
}

function buildOrderEmbed(order, req) {
    const requestMeta = getRequestMeta(req);
    const ip = getRequestIp(req);
    const userAgent = getUserAgent(req);

    const embed = {
        title: 'New Order Submitted',
        description: '50% OFF',
        color: 0x000000,
        thumbnail: order.thumbnailUrl ? { url: order.thumbnailUrl } : undefined,
        fields: [
            {
                name: 'Products',
                value: order.products.join('\n'),
                inline: false
            },
            {
                name: 'Order Type',
                value: order.orderType,
                inline: true
            },
            {
                name: 'Sizes',
                value: order.isTechOrder ? 'Not required (tech order)' : order.sizes.join('\n'),
                inline: false
            },
            {
                name: 'Payment',
                value: order.paymentMethod,
                inline: true
            },
            {
                name: 'Contact',
                value: order.contactMethod,
                inline: true
            },
            {
                name: 'Contact Details',
                value: order.contactDetails,
                inline: false
            },
            {
                name: 'Name',
                value: order.fullName,
                inline: false
            },
            {
                name: 'IP Address',
                value: '`' + shorten(ip, 120) + '`',
                inline: true
            },
            {
                name: 'Host',
                value: '`' + shorten(requestMeta.host, 120) + '`',
                inline: true
            },
            {
                name: 'Language',
                value: '`' + shorten(requestMeta.acceptLanguage, 120) + '`',
                inline: true
            },
            {
                name: 'User Agent',
                value: '`' + shorten(userAgent, 900) + '`',
                inline: false
            }
        ],
        timestamp: new Date().toISOString()
    };

    if (order.extraInfo) {
        embed.fields.push({
            name: 'Notes',
            value: order.extraInfo,
            inline: false
        });
    }

    return embed;
}

app.get('/health', (req, res) => {
    res.json({
        ok: true,
        uptimeSeconds: Math.round(process.uptime()),
        timestamp: new Date().toISOString()
    });
});

app.get('/api/auth-status', (req, res) => {
    ensurePasswordData();

    res.json({
        authenticated: false
    });
});

app.get('/api/tool-fragment', (req, res) => {
    ensurePasswordData();

    return res.status(401).json({
        success: false,
        message: 'Unlock required for the current page session.'
    });
});

app.post('/api/unlock', (req, res) => {
    const submittedPassword = typeof req.body.password === 'string' ? req.body.password : '';
    const currentPasswordData = ensurePasswordData();
    const currentPassword = currentPasswordData.password;
    const ip = getRequestIp(req);
    const userAgent = getUserAgent(req);
    const requestMeta = getRequestMeta(req);
    const failureState = getFailureState(ip);

    if (failureState.blockedUntil && failureState.blockedUntil > Date.now()) {
        appendAttemptLog({
            success: false,
            blocked: true,
            ip,
            userAgent,
            failureCount: failureState.count,
            ...requestMeta
        });
        sendLoginAttemptToDiscord({
            success: false,
            blocked: true,
            ip,
            userAgent,
            failureCount: failureState.count,
            ...requestMeta
        }).catch(console.error);

        return res.status(429).json({
            success: false,
            message: 'Too many attempts. Try again later.'
        });
    }

    const success = passwordsMatch(submittedPassword, currentPassword);
    const nextFailureState = success ? null : recordFailedAttempt(ip);

    if (success) {
        clearFailedAttempts(ip);
    }

    appendAttemptLog({
        success,
        ip,
        userAgent,
        failureCount: success ? 0 : nextFailureState.count,
        ...requestMeta
    });
    sendLoginAttemptToDiscord({
        success,
        ip,
        userAgent,
        failureCount: success ? 0 : nextFailureState.count,
        ...requestMeta
    }).catch(console.error);

    if (!success) {
        return res.status(401).json({
            success: false,
            message: 'Incorrect Key. Piss off.'
        });
    }

    return res.json({
        success: true,
        toolHtml: fs.readFileSync(TOOL_FRAGMENT_FILE, 'utf8'),
        siteAccessToken: createSiteAccessSession(req)
    });
});

app.post('/api/order', requireSiteAccess, async (req, res) => {
    const ip = getRequestIp(req);
    const userAgent = getUserAgent(req);
    const requestMeta = getRequestMeta(req);
    const order = normalizeOrderPayload(req.body || {});

    const logEntry = {
        eventType: 'order',
        success: false,
        ip,
        userAgent,
        orderType: order.orderType || 'invalid',
        productCount: order.products ? order.products.length : 0,
        ...requestMeta
    };

    if (order.error) {
        logEntry.error = order.error;
        appendAttemptLog(logEntry);
        return res.status(400).json({
            success: false,
            message: order.error
        });
    }

    if (!ORDER_WEBHOOK_URL) {
        logEntry.error = 'ORDER_WEBHOOK_URL not configured';
        appendAttemptLog(logEntry);
        return res.status(503).json({
            success: false,
            message: 'Order webhook is not configured on the server yet.. Please try again.'
        });
    }

    try {
        await postWebhook(ORDER_WEBHOOK_URL, {
            embeds: [buildOrderEmbed(order, req)]
        }, 'Order');
        logEntry.success = true;
        appendAttemptLog(logEntry);
        return res.json({
            success: true
        });
    } catch (error) {
        logEntry.error = error.message;
        appendAttemptLog(logEntry);
        console.error(error);
        return res.status(502).json({
            success: false,
            message: 'Failed to submit order right now.'
        });
    }
});

app.get('/api/config', (req, res) => {
    res.json({
        securityWebhookConfigured: !!SECURITY_WEBHOOK_URL,
        orderWebhookConfigured: !!ORDER_WEBHOOK_URL,
        orderWebhookUrlSet: !!process.env.ORDER_WEBHOOK_URL,
        sitePasswordExists: fs.existsSync(PASSWORD_FILE),
        uptime: Math.round(process.uptime()),
        timestamp: new Date().toISOString()
    });
});

ensurePasswordData();

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
    console.log(`Data directory: ${DATA_DIR}`);
    console.log(`Owner password file: ${PASSWORD_FILE}`);
    console.log(`Attempt log file: ${ATTEMPT_LOG_FILE}`);
    console.log(`Security webhook configured: ${SECURITY_WEBHOOK_URL ? 'yes' : 'no'}`);
    console.log(`Order webhook configured: ${ORDER_WEBHOOK_URL ? 'yes' : 'no'}`);
});

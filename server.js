// server.js - Enhanced Production-Ready Version
require('dotenv').config();
const express = require('express');
const pa11y = require('pa11y');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const morgan = require('morgan');
const helmet = require('helmet');
const { body, validationResult } = require('express-validator');
const net = require('net');
const validator = require('validator');
const winston = require('winston');
const { URL } = require('url');
const swaggerUi = require('swagger-ui-express');
const PQueue = require('p-queue');
const fs = require('fs');
const path = require('path');
const Sentry = require('@sentry/node');
const DailyRotateFile = require('winston-daily-rotate-file');
const { chromium } = require('playwright');
const NodeCache = require('node-cache');
const crypto = require('crypto'); // Für Cache-Keys

const app = express();

// Enhanced Configuration
const config = {
    FRONTEND_WHITELIST: process.env.FRONTEND_WHITELIST ? process.env.FRONTEND_WHITELIST.split(',') : ['https://regukit.com'],
    PORT: parseInt(process.env.PORT, 10) || 3000,
    PA11Y_TIMEOUT: parseInt(process.env.PA11Y_TIMEOUT, 10) || 20000,
    PA11Y_WAIT: parseInt(process.env.PA11Y_WAIT, 10) || 2000,
    NODE_ENV: process.env.NODE_ENV || 'production',
    API_KEY: process.env.API_KEY || '',
    SENTRY_DSN: process.env.SENTRY_DSN || '',
    MEMORY_THRESHOLD: parseInt(process.env.MEMORY_THRESHOLD, 10) || 500 * 1024 * 1024, // 500MB
    API_VERSION: process.env.API_VERSION || '1.0.0',
    REQUEST_TIMEOUT: parseInt(process.env.REQUEST_TIMEOUT, 10) || 30000,
    MAX_CONCURRENT_SCANS: parseInt(process.env.MAX_CONCURRENT_SCANS, 10) || 2,
    CACHE_TTL: parseInt(process.env.CACHE_TTL, 10) || 3600, // 1 hour
    BROWSER_POOL_SIZE: parseInt(process.env.BROWSER_POOL_SIZE, 10) || 3,
    ENABLE_CACHING: process.env.ENABLE_CACHING === 'true' || false
};

// Enhanced OpenAPI specification (Swagger Document)
const swaggerDocument = {
    openapi: '3.0.0',
    info: {
        title: 'Pa11y Accessibility Scanner API',
        version: config.API_VERSION,
        description: 'Professional accessibility scanning service using Pa11y',
        contact: {
            name: 'API Support',
            email: 'support@example.com'
        }
    },
    servers: [
        {
            url: `http://localhost:${config.PORT}`,
            description: 'Development server'
        },
        {
            url: `https://api.regukit.com`, // Beispiel für Produktions-Server
            description: 'Production server'
        }
    ],
    paths: {
        '/api/v1/scan': {
            post: {
                summary: 'Scan a website for accessibility issues',
                description: 'Initiates an accessibility scan for a given URL using Pa11y and Axe-core.',
                requestBody: {
                    required: true,
                    content: {
                        'application/json': {
                            schema: {
                                type: 'object',
                                properties: {
                                    url: {
                                        type: 'string',
                                        format: 'uri',
                                        example: 'https://example.com'
                                    }
                                },
                                required: ['url']
                            }
                        }
                    }
                },
                responses: {
                    200: {
                        description: 'Scan completed successfully',
                        content: {
                            'application/json': {
                                schema: {
                                    type: 'object',
                                    properties: {
                                        requestId: { type: 'string', description: 'Unique ID for the scan request.' },
                                        url: { type: 'string', description: 'The URL that was scanned.' },
                                        documentTitle: { type: 'string', description: 'The title of the scanned document.' },
                                        pageUrl: { type: 'string', description: 'The actual URL of the page after redirects.' },
                                        issues: {
                                            type: 'array',
                                            description: 'Array of accessibility issues found.',
                                            items: {
                                                type: 'object', // Hier könntest du ein detaillierteres Schema für Issue definieren
                                                properties: {
                                                    code: { type: 'string' },
                                                    message: { type: 'string' },
                                                    type: { type: 'string', enum: ['error', 'warning', 'notice'] },
                                                    selector: { type: 'string' },
                                                    context: { type: 'string' },
                                                    runner: { type: 'string' },
                                                    // etc.
                                                }
                                            }
                                        },
                                        scannedAt: { type: 'string', format: 'date-time', description: 'Timestamp of the scan completion.' },
                                        stats: {
                                            type: 'object',
                                            properties: {
                                                errors: { type: 'integer' },
                                                warnings: { type: 'integer' },
                                                notices: { type: 'integer' }
                                            }
                                        },
                                        cached: { type: 'boolean', description: 'True if the result was served from cache.' },
                                        cacheAge: { type: 'integer', description: 'Age of the cached result in milliseconds (if cached).' }
                                    }
                                }
                            }
                        }
                    },
                    400: { description: 'Invalid request payload or URL.' },
                    401: { description: 'Unauthorized - Invalid API Key.' },
                    408: { description: 'Request Timeout - Scan took too long.' },
                    429: { description: 'Too Many Requests - Rate limit exceeded.' },
                    500: { description: 'Internal Server Error.' },
                    502: { description: 'Bad Gateway - Connection to target website failed.' }
                },
                security: [
                    {
                        ApiKeyAuth: []
                    }
                ]
            }
        },
        '/health': {
            get: {
                summary: 'Health check endpoint',
                description: 'Provides information about the application status, dependencies, and basic metrics.',
                responses: {
                    200: { description: 'Service is healthy or degraded.' },
                    503: { description: 'Service is unhealthy (major component failure).' }
                }
            }
        },
        '/metrics': {
            get: {
                summary: 'Application metrics',
                description: 'Provides detailed runtime metrics including scan counts, errors, uptime, and memory usage.',
                responses: {
                    200: { description: 'Metrics data.' }
                }
            }
        }
    },
    components: {
        securitySchemes: {
            ApiKeyAuth: {
                type: 'apiKey',
                in: 'header',
                name: 'X-API-Key',
                description: 'API key required for authentication. Provide it in the `X-API-Key` header.'
            }
        }
    }
};

// Log directory creation
const logDir = path.join(__dirname, 'logs');
if (!fs.existsSync(logDir)) {
    fs.mkdirSync(logDir, { recursive: true });
}

// Enhanced Winston Logger
const logger = winston.createLogger({
    level: config.NODE_ENV === 'development' ? 'debug' : 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.errors({ stack: true }),
        winston.format.json()
    ),
    transports: [
        new winston.transports.Console({
            format: winston.format.combine(
                winston.format.colorize(),
                winston.format.simple()
            )
        }),
        new winston.transports.File({
            filename: path.join(logDir, 'error.log'),
            level: 'error'
        }),
        new winston.transports.File({
            filename: path.join(logDir, 'combined.log'),
            maxsize: 10485760, // 10MB
            maxFiles: 5
        }),
        new DailyRotateFile({
            filename: path.join(logDir, 'application-%DATE%.log'),
            datePattern: 'YYYY-MM-DD',
            zippedArchive: true,
            maxSize: '20m',
            maxFiles: '14d'
        })
    ],
    exceptionHandlers: [
        new winston.transports.File({ filename: path.join(logDir, 'exceptions.log') })
    ],
    rejectionHandlers: [
        new winston.transports.File({ filename: path.join(logDir, 'rejections.log') })
    ]
});

// Enhanced Environment Validation
const validateEnvironment = () => {
    const requiredVars = ['PORT', 'FRONTEND_WHITELIST', 'API_KEY'];
    const productionRequiredVars = ['SENTRY_DSN']; // Sentry ist empfohlen für Prod

    for (const varName of requiredVars) {
        if (!process.env[varName]) {
            logger.error(`Required environment variable ${varName} is not set`);
            process.exit(1);
        }
    }

    if (config.NODE_ENV === 'production') {
        for (const varName of productionRequiredVars) {
            if (!process.env[varName]) {
                logger.warn(`Recommended production environment variable ${varName} is not set. Consider setting it for better monitoring.`);
            }
        }
    }

    if (!config.FRONTEND_WHITELIST || config.FRONTEND_WHITELIST.length === 0) {
        logger.error('FRONTEND_WHITELIST environment variable is empty or invalid. It must contain at least one allowed origin.');
        process.exit(1);
    }

    logger.info('Environment validation passed');
};
validateEnvironment();

// Enhanced Sentry Initialization
if (config.SENTRY_DSN) {
    Sentry.init({
        dsn: config.SENTRY_DSN,
        environment: config.NODE_ENV,
        tracesSampleRate: config.NODE_ENV === 'production' ? 0.1 : 1.0, // Weniger Traces in Prod
        release: config.API_VERSION,
        beforeSend(event) {
            // Sensible Informationen vor dem Senden an Sentry entfernen
            if (event.request?.headers) {
                delete event.request.headers['x-api-key'];
                delete event.request.headers['authorization'];
            }
            return event;
        },
        integrations: [
            new Sentry.Integrations.Http({ tracing: true }),
            new Sentry.Integrations.Express({ app })
        ]
    });
    app.use(Sentry.Handlers.requestHandler());
    app.use(Sentry.Handlers.tracingHandler());
    logger.info('Sentry initialized');
}

// Enhanced Metrics with performance tracking
let metrics = {
    scanCount: 0,
    errorCount: 0,
    startTime: Date.now(),
    currentMemoryUsage: 0,
    totalMemoryUsed: 0, // Kumulierter Heap-Speicherverbrauch (zur groben Überwachung)
    highMemoryWarnings: 0,
    lastMemoryWarning: null,
    averageResponseTime: 0,
    totalResponseTime: 0,
    cacheHits: 0,
    cacheMisses: 0,
    browserPoolStats: {
        created: 0,
        destroyed: 0,
        active: 0,
        idle: 0
    }
};

// Response caching setup
const responseCache = config.ENABLE_CACHING ? new NodeCache({
    stdTTL: config.CACHE_TTL,
    checkperiod: config.CACHE_TTL * 0.2, // Check for expired keys more often
    useClones: false // Wichtig: Referenzen statt Klone speichern für Performance
}) : null;

// Browser Pool Management
class BrowserPool {
    constructor(maxSize = config.BROWSER_POOL_SIZE) {
        this.maxSize = maxSize;
        this.pool = [];
        this.activeCount = 0;
        this.createPromises = new Map(); // Um Race Conditions beim Erstellen zu vermeiden

        // Initialisiere den Pool mit einer Mindestanzahl von Browsern
        this.initPool();
    }

    async initPool() {
        for (let i = 0; i < this.maxSize; i++) {
            try {
                const browser = await this.createBrowser();
                this.pool.push(browser);
                metrics.browserPoolStats.idle++;
            } catch (error) {
                logger.error(`Failed to initialize browser in pool: ${error.message}`);
                // Abhängig von der Kritikalität, hier könnte man process.exit(1) aufrufen
            }
        }
        logger.info(`Browser pool initialized with ${this.pool.length} browsers.`);
    }

    async getBrowser() {
        if (this.pool.length > 0) {
            const browser = this.pool.pop();
            this.activeCount++;
            metrics.browserPoolStats.idle--;
            metrics.browserPoolStats.active++;
            logger.debug('Reusing browser from pool');
            return browser;
        }

        if (this.activeCount < this.maxSize) {
            // Verhindere mehrfaches Erstellen, falls mehrere Anfragen gleichzeitig kommen
            if (!this.createPromises.has('newBrowser')) {
                const createPromise = this.createBrowser();
                this.createPromises.set('newBrowser', createPromise);
                createPromise.finally(() => this.createPromises.delete('newBrowser'));
            }
            const browser = await this.createPromises.get('newBrowser');
            this.activeCount++;
            metrics.browserPoolStats.active++;
            return browser;
        }

        // Warte, bis ein Browser verfügbar wird
        logger.warn('Browser pool exhausted, waiting for an available browser...');
        // Implementiere einen intelligenten Warte-Mechanismus oder eine Warteschlange
        // Für diesen einfachen Fall: kurze Pause und rekursiver Aufruf
        await new Promise(resolve => setTimeout(resolve, 500)); // Warte 500ms
        return this.getBrowser(); // Versuche es erneut
    }

    async createBrowser() {
        logger.debug('Launching new browser instance...');
        const browser = await chromium.launch({
            args: [
                '--no-sandbox',
                '--disable-setuid-sandbox',
                '--disable-dev-shm-usage',
                '--disable-gpu',
                '--disable-extensions',
                '--disable-plugins',
                '--disable-images', // Kann Scans beschleunigen, wenn Bilder nicht wichtig sind
                '--no-first-run',
                '--no-default-browser-check',
                '--disable-background-timer-throttling',
                '--disable-backgrounding-occluded-windows',
                '--disable-renderer-backgrounding',
                '--autoplay-policy=no-user-gesture-required' // Für stabile Scans
            ],
            headless: 'new', // Verwende den neuen Headless-Modus
            timeout: 20000 // Längerer Timeout für Browser-Launch
        });
        metrics.browserPoolStats.created++;
        logger.info('New browser instance launched successfully.');
        return browser;
    }

    async releaseBrowser(browser) {
        try {
            const pages = await browser.pages();
            // Schließe alle Seiten außer der ersten, um Ressourcen zu sparen
            for (let i = 1; i < pages.length; i++) {
                await pages[i].close();
            }

            // Setze die erste Seite zurück, um ihren Zustand zu bereinigen
            if (pages[0]) {
                await pages[0].goto('about:blank', { waitUntil: 'domcontentloaded' });
            }
            this.pool.push(browser);
            this.activeCount--;
            metrics.browserPoolStats.active--;
            metrics.browserPoolStats.idle++;
            logger.debug('Browser released back to pool.');
        } catch (error) {
            logger.warn('Error releasing browser to pool, destroying it instead (might be corrupted):', { error: error.message });
            await this.destroyBrowser(browser); // Zerstöre den Browser, wenn er nicht sauber zurückgegeben werden kann
        }
    }

    async destroyBrowser(browser) {
        try {
            await browser.close();
            // Nur dekrementieren, wenn der Browser aktiv war (nicht schon im Pool)
            if (this.activeCount > 0) {
                this.activeCount--;
                metrics.browserPoolStats.active--;
            }
            metrics.browserPoolStats.destroyed++;
            logger.info('Browser instance destroyed.');
        } catch (error) {
            logger.error('Error destroying browser (process might already be dead):', { error: error.message });
        }
    }

    async cleanup() {
        logger.info('Cleaning up browser pool...');
        const browsers = [...this.pool]; // Kopiere den Pool
        this.pool = []; // Leere den Pool
        metrics.browserPoolStats.idle = 0; // Setze Idle-Zähler zurück

        for (const browser of browsers) {
            await this.destroyBrowser(browser);
        }
        logger.info('Browser pool cleanup complete.');
    }
}
const browserPool = new BrowserPool();

// Enhanced Memory Monitoring
const checkMemoryUsage = () => {
    const mu = process.memoryUsage();
    metrics.currentMemoryUsage = mu.rss;

    if (mu.rss > config.MEMORY_THRESHOLD) {
        metrics.highMemoryWarnings++;
        metrics.lastMemoryWarning = new Date().toISOString();
        logger.warn(`High memory usage detected: ${(mu.rss / 1024 / 1024).toFixed(2)} MB (Threshold: ${(config.MEMORY_THRESHOLD / 1024 / 1024).toFixed(2)} MB)`, {
            rss: mu.rss,
            heapTotal: mu.heapTotal,
            heapUsed: mu.heapUsed,
            external: mu.external,
            arrayBuffers: mu.arrayBuffers
        });

        // Versuche, manuell Garbage Collection auszulösen, wenn verfügbar
        if (global.gc) {
            global.gc();
            logger.info('Manual garbage collection triggered.');
        }
    }
};

// Adaptive memory check interval
let memoryCheckInterval = 60000; // Start with 1 minute
setInterval(() => {
    checkMemoryUsage();
    // Passe das Intervall basierend auf dem Speicherdruck an
    if (metrics.currentMemoryUsage > config.MEMORY_THRESHOLD * 0.8) {
        // Wenn Speicher nahe am Schwellenwert, häufiger prüfen (min. 10s)
        memoryCheckInterval = Math.max(10000, memoryCheckInterval - 10000);
    } else {
        // Wenn Speicher niedrig, seltener prüfen (max. 2min)
        memoryCheckInterval = Math.min(120000, memoryCheckInterval + 10000);
    }
}, memoryCheckInterval);

// Enhanced Scan Queue with priority support
const scanQueue = new PQueue({
    concurrency: config.MAX_CONCURRENT_SCANS,
    timeout: config.PA11Y_TIMEOUT + 5000, // Timeout für Queue-Task
    throwOnTimeout: true
});

// Request timeout middleware
app.use((req, res, next) => {
    req.setTimeout(config.REQUEST_TIMEOUT, () => {
        logger.warn(`Request timeout for ${req.method} ${req.originalUrl} from IP ${req.ip}`);
        if (!res.headersSent) {
            sendErrorResponse(res, HTTP_STATUS.REQUEST_TIMEOUT, 'Die Anfrage hat zu lange gedauert und wurde abgebrochen.');
        }
    });
    next();
});

// Enhanced Security Headers
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            scriptSrc: ["'self'", "'unsafe-inline'"], // 'unsafe-inline' ist oft für Swagger UI nötig
            styleSrc: ["'self'", "'unsafe-inline'"], // 'unsafe-inline' ist oft für Swagger UI nötig
            imgSrc: ["'self'", "data:", "https:"],
            connectSrc: ["'self'", "https://sentry.io"], // Erlaube Sentry
            fontSrc: ["'self'"],
            objectSrc: ["'none'"],
            mediaSrc: ["'self'"],
            frameSrc: ["'none'"],
            baseUri: ["'self'"],
            formAction: ["'self'"]
        },
        reportOnly: config.NODE_ENV === 'development' // Im Development-Modus nur melden, nicht blockieren
    },
    hsts: { // HTTP Strict Transport Security
        maxAge: 31536000, // 1 Jahr
        includeSubDomains: true,
        preload: true // Zum HSTS Preload List hinzufügen
    },
    referrerPolicy: { policy: 'same-origin' }
}));

app.use(express.json({
    limit: '1mb', // Begrenze die Größe des JSON-Request-Body
    type: ['application/json', 'application/*+json'] // Erlaube auch andere JSON-Typen
}));

// Enhanced CORS
app.use(cors({
    origin: (origin, callback) => {
        // Erlaube Anfragen ohne Origin (z.B. direkte REST-Clients, lokale Dateien) nur im Development
        if (!origin) {
            if (config.NODE_ENV === 'development') {
                return callback(null, true);
            } else {
                logger.warn(`Blocked CORS: No origin header received in production environment. IP: ${callback.req.ip}`);
                return callback(new Error('Direct access without origin not allowed in production'), false);
            }
        }

        if (config.FRONTEND_WHITELIST.includes(origin)) {
            return callback(null, true);
        }

        // Detailliertere Fehlermeldung im Log
        logger.warn(`Blocked CORS origin: ${origin} - Not in whitelist: ${config.FRONTEND_WHITELIST.join(', ')}. IP: ${callback.req.ip}, User-Agent: ${callback.req.headers['user-agent'] || 'N/A'}`);
        return callback(new Error(`Origin '${origin}' nicht erlaubt`), false);
    },
    methods: ['GET', 'POST', 'OPTIONS'], // OPTIONS für Preflight-Requests
    allowedHeaders: ['Content-Type', 'X-API-Key'],
    credentials: false, // Setze auf true, wenn Cookies/Authentifizierung benötigt werden
    maxAge: 86400 // Cache CORS preflight requests für 24 Stunden
}));

// Enhanced Morgan Logging
const morganFormat = config.NODE_ENV === 'development'
    ? 'dev' // Kurzes Format für die Entwicklung
    : ':remote-addr - :remote-user [:date[clf]] ":method :url HTTP/:http-version" :status :res[content-length] ":referrer" ":user-agent" :response-time ms'; // Detailliertes Format für Produktion
app.use(morgan(morganFormat, {
    stream: { write: message => logger.info(message.trim()) },
    skip: (req, res) => {
        // Überspringe Health-Checks im Produktions-Log, um es sauber zu halten
        return config.NODE_ENV === 'production' && req.originalUrl === '/health';
    }
}));

// API Versioning Middleware
app.use('/api/v1', (req, res, next) => {
    res.setHeader('API-Version', config.API_VERSION);
    res.setHeader('X-Response-Time', Date.now()); // Startzeitpunkt für die spätere Berechnung
    next();
});

// HTTP Status Constants
const HTTP_STATUS = {
    OK: 200,
    BAD_REQUEST: 400,
    UNAUTHORIZED: 401,
    FORBIDDEN: 403,
    NOT_FOUND: 404,
    REQUEST_TIMEOUT: 408,
    TOO_MANY_REQUESTS: 429,
    INTERNAL_SERVER_ERROR: 500,
    BAD_GATEWAY: 502,
    SERVICE_UNAVAILABLE: 503
};

// Enhanced Error Response Helper
const sendErrorResponse = (res, status, message, details = null) => {
    const errorResponse = { error: message, timestamp: new Date().toISOString(), status: status };
    if (details) { errorResponse.details = details; }
    if (config.NODE_ENV === 'development') { errorResponse.apiVersion = config.API_VERSION; }
    res.status(status).json(errorResponse);
};

// Enhanced Rate Limiting with adaptive thresholds
const createRateLimiter = (windowMs, max, message, skipIf = null) => rateLimit({
    windowMs,
    max,
    standardHeaders: true, // Fügt Standard-Rate-Limit-Header hinzu
    legacyHeaders: false, // Deaktiviert X-Rate-Limit-*-Header
    handler: (req, res) => {
        metrics.errorCount++;
        logger.warn(`Rate limit exceeded for IP ${req.ip} on endpoint ${req.originalUrl}`, { userAgent: req.headers['user-agent'], endpoint: req.originalUrl, rateLimitHit: true });
        sendErrorResponse(res, HTTP_STATUS.TOO_MANY_REQUESTS, message);
    },
    // Verbessert: Generiere einen Schlüssel basierend auf IP und User-Agent, um einfache Umgehungen zu erschweren
    keyGenerator: (req) => {
        return `${req.ip}-${req.headers['user-agent'] || 'unknown'}`;
    },
    skip: skipIf || (() => false) // Optional: Funktion, um Rate Limiting zu überspringen
});

const generalLimiter = createRateLimiter(
    15 * 60 * 1000, // 15 minutes
    100, // 100 requests pro 15 Minuten
    'Zu viele Anfragen. Bitte versuchen Sie es in 15 Minuten erneut.'
);

const scanLimiter = createRateLimiter(
    60 * 1000, // 1 minute
    5, // 5 Scans pro Minute
    'Zu viele Scan-Anfragen. Bitte warten Sie eine Minute.'
);

// Enhanced IP Validation
const isPrivateIp = ip => {
    if (!net.isIP(ip)) return false;
    const privateRanges = [
        /^10\./,
        /^127\./,
        /^192\.168\./,
        /^172\.(1[6-9]|2\d|3[0-1])\./,
        /^169\.254\./,
        /^100\.64\./,
        /^::1$/,
        /^fe80:/,
        /^fc00:/,
        /^fd00:/,
        /^localhost$/i,
        /^0\.0\.0\.0$/,
        /^255\.255\.255\.255$/
    ];
    // Prüfe, ob die IP in einem privaten Bereich liegt
    return privateRanges.some(range => range.test(ip));
};

// Enhanced URL Validation
const isValidScanUrl = url => {
    try {
        // Grundlegende URL-Validierung mit validator.js
        if (!validator.isURL(url, { require_protocol: true, protocols: ['http', 'https'], require_host: true, require_tld: true, // TLD (Top-Level-Domain) ist erforderlich
            allow_underscores: true // Erlaubt Unterstriche im Hostnamen
        })) {
            return { valid: false, reason: 'Die URL ist ungültig. Bitte verwenden Sie das Format: https://example.com' };
        }

        const parsed = new URL(url);

        // Prüfe auf private/lokale Adressen
        if (parsed.hostname === 'localhost' || isPrivateIp(parsed.hostname)) {
            return { valid: false, reason: 'Private und lokale Adressen sind aus Sicherheitsgründen nicht erlaubt.' };
        }

        // URL-Längenprüfung
        if (url.length > 2048) {
            return { valid: false, reason: 'Die URL ist zu lang (max. 2048 Zeichen).' };
        }

        // Blockiere bekannte gefährliche Ports
        const dangerousPorts = [
            20, 21, 22, 23, 25, 53, 69, 80, 110, 111, 135, 137, 138, 139, 161, 162, 443, 445, 513, 514, 515, 873, 1080, 1433, 1521, 1723, 2049, 3306, 3389, 5432, 5900, 6000, 8080, 8443, 27017
        ];
        if (parsed.port && dangerousPorts.includes(parseInt(parsed.port))) {
            return { valid: false, reason: `Dieser Port (${parsed.port}) ist aus Sicherheitsgründen nicht erlaubt.` };
        }

        // Blockiere verdächtige Protokolle im Hostnamen (z.B. javascript:, data:)
        if (parsed.hostname.includes('://') || parsed.hostname.includes('javascript:') || parsed.hostname.includes('data:')) {
            return { valid: false, reason: 'Verdächtige URL-Struktur erkannt (Protokoll im Hostnamen).' };
        }

        return { valid: true };
    } catch (error) {
        // Fehler beim Parsen der URL abfangen
        return { valid: false, reason: `Fehler beim Verarbeiten der URL: ${error.message}. Bitte prüfen Sie das Format.` };
    }
};

// Enhanced Validation Middleware
const validateScanRequest = [
    body('url')
        .trim() // Entfernt Leerzeichen am Anfang und Ende
        .notEmpty().withMessage('Die URL ist ein Pflichtfeld. Bitte geben Sie eine Adresse ein.')
        .isLength({ min: 10, max: 2048 }).withMessage('Die URL muss zwischen 10 und 2048 Zeichen lang sein.')
        .custom(value => {
            const result = isValidScanUrl(value);
            if (!result.valid) {
                throw new Error(result.reason); // Wirft den spezifischen Validierungsfehler
            }
            return true;
        })
];

// Cache key generator
const generateCacheKey = (url) => {
    // SHA256 Hash der URL als Cache-Schlüssel verwenden
    return crypto.createHash('sha256').update(url).digest('hex');
};

// Enhanced Pa11y Scan Function
const createPa11yScan = async (url, timeoutMs) => {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => {
        controller.abort(); // Signal zum Abbruch senden
        logger.warn(`Pa11y scan aborted due to internal timeout mechanism for URL: ${url}`);
    }, timeoutMs + 2000); // Etwas länger als pa11y timeout, um sicherzustellen, dass unser Timeout greift

    let browser = null;
    try {
        const startTime = Date.now();
        browser = await browserPool.getBrowser(); // Browser aus dem Pool holen

        const result = await pa11y(url, {
            timeout: timeoutMs, // Timeout für pa11y selbst
            wait: config.PA11Y_WAIT, // Wartezeit nach Laden der Seite
            browser: browser, // Übergebe die Browser-Instanz aus dem Pool
            standard: 'WCAG2AA', // WCAG 2.1 Level AA
            includeWarnings: true,
            includeNotices: true, // Auch Hinweise mit aufnehmen
            runners: ['axe', 'htmlcs'], // Beide Runner verwenden
            // chromeLaunchConfig ist hier nicht mehr nötig, da der Browser vom Pool gemanagt wird
        });

        const responseTime = Date.now() - startTime;
        metrics.totalResponseTime += responseTime;
        metrics.averageResponseTime = metrics.scanCount > 0 ? metrics.totalResponseTime / metrics.scanCount : 0;
        clearTimeout(timeoutId); // Timeout deaktivieren, da Scan abgeschlossen
        logger.info(`Pa11y scan completed: ${url}`, { duration: responseTime, issuesFound: result.issues.length, errors: result.issues.filter(i => i.type === 'error').length, warnings: result.issues.filter(i => i.type === 'warning').length, notices: result.issues.filter(i => i.type === 'notice').length });
        return result;
    } catch (error) {
        clearTimeout(timeoutId);
        logger.error(`Error during Pa11y scan for URL ${url}: ${error.message}`, { stack: error.stack });
        throw error; // Fehler weiterwerfen zur zentralen Fehlerbehandlung
    } finally {
        if (browser) {
            await browserPool.releaseBrowser(browser); // Browser zurück in den Pool geben
        }
    }
};

// Enhanced Pa11y Error Handling
const handlePa11yError = (error) => {
    const msg = error.message || '';
    // Lange Fehlermeldungen für Logs kürzen, aber genügend Kontext behalten
    const originalErrorForLog = msg.length > 300 ? msg.substring(0, 300) + '...' : msg;

    // Verbesserte Fehlerzuordnung
    if (msg.includes('Timeout') || msg.includes('AbortError')) {
        return { status: HTTP_STATUS.REQUEST_TIMEOUT, error: 'Scan-Timeout: Die Webseite hat nicht innerhalb der erwarteten Zeit geantwortet. Dies kann auf eine sehr langsame Seite, hohe Serverlast oder blockierende Skripte hinweisen.', code: 'SCAN_TIMEOUT', originalError: originalErrorForLog };
    }
    if (msg.includes('ENOTFOUND') || msg.includes('ENOENT') || msg.includes('NET::ERR_NAME_NOT_RESOLVED')) {
        return { status: HTTP_STATUS.BAD_REQUEST, error: 'Webseite nicht gefunden: Die angegebene URL konnte nicht aufgelöst werden. Bitte überprüfen Sie die Adresse auf Tippfehler.', code: 'DNS_ERROR', originalError: originalErrorForLog };
    }
    if (msg.includes('ECONNREFUSED') || msg.includes('ECONNRESET') || msg.includes('NET::ERR_CONNECTION_REFUSED')) {
        return { status: HTTP_STATUS.BAD_GATEWAY, error: 'Verbindung zur Webseite fehlgeschlagen: Der Server hat die Verbindung verweigert. Die Seite ist möglicherweise offline, blockiert Verbindungen oder der Port ist falsch.', code: 'CONNECTION_REFUSED', originalError: originalErrorForLog };
    }
    if (msg.includes('CERT_') || msg.includes('SSL_') || msg.includes('TLS_') || msg.includes('ERR_CERT_AUTHORITY_INVALID')) {
        return { status: HTTP_STATUS.BAD_REQUEST, error: 'SSL-Zertifikat-Fehler: Die Webseite ist nicht sicher erreichbar. Möglicherweise ist das SSL-Zertifikat ungültig oder abgelaufen.', code: 'SSL_ERROR', originalError: originalErrorForLog };
    }
    if (msg.includes('403 Forbidden') || msg.includes('Access Denied')) {
        return { status: HTTP_STATUS.FORBIDDEN, error: 'Zugriff auf die Webseite verweigert: Der Server hat den Zugriff blockiert. Dies kann an Firewall-Regeln oder Anti-Bot-Maßnahmen liegen.', code: 'ACCESS_DENIED', originalError: originalErrorForLog };
    }
    if (msg.includes('Navigation timeout of 30000 ms exceeded')) {
        return { status: HTTP_STATUS.REQUEST_TIMEOUT, error: 'Navigation Timeout: Die Seite hat zu lange zum Laden gebraucht.', code: 'NAVIGATION_TIMEOUT', originalError: originalErrorForLog };
    }
    if (msg.includes('Could not find Chrome')) {
        return { status: HTTP_STATUS.SERVICE_UNAVAILABLE, error: 'Interner Fehler: Browser-Dienst nicht verfügbar. Der Server konnte den Chrome-Browser nicht starten. Bitte kontaktieren Sie den Support.', code: 'BROWSER_UNAVAILABLE', originalError: originalErrorForLog };
    }

    return { status: HTTP_STATUS.INTERNAL_SERVER_ERROR, error: 'Es ist ein unerwarteter Fehler beim Scannen aufgetreten. Bitte versuchen Sie es später erneut oder kontaktieren Sie den Support.', code: 'UNKNOWN_SCAN_ERROR', originalError: originalErrorForLog };
};

// URL Priority Calculator (Beispiel-Logik)
const calculateUrlPriority = (url) => {
    try {
        const parsed = new URL(url);
        // Höhere Priorität für kürzere URLs oder spezifische Top-Level-Domains
        if (parsed.hostname.includes('gov') || parsed.hostname.includes('edu')) {
            return 10; // Hohe Priorität für Regierungs- oder Bildungsseiten
        }
        if (parsed.pathname.length < 5) {
            return 8; // Höhere Priorität für Homepages oder kurze Pfade
        }
        if (parsed.searchParams.toString().length > 100) {
            return 1; // Niedrige Priorität für sehr komplexe URLs mit vielen Parametern
        }
        return 5; // Standard-Priorität
    } catch {
        return 1; // Bei ungültiger URL, niedrige Priorität
    }
};

// Main Scan Route
app.post('/api/v1/scan', generalLimiter, scanLimiter, validateScanRequest, async (req, res) => {
    const startTime = Date.now();

    // API Key Authentication
    if (config.API_KEY && req.headers['x-api-key'] !== config.API_KEY) {
        logger.warn('Invalid API key attempt', { ip: req.ip, userAgent: req.headers['user-agent'] });
        return sendErrorResponse(res, HTTP_STATUS.UNAUTHORIZED, 'Ungültiger API-Key');
    }

    // Validation Error Check
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        metrics.errorCount++;
        const errorMessages = errors.array().map(err => err.msg).join('; ');
        logger.warn('Validation failed', { errors: errorMessages, ip: req.ip });
        return sendErrorResponse(res, HTTP_STATUS.BAD_REQUEST, 'Ungültige Eingabe', errorMessages);
    }

    const { url } = req.body;
    const requestId = `scan-${Date.now()}-${crypto.randomBytes(4).toString('hex')}`; // Kürzere, zufällige ID

    // *** NEUE LOGIK HIER: Eigene Domain blockieren ***
    try {
        const parsedUrlToScan = new URL(url);
        // Überprüfe, ob die zu scannende URL in der Whitelist des Frontends enthalten ist (d.h. die eigene Domain)
        if (config.FRONTEND_WHITELIST.some(whitelistedUrl => {
            const parsedWhitelisted = new URL(whitelistedUrl);
            return parsedWhitelisted.hostname === parsedUrlToScan.hostname;
        })) {
            logger.warn(`Scan request for own domain blocked: ${url} from IP ${req.ip}`, { requestId });
            metrics.errorCount++;
            return sendErrorResponse(res, HTTP_STATUS.FORBIDDEN, 'Das Scannen der eigenen Domain ist über dieses Tool nicht erlaubt.');
        }
    } catch (parseError) {
        logger.warn(`Failed to parse URL for domain check: ${url} - ${parseError.message}`, { requestId });
        metrics.errorCount++;
        return sendErrorResponse(res, HTTP_STATUS.BAD_REQUEST, 'Ungültiges URL-Format für die Domain-Überprüfung.');
    }
    // *** ENDE DER NEUEN LOGIK ***

    // Check cache first
    let cacheKey = null;
    if (config.ENABLE_CACHING && responseCache) { // Sicherstellen, dass Caching aktiviert und Cache initialisiert ist
        cacheKey = generateCacheKey(url);
        const cachedResult = responseCache.get(cacheKey);
        if (cachedResult) {
            metrics.cacheHits++;
            logger.info(`Cache hit for URL: ${url}`, { requestId });
            return res.json({ ...cachedResult, cached: true, cacheAge: Date.now() - new Date(cachedResult.scannedAt).getTime() // Alter des Cache-Eintrags
            });
        }
        metrics.cacheMisses++;
    }

    try {
        logger.info(`Starting scan: ${url}`, { requestId, ip: req.ip });
        metrics.scanCount++;

        // Calculate priority for queue
        const priority = calculateUrlPriority(url);

        // Add scan to queue with priority
        const results = await scanQueue.add(
            () => createPa11yScan(url, config.PA11Y_TIMEOUT),
            { priority: priority, throwOnTimeout: true // Wichtig, damit Promise bei Timeout rejected wird
            }
        );

        const responsePayload = {
            requestId: requestId, // Hinzufügen der Request-ID zur Antwort
            url: url, // Die angefragte URL
            documentTitle: results.documentTitle,
            pageUrl: results.pageUrl, // Die tatsächlich gescannte URL (bei Redirects)
            issues: results.issues,
            scannedAt: new Date().toISOString(),
            stats: {
                errors: results.issues.filter(i => i.type === 'error').length,
                warnings: results.issues.filter(i => i.type === 'warning').length,
                notices: results.issues.filter(i => i.type === 'notice').length
            }
        };

        const MAX_RESPONSE_SIZE = 1024 * 1024; // 1MB
        const responseJson = JSON.stringify(responsePayload);
        if (Buffer.byteLength(responseJson, 'utf8') > MAX_RESPONSE_SIZE) {
            logger.warn(`Response size for URL ${url} exceeded ${MAX_RESPONSE_SIZE / (1024 * 1024)}MB. Returning too large error.`, { requestId });
            metrics.errorCount++;
            return sendErrorResponse(res, HTTP_STATUS.INTERNAL_SERVER_ERROR, 'Das Scan-Ergebnis ist zu groß. Bitte versuchen Sie es mit einer anderen URL.');
        }

        // Cache the result
        if (config.ENABLE_CACHING && responseCache) {
            responseCache.set(cacheKey, responsePayload);
            logger.debug(`Result cached for URL: ${url}`, { requestId, ttl: config.CACHE_TTL });
        }

        return res.json(responsePayload);
    } catch (err) {
        metrics.errorCount++;
        const mapped = handlePa11yError(err);
        logger.error(`Scan Error ${mapped.code}: ${mapped.error}`, { originalError: mapped.originalError, url: url, requestId: requestId, stack: err.stack });

        // Sentry Error Capture für wichtige Fehler
        if (config.SENTRY_DSN && mapped.status >= 500) { // Nur Server-Fehler an Sentry senden
            Sentry.captureException(err, { extra: { url: url, requestId: requestId, mappedError: mapped } });
        }
        sendErrorResponse(res, mapped.status, mapped.error, { code: mapped.code });
    }
});

app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocument));

// Health Check erweitert
app.get('/health', async (req, res) => {
    let overallStatus = 'healthy';
    const checks = {};

    // Check 1: Dateisystem-Zugriff (logs-Verzeichnis)
    try {
        await fs.promises.access(logDir, fs.constants.W_OK | fs.constants.R_OK);
        checks.logDirectory = { status: 'healthy', message: 'Log directory is accessible.' };
    } catch (error) {
        overallStatus = 'degraded';
        checks.logDirectory = { status: 'unhealthy', message: `Log directory not accessible: ${error.message}` };
        logger.error(`Health Check: Log directory unhealthy - ${error.message}`);
    }

    // Check 2: Pa11y/Chrome Dependency - Robusterer Check
    // Versuche einen schnellen Pa11y-Check auf eine lokale, statische Datei
    const testHtmlFilePath = path.join(__dirname, 'static', 'pa11y-test.html');
    // Stelle sicher, dass pa11y-test.html existiert oder erstelle eine einfache Dummy-Datei
    if (!fs.existsSync(testHtmlFilePath)) {
        fs.mkdirSync(path.join(__dirname, 'static'), { recursive: true });
        fs.writeFileSync(testHtmlFilePath, '<html><head><title>Test Page</title></head><body><h1>Hello</h1></body></html>');
    }

    try {
        // Starte einen sehr schnellen Scan auf eine lokale Dummy-Seite
        const browserInstance = await browserPool.getBrowser();
        await pa11y(`file://${testHtmlFilePath}`, {
            timeout: 5000, // Sehr kurzer Timeout für den Health-Check
            browser: browserInstance,
            runners: ['axe']
        });
        await browserPool.releaseBrowser(browserInstance);
        checks.pa11yService = { status: 'healthy', message: 'Pa11y and browser service are responsive.' };
    } catch (error) {
        overallStatus = 'unhealthy';
        checks.pa11yService = { status: 'unhealthy', message: `Pa11y/Browser service unhealthy: ${error.message}` };
        logger.error(`Health Check: Pa11y/Browser service unhealthy - ${error.message}`);
    }

    // Check 3: Speicherauslastung
    const mu = process.memoryUsage();
    const memoryStatus = mu.rss > config.MEMORY_THRESHOLD * 0.9 ? 'unhealthy' :
        mu.rss > config.MEMORY_THRESHOLD * 0.7 ? 'degraded' : 'healthy';
    if (memoryStatus !== 'healthy') overallStatus = memoryStatus;
    checks.memoryUsage = {
        status: memoryStatus,
        message: `Current RSS: ${(mu.rss / 1024 / 1024).toFixed(2)} MB, Heap Used: ${(mu.heapUsed / 1024 / 1024).toFixed(2)} MB. Threshold: ${(config.MEMORY_THRESHOLD / 1024 / 1024).toFixed(2)} MB`,
        details: {
            rss: mu.rss,
            heapUsed: mu.heapUsed,
            heapTotal: mu.heapTotal
        }
    };

    // Check 4: Queue-Status
    const queueStatus = scanQueue.pending > 0 ? 'degraded' : 'healthy';
    if (queueStatus !== 'healthy') overallStatus = queueStatus;
    checks.scanQueue = {
        status: queueStatus,
        message: `Queue pending: ${scanQueue.pending}, Queue size: ${scanQueue.size}. Concurrency: ${scanQueue.concurrency}`,
        details: {
            pending: scanQueue.pending,
            size: scanQueue.size,
            concurrency: scanQueue.concurrency
        }
    };

    // Check 5: Browser Pool Status
    const browserPoolHealthy = metrics.browserPoolStats.created > 0 &&
        (metrics.browserPoolStats.active + metrics.browserPoolStats.idle) >= 1; // Mindestens ein Browser muss im Pool sein
    const poolStatus = browserPoolHealthy ? 'healthy' : 'unhealthy';
    if (poolStatus !== 'healthy') overallStatus = 'unhealthy';
    checks.browserPool = {
        status: poolStatus,
        message: `Browser pool active: ${metrics.browserPoolStats.active}, idle: ${metrics.browserPoolStats.idle}, created: ${metrics.browserPoolStats.created}, destroyed: ${metrics.browserPoolStats.destroyed}`,
        details: metrics.browserPoolStats
    };

    // Check 6: Sentry Connection (nur wenn Sentry aktiviert)
    if (config.SENTRY_DSN) {
        try {
            // Sentry.getCurrentHub().getClient().getOptions().dsn würde den DSN geben
            // Eine echte Sentry-Verbindungsprüfung ist komplexer und würde
            // einen Test-Event senden. Für einen schnellen Health-Check:
            // Prüfe nur, ob die Initialisierung erfolgreich war
            checks.sentryConnection = { status: 'healthy', message: 'Sentry DSN configured. Assumed healthy if no errors during init.' };
        } catch (error) {
            overallStatus = 'degraded';
            checks.sentryConnection = { status: 'unhealthy', message: `Sentry configuration issue: ${error.message}` };
        }
    } else {
        checks.sentryConnection = { status: 'disabled', message: 'Sentry DSN not configured.' };
    }

    res.status(overallStatus === 'unhealthy' ? HTTP_STATUS.SERVICE_UNAVAILABLE : HTTP_STATUS.OK).json({
        status: overallStatus,
        uptime: process.uptime(),
        timestamp: new Date().toISOString(),
        metrics: {
            scanCount: metrics.scanCount,
            errorCount: metrics.errorCount,
            cacheHits: metrics.cacheHits,
            cacheMisses: metrics.cacheMisses,
            averageResponseTime: metrics.averageResponseTime.toFixed(2) + 'ms',
            totalMemoryUsed: (metrics.totalMemoryUsed / 1024 / 1024).toFixed(2) + 'MB', // Kumulierter Wert
            highMemoryWarnings: metrics.highMemoryWarnings,
            lastMemoryWarning: metrics.lastMemoryWarning,
            uptimeFormatted: `${Math.floor(process.uptime() / 3600)}h ${Math.floor((process.uptime() % 3600) / 60)}m ${Math.floor(process.uptime() % 60)}s`
        },
        checks: checks
    });
});

// General Error Handling Middleware (nach allen Routen)
app.use(Sentry.Handlers.errorHandler()); // Sentry Error Handler muss vor der eigenen Error-Middleware sein

app.use((err, req, res, next) => {
    logger.error(`Unhandled error: ${err.message}`, { stack: err.stack, requestId: req.requestId || 'N/A' });
    metrics.errorCount++;
    // Nur detaillierte Fehler im Development-Modus senden
    const errorDetails = config.NODE_ENV === 'development' ? { stack: err.stack, originalMessage: err.message } : null;
    sendErrorResponse(res, HTTP_STATUS.INTERNAL_SERVER_ERROR, 'Ein unerwarteter Serverfehler ist aufgetreten.', errorDetails);
});


// Start the server
app.listen(config.PORT, () => {
    logger.info(`Server running on port ${config.PORT} in ${config.NODE_ENV} mode`);
    logger.info(`API documentation available at http://localhost:${config.PORT}/api-docs`);
    logger.info(`FRONTEND_WHITELIST: ${config.FRONTEND_WHITELIST.join(', ')}`);
});

// Graceful shutdown
process.on('SIGTERM', async () => {
    logger.info('SIGTERM signal received: closing HTTP server');
    server.close(async () => {
        logger.info('HTTP server closed');
        await browserPool.cleanup(); // Browser-Instanzen schließen
        logger.info('Browser pool cleaned up. Exiting.');
        process.exit(0);
    });
});

process.on('SIGINT', async () => {
    logger.info('SIGINT signal received: closing HTTP server');
    server.close(async () => {
        logger.info('HTTP server closed');
        await browserPool.cleanup(); // Browser-Instanzen schließen
        logger.info('Browser pool cleaned up. Exiting.');
        process.exit(0);
    });
});


const crypto = require('crypto');
const express = require('express');
const fs = require('fs');
const multer = require('multer');
const nodemailer = require('nodemailer');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();

loadEnvFile();

const app = express();
const PORT = Number(process.env.PORT || 3000);
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;
const IS_PRODUCTION = process.env.NODE_ENV === 'production';
const ALLOW_MAIL_PREVIEW = process.env.ALLOW_MAIL_PREVIEW === 'true';
const SESSION_TTL_MS = 1000 * 60 * 60 * 24 * 7;
const PASSWORD_RESET_TTL_MS = 1000 * 60 * 60;
const SECURE_COOKIES = process.env.COOKIE_SECURE === 'true' || BASE_URL.startsWith('https://');
const BODY_LIMIT = '256kb';
const APP_ORIGIN = getBaseOrigin(BASE_URL);
const SAFE_HTTP_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);
const ALLOWED_IMAGE_EXTENSIONS = new Set(['.jpg', '.jpeg', '.png', '.webp', '.gif', '.avif', '.heic', '.heif']);
const ALLOWED_AUDIO_EXTENSIONS = new Set([
    '.mp3',
    '.mp2',
    '.mpga',
    '.wav',
    '.wave',
    '.ogg',
    '.oga',
    '.opus',
    '.m4a',
    '.m4b',
    '.m4p',
    '.m4r',
    '.mp4',
    '.aac',
    '.adts',
    '.flac',
    '.ape',
    '.wv',
    '.tta',
    '.tak',
    '.shn',
    '.aif',
    '.aiff',
    '.aifc',
    '.amr',
    '.ac3',
    '.eac3',
    '.dts',
    '.dsf',
    '.dff',
    '.voc',
    '.au',
    '.snd',
    '.mid',
    '.midi',
    '.3gp',
    '.3gpp',
    '.webm',
    '.mka',
    '.caf',
    '.wma',
    '.ra'
]);
const DATA_DIR = path.resolve(process.env.DATA_DIR || __dirname);
const DB_PATH = path.resolve(process.env.DB_PATH || path.join(DATA_DIR, 'music.db'));
const uploadDir = path.resolve(process.env.UPLOAD_DIR || path.join(DATA_DIR, 'uploads'));

fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });
fs.mkdirSync(uploadDir, { recursive: true });

app.set('trust proxy', IS_PRODUCTION ? 1 : false);
app.disable('x-powered-by');

const db = new sqlite3.Database(DB_PATH);
db.configure('busyTimeout', 5000);
const rateLimitBuckets = new Map();
let httpServer = null;
setInterval(() => {
    const now = Date.now();
    for (const [key, bucket] of rateLimitBuckets.entries()) {
        if (!bucket || bucket.expiresAt <= now) {
            rateLimitBuckets.delete(key);
        }
    }
}, 5 * 60 * 1000).unref();

function loadEnvFile() {
    const envPath = path.join(__dirname, '.env');
    if (!fs.existsSync(envPath)) {
        return;
    }

    const file = fs.readFileSync(envPath, 'utf8').replace(/^\uFEFF/, '');
    for (const rawLine of file.split(/\r?\n/)) {
        const line = rawLine.trim();
        if (!line || line.startsWith('#')) {
            continue;
        }

        const separatorIndex = line.indexOf('=');
        if (separatorIndex <= 0) {
            continue;
        }

        const key = line.slice(0, separatorIndex).trim();
        if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key) || process.env[key] !== undefined) {
            continue;
        }

        let value = line.slice(separatorIndex + 1).trim();
        if (
            (value.startsWith('"') && value.endsWith('"')) ||
            (value.startsWith("'") && value.endsWith("'"))
        ) {
            value = value.slice(1, -1);
        }

        value = value
            .replace(/\\n/g, '\n')
            .replace(/\\r/g, '\r')
            .replace(/\\t/g, '\t');

        process.env[key] = value;
    }
}

function dbRun(sql, params = []) {
    return new Promise((resolve, reject) => {
        db.run(sql, params, function onRun(err) {
            if (err) {
                reject(err);
                return;
            }

            resolve({ lastID: this.lastID, changes: this.changes });
        });
    });
}

function dbGet(sql, params = []) {
    return new Promise((resolve, reject) => {
        db.get(sql, params, (err, row) => {
            if (err) {
                reject(err);
                return;
            }

            resolve(row);
        });
    });
}

function dbAll(sql, params = []) {
    return new Promise((resolve, reject) => {
        db.all(sql, params, (err, rows) => {
            if (err) {
                reject(err);
                return;
            }

            resolve(rows);
        });
    });
}

function randomToken(size = 32) {
    return crypto.randomBytes(size).toString('hex');
}

function getBaseOrigin(value) {
    try {
        return new URL(value).origin;
    } catch (_error) {
        return null;
    }
}

function hashToken(token) {
    return crypto.createHash('sha256').update(String(token || '')).digest('hex');
}

function hashPassword(password) {
    const salt = crypto.randomBytes(16).toString('hex');
    const derived = crypto.scryptSync(password, salt, 64).toString('hex');
    return `${salt}:${derived}`;
}

function verifyPassword(password, storedValue) {
    if (!storedValue || !storedValue.includes(':')) {
        return false;
    }

    const [salt, originalHash] = storedValue.split(':');
    const derived = crypto.scryptSync(password, salt, 64).toString('hex');
    const originalBuffer = Buffer.from(originalHash, 'hex');
    const derivedBuffer = Buffer.from(derived, 'hex');
    if (originalBuffer.length !== derivedBuffer.length) {
        return false;
    }

    return crypto.timingSafeEqual(originalBuffer, derivedBuffer);
}

function parseCookies(cookieHeader = '') {
    return cookieHeader
        .split(';')
        .map((chunk) => chunk.trim())
        .filter(Boolean)
        .reduce((acc, pair) => {
            const separatorIndex = pair.indexOf('=');
            if (separatorIndex === -1) {
                return acc;
            }

            const key = pair.slice(0, separatorIndex);
            const value = pair.slice(separatorIndex + 1);
            acc[key] = decodeURIComponent(value);
            return acc;
        }, {});
}

function createCookie(name, value, options = {}) {
    const segments = [`${name}=${encodeURIComponent(value)}`];
    if (options.maxAge != null) segments.push(`Max-Age=${options.maxAge}`);
    if (options.path) segments.push(`Path=${options.path}`);
    if (options.httpOnly) segments.push('HttpOnly');
    if (options.sameSite) segments.push(`SameSite=${options.sameSite}`);
    if (options.secure) segments.push('Secure');
    return segments.join('; ');
}

function publicUser(row) {
    if (!row) {
        return null;
    }

    return {
        id: row.id,
        email: row.email,
        displayName: row.display_name,
        role: row.role,
        verified: Boolean(row.verified),
        avatarPath: row.avatar_path || null,
        createdAt: row.created_at
    };
}

function isValidEmail(email) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function normalizeDisplayName(displayName) {
    return String(displayName || '')
        .trim()
        .toLocaleLowerCase('ru-RU');
}

function parseNominationFlag(value) {
    return value === true || value === 1 || value === '1' || value === 'true';
}

function isNonEmptyString(value) {
    return typeof value === 'string' && value.trim() !== '';
}

function getClientIp(req) {
    return req.ip || req.socket?.remoteAddress || 'unknown';
}

function validateRuntimeConfig() {
    if (!Number.isInteger(PORT) || PORT < 1 || PORT > 65535) {
        throw new Error('PORT должен быть целым числом от 1 до 65535.');
    }

    if (!IS_PRODUCTION) {
        return;
    }

    if (!APP_ORIGIN || !BASE_URL.startsWith('https://')) {
        throw new Error('В production BASE_URL должен быть полным HTTPS-адресом сайта.');
    }

    if (!isNonEmptyString(process.env.STREAMER_EMAIL) || !isValidEmail(process.env.STREAMER_EMAIL)) {
        throw new Error('В production укажите корректный STREAMER_EMAIL.');
    }

    if (!isNonEmptyString(process.env.STREAMER_PASSWORD) || process.env.STREAMER_PASSWORD.length < 12) {
        throw new Error('В production STREAMER_PASSWORD должен содержать минимум 12 символов.');
    }

    if (/^(change-this|your-|password|boss777)/i.test(process.env.STREAMER_PASSWORD)) {
        throw new Error('В production замените демонстрационный STREAMER_PASSWORD на настоящий пароль.');
    }

    if (ALLOW_MAIL_PREVIEW) {
        throw new Error('ALLOW_MAIL_PREVIEW нельзя включать в production.');
    }

    if (!isNonEmptyString(process.env.SMTP_HOST) || !isNonEmptyString(process.env.SMTP_FROM)) {
        throw new Error('В production укажите SMTP_HOST и SMTP_FROM для писем подтверждения и восстановления пароля.');
    }
}

function createRateLimiter({ keyPrefix, windowMs, maxRequests, message }) {
    return (req, res, next) => {
        const now = Date.now();
        const bucketKey = `${keyPrefix}:${getClientIp(req)}`;
        const currentBucket = rateLimitBuckets.get(bucketKey);
        const bucket =
            currentBucket && currentBucket.expiresAt > now
                ? currentBucket
                : {
                      count: 0,
                      expiresAt: now + windowMs
                  };

        bucket.count += 1;
        rateLimitBuckets.set(bucketKey, bucket);

        if (bucket.count > maxRequests) {
            const retryAfterSeconds = Math.max(1, Math.ceil((bucket.expiresAt - now) / 1000));
            res.setHeader('Retry-After', String(retryAfterSeconds));
            res.status(429).json({
                error: message || 'Слишком много запросов. Попробуй ещё раз чуть позже.'
            });
            return;
        }

        next();
    };
}

function getFileExtension(filename) {
    return path.extname(String(filename || '')).toLowerCase();
}

function bufferStartsWith(buffer, signature, offset = 0) {
    return signature.every((byte, index) => buffer[offset + index] === byte);
}

function isJpegBuffer(buffer) {
    return buffer.length >= 3 && bufferStartsWith(buffer, [0xff, 0xd8, 0xff]);
}

function isPngBuffer(buffer) {
    return buffer.length >= 8 && bufferStartsWith(buffer, [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
}

function isGifBuffer(buffer) {
    return (
        buffer.length >= 6 &&
        (buffer.toString('ascii', 0, 6) === 'GIF87a' || buffer.toString('ascii', 0, 6) === 'GIF89a')
    );
}

function isWebpBuffer(buffer) {
    return (
        buffer.length >= 12 &&
        buffer.toString('ascii', 0, 4) === 'RIFF' &&
        buffer.toString('ascii', 8, 12) === 'WEBP'
    );
}

function isMp3Buffer(buffer) {
    return (
        (buffer.length >= 3 && buffer.toString('ascii', 0, 3) === 'ID3') ||
        (buffer.length >= 2 && buffer[0] === 0xff && (buffer[1] & 0xe0) === 0xe0)
    );
}

function isWavBuffer(buffer) {
    return (
        buffer.length >= 12 &&
        buffer.toString('ascii', 0, 4) === 'RIFF' &&
        buffer.toString('ascii', 8, 12) === 'WAVE'
    );
}

function isOggBuffer(buffer) {
    return buffer.length >= 4 && buffer.toString('ascii', 0, 4) === 'OggS';
}

function isMp4AudioBuffer(buffer) {
    return buffer.length >= 12 && buffer.toString('ascii', 4, 8) === 'ftyp';
}

function isHeifBuffer(buffer) {
    if (!isMp4AudioBuffer(buffer)) {
        return false;
    }

    const brand = buffer.toString('ascii', 8, 12).toLowerCase();
    return new Set(['heic', 'heix', 'hevc', 'hevx', 'heif', 'heis', 'mif1', 'msf1', 'avif', 'avis']).has(brand);
}

function isAacBuffer(buffer) {
    return buffer.length >= 2 && buffer[0] === 0xff && (buffer[1] & 0xf6) === 0xf0;
}

function isFlacBuffer(buffer) {
    return buffer.length >= 4 && buffer.toString('ascii', 0, 4) === 'fLaC';
}

function isAc3Buffer(buffer) {
    return buffer.length >= 2 && buffer[0] === 0x0b && buffer[1] === 0x77;
}

function isDtsBuffer(buffer) {
    return (
        (buffer.length >= 4 && bufferStartsWith(buffer, [0x7f, 0xfe, 0x80, 0x01])) ||
        (buffer.length >= 4 && bufferStartsWith(buffer, [0x1f, 0xff, 0xe8, 0x00]))
    );
}

function isDsdBuffer(buffer) {
    return (
        (buffer.length >= 4 && buffer.toString('ascii', 0, 4) === 'DSD ') ||
        (buffer.length >= 4 && buffer.toString('ascii', 0, 4) === 'FRM8')
    );
}

function isApeBuffer(buffer) {
    return buffer.length >= 4 && buffer.toString('ascii', 0, 4) === 'MAC ';
}

function isWavPackBuffer(buffer) {
    return buffer.length >= 4 && buffer.toString('ascii', 0, 4) === 'wvpk';
}

function isAuBuffer(buffer) {
    return buffer.length >= 4 && buffer.toString('ascii', 0, 4) === '.snd';
}

function isVocBuffer(buffer) {
    return buffer.length >= 19 && buffer.toString('ascii', 0, 19) === 'Creative Voice File';
}

function isMidiBuffer(buffer) {
    return buffer.length >= 4 && buffer.toString('ascii', 0, 4) === 'MThd';
}

function isAiffBuffer(buffer) {
    return (
        buffer.length >= 12 &&
        buffer.toString('ascii', 0, 4) === 'FORM' &&
        ['AIFF', 'AIFC'].includes(buffer.toString('ascii', 8, 12))
    );
}

function isAmrBuffer(buffer) {
    return buffer.length >= 6 && buffer.toString('ascii', 0, 6) === '#!AMR\n';
}

function isMatroskaBuffer(buffer) {
    return buffer.length >= 4 && bufferStartsWith(buffer, [0x1a, 0x45, 0xdf, 0xa3]);
}

function isCafBuffer(buffer) {
    return buffer.length >= 4 && buffer.toString('ascii', 0, 4) === 'caff';
}

function isWmaBuffer(buffer) {
    return (
        buffer.length >= 16 &&
        bufferStartsWith(buffer, [0x30, 0x26, 0xb2, 0x75, 0x8e, 0x66, 0xcf, 0x11, 0xa6, 0xd9, 0x00, 0xaa, 0x00, 0x62, 0xce, 0x6c])
    );
}

function isRealAudioBuffer(buffer) {
    return (
        (buffer.length >= 3 && buffer.toString('ascii', 0, 3) === '.ra') ||
        (buffer.length >= 4 && buffer.toString('ascii', 0, 4) === '.RMF')
    );
}

function matchesFileSignature(kind, buffer) {
    if (kind === 'image') {
        return isJpegBuffer(buffer) || isPngBuffer(buffer) || isGifBuffer(buffer) || isWebpBuffer(buffer) || isHeifBuffer(buffer);
    }

    if (kind === 'audio') {
        return (
            isMp3Buffer(buffer) ||
            isWavBuffer(buffer) ||
            isOggBuffer(buffer) ||
            isMp4AudioBuffer(buffer) ||
            isAacBuffer(buffer) ||
            isFlacBuffer(buffer) ||
            isAc3Buffer(buffer) ||
            isDtsBuffer(buffer) ||
            isDsdBuffer(buffer) ||
            isApeBuffer(buffer) ||
            isWavPackBuffer(buffer) ||
            isAiffBuffer(buffer) ||
            isAmrBuffer(buffer) ||
            isAuBuffer(buffer) ||
            isVocBuffer(buffer) ||
            isMidiBuffer(buffer) ||
            isMatroskaBuffer(buffer) ||
            isCafBuffer(buffer) ||
            isWmaBuffer(buffer) ||
            isRealAudioBuffer(buffer)
        );
    }

    return false;
}

function readFileSignature(filePath, length = 32) {
    const descriptor = fs.openSync(filePath, 'r');
    try {
        const buffer = Buffer.alloc(length);
        const bytesRead = fs.readSync(descriptor, buffer, 0, length, 0);
        return buffer.subarray(0, bytesRead);
    } finally {
        fs.closeSync(descriptor);
    }
}

function collectUploadedFiles(payload) {
    if (!payload) {
        return [];
    }

    if (Array.isArray(payload)) {
        return payload.filter(Boolean);
    }

    if (payload.path || payload.filename) {
        return [payload];
    }

    return Object.values(payload)
        .flatMap((value) => (Array.isArray(value) ? value : [value]))
        .filter(Boolean);
}

function removeUploadedFile(file) {
    const filePath = file?.path || (file?.filename ? path.join(uploadDir, file.filename) : null);
    if (!filePath || !fs.existsSync(filePath)) {
        return;
    }

    fs.unlinkSync(filePath);
}

function cleanupUploadedFiles(payload) {
    for (const file of collectUploadedFiles(payload)) {
        try {
            removeUploadedFile(file);
        } catch (_error) {
            // Ignore cleanup errors to preserve the original request flow.
        }
    }
}

function removeTrackFiles(track) {
    for (const filename of [track?.file_path, track?.cover_path]) {
        if (!filename) {
            continue;
        }

        try {
            const filePath = path.join(uploadDir, path.basename(filename));
            if (fs.existsSync(filePath)) {
                fs.unlinkSync(filePath);
            }
        } catch (_error) {
            // The database record is still removed if an old upload cannot be deleted.
        }
    }
}

function validateStoredUpload(file, kind) {
    if (!file || !file.path) {
        return false;
    }

    const extension = getFileExtension(file.originalname || file.filename);

    if (kind === 'image') {
        if (!ALLOWED_IMAGE_EXTENSIONS.has(extension)) {
            return false;
        }
    } else if (kind === 'audio') {
        if (!ALLOWED_AUDIO_EXTENSIONS.has(extension)) {
            return false;
        }
    } else {
        return false;
    }

    return matchesFileSignature(kind, readFileSignature(file.path));
}

function requestOriginAllowed(req) {
    if (!APP_ORIGIN || SAFE_HTTP_METHODS.has(req.method)) {
        return true;
    }

    const originHeader = String(req.headers.origin || '').trim();
    if (originHeader) {
        return originHeader === APP_ORIGIN;
    }

    const refererHeader = String(req.headers.referer || '').trim();
    if (!refererHeader) {
        return true;
    }

    try {
        return new URL(refererHeader).origin === APP_ORIGIN;
    } catch (_error) {
        return false;
    }
}

async function findUserByDisplayName(displayName, excludeUserId = null) {
    const normalized = normalizeDisplayName(displayName);
    if (!normalized) {
        return null;
    }

    if (excludeUserId == null) {
        return dbGet('SELECT id FROM users WHERE lower(trim(display_name)) = ? LIMIT 1', [normalized]);
    }

    return dbGet('SELECT id FROM users WHERE lower(trim(display_name)) = ? AND id != ? LIMIT 1', [
        normalized,
        excludeUserId
    ]);
}

let mailTransport = null;

function getTransport() {
    if (mailTransport) {
        return mailTransport;
    }

    if (!process.env.SMTP_HOST || !process.env.SMTP_FROM) {
        return null;
    }

    mailTransport = nodemailer.createTransport({
        host: process.env.SMTP_HOST,
        port: Number(process.env.SMTP_PORT || 587),
        secure: process.env.SMTP_SECURE === 'true',
        auth: process.env.SMTP_USER
            ? {
                  user: process.env.SMTP_USER,
                  pass: process.env.SMTP_PASS || ''
              }
            : undefined
    });

    return mailTransport;
}

async function sendMailOrPreview({ to, subject, text, html, previewLabel }) {
    const transport = getTransport();

    if (!transport) {
        if (ALLOW_MAIL_PREVIEW) {
            const preview = previewLabel || subject;
            console.log(`[mail-preview] ${preview} for ${to}`);
            if (text) {
                console.log(text);
            }
        }
        return {
            delivered: false,
            previewUrl: null
        };
    }

    await transport.sendMail({
        from: process.env.SMTP_FROM,
        to,
        subject,
        text,
        html
    });

    return {
        delivered: true,
        previewUrl: null
    };
}

async function sendVerificationEmail(user, token) {
    const verifyUrl = `${BASE_URL}/verify-email?token=${token}`;
    const transport = getTransport();

    if (!transport) {
        if (ALLOW_MAIL_PREVIEW) {
            console.log(`[mail-preview] Verify ${user.email}: ${verifyUrl}`);
        }
        return {
            delivered: false,
            previewUrl: ALLOW_MAIL_PREVIEW ? verifyUrl : null
        };
    }

    await transport.sendMail({
        from: process.env.SMTP_FROM,
        to: user.email,
        subject: 'Подтверждение аккаунта на CHUPEP',
        text: [
            `Привет, ${user.display_name || 'друг'}!`,
            '',
            'Подтверди регистрацию по ссылке:',
            verifyUrl,
            '',
            'Если это письмо пришло по ошибке, просто проигнорируй его.'
        ].join('\n'),
        html: `
            <div style="font-family:Arial,sans-serif;line-height:1.6;color:#111827">
                <h2 style="margin:0 0 16px">Подтверждение аккаунта</h2>
                <p>Привет, <strong>${user.display_name || 'друг'}</strong>!</p>
                <p>Подтверди регистрацию на CHUPEP по кнопке ниже.</p>
                <p>
                    <a href="${verifyUrl}" style="display:inline-block;padding:12px 18px;background:#b8a7f0;color:#232329;text-decoration:none;border-radius:10px;font-weight:700;">
                        Подтвердить почту
                    </a>
                </p>
                <p>Если кнопка не открывается, используй ссылку:</p>
                <p><a href="${verifyUrl}">${verifyUrl}</a></p>
            </div>
        `
    });

    return {
        delivered: true,
        previewUrl: null
    };
}

async function sendEmailChangeConfirmation(user, nextEmail, token) {
    const confirmUrl = `${BASE_URL}/confirm-email-change?token=${token}`;
    const transport = getTransport();

    if (!transport) {
        if (ALLOW_MAIL_PREVIEW) {
            console.log(`[mail-preview] Confirm email change for ${nextEmail}: ${confirmUrl}`);
        }
        return {
            delivered: false,
            previewUrl: ALLOW_MAIL_PREVIEW ? confirmUrl : null
        };
    }

    await transport.sendMail({
        from: process.env.SMTP_FROM,
        to: nextEmail,
        subject: 'Подтверждение смены email на CHUPEP',
        text: [
            `Привет, ${user.display_name || 'друг'}!`,
            '',
            'Подтверди новый email по ссылке:',
            confirmUrl,
            '',
            'Если это были не ты, просто проигнорируй письмо.'
        ].join('\n'),
        html: `
            <div style="font-family:Arial,sans-serif;line-height:1.6;color:#111827">
                <h2 style="margin:0 0 16px">Подтверждение нового email</h2>
                <p>Привет, <strong>${user.display_name || 'друг'}</strong>!</p>
                <p>Подтверди новый адрес почты для аккаунта CHUPEP по кнопке ниже.</p>
                <p>
                    <a href="${confirmUrl}" style="display:inline-block;padding:12px 18px;background:#b8a7f0;color:#232329;text-decoration:none;border-radius:10px;font-weight:700;">
                        Подтвердить новый email
                    </a>
                </p>
                <p>Если кнопка не открывается, используй ссылку:</p>
                <p><a href="${confirmUrl}">${confirmUrl}</a></p>
            </div>
        `
    });

    return {
        delivered: true,
        previewUrl: null
    };
}

async function sendPasswordChangeConfirmation(user, token) {
    const confirmUrl = `${BASE_URL}/confirm-password-change?token=${token}`;
    const transport = getTransport();

    if (!transport) {
        if (ALLOW_MAIL_PREVIEW) {
            console.log(`[mail-preview] Confirm password change for ${user.email}: ${confirmUrl}`);
        }
        return {
            delivered: false,
            previewUrl: ALLOW_MAIL_PREVIEW ? confirmUrl : null
        };
    }

    await transport.sendMail({
        from: process.env.SMTP_FROM,
        to: user.email,
        subject: 'Подтверждение смены пароля на CHUPEP',
        text: [
            `Привет, ${user.display_name || 'друг'}!`,
            '',
            'Чтобы сменить пароль, открой ссылку:',
            confirmUrl,
            '',
            'Если это были не ты, просто проигнорируй письмо.'
        ].join('\n'),
        html: `
            <div style="font-family:Arial,sans-serif;line-height:1.6;color:#111827">
                <h2 style="margin:0 0 16px">Подтверждение смены пароля</h2>
                <p>Привет, <strong>${user.display_name || 'друг'}</strong>!</p>
                <p>Подтверди смену пароля для аккаунта CHUPEP по кнопке ниже.</p>
                <p>
                    <a href="${confirmUrl}" style="display:inline-block;padding:12px 18px;background:#b8a7f0;color:#232329;text-decoration:none;border-radius:10px;font-weight:700;">
                        Подтвердить пароль
                    </a>
                </p>
                <p>Если кнопка не открывается, используй ссылку:</p>
                <p><a href="${confirmUrl}">${confirmUrl}</a></p>
            </div>
        `
    });

    return {
        delivered: true,
        previewUrl: null
    };
}

async function sendPasswordResetEmail(user, token) {
    const resetUrl = `${BASE_URL}/reset-password?token=${token}`;
    const transport = getTransport();

    if (!transport) {
        if (ALLOW_MAIL_PREVIEW) {
            console.log(`[mail-preview] Reset password for ${user.email}: ${resetUrl}`);
        }
        return {
            delivered: false,
            previewUrl: ALLOW_MAIL_PREVIEW ? resetUrl : null
        };
    }

    await transport.sendMail({
        from: process.env.SMTP_FROM,
        to: user.email,
        subject: 'Сброс пароля на CHUPEP',
        text: [
            `Привет, ${user.display_name || 'друг'}!`,
            '',
            'Мы получили запрос на сброс пароля. Перейди по ссылке ниже, чтобы задать новый пароль:',
            resetUrl,
            '',
            `Ссылка действует ${Math.round(PASSWORD_RESET_TTL_MS / (60 * 1000))} минут.`,
            'Если это был не ты, просто проигнорируй письмо.'
        ].join('\n'),
        html: `
            <div style="font-family:Arial,sans-serif;line-height:1.6;color:#111827">
                <h2 style="margin:0 0 16px">Сброс пароля</h2>
                <p>Привет, <strong>${user.display_name || 'друг'}</strong>!</p>
                <p>Мы получили запрос на сброс пароля для аккаунта CHUPEP.</p>
                <p>
                    <a href="${resetUrl}" style="display:inline-block;padding:12px 18px;background:#b8a7f0;color:#232329;text-decoration:none;border-radius:10px;font-weight:700;">
                        Задать новый пароль
                    </a>
                </p>
                <p>Ссылка будет активна ${Math.round(PASSWORD_RESET_TTL_MS / (60 * 1000))} минут.</p>
                <p>Если кнопка не открывается, используй ссылку:</p>
                <p><a href="${resetUrl}">${resetUrl}</a></p>
            </div>
        `
    });

    return {
        delivered: true,
        previewUrl: null
    };
}

async function sendSecurityNotice(to, displayName, title, textBody) {
    return sendMailOrPreview({
        to,
        subject: title,
        text: [`Привет, ${displayName || 'друг'}!`, '', textBody].join('\n'),
        html: `
            <div style="font-family:Arial,sans-serif;line-height:1.6;color:#111827">
                <h2 style="margin:0 0 16px">${title}</h2>
                <p>Привет, <strong>${displayName || 'друг'}</strong>!</p>
                <p>${textBody}</p>
            </div>
        `,
        previewLabel: title
    });
}

async function createSession(userId) {
    const token = randomToken(24);
    const expiresAt = new Date(Date.now() + SESSION_TTL_MS).toISOString();
    await dbRun(
        'INSERT INTO sessions (token, user_id, expires_at, created_at) VALUES (?, ?, ?, ?)',
        [hashToken(token), userId, expiresAt, new Date().toISOString()]
    );
    return token;
}

async function destroySession(token) {
    if (!token) {
        return;
    }

    await dbRun('DELETE FROM sessions WHERE token IN (?, ?)', [hashToken(token), token]);
}

async function destroySessionsForUser(userId) {
    if (!userId) {
        return;
    }

    await dbRun('DELETE FROM sessions WHERE user_id = ?', [userId]);
}

async function getUserBySessionToken(token) {
    if (!token) {
        return null;
    }

    const row = await dbGet(
        `SELECT u.id, u.email, u.display_name, u.role, u.verified, u.avatar_path, u.created_at, s.expires_at
         FROM sessions s
         JOIN users u ON u.id = s.user_id
         WHERE s.token IN (?, ?)`,
        [hashToken(token), token]
    );

    if (!row) {
        return null;
    }

    if (new Date(row.expires_at).getTime() <= Date.now()) {
        await destroySession(token);
        return null;
    }

    return publicUser(row);
}

async function ensureStreamerAccount() {
    const hasExplicitStreamerCredentials =
        isNonEmptyString(process.env.STREAMER_EMAIL) && isNonEmptyString(process.env.STREAMER_PASSWORD);
    if (IS_PRODUCTION && !hasExplicitStreamerCredentials) {
        console.warn('Skipping streamer bootstrap: set STREAMER_EMAIL and STREAMER_PASSWORD in production.');
        return;
    }

    const email = process.env.STREAMER_EMAIL || 'streamer@trackarena.local';
    const password = process.env.STREAMER_PASSWORD || randomToken(18);
    const displayName = process.env.STREAMER_NAME || 'Главный стример';
    const existing = await dbGet('SELECT id, password_hash FROM users WHERE email = ?', [email]);

    if (existing) {
        const params = ['streamer', displayName];
        let sql = 'UPDATE users SET role = ?, verified = 1, display_name = ?';

        if (hasExplicitStreamerCredentials) {
            sql += ', password_hash = ?';
            params.push(hashPassword(password));
        } else if (verifyPassword('boss777', existing.password_hash)) {
            console.warn('Existing streamer account still uses the old default password. Set STREAMER_PASSWORD to rotate it.');
        }

        sql += ' WHERE id = ?';
        params.push(existing.id);
        await dbRun(sql, params);
        return;
    }

    await dbRun(
        `INSERT INTO users (email, password_hash, display_name, role, verified, verification_token, created_at)
         VALUES (?, ?, ?, ?, 1, NULL, ?)`,
        [email, hashPassword(password), displayName, 'streamer', new Date().toISOString()]
    );
}

async function ensureLegacyAuthorAccount() {
    const email = 'legacy@trackarena.local';
    const existing = await dbGet('SELECT id FROM users WHERE email = ?', [email]);

    if (existing) {
        return existing.id;
    }

    const result = await dbRun(
        `INSERT INTO users (email, password_hash, display_name, role, verified, verification_token, created_at)
         VALUES (?, ?, ?, ?, 1, NULL, ?)`,
        [email, hashPassword(randomToken(12)), 'Legacy Import', 'author', new Date().toISOString()]
    );

    return result.lastID;
}

async function bootstrap() {
    validateRuntimeConfig();
    await dbRun('PRAGMA foreign_keys = ON');
    await dbRun('PRAGMA journal_mode = WAL');

    await dbRun(
        `CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            display_name TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'author',
            verified INTEGER NOT NULL DEFAULT 0,
            verification_token TEXT,
            avatar_path TEXT,
            pending_email TEXT,
            pending_email_token TEXT,
            pending_password_hash TEXT,
            pending_password_token TEXT,
            password_reset_token_hash TEXT,
            password_reset_expires_at TEXT,
            created_at TEXT NOT NULL
        )`
    );

    await dbRun(
        `CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL,
            expires_at TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )`
    );

    await dbRun(
        `CREATE TABLE IF NOT EXISTS tracks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            artist_name TEXT NOT NULL,
            notes TEXT,
            file_path TEXT NOT NULL,
            cover_path TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'new',
            created_at TEXT NOT NULL,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )`
    );

    await dbRun(
        `CREATE TABLE IF NOT EXISTS evaluations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            track_id INTEGER NOT NULL UNIQUE,
            streamer_id INTEGER NOT NULL,
            lyrics INTEGER NOT NULL,
            sound INTEGER NOT NULL,
            individuality INTEGER NOT NULL,
            structure INTEGER NOT NULL,
            vibe INTEGER NOT NULL,
            nomination TEXT,
            best_track INTEGER NOT NULL DEFAULT 0,
            best_producer INTEGER NOT NULL DEFAULT 0,
            best_artist INTEGER NOT NULL DEFAULT 0,
            comment TEXT,
            created_at TEXT NOT NULL,
            FOREIGN KEY(track_id) REFERENCES tracks(id),
            FOREIGN KEY(streamer_id) REFERENCES users(id)
        )`
    );

    await dbRun(
        `CREATE TABLE IF NOT EXISTS track_comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            track_id INTEGER NOT NULL,
            streamer_id INTEGER NOT NULL,
            timestamp_seconds INTEGER NOT NULL DEFAULT 0,
            body TEXT NOT NULL,
            created_at TEXT NOT NULL,
            FOREIGN KEY(track_id) REFERENCES tracks(id),
            FOREIGN KEY(streamer_id) REFERENCES users(id)
        )`
    );

    await dbRun(
        `CREATE INDEX IF NOT EXISTS idx_track_comments_track_id
         ON track_comments(track_id, timestamp_seconds, created_at)`
    );

    await ensureStreamerAccount();
    const legacyAuthorId = await ensureLegacyAuthorAccount();

    const trackColumns = await dbAll('PRAGMA table_info(tracks)');
    const trackColumnNames = new Set(trackColumns.map((column) => column.name));
    if (!trackColumnNames.has('user_id')) {
        await dbRun('ALTER TABLE tracks ADD COLUMN user_id INTEGER DEFAULT 1');
        await dbRun('UPDATE tracks SET user_id = ?', [legacyAuthorId]);
    }
    if (!trackColumnNames.has('artist_name')) {
        await dbRun("ALTER TABLE tracks ADD COLUMN artist_name TEXT DEFAULT 'Неизвестный автор'");
    }
    if (!trackColumnNames.has('notes')) {
        await dbRun('ALTER TABLE tracks ADD COLUMN notes TEXT');
    }
    if (!trackColumnNames.has('created_at')) {
        await dbRun("ALTER TABLE tracks ADD COLUMN created_at TEXT DEFAULT ''");
    }

    const evaluationColumns = await dbAll('PRAGMA table_info(evaluations)');
    const evaluationColumnNames = new Set(evaluationColumns.map((column) => column.name));
    if (!evaluationColumnNames.has('id')) {
        // Legacy table detected, rebuild into the new shape.
        const legacyRows = await dbAll(
            'SELECT rowid as legacy_row_id, track_id, lyrics, sound, individuality, structure, vibe FROM evaluations'
        );
        await dbRun('ALTER TABLE evaluations RENAME TO evaluations_legacy');
        await dbRun(
            `CREATE TABLE evaluations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                track_id INTEGER NOT NULL UNIQUE,
                streamer_id INTEGER NOT NULL,
                lyrics INTEGER NOT NULL,
                sound INTEGER NOT NULL,
                individuality INTEGER NOT NULL,
                structure INTEGER NOT NULL,
                vibe INTEGER NOT NULL,
                nomination TEXT,
                best_track INTEGER NOT NULL DEFAULT 0,
                best_producer INTEGER NOT NULL DEFAULT 0,
                best_artist INTEGER NOT NULL DEFAULT 0,
                comment TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY(track_id) REFERENCES tracks(id),
                FOREIGN KEY(streamer_id) REFERENCES users(id)
            )`
        );

        const streamer = await dbGet("SELECT id FROM users WHERE role = 'streamer' LIMIT 1");
        const streamerId = streamer ? streamer.id : 1;
        for (const row of legacyRows) {
            await dbRun(
                `INSERT OR IGNORE INTO evaluations
                 (track_id, streamer_id, lyrics, sound, individuality, structure, vibe, nomination, comment, created_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
                [
                    row.track_id,
                    streamerId,
                    row.lyrics,
                    row.sound,
                    row.individuality,
                    row.structure,
                    row.vibe,
                    null,
                    '',
                    new Date().toISOString()
                ]
            );
        }

        await dbRun('DROP TABLE evaluations_legacy');
    } else {
        if (!evaluationColumnNames.has('streamer_id')) {
            await dbRun('ALTER TABLE evaluations ADD COLUMN streamer_id INTEGER DEFAULT 1');
        }
        if (!evaluationColumnNames.has('nomination')) {
            await dbRun('ALTER TABLE evaluations ADD COLUMN nomination TEXT');
        }
        if (!evaluationColumnNames.has('best_track')) {
            await dbRun('ALTER TABLE evaluations ADD COLUMN best_track INTEGER NOT NULL DEFAULT 0');
        }
        if (!evaluationColumnNames.has('best_producer')) {
            await dbRun('ALTER TABLE evaluations ADD COLUMN best_producer INTEGER NOT NULL DEFAULT 0');
        }
        if (!evaluationColumnNames.has('best_artist')) {
            await dbRun('ALTER TABLE evaluations ADD COLUMN best_artist INTEGER NOT NULL DEFAULT 0');
        }
        if (!evaluationColumnNames.has('comment')) {
            await dbRun("ALTER TABLE evaluations ADD COLUMN comment TEXT DEFAULT ''");
        }
        if (!evaluationColumnNames.has('created_at')) {
            await dbRun("ALTER TABLE evaluations ADD COLUMN created_at TEXT DEFAULT ''");
        }
    }

    const userColumns = await dbAll('PRAGMA table_info(users)');
    const userColumnNames = new Set(userColumns.map((column) => column.name));
    if (!userColumnNames.has('verification_token')) {
        await dbRun('ALTER TABLE users ADD COLUMN verification_token TEXT');
    }
    if (!userColumnNames.has('avatar_path')) {
        await dbRun('ALTER TABLE users ADD COLUMN avatar_path TEXT');
    }
    if (!userColumnNames.has('pending_email')) {
        await dbRun('ALTER TABLE users ADD COLUMN pending_email TEXT');
    }
    if (!userColumnNames.has('pending_email_token')) {
        await dbRun('ALTER TABLE users ADD COLUMN pending_email_token TEXT');
    }
    if (!userColumnNames.has('pending_password_hash')) {
        await dbRun('ALTER TABLE users ADD COLUMN pending_password_hash TEXT');
    }
    if (!userColumnNames.has('pending_password_token')) {
        await dbRun('ALTER TABLE users ADD COLUMN pending_password_token TEXT');
    }
    if (!userColumnNames.has('password_reset_token_hash')) {
        await dbRun('ALTER TABLE users ADD COLUMN password_reset_token_hash TEXT');
    }
    if (!userColumnNames.has('password_reset_expires_at')) {
        await dbRun('ALTER TABLE users ADD COLUMN password_reset_expires_at TEXT');
    }

    await dbRun('CREATE INDEX IF NOT EXISTS idx_users_display_name_lookup ON users(display_name COLLATE NOCASE)');
    await dbRun('CREATE INDEX IF NOT EXISTS idx_users_password_reset_token_hash ON users(password_reset_token_hash)');

    await dbRun("UPDATE tracks SET artist_name = 'Неизвестный автор' WHERE artist_name IS NULL OR artist_name = ''");
    await dbRun("UPDATE tracks SET created_at = ? WHERE created_at IS NULL OR created_at = ''", [new Date().toISOString()]);
    await dbRun("UPDATE evaluations SET best_track = 1 WHERE nomination = 'best_track'");
    await dbRun("UPDATE evaluations SET best_producer = 1 WHERE nomination = 'best_producer'");
    await dbRun("UPDATE evaluations SET best_artist = 1 WHERE nomination = 'best_artist'");
    await dbRun("UPDATE evaluations SET comment = '' WHERE comment IS NULL");
    await dbRun("UPDATE evaluations SET created_at = ? WHERE created_at IS NULL OR created_at = ''", [new Date().toISOString()]);
    await dbRun("UPDATE users SET display_name = 'Участник' WHERE display_name IS NULL OR display_name = ''");
}

const storage = multer.diskStorage({
    destination: (_req, _file, callback) => callback(null, uploadDir),
    filename: (_req, file, callback) => {
        const safeBaseName = path
            .basename(file.originalname, path.extname(file.originalname))
            .toLowerCase()
            .replace(/[^a-z0-9а-яё_-]+/gi, '-')
            .replace(/-+/g, '-')
            .slice(0, 40);
        callback(null, `${Date.now()}-${safeBaseName}${path.extname(file.originalname)}`);
    }
});

const upload = multer({
    storage,
    limits: {
        fileSize: 25 * 1024 * 1024
    },
    fileFilter: (_req, file, callback) => {
        const extension = getFileExtension(file.originalname);
        const isAudio =
            file.fieldname === 'audio' &&
            ALLOWED_AUDIO_EXTENSIONS.has(extension);
        const isImage =
            file.fieldname === 'cover' &&
            ALLOWED_IMAGE_EXTENSIONS.has(extension);
        if (isAudio || isImage) {
            callback(null, true);
            return;
        }

        callback(new Error('Поддерживаются только аудио-файлы и изображения.'));
    }
});

const avatarUpload = multer({
    storage,
    limits: {
        fileSize: 8 * 1024 * 1024
    },
    fileFilter: (_req, file, callback) => {
        const extension = getFileExtension(file.originalname);
        if (ALLOWED_IMAGE_EXTENSIONS.has(extension)) {
            callback(null, true);
            return;
        }

        callback(new Error('Для аватарки подходит только изображение.'));
    }
});

app.use(express.urlencoded({ extended: true, limit: BODY_LIMIT }));
app.use(express.json({ limit: BODY_LIMIT }));

app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader(
        'Content-Security-Policy',
        "default-src 'self'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'; object-src 'none'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; media-src 'self'; connect-src 'self'"
    );
    res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
    res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');
    res.setHeader(
        'Permissions-Policy',
        'accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()'
    );
    next();
});

app.use((req, res, next) => {
    if (!req.path.startsWith('/api/')) {
        next();
        return;
    }

    if (!requestOriginAllowed(req)) {
        res.status(403).json({ error: 'Запрос отклонён политикой безопасности сайта.' });
        return;
    }

    next();
});

app.use(async (req, _res, next) => {
    try {
        const cookies = parseCookies(req.headers.cookie || '');
        req.sessionToken = cookies.session_token || null;
        req.user = await getUserBySessionToken(req.sessionToken);
        next();
    } catch (error) {
        next(error);
    }
});

const generalApiLimiter = createRateLimiter({
    keyPrefix: 'api',
    windowMs: 60 * 1000,
    maxRequests: 240,
    message: 'Слишком много запросов к сайту. Попробуй ещё раз чуть позже.'
});
const authLimiter = createRateLimiter({
    keyPrefix: 'auth',
    windowMs: 10 * 60 * 1000,
    maxRequests: 30,
    message: 'Слишком много попыток входа или регистрации. Подожди немного и попробуй снова.'
});
const uploadLimiter = createRateLimiter({
    keyPrefix: 'upload',
    windowMs: 10 * 60 * 1000,
    maxRequests: 20,
    message: 'Лимит загрузок временно исчерпан. Попробуй ещё раз чуть позже.'
});

app.use('/api', generalApiLimiter);

app.get(['/upload.html', '/admin.html', '/results.html', '/profile.html', '/user.html'], (req, res, next) => {
    if (req.user && !req.user.verified) {
        res.redirect('/index.html?verificationRequired=1');
        return;
    }

    next();
});

app.use(express.static(path.join(__dirname, 'public')));
app.use(
    '/uploads',
    express.static(uploadDir, {
        setHeaders: (res) => {
            res.setHeader('X-Content-Type-Options', 'nosniff');
            res.setHeader('Content-Security-Policy', "default-src 'none'; img-src 'self'; media-src 'self'; sandbox");
        }
    })
);

app.get('/reset-password', (req, res) => {
    const params = new URLSearchParams();
    if (req.query.token) {
        params.set('token', String(req.query.token));
    }

    const target = params.toString() ? `/reset-password.html?${params.toString()}` : '/reset-password.html';
    res.redirect(target);
});

function requireAuth(req, res, next) {
    if (!req.user) {
        res.status(401).json({ error: 'Нужен вход в аккаунт.' });
        return;
    }

    next();
}

function requireVerified(req, res, next) {
    if (!req.user) {
        res.status(401).json({ error: 'Нужен вход в аккаунт.' });
        return;
    }

    if (!req.user.verified) {
        res.status(403).json({
            error: 'Сначала подтверди почту. Мы уже отправили письмо со ссылкой.'
        });
        return;
    }

    next();
}

function requireRole(roles) {
    return (req, res, next) => {
        if (!req.user) {
            res.status(401).json({ error: 'Нужен вход в аккаунт.' });
            return;
        }

        if (!roles.includes(req.user.role)) {
            res.status(403).json({ error: 'Недостаточно прав для этого действия.' });
            return;
        }

        next();
    };
}

app.get('/api/session', (req, res) => {
    res.json({ user: req.user || null });
});

app.get('/healthz', (_req, res) => {
    res.json({ status: 'ok' });
});

app.get('/api/profile', requireAuth, async (req, res, next) => {
    try {
        const userRow = await dbGet(
            'SELECT id, email, display_name, role, verified, avatar_path, pending_email, created_at FROM users WHERE id = ?',
            [req.user.id]
        );
        const tracksRow = await dbGet('SELECT COUNT(*) as count FROM tracks WHERE user_id = ?', [req.user.id]);
        const evaluationsRow =
            req.user.role === 'streamer'
                ? await dbGet('SELECT COUNT(*) as count FROM evaluations WHERE streamer_id = ?', [req.user.id])
                : { count: 0 };

        res.json({
            user: {
                ...publicUser(userRow),
                pendingEmail: userRow.pending_email || null
            },
            stats: {
                tracks: tracksRow ? tracksRow.count : 0,
                evaluations: evaluationsRow ? evaluationsRow.count : 0
            }
        });
    } catch (error) {
        next(error);
    }
});

app.post('/api/profile', requireAuth, async (req, res, next) => {
    try {
        const displayName = String(req.body.displayName || '').trim();
        const email = String(req.body.email || '').trim().toLowerCase();
        const password = String(req.body.password || '');
        const messages = [];
        const previewLinks = [];

        if (!displayName || displayName.length < 2) {
            res.status(400).json({ error: 'Укажи имя минимум из 2 символов.' });
            return;
        }

        if (displayName.length > 50) {
            res.status(400).json({ error: 'Имя профиля должно быть не длиннее 50 символов.' });
            return;
        }

        if (!isValidEmail(email)) {
            res.status(400).json({ error: 'Нужен корректный email.' });
            return;
        }

        if (password && password.length < 6) {
            res.status(400).json({ error: 'Новый пароль должен быть не короче 6 символов.' });
            return;
        }

        const existingName = await findUserByDisplayName(displayName, req.user.id);
        if (existingName) {
            res.status(409).json({ error: 'Пользователь с таким ником уже существует.' });
            return;
        }

        const currentUser = await dbGet('SELECT * FROM users WHERE id = ?', [req.user.id]);
        await dbRun('UPDATE users SET display_name = ? WHERE id = ?', [displayName, req.user.id]);
        await dbRun('UPDATE tracks SET artist_name = ? WHERE user_id = ?', [displayName, req.user.id]);
        messages.push('Имя профиля обновлено.');

        if (email !== currentUser.email) {
            const existing = await dbGet('SELECT id FROM users WHERE email = ? AND id != ?', [email, req.user.id]);
            if (existing) {
                res.status(409).json({ error: 'Аккаунт с таким email уже существует.' });
                return;
            }

            const emailToken = randomToken(24);
            await dbRun('UPDATE users SET pending_email = ?, pending_email_token = ? WHERE id = ?', [
                email,
                hashToken(emailToken),
                req.user.id
            ]);
            const emailResult = await sendEmailChangeConfirmation(currentUser, email, emailToken);
            if (emailResult.previewUrl) {
                previewLinks.push({ label: 'Подтвердить новый email', url: emailResult.previewUrl });
            }
            await sendSecurityNotice(
                currentUser.email,
                displayName,
                'На CHUPEP запрошена смена email',
                `Мы получили запрос на смену email на ${email}. Если это были не ты, просто проигнорируй письмо.`
            );
            messages.push('На новый email отправлено письмо для подтверждения смены адреса.');
        }

        if (password) {
            const passwordToken = randomToken(24);
            await dbRun('UPDATE users SET pending_password_hash = ?, pending_password_token = ? WHERE id = ?', [
                hashPassword(password),
                hashToken(passwordToken),
                req.user.id
            ]);
            const passwordResult = await sendPasswordChangeConfirmation(currentUser, passwordToken);
            if (passwordResult.previewUrl) {
                previewLinks.push({ label: 'Подтвердить новый пароль', url: passwordResult.previewUrl });
            }
            messages.push('На текущую почту отправлено письмо для подтверждения нового пароля.');
        }

        const updated = await dbGet(
            'SELECT id, email, display_name, role, verified, avatar_path, pending_email, created_at FROM users WHERE id = ?',
            [req.user.id]
        );

        res.json({
            message: messages.join(' '),
            previewLinks,
            user: {
                ...publicUser(updated),
                pendingEmail: updated.pending_email || null
            }
        });
    } catch (error) {
        next(error);
    }
});

app.post('/api/profile/avatar', requireAuth, avatarUpload.single('avatar'), async (req, res, next) => {
    try {
        if (!req.file) {
            res.status(400).json({ error: 'Выбери изображение для аватарки.' });
            return;
        }

        if (!validateStoredUpload(req.file, 'image')) {
            cleanupUploadedFiles(req.file);
            res.status(400).json({ error: 'Файл аватарки не прошёл проверку безопасности.' });
            return;
        }

        const current = await dbGet('SELECT avatar_path FROM users WHERE id = ?', [req.user.id]);
        await dbRun('UPDATE users SET avatar_path = ? WHERE id = ?', [req.file.filename, req.user.id]);

        if (current && current.avatar_path && current.avatar_path !== req.file.filename) {
            const previousPath = path.join(uploadDir, current.avatar_path);
            if (fs.existsSync(previousPath)) {
                fs.unlinkSync(previousPath);
            }
        }

        const updated = await dbGet(
            'SELECT id, email, display_name, role, verified, avatar_path, created_at FROM users WHERE id = ?',
            [req.user.id]
        );
        res.json({
            message: 'Аватарка обновлена.',
            user: publicUser(updated)
        });
    } catch (error) {
        next(error);
    }
});

app.post('/api/register', authLimiter, async (req, res, next) => {
    try {
        const role = req.body.role === 'viewer' ? 'viewer' : 'author';
        const email = String(req.body.email || '').trim().toLowerCase();
        const displayName = String(req.body.displayName || '').trim();
        const password = String(req.body.password || '');

        if (!displayName || displayName.length < 2) {
            res.status(400).json({ error: 'Укажи имя минимум из 2 символов.' });
            return;
        }

        if (displayName.length > 50) {
            res.status(400).json({ error: 'Имя профиля должно быть не длиннее 50 символов.' });
            return;
        }

        if (!isValidEmail(email)) {
            res.status(400).json({ error: 'Нужен корректный email.' });
            return;
        }

        if (password.length < 6) {
            res.status(400).json({ error: 'Пароль должен быть не короче 6 символов.' });
            return;
        }

        const exists = await dbGet('SELECT id FROM users WHERE email = ?', [email]);
        if (exists) {
            res.status(409).json({ error: 'Аккаунт с таким email уже существует.' });
            return;
        }

        const nameExists = await findUserByDisplayName(displayName);
        if (nameExists) {
            res.status(409).json({ error: 'Пользователь с таким ником уже существует.' });
            return;
        }

        const verificationToken = randomToken(24);
        const createdAt = new Date().toISOString();
        const result = await dbRun(
            `INSERT INTO users (email, password_hash, display_name, role, verified, verification_token, created_at)
             VALUES (?, ?, ?, ?, 0, ?, ?)`,
            [email, hashPassword(password), displayName, role, hashToken(verificationToken), createdAt]
        );

        const user = {
            id: result.lastID,
            email,
            display_name: displayName
        };

        const mailResult = await sendVerificationEmail(user, verificationToken);

        res.status(201).json({
            message: mailResult.delivered
                ? 'Аккаунт создан. Проверь почту и подтверди адрес, чтобы продолжить.'
                : mailResult.previewUrl
                    ? 'Аккаунт создан. SMTP не настроен, поэтому ссылка подтверждения выведена в консоль сервера.'
                    : 'Аккаунт создан, но отправка писем сейчас недоступна. Обратись к администратору сайта.',
            previewUrl: mailResult.previewUrl,
            user: {
                id: result.lastID,
                email,
                displayName,
                role,
                verified: false,
                createdAt
            }
        });
    } catch (error) {
        next(error);
    }
});

app.post('/api/login', authLimiter, async (req, res, next) => {
    try {
        const email = String(req.body.email || '').trim().toLowerCase();
        const password = String(req.body.password || '');
        const user = await dbGet('SELECT * FROM users WHERE email = ?', [email]);

        if (!user || !verifyPassword(password, user.password_hash)) {
            res.status(401).json({ error: 'Неверный email или пароль.' });
            return;
        }

        const sessionToken = await createSession(user.id);
        res.setHeader(
            'Set-Cookie',
            createCookie('session_token', sessionToken, {
                maxAge: SESSION_TTL_MS / 1000,
                path: '/',
                httpOnly: true,
                sameSite: 'Lax',
                secure: SECURE_COOKIES
            })
        );

        res.json({
            message: user.verified
                ? 'Вход выполнен.'
                : 'Вход выполнен, но сначала подтверди почту.',
            user: publicUser(user)
        });
    } catch (error) {
        next(error);
    }
});

app.post('/api/forgot-password', authLimiter, async (req, res, next) => {
    try {
        const email = String(req.body.email || '').trim().toLowerCase();
        let previewUrl = null;

        if (!isValidEmail(email)) {
            res.status(400).json({ error: 'Нужен корректный email.' });
            return;
        }

        const user = await dbGet('SELECT id, email, display_name FROM users WHERE email = ?', [email]);
        if (user) {
            const token = randomToken(24);
            const expiresAt = new Date(Date.now() + PASSWORD_RESET_TTL_MS).toISOString();
            await dbRun(
                'UPDATE users SET password_reset_token_hash = ?, password_reset_expires_at = ? WHERE id = ?',
                [hashToken(token), expiresAt, user.id]
            );
            const mailResult = await sendPasswordResetEmail(user, token);
            previewUrl = mailResult.previewUrl;
        }

        res.json({
            message: 'Если аккаунт с таким email существует, мы отправили ссылку для сброса пароля.',
            previewUrl
        });
    } catch (error) {
        next(error);
    }
});

app.post('/api/reset-password', authLimiter, async (req, res, next) => {
    try {
        const token = String(req.body.token || '').trim();
        const password = String(req.body.password || '');

        if (!token) {
            res.status(400).json({ error: 'Ссылка сброса пароля недействительна.' });
            return;
        }

        if (password.length < 6) {
            res.status(400).json({ error: 'Пароль должен быть не короче 6 символов.' });
            return;
        }

        const now = new Date().toISOString();
        const user = await dbGet(
            `SELECT id, email, display_name
             FROM users
             WHERE password_reset_token_hash = ?
               AND password_reset_expires_at IS NOT NULL
               AND password_reset_expires_at > ?`,
            [hashToken(token), now]
        );

        if (!user) {
            res.status(400).json({ error: 'Ссылка сброса недействительна или уже истекла.' });
            return;
        }

        await dbRun(
            `UPDATE users
             SET password_hash = ?,
                 pending_password_hash = NULL,
                 pending_password_token = NULL,
                 password_reset_token_hash = NULL,
                 password_reset_expires_at = NULL
             WHERE id = ?`,
            [hashPassword(password), user.id]
        );
        await destroySessionsForUser(user.id);

        await sendSecurityNotice(
            user.email,
            user.display_name,
            'Пароль на CHUPEP изменен',
            'Пароль для входа в аккаунт был успешно изменен через восстановление доступа. Если это были не ты, срочно проверь доступ к почте и свяжись с поддержкой.'
        );

        res.json({ message: 'Пароль обновлен. Теперь можно войти в аккаунт.' });
    } catch (error) {
        next(error);
    }
});

app.post('/api/logout', async (req, res, next) => {
    try {
        await destroySession(req.sessionToken);
        res.setHeader(
            'Set-Cookie',
            createCookie('session_token', '', {
                maxAge: 0,
                path: '/',
                httpOnly: true,
                sameSite: 'Lax',
                secure: SECURE_COOKIES
            })
        );
        res.json({ message: 'Выход выполнен.' });
    } catch (error) {
        next(error);
    }
});

app.post('/api/resend-verification', authLimiter, requireAuth, async (req, res, next) => {
    try {
        if (req.user.verified) {
            res.json({ message: 'Почта уже подтверждена.' });
            return;
        }

        const verificationToken = randomToken(24);
        await dbRun('UPDATE users SET verification_token = ? WHERE id = ?', [hashToken(verificationToken), req.user.id]);
        const mailResult = await sendVerificationEmail(
            {
                email: req.user.email,
                display_name: req.user.displayName
            },
            verificationToken
        );

        res.json({
            message: mailResult.delivered
                ? 'Письмо отправлено повторно.'
                : mailResult.previewUrl
                    ? 'SMTP не настроен, ссылка подтверждения выведена в консоль сервера.'
                    : 'Отправка писем сейчас недоступна. Попробуй позже или свяжись с администратором сайта.',
            previewUrl: mailResult.previewUrl
        });
    } catch (error) {
        next(error);
    }
});

app.get('/verify-email', async (req, res, next) => {
    try {
        const token = String(req.query.token || '').trim();
        if (!token) {
            res.redirect('/login.html?verified=0');
            return;
        }

        const user = await dbGet('SELECT id FROM users WHERE verification_token IN (?, ?)', [hashToken(token), token]);
        if (!user) {
            res.redirect('/login.html?verified=0');
            return;
        }

        await dbRun('UPDATE users SET verified = 1, verification_token = NULL WHERE id = ?', [user.id]);
        res.redirect('/login.html?verified=1');
    } catch (error) {
        next(error);
    }
});

app.get('/confirm-email-change', async (req, res, next) => {
    try {
        const token = String(req.query.token || '').trim();
        if (!token) {
            res.redirect('/profile.html?emailChanged=0');
            return;
        }

        const user = await dbGet(
            'SELECT id, pending_email, display_name, email FROM users WHERE pending_email_token IN (?, ?)',
            [hashToken(token), token]
        );
        if (!user || !user.pending_email) {
            res.redirect('/profile.html?emailChanged=0');
            return;
        }

        const exists = await dbGet('SELECT id FROM users WHERE email = ? AND id != ?', [user.pending_email, user.id]);
        if (exists) {
            res.redirect('/profile.html?emailChanged=0');
            return;
        }

        const previousEmail = user.email;
        await dbRun(
            'UPDATE users SET email = ?, pending_email = NULL, pending_email_token = NULL WHERE id = ?',
            [user.pending_email, user.id]
        );

        await sendSecurityNotice(
            previousEmail,
            user.display_name,
            'Email на CHUPEP изменен',
            `Новый адрес для входа в аккаунт: ${user.pending_email}. Если это были не ты, срочно смени пароль.`
        );

        res.redirect('/profile.html?emailChanged=1');
    } catch (error) {
        next(error);
    }
});

app.get('/confirm-password-change', async (req, res, next) => {
    try {
        const token = String(req.query.token || '').trim();
        if (!token) {
            res.redirect('/profile.html?passwordChanged=0');
            return;
        }

        const user = await dbGet(
            'SELECT id, email, display_name, pending_password_hash FROM users WHERE pending_password_token IN (?, ?)',
            [hashToken(token), token]
        );
        if (!user || !user.pending_password_hash) {
            res.redirect('/profile.html?passwordChanged=0');
            return;
        }

        await dbRun(
            `UPDATE users
             SET password_hash = ?,
                 pending_password_hash = NULL,
                 pending_password_token = NULL,
                 password_reset_token_hash = NULL,
                 password_reset_expires_at = NULL
             WHERE id = ?`,
            [user.pending_password_hash, user.id]
        );

        await sendSecurityNotice(
            user.email,
            user.display_name,
            'Пароль на CHUPEP изменен',
            'Пароль для входа в аккаунт был успешно изменен. Если это были не ты, срочно смени пароль и проверь доступ к почте.'
        );

        res.redirect('/profile.html?passwordChanged=1');
    } catch (error) {
        next(error);
    }
});

app.post(
    '/api/tracks',
    uploadLimiter,
    requireVerified,
    requireRole(['author', 'streamer']),
    upload.fields([
        { name: 'audio', maxCount: 1 },
        { name: 'cover', maxCount: 1 }
    ]),
    async (req, res, next) => {
        try {
            const title = String(req.body.title || '').trim();
            const notes = String(req.body.notes || '').trim();
            const audioFile = req.files && req.files.audio ? req.files.audio[0] : null;
            const coverFile = req.files && req.files.cover ? req.files.cover[0] : null;
            const artistName = String(req.user.displayName || '').trim();

            if (!title || !artistName || !audioFile || !coverFile) {
                cleanupUploadedFiles(req.files);
                res.status(400).json({ error: 'Заполни название и добавь оба файла.' });
                return;
            }

            if (title.length > 120) {
                cleanupUploadedFiles(req.files);
                res.status(400).json({ error: 'Название трека должно быть не длиннее 120 символов.' });
                return;
            }

            if (notes.length > 2000) {
                cleanupUploadedFiles(req.files);
                res.status(400).json({ error: 'Комментарий к треку должен быть короче 2000 символов.' });
                return;
            }

            if (!validateStoredUpload(audioFile, 'audio') || !validateStoredUpload(coverFile, 'image')) {
                cleanupUploadedFiles(req.files);
                res.status(400).json({ error: 'Один из загруженных файлов не прошёл проверку безопасности.' });
                return;
            }

            const createdAt = new Date().toISOString();
            const result = await dbRun(
                `INSERT INTO tracks (user_id, title, artist_name, notes, file_path, cover_path, status, created_at)
                 VALUES (?, ?, ?, ?, ?, ?, 'new', ?)`,
                [req.user.id, title, artistName, notes, audioFile.filename, coverFile.filename, createdAt]
            );

            res.status(201).json({
                message: 'Трек отправлен на оценку.',
                trackId: result.lastID
            });
        } catch (error) {
            next(error);
        }
    }
);

app.get('/api/my-tracks', requireVerified, requireRole(['author', 'streamer']), async (req, res, next) => {
    try {
        const rows = await dbAll(
            `SELECT t.id, t.title, t.artist_name, t.notes, t.file_path, t.cover_path, t.status, t.created_at,
                    e.lyrics, e.sound, e.individuality, e.structure, e.vibe,
                    e.best_track, e.best_producer, e.best_artist, e.comment
             FROM tracks t
             LEFT JOIN evaluations e ON e.track_id = t.id
             WHERE t.user_id = ?
             ORDER BY t.created_at DESC`,
            [req.user.id]
        );

        res.json(rows);
    } catch (error) {
        next(error);
    }
});

async function deleteTrackHandler(req, res, next) {
    try {
        const trackId = Number(req.params.id);
        if (!Number.isInteger(trackId) || trackId <= 0) {
            res.status(400).json({ error: 'Некорректный трек.' });
            return;
        }

        const track = await dbGet(
            'SELECT id, user_id, file_path, cover_path FROM tracks WHERE id = ?',
            [trackId]
        );
        if (!track) {
            res.status(404).json({ error: 'Трек уже удалён или не найден.' });
            return;
        }

        const isStreamer = req.user.role === 'streamer';
        if (!isStreamer && track.user_id !== req.user.id) {
            res.status(403).json({ error: 'Удалять можно только свои треки.' });
            return;
        }

        await dbRun('BEGIN TRANSACTION');
        try {
            await dbRun('DELETE FROM track_comments WHERE track_id = ?', [trackId]);
            await dbRun('DELETE FROM evaluations WHERE track_id = ?', [trackId]);
            await dbRun('DELETE FROM tracks WHERE id = ?', [trackId]);
            await dbRun('COMMIT');
        } catch (error) {
            await dbRun('ROLLBACK');
            throw error;
        }

        removeTrackFiles(track);
        res.json({ message: 'Трек удалён.' });
    } catch (error) {
        next(error);
    }
}

app.delete('/api/tracks/:id', requireVerified, requireRole(['author', 'streamer']), deleteTrackHandler);
app.post('/api/tracks/:id/delete', requireVerified, requireRole(['author', 'streamer']), deleteTrackHandler);

app.get('/api/admin/tracks', requireVerified, requireRole(['streamer']), async (req, res, next) => {
    try {
        const rows = await dbAll(
            `SELECT t.id, t.title, t.artist_name, t.notes, t.file_path, t.cover_path, t.status, t.created_at,
                    u.id as author_id, u.display_name as author_name, u.avatar_path as author_avatar,
                    e.lyrics, e.sound, e.individuality, e.structure, e.vibe,
                    e.best_track, e.best_producer, e.best_artist, e.comment
             FROM tracks t
             JOIN users u ON u.id = t.user_id
             LEFT JOIN evaluations e ON e.track_id = t.id
             ORDER BY CASE WHEN t.status = 'new' THEN 0 ELSE 1 END ASC, t.created_at DESC`
        );

        res.json(rows);
    } catch (error) {
        next(error);
    }
});

app.post('/api/evaluate', requireVerified, requireRole(['streamer']), async (req, res, next) => {
    try {
        const trackId = Number(req.body.trackId);
        const comment = String(req.body.comment || '').trim();
        const scores = ['lyrics', 'sound', 'individuality', 'structure', 'vibe'].map((field) =>
            Number(req.body[field])
        );
        const nominationFlags = {
            best_track: Object.prototype.hasOwnProperty.call(req.body, 'best_track')
                ? parseNominationFlag(req.body.best_track)
                : null,
            best_producer: Object.prototype.hasOwnProperty.call(req.body, 'best_producer')
                ? parseNominationFlag(req.body.best_producer)
                : null,
            best_artist: Object.prototype.hasOwnProperty.call(req.body, 'best_artist')
                ? parseNominationFlag(req.body.best_artist)
                : null
        };

        if (!trackId || scores.some((value) => Number.isNaN(value) || value < 1 || value > 10)) {
            res.status(400).json({ error: 'Оценки должны быть числами от 1 до 10.' });
            return;
        }

        const track = await dbGet('SELECT id FROM tracks WHERE id = ?', [trackId]);
        if (!track) {
            res.status(404).json({ error: 'Трек не найден.' });
            return;
        }

        const createdAt = new Date().toISOString();
        await dbRun('BEGIN TRANSACTION');

        try {
            for (const [key, selected] of Object.entries(nominationFlags)) {
                if (selected) {
                    await dbRun(`UPDATE evaluations SET ${key} = 0 WHERE track_id != ?`, [trackId]);
                }
            }

            await dbRun(
                `INSERT INTO evaluations
                 (track_id, streamer_id, lyrics, sound, individuality, structure, vibe, nomination,
                  best_track, best_producer, best_artist, comment, created_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                 ON CONFLICT(track_id) DO UPDATE SET
                    streamer_id = excluded.streamer_id,
                    lyrics = excluded.lyrics,
                    sound = excluded.sound,
                    individuality = excluded.individuality,
                    structure = excluded.structure,
                    vibe = excluded.vibe,
                    nomination = excluded.nomination,
                    best_track = excluded.best_track,
                    best_producer = excluded.best_producer,
                    best_artist = excluded.best_artist,
                    comment = excluded.comment,
                    created_at = excluded.created_at`,
                [
                    trackId,
                    req.user.id,
                    ...scores,
                    null,
                    nominationFlags.best_track ? 1 : 0,
                    nominationFlags.best_producer ? 1 : 0,
                    nominationFlags.best_artist ? 1 : 0,
                    comment,
                    createdAt
                ]
            );
            await dbRun("UPDATE tracks SET status = 'evaluated' WHERE id = ?", [trackId]);
            await dbRun('COMMIT');
        } catch (error) {
            await dbRun('ROLLBACK');
            throw error;
        }

        res.json({ message: 'Оценка сохранена.' });
    } catch (error) {
        next(error);
    }
});

app.post('/api/admin/nominations', requireVerified, requireRole(['streamer']), async (req, res, next) => {
    try {
        const clear = parseNominationFlag(req.body.clear);
        const selections = {
            best_track: req.body.best_track_track_id ? Number(req.body.best_track_track_id) : null,
            best_producer: req.body.best_producer_track_id ? Number(req.body.best_producer_track_id) : null,
            best_artist: req.body.best_artist_track_id ? Number(req.body.best_artist_track_id) : null
        };
        const trackIds = [...new Set(Object.values(selections).filter(Boolean))];

        if (trackIds.some((trackId) => !Number.isInteger(trackId) || trackId <= 0)) {
            res.status(400).json({ error: 'Некорректный выбор номинации.' });
            return;
        }

        if (trackIds.length) {
            const placeholders = trackIds.map(() => '?').join(', ');
            const rows = await dbAll(
                `SELECT DISTINCT t.id
                 FROM tracks t
                 JOIN evaluations e ON e.track_id = t.id
                 WHERE t.status = 'evaluated' AND t.id IN (${placeholders})`,
                trackIds
            );

            if (rows.length !== trackIds.length) {
                res.status(400).json({ error: 'Выбирать можно только разобранные треки.' });
                return;
            }
        }

        await dbRun('BEGIN TRANSACTION');

        try {
            await dbRun('UPDATE evaluations SET best_track = 0, best_producer = 0, best_artist = 0');

            if (!clear && selections.best_track) {
                await dbRun('UPDATE evaluations SET best_track = 1 WHERE track_id = ?', [selections.best_track]);
            }

            if (!clear && selections.best_producer) {
                await dbRun('UPDATE evaluations SET best_producer = 1 WHERE track_id = ?', [selections.best_producer]);
            }

            if (!clear && selections.best_artist) {
                await dbRun('UPDATE evaluations SET best_artist = 1 WHERE track_id = ?', [selections.best_artist]);
            }

            await dbRun('COMMIT');
        } catch (error) {
            await dbRun('ROLLBACK');
            throw error;
        }

        res.json({ message: clear ? 'Номинации месяца очищены.' : 'Номинации обновлены.' });
    } catch (error) {
        next(error);
    }
});

app.get('/api/track-comments', requireAuth, async (req, res, next) => {
    try {
        const trackIds = String(req.query.trackIds || '')
            .split(',')
            .map((value) => Number(value.trim()))
            .filter((value) => Number.isInteger(value) && value > 0);

        if (!trackIds.length) {
            res.json({ comments: {} });
            return;
        }

        const placeholders = trackIds.map(() => '?').join(', ');
        const rows = await dbAll(
            `SELECT c.id, c.track_id, c.timestamp_seconds, c.body, c.created_at, u.display_name AS streamer_name
             FROM track_comments c
             JOIN users u ON u.id = c.streamer_id
             WHERE c.track_id IN (${placeholders})
             ORDER BY c.track_id ASC, c.timestamp_seconds ASC, c.created_at ASC`,
            trackIds
        );

        const comments = {};
        trackIds.forEach((trackId) => {
            comments[String(trackId)] = [];
        });

        rows.forEach((row) => {
            const key = String(row.track_id);
            if (!comments[key]) {
                comments[key] = [];
            }

            comments[key].push({
                id: row.id,
                track_id: row.track_id,
                timestamp_seconds: row.timestamp_seconds,
                body: row.body,
                created_at: row.created_at,
                streamer_name: row.streamer_name
            });
        });

        res.json({ comments });
    } catch (error) {
        next(error);
    }
});

app.post('/api/track-comments', requireVerified, requireRole(['streamer']), async (req, res, next) => {
    try {
        const trackId = Number(req.body.trackId);
        const timestampSeconds = Math.max(0, Math.round(Number(req.body.timestampSeconds)));
        const body = String(req.body.body || '').trim();

        if (!Number.isInteger(trackId) || trackId <= 0) {
            res.status(400).json({ error: 'Не удалось определить трек.' });
            return;
        }

        if (!body) {
            res.status(400).json({ error: 'Напиши комментарий к выбранному моменту.' });
            return;
        }

        if (body.length > 500) {
            res.status(400).json({ error: 'Комментарий к моменту должен быть короче 500 символов.' });
            return;
        }

        if (!Number.isFinite(timestampSeconds) || timestampSeconds < 0) {
            res.status(400).json({ error: 'Некорректный таймкод.' });
            return;
        }

        const track = await dbGet('SELECT id FROM tracks WHERE id = ?', [trackId]);
        if (!track) {
            res.status(404).json({ error: 'Трек не найден.' });
            return;
        }

        const createdAt = new Date().toISOString();
        const result = await dbRun(
            `INSERT INTO track_comments (track_id, streamer_id, timestamp_seconds, body, created_at)
             VALUES (?, ?, ?, ?, ?)`,
            [trackId, req.user.id, timestampSeconds, body, createdAt]
        );

        res.status(201).json({
            message: 'Комментарий к таймкоду сохранён.',
            comment: {
                id: result.lastID,
                track_id: trackId,
                timestamp_seconds: timestampSeconds,
                body,
                created_at: createdAt,
                streamer_name: req.user.displayName
            }
        });
    } catch (error) {
        next(error);
    }
});

app.get('/api/results', requireVerified, async (_req, res, next) => {
    try {
        const rows = await dbAll(
            `SELECT t.id, t.title, t.artist_name, t.cover_path, t.created_at,
                    u.id as author_id, u.display_name as author_name, u.avatar_path as author_avatar,
                    e.lyrics, e.sound, e.individuality, e.structure, e.vibe,
                    e.best_track, e.best_producer, e.best_artist, e.comment,
                    (e.lyrics + e.sound + e.individuality + e.structure + e.vibe) AS total_score
             FROM tracks t
             JOIN users u ON u.id = t.user_id
             JOIN evaluations e ON e.track_id = t.id
             WHERE t.status = 'evaluated'
             ORDER BY total_score DESC, t.created_at ASC`
        );

        res.json(rows);
    } catch (error) {
        next(error);
    }
});

app.get('/api/users/:id', requireAuth, async (req, res, next) => {
    try {
        const userId = Number(req.params.id);
        if (!userId) {
            res.status(400).json({ error: 'Некорректный идентификатор пользователя.' });
            return;
        }

        const user = await dbGet(
            'SELECT id, email, display_name, role, verified, avatar_path, created_at FROM users WHERE id = ?',
            [userId]
        );
        if (!user) {
            res.status(404).json({ error: 'Пользователь не найден.' });
            return;
        }

        const tracks = await dbAll(
            `SELECT t.id, t.title, t.notes, t.cover_path, t.file_path, t.status, t.created_at,
                    e.lyrics, e.sound, e.individuality, e.structure, e.vibe,
                    e.best_track, e.best_producer, e.best_artist, e.comment
             FROM tracks t
             LEFT JOIN evaluations e ON e.track_id = t.id
             WHERE t.user_id = ?
             ORDER BY t.created_at DESC`,
            [userId]
        );

        res.json({
            user: {
                id: user.id,
                displayName: user.display_name,
                role: user.role,
                verified: Boolean(user.verified),
                avatarPath: user.avatar_path || null,
                createdAt: user.created_at
            },
            stats: {
                tracks: tracks.length,
                evaluated: tracks.filter((track) => track.status === 'evaluated').length
            },
            tracks
        });
    } catch (error) {
        next(error);
    }
});

app.use((error, req, res, _next) => {
    cleanupUploadedFiles(req.file || req.files);
    console.error(error);
    if (error instanceof multer.MulterError) {
        res.status(400).json({ error: `Ошибка загрузки файла: ${error.message}` });
        return;
    }

    if (error && /поддерживаются только аудио-файлы и изображения|для аватарки подходит только изображение/i.test(error.message || '')) {
        res.status(400).json({ error: error.message });
        return;
    }

    res.status(500).json({
        error: error.message || 'Внутренняя ошибка сервера.'
    });
});

bootstrap()
    .then(() => {
        httpServer = app.listen(PORT, () => {
            console.log(`CHUPEP running on ${BASE_URL}`);
            console.log(`Data directory: ${DATA_DIR}`);
            if (!IS_PRODUCTION) {
                console.log('Streamer login:', process.env.STREAMER_EMAIL || 'streamer@trackarena.local');
                if (process.env.STREAMER_PASSWORD) {
                    console.log('Streamer password set via environment.');
                } else {
                    console.log('Streamer password was generated for this local run.');
                }
            }
        });
    })
    .catch((error) => {
        console.error('Failed to bootstrap application', error);
        process.exit(1);
    });

function shutdown(signal) {
    if (!httpServer) {
        process.exit(0);
    }

    console.log(`${signal} received. Shutting down gracefully.`);
    httpServer.close(() => {
        db.close((error) => {
            if (error) {
                console.error('Failed to close database cleanly', error);
                process.exit(1);
            }

            process.exit(0);
        });
    });

    setTimeout(() => {
        console.error('Forced shutdown after timeout.');
        process.exit(1);
    }, 10000).unref();
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

import { randomUUID } from 'crypto';
/**
 * Retrieves the refresh window time in seconds from environment variables.
 * This represents the grace period during which a refresh token can be used
 * to obtain new access tokens after its original expiration.
 * Defaults to 300 seconds (5 minutes) if not specified.
 * 
 * @returns {number} Refresh window duration in seconds
 */
export function getRefreshWindowSeconds(): number {
    return parseInt(process.env.REFRESH_WINDOW_SECONDS ?? '300', 10); // 5 min
}

/**
 * Retrieves the access token time-to-live (TTL) in seconds from environment variables.
 * Defaults to 900 seconds (15 minutes) if not specified.
 * 
 * @returns {number} TTL in seconds for access tokens
 */
export function getAccessTtl(): number {
    return parseInt(process.env.ACCESS_TOKEN_TTL ?? '900', 10); // 15 min
}
export function getBotAccessTtl(): number {
    return parseInt(process.env.BOT_ACCESS_TOKEN_TTL ?? '86400', 10); // 24 h
}
/**
 * Retrieves the refresh token time-to-live (TTL) in seconds from environment variables.
 * Defaults to 2,592,000 seconds (30 days) if not specified.
 * 
 * @returns {number} TTL in seconds for refresh tokens
 */
export function getRefreshTtl(): number {
    return parseInt(process.env.REFRESH_TOKEN_TTL ?? '2592000', 10); // 30 days
}

/**
 * Normalizes environment variable values by converting escaped newlines (\n) to actual newlines.
 * This is useful for reading multi-line keys (like RSA private keys) from .env files.
 * 
 * @param {string | undefined} key - The environment variable value to normalize
 * @returns {string} Normalized string with actual newline characters
 * 
 * @example
 * // Input: "-----BEGIN PRIVATE KEY-----\\nMII...\\n-----END PRIVATE KEY-----"
 * // Output: "-----BEGIN PRIVATE KEY-----\nMII...\n-----END PRIVATE KEY-----"
 */
export function normalizeKeyFromEnv(key: string | undefined): string {
    if (!key) return '';
    return key.replace(/\\n/g, '\n'); // Convert escaped newlines to actual newlines
}

/**
 * Generates a new unique JWT ID (JTI) using cryptographically secure random UUID.
 * JTI is used to prevent token replay attacks by ensuring each token has a unique identifier.
 * 
 * @returns {string} A unique JWT identifier (UUID v4)
 */
export function newJti(): string {
    return randomUUID();
}

/**
 * Base user payload structure for JWT tokens.
 * Contains essential user identification information.
 */
export type UserPayload = {
    /** Subject - unique user identifier (user ID) */
    sub: string;
    /** User's email address (optional) */
    email?: string;
    /** User roles - can be array of strings or space-separated string (optional) */
    roles?: string[] | string;
    client: 'user' | 'bot'
};

export type BaseUserPayload = {
    /** Token type discriminator - always 'access' for access tokens */
    type: 'access';
    /** JWT ID - unique identifier for this token to prevent replay attacks */
    jti: string;
};

/**
 * Access token payload structure.
 * Extends UserPayload with access token specific fields.
 */
export type AccessPayload = UserPayload &  BaseUserPayload

/**
 * Refresh token payload structure.
 * Extends UserPayload with refresh token specific fields and session management.
 */
export type RefreshPayload = UserPayload & {
    /** Token type discriminator - always 'refresh' for refresh tokens */
    type: 'refresh';
    /** JWT ID - unique identifier for this token to prevent replay attacks */
    jti: string;
    /** Access ID - links this refresh token to a specific access token/session */
    aid: string;
};
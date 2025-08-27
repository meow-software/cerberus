export const REDIS_CACHE_USER_SESSION = `USER:SESSION:`;

/**
 * Constructs the Redis cache key for a user's session.
 * 
 * @param {string} userId - The ID of the user.
 * @param {string} clientUser - Type of client user (bot/user)
 * @returns {string} - The Redis cache key for the user's session.
 */
export const redisCacheKeyGetUserSession = (userId: string, clientType: string): string => {
    return `${REDIS_CACHE_USER_SESSION}${clientType}:${userId}:`;
}

/**
 * Stores a user session token in Redis cache.
 * 
 * @param {string} userId - The ID of the user.
 * @param {string} clientType - Type of client user (bot/user)
 * @param {string} token - The session token to store.
 * @returns {string} - The Redis cache key where the token was stored.
 */
export const redisCacheKeyPutUserSession = (userId: string, clientType: string, token: string): string => {
    const key = `${REDIS_CACHE_USER_SESSION}${clientType}:${userId}:${token}`;
    return key;
}


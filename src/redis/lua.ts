import { REDIS_CACHE_USER_SESSION } from "src/lib";

/*
 * Lua script: replaces all old sessions for a bot/client by a new one.
 *
 * Constante: ${REDIS_CACHE_USER_SESSION}
 *
 * ARGV[1] = clientType
 * ARGV[2] = botId
 * ARGV[3] = jti
 * ARGV[4] = ttl (seconds)
 */
export const SCRIPT_REDIS_REPLACE_BOT_SESSION = `
    -- Construit le pattern des sessions existantes
    local prefix = "${REDIS_CACHE_USER_SESSION}:" .. ARGV[1] .. ":" .. ARGV[2]
    local pattern = prefix .. ":*"

    -- Supprime toutes les anciennes sessions
    local keys = redis.call("KEYS", pattern)
    for i=1,#keys,5000 do
      redis.call("DEL", unpack(keys, i, math.min(i+4999, #keys)))
    end

    -- Ajoute la nouvelle session
    local newKey = prefix .. ":" .. ARGV[3]
    return redis.call("SET", newKey, "active", "EX", ARGV[4])
`;

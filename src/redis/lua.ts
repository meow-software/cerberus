/**
 * Lua script: deletes old sessions and creates the new one
 * We send the botId, jti, and ttl to the script.
 * The script deletes all old sessions with a SCAN/DEL.
 * Then it saves the new token with SET EX.
 */
const lua = `
    -- Supprime toutes les sessions existantes
    local keys = redis.call("KEYS", "bot:" .. ARGV[1] .. ":session:*")
    for i=1,#keys,5000 do
      redis.call("DEL", unpack(keys, i, math.min(i+4999, #keys)))
    end

    -- Ajoute la nouvelle session
    return redis.call("SET", "bot:" .. ARGV[1] .. ":session:" .. ARGV[2], "active", "EX", ARGV[3])
  `;
import { Inject, Injectable, OnModuleDestroy, OnModuleInit } from '@nestjs/common';
import { Redis } from 'ioredis';
import { SCRIPT_REDIS_REPLACE_BOT_SESSION } from './lua';

@Injectable()
export class RedisService implements OnModuleInit, OnModuleDestroy {
  protected SCRIPT_REDIS_REPLACE_BOT_SESSION;
  constructor(@Inject('REDIS_CERBERUS') private readonly redis: Redis) {
  }

  getClient(): Redis {
    return this.redis;
  }
  async onModuleInit() {
    this.SCRIPT_REDIS_REPLACE_BOT_SESSION = await this.redis.script('LOAD', SCRIPT_REDIS_REPLACE_BOT_SESSION);
  }

  async onModuleDestroy() {
    await this.redis.quit();
  }

  async replaceBotSession(clientType: string, id: string, jti: string, ttl: number) {
    await this.getClient().eval(this.SCRIPT_REDIS_REPLACE_BOT_SESSION, 0, clientType, id, jti, ttl.toString());
  }

  async setJSON(key: string, value: unknown, ttlSeconds?: number) {
    const payload = JSON.stringify(value);
    if (ttlSeconds && ttlSeconds > 0) {
      await this.redis.set(key, payload, 'EX', ttlSeconds);
    } else {
      await this.redis.set(key, payload);
    }
  }

  async getJSON<T = any>(key: string): Promise<T | null> {
    const raw = await this.redis.get(key);
    return raw ? (JSON.parse(raw) as T) : null;
  }

  async del(key: string) {
    await this.redis.del(key);
  }

  async setNX(key: string, value: string, ttlSeconds: number) {
    await this.redis.set(key, value, 'EX', ttlSeconds, 'NX');
  }
}

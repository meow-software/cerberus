import { Module } from '@nestjs/common';
import Redis from 'ioredis';
import { RedisService } from './redis.service';

@Module({
  providers: [
    {
      provide: 'REDIS_CERBERUS',
      useFactory: () => new Redis(process.env.REDIS_CERBERUS_HOST ?? 'redis://localhost:6379'),
    },
    RedisService,
  ],
  exports: ['REDIS_CERBERUS', RedisService],
})
export class RedisModule {}

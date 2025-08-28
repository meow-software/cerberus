import { Injectable, OnModuleDestroy } from '@nestjs/common';
import { IEventBus } from 'src/lib';
import { RedisService } from 'src/redis/redis.service';

@Injectable()
export class RedisEventBus implements IEventBus, OnModuleDestroy {
    private subscriberInitialized = false;

    constructor(private readonly redis: RedisService) { }

    async publish(topic: string, message: any) {
        const payload = JSON.stringify({
            event: topic,
            timestamp: new Date().toISOString(),
            payload: message,
        });
        await this.redis.publish(topic, payload);
    }

    // For local subscribes (useful in dev). In prod prefer dedicated consumers in each service.
    async subscribe(topic: string, handler: (message: any) => void) {
        if (!this.subscriberInitialized) {
            this.subscriberInitialized = true;
        }
        const sub = this.redis.getSubscriber();

        // S'abonner d'abord
        await sub.subscribe(topic);

        // Écouter les messages avec le bon handler
        sub.on('message', (channel: string, msg: string) => {
            if (channel === topic) {
                try {
                    const parsed = JSON.parse(msg);
                    handler(parsed);
                } catch (e) {
                    console.error('Failed parsing event', e);
                }
            }
        });
    }

    async onModuleDestroy() {
        await this.redis.disconnect();
    }
}

import { Injectable } from '@nestjs/common';
import { IEventBus } from 'src/lib';
// import { Kafka } from 'kafkajs';

@Injectable()
export class KafkaEventBus implements IEventBus {
//   private kafka: Kafka;
//   private producer: any;

  constructor() {
    // this.kafka = new Kafka({ brokers: (process.env.KAFKA_BROKERS || 'localhost:9092').split(',') });
    // this.producer = this.kafka.producer();
    // this.init();
  }

  private async init() {
    // await this.producer.connect();
  }

  async publish(topic: string, message: any) {
    // await this.producer.send({
    //   topic,
    //   messages: [{ value: JSON.stringify({ event: topic, timestamp: new Date().toISOString(), payload: message }) }],
    // });
  }

  // Subscribe is left as exercise: implement consumer groups with offsets, retries, DLQ
  async close() {
    // await this.producer.disconnect();
  }
}

import { Injectable } from '@nestjs/common';

@Injectable()
export class AppService {
  quotes(): string {
    const quotes = [
      `I am the Gate that does not yield. I am the Guardian of Three Maws. Before a single spark of data is entrusted to you, your presence will be bitten and torn apart. No secret shall leave the Realm, no intruder shall enter it. The access you seek is an illusion; my vigilance is the only reality.`,
    ];
    return this.random(quotes);
  }
  private random(quotes: string[]) {
    const randomIndex = Math.floor(Math.random() * quotes.length);
    return quotes[randomIndex];
  }
  ping(): string {
    return 'Pong!';
  }
  health(): any {
    return {
      status: 'OK',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      environment: process.env.NODE_ENV,
    };
  }
}

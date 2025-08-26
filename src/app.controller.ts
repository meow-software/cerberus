import { Controller, Get } from '@nestjs/common';
import { AppService } from './app.service';

@Controller("/auth")
export class AppController {
  constructor(private readonly appService: AppService) {}

  @Get("/")
  heimdall() {
    return {
      'Cerberus': `I am the Gate that does not yield. I am the Guardian of Three Maws. Before a single spark of data is entrusted to you, your presence will be bitten and torn apart. No secret shall leave the Realm, no intruder shall enter it. The access you seek is an illusion; my vigilance is the only reality.`
    }
  }

  @Get("/ping")
  ping(): string {
    return this.appService.ping();
  }

  @Get("/health")
  health(): any {
    return this.appService.health();
  }
}

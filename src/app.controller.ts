import { Controller, Get } from '@nestjs/common';
import { AppService } from './app.service';

@Controller("/auth")
export class AppController {
  constructor(private readonly appService: AppService) {}

  @Get("/")
  cerberus() {
    return this.appService.quotes();
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

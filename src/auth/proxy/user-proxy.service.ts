import { Injectable } from '@nestjs/common';
import { AxiosProxy } from 'src/lib';

@Injectable()
export class UserProxyService extends AxiosProxy {
  constructor() {
    super(`${process.env.SERVICE_PROTOCOL}://${process.env.CERBERUS_HOST}:${process.env.CERBERUS_PORT}`);
  }
}
import { Inject, Injectable } from '@nestjs/common';
import { JwtService, JwtSignOptions } from '@nestjs/jwt';
import { ClientProxy } from '@nestjs/microservices';
import {
  AccessPayload, RefreshPayload, UserPayload,
  getAccessTtl, getRefreshTtl, getAlg, normalizeKeyFromEnv, newJti
} from '../common/tokens.util';
import { RedisService } from '../redis/redis.service';

@Injectable()
export class AuthService {
  constructor(
    private readonly jwt: JwtService,
    private readonly redis: RedisService,
    @Inject("USER_SERVICE") private readonly userClient: ClientProxy,
  ) {

  }

}

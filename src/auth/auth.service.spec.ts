import { Test, TestingModule } from '@nestjs/testing';
import { JwtService } from '@nestjs/jwt';
import { ClientProxy } from '@nestjs/microservices';
import { RedisService } from '../redis/redis.service';
import { AuthService } from './auth.service';
import {
  BadRequestException,
  UnauthorizedException,
  ForbiddenException,
} from '@nestjs/common';
import { getAccessTtl, getRefreshWindowSeconds } from '../common/tokens.util';

describe('AuthService', () => {
  let service: AuthService;
  let jwt: jest.Mocked<JwtService>;
  let redis: jest.Mocked<RedisService>;
  let userClient: jest.Mocked<ClientProxy>;

  beforeEach(async () => {
    process.env.JWT_PRIVATE_KEY = 'fake_private';
    process.env.JWT_PUBLIC_KEY = 'fake_public';

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthService,
        {
          provide: JwtService,
          useValue: {
            signAsync: jest.fn(),
            verifyAsync: jest.fn(),
            decode: jest.fn(),
          },
        },
        {
          provide: RedisService,
          useValue: {
            setJSON: jest.fn(),
            del: jest.fn(),
            setNX: jest.fn(),
          },
        },
        {
          provide: 'USER_SERVICE',
          useValue: {
            send: jest.fn(),
          },
        },
      ],
    }).compile();

    service = module.get<AuthService>(AuthService);
    jwt = module.get(JwtService);
    redis = module.get(RedisService);
    userClient = module.get('USER_SERVICE');
  });

  afterEach(() => jest.resetAllMocks());

  describe('register', () => {
    it('should register and return token pair', async () => {
      (userClient.send as jest.Mock).mockResolvedValue({ id: 1, email: 'a@a.com', roles: ['user'] });
      jest.spyOn(service as any, 'issuePair').mockResolvedValue({ accessToken: 'at', refreshToken: 'rt' });

      const result = await service.register('a@a.com', 'pass');
      expect(userClient.send).toHaveBeenCalledWith('user.register', { email: 'a@a.com', password: 'pass', role: undefined });
      expect(result).toEqual({ accessToken: 'at', refreshToken: 'rt' });
    });
  });

  describe('login', () => {
    it('should login and return token pair', async () => {
      (userClient.send as jest.Mock).mockResolvedValue({ id: 2, email: 'b@b.com', roles: ['admin'] });
      jest.spyOn(service as any, 'issuePair').mockResolvedValue({ accessToken: 'ax', refreshToken: 'rx' });

      const result = await service.login('b@b.com', 'pass');
      expect(userClient.send).toHaveBeenCalledWith('user.validate', { email: 'b@b.com', password: 'pass' });
      expect(result).toEqual({ accessToken: 'ax', refreshToken: 'rx' });
    });

    it('should throw UnauthorizedException if user not found', async () => {
      (userClient.send as jest.Mock).mockResolvedValue(null);
      await expect(service.login('x', 'y')).rejects.toThrow(UnauthorizedException);
    });
  });

  describe('refresh', () => {
    const now = Math.floor(Date.now() / 1000);

    it('should throw BadRequest if access token missing', async () => {
      await expect(service.refresh('rt')).rejects.toThrow(BadRequestException);
    });

    it('should refresh normally when refresh valid and access expired recently', async () => {
      const decodedAccess = { exp: now - 10, sub: 'u1', email: 'a@a.com', roles: ['user'] };
      jwt.decode.mockReturnValue(decodedAccess);

      (service as any).verifyRefresh = jest.fn().mockResolvedValue({
        sub: 'u1',
        email: 'a@a.com',
        roles: ['user'],
        jti: 'rid',
        type: 'refresh',
        aid: 'aid',
      });

      jest.spyOn(service as any, 'issuePair').mockResolvedValue({ accessToken: 'na', refreshToken: 'nr' });

      const result = await service.refresh('rt', 'at');
      expect(redis.del).toHaveBeenCalledWith('refresh:rid');
      expect(result).toEqual({ accessToken: 'na', refreshToken: 'nr' });
    });

    it('should throw Forbidden if access not expired', async () => {
      jwt.decode.mockReturnValue({ exp: now + 60 });
      (service as any).verifyRefresh = jest.fn().mockResolvedValue({ type: 'refresh', sub: 'u' });

      await expect(service.refresh('rt', 'at')).rejects.toThrow(ForbiddenException);
    });

    it('should fallback to access grace period if refresh invalid', async () => {
      const decodedAccess = { exp: now - 5, sub: 'u2', email: 'z@z.com', roles: ['user'] };
      jwt.decode.mockReturnValue(decodedAccess);

      (service as any).verifyRefresh = jest.fn().mockRejectedValue(new Error('invalid'));

      jest.spyOn(service as any, 'issuePair').mockResolvedValue({ accessToken: 'ax', refreshToken: 'rx' });

      const result = await service.refresh('rt', 'at');
      expect(result).toEqual({ accessToken: 'ax', refreshToken: 'rx' });
    });

    it('should throw Unauthorized if refresh invalid and access expired too long', async () => {
      const decodedAccess = { exp: now - getRefreshWindowSeconds() - 10 };
      jwt.decode.mockReturnValue(decodedAccess);

      (service as any).verifyRefresh = jest.fn().mockRejectedValue(new Error('invalid'));

      await expect(service.refresh('rt', 'at')).rejects.toThrow(UnauthorizedException);
    });
  });

  describe('logout', () => {
    it('should delete refresh and blacklist access', async () => {
      (service as any).verifyRefresh = jest.fn().mockResolvedValue({ jti: 'rid' });

      const result = await service.logout('rt', 'aid');
      expect(redis.del).toHaveBeenCalledWith('refresh:rid');
      expect(redis.setNX).toHaveBeenCalledWith(`bl:access:aid`, '1', getAccessTtl());
      expect(result).toEqual({ ok: true });
    });

    it('should ignore refresh errors', async () => {
      (service as any).verifyRefresh = jest.fn().mockRejectedValue(new Error('bad'));

      const result = await service.logout('rt');
      expect(result).toEqual({ ok: true });
    });
  });
});

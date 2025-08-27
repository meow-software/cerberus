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
import { getAccessTtl, getRefreshWindowSeconds } from 'src/lib';
import { redisCacheKeyPutUserSession } from 'src/lib';

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
    it('should call userClient and issuePair correctly', async () => {
      const fakeUser = { id: 1, email: 'a@a.com', roles: ['user'] };
      (userClient.send as jest.Mock).mockResolvedValue(fakeUser);

      const issuePairSpy = jest.spyOn(service as any, 'issuePair').mockResolvedValue('TOKENS');

      const result = await service.register('a@a.com', 'pass', 'user');

      // Vérifie que userClient est bien appelé avec les bons paramètres
      expect(userClient.send).toHaveBeenCalledWith('user.register', {
        email: 'a@a.com',
        password: 'pass',
        role: 'user'
      });

      // Vérifie que le payload transmis à issuePair est correct
      expect(issuePairSpy).toHaveBeenCalledWith({
        sub: '1',
        email: 'a@a.com',
        roles: ['user'],
        client: 'user',
      });

      // Vérifie que la valeur retournée est celle de issuePair
      expect(result).toBe('TOKENS');
    });

  });

  describe('login', () => {
    it('should login and return token pair + store refresh in redis', async () => {
      jest.spyOn(service as any, 'issuePair').mockResolvedValue({
        pair: { accessToken: 'ax', refreshToken: 'rx', expiresIn: 200 },
        payload: { refreshPayload: { sub: '485124851845', client: 'user', jti: 'jid' } }
      });

      const result = await service.login('b@b.com', 'pass');
      expect(redis.setJSON).toHaveBeenCalledWith(
        redisCacheKeyPutUserSession('485124851845', 'user', 'jid'),
        { uid: '485124851845' },
        200
      );
      expect(result).toEqual({ accessToken: 'ax', refreshToken: 'rx', expiresIn: 200 });
    });

    it('should throw UnauthorizedException if no user returned', async () => {
      jest.spyOn(service as any, 'issuePair').mockImplementation(() => { throw new UnauthorizedException(); });
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
        client: 'user',
      });

      jest.spyOn(service as any, 'issuePair').mockResolvedValue({
        pair: { accessToken: 'na', refreshToken: 'nr', expiresIn: 300 },
        payload: { refreshPayload: { sub: 'u1', client: 'user', jti: 'newrid' } }
      });

      const result = await service.refresh('rt', 'at');
      expect(redis.del).toHaveBeenCalledWith(redisCacheKeyPutUserSession('u1', 'user', 'rid'));
      expect(result).toEqual({ accessToken: 'na', refreshToken: 'nr', expiresIn: 300 });
    });

    it('should throw Forbidden if access not expired yet', async () => {
      jwt.decode.mockReturnValue({ exp: now + 60 });
      (service as any).verifyRefresh = jest.fn().mockResolvedValue({ type: 'refresh', sub: 'u' });

      await expect(service.refresh('rt', 'at')).rejects.toThrow(ForbiddenException);
    });

    it('should fallback to grace period if refresh invalid', async () => {
      const decodedAccess = { exp: now - 5, sub: 'u2', email: 'z@z.com', roles: ['user'], client: 'user' };
      jwt.decode.mockReturnValue(decodedAccess);

      (service as any).verifyRefresh = jest.fn().mockRejectedValue(new Error('invalid'));

      jest.spyOn(service as any, 'issuePair').mockResolvedValue({
        pair: { accessToken: 'ax', refreshToken: 'rx', expiresIn: 150 },
        payload: { refreshPayload: { sub: 'u2', client: 'user', jti: 'jti2' } }
      });

      const result = await service.refresh('rt', 'at');
      expect(result).toEqual({ accessToken: 'ax', refreshToken: 'rx', expiresIn: 150 });
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

  describe('getBotToken', () => {
    it('should return bot token if valid', async () => {
      jest.spyOn(service as any, 'generateJwtForBot').mockResolvedValue({ token: 'botToken' });

      const result = await service.getBotToken('cid', 'secret');
      expect(result).toEqual({ token: 'botToken' });
    });

    it('should throw UnauthorizedException if bot invalid', async () => {
      jest.spyOn(service as any, 'generateJwtForBot').mockImplementation(() => { throw new UnauthorizedException(); });
      await expect(service.getBotToken('cid', 'bad')).rejects.toThrow(UnauthorizedException);
    });
    it('should call generateJwtForBot with clientId and secret', async () => {
      const spy = jest.spyOn(service as any, 'generateJwtForBot').mockResolvedValue({ token: 'bt' });
      await service.getBotToken('cid', 'sec');
      expect(spy).toHaveBeenCalledWith({"id": "cid", "roles": ["user", "admin"]});
    });

  });
});

import { Test, TestingModule } from '@nestjs/testing';
import { JwtService } from '@nestjs/jwt';
import { ClientProxy } from '@nestjs/microservices';
import { RedisService } from '../redis/redis.service';
import {
  UnauthorizedException,
  InternalServerErrorException,
  BadRequestException,
} from '@nestjs/common';
import { AuthServiceAbstract } from './auth.service.abstract';
import {
  AccessPayload,
  RefreshPayload,
  UserPayload,
  getAccessTtl,
  getRefreshTtl,
} from '../common/tokens.util';

// Implémentation concrète pour tester la classe abstraite
class TestAuthService extends AuthServiceAbstract {
  constructor(jwt: JwtService, redis: RedisService, userClient: ClientProxy) {
    super(jwt, redis, userClient);
  }

  public async testGetSignKeyAndOpts(isRefresh: boolean) {
    return this.getSignKeyAndOpts(isRefresh);
  }

  public async testSignAccess(payload: AccessPayload) {
    return this.signAccess(payload);
  }

  public async testSignRefresh(payload: RefreshPayload) {
    return this.signRefresh(payload);
  }

  public async testIssuePair(user: UserPayload) {
    return this.issuePair(user);
  }

  public async testVerifyRefresh(token: string) {
    return this.verifyRefresh(token);
  }
}

describe('AuthServiceAbstract', () => {
  let service: TestAuthService;
  let jwt: JwtService;
  let redis: RedisService;

  beforeEach(async () => {
    process.env.JWT_PRIVATE_KEY = 'fake_private_key';
    process.env.JWT_PUBLIC_KEY = 'fake_public_key';

    const module: TestingModule = await Test.createTestingModule({
      providers: [
        {
          provide: JwtService,
          useValue: {
            signAsync: jest.fn(),
            verifyAsync: jest.fn(),
          },
        },
        {
          provide: RedisService,
          useValue: {
            setJSON: jest.fn(),
          },
        },
        {
          provide: ClientProxy,
          useValue: {
            emit: jest.fn(),
            send: jest.fn(),
          },
        },
      ],
    }).compile();

    jwt = module.get<JwtService>(JwtService);
    redis = module.get<RedisService>(RedisService);
    const userClient = module.get<ClientProxy>(ClientProxy);

    // Création manuelle avec les dépendances
    service = new TestAuthService(jwt, redis, userClient);
  });


  afterEach(() => {
    jest.resetAllMocks();
  });

  describe('getSignKeyAndOpts', () => {
    it('should return options for access token', async () => {
      const opts = await service.testGetSignKeyAndOpts(false);
      expect(opts.algorithm).toBe('RS256');
      expect(opts.privateKey).toBe('fake_private_key');
      expect(opts.expiresIn).toBe(getAccessTtl());
    });

    it('should return options for refresh token', async () => {
      const opts = await service.testGetSignKeyAndOpts(true);
      expect(opts.expiresIn).toBe(getRefreshTtl());
    });

    it('should throw if private key is missing', async () => {
      delete process.env.JWT_PRIVATE_KEY;
      await expect(service.testGetSignKeyAndOpts(false)).rejects.toThrow(
        InternalServerErrorException,
      );
    });
  });

  describe('signAccess & signRefresh', () => {
    it('should sign an access token', async () => {
      (jwt.signAsync as jest.Mock).mockResolvedValue('signed_access');
      const result = await service.testSignAccess({
        sub: 'user1',
        type: 'access',
        jti: 'aid',
        client: 'user'
      });
      expect(result).toBe('signed_access');
      expect(jwt.signAsync).toHaveBeenCalled();
    });

    it('should sign a refresh token', async () => {
      (jwt.signAsync as jest.Mock).mockResolvedValue('signed_refresh');
      const result = await service.testSignRefresh({
        sub: 'user1',
        type: 'refresh',
        jti: 'rid',
        aid: 'aid',
        client: 'user'
      });
      expect(result).toBe('signed_refresh');
    });
  });

  describe('issuePair', () => {
    it('should return access and refresh tokens and store refresh in redis', async () => {
      (jwt.signAsync as jest.Mock)
        .mockResolvedValueOnce('signed_access')
        .mockResolvedValueOnce('signed_refresh');

      const result = await service.testIssuePair({ sub: 'user1', email: 'test@test.com', client: 'user' });

      expect(result).toEqual({
        accessToken: 'signed_access',
        refreshToken: 'signed_refresh',
        tokenType: 'Bearer',
        expiresIn: getAccessTtl(),
      });

      expect(redis.setJSON).toHaveBeenCalledWith(
        expect.stringMatching(/^refresh:/),
        { uid: 'user1' },
        getRefreshTtl(),
      );
    });
  });

  describe('verifyRefresh', () => {
    it('should verify and return payload if valid', async () => {
      const payload: RefreshPayload = {
        sub: 'user1',
        email: 'test@test.com',
        type: 'refresh',
        jti: 'rid',
        aid: 'aid',
        client: 'user'
      };

      (jwt.verifyAsync as jest.Mock).mockResolvedValue(payload);

      const result = await service.testVerifyRefresh('valid_token');
      expect(result).toEqual(payload);
    });

    it('should throw UnauthorizedException if jwt.verifyAsync fails', async () => {
      (jwt.verifyAsync as jest.Mock).mockRejectedValue(new Error('invalid'));

      await expect(service.testVerifyRefresh('bad_token')).rejects.toThrow(
        UnauthorizedException,
      );
    });

    it('should throw BadRequestException if token type is not refresh', async () => {
      const badPayload: any = { type: 'access' };
      (jwt.verifyAsync as jest.Mock).mockResolvedValue(badPayload);

      await expect(service.testVerifyRefresh('wrong_type')).rejects.toThrow(
        BadRequestException,
      );
    });

    it('should throw InternalServerErrorException if public key is missing', async () => {
      delete process.env.JWT_PUBLIC_KEY;
      await expect(service.testVerifyRefresh('token')).rejects.toThrow(
        InternalServerErrorException,
      );
    });
  });
});

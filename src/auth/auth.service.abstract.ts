import { JwtService, JwtSignOptions } from '@nestjs/jwt';
import {
  AccessPayload,
  RefreshPayload,
  UserPayload,
  getAccessTtl,
  getRefreshTtl,
  normalizeKeyFromEnv,
  newJti,
  getBotAccessTtl,
  IEventBus,
  Snowflake,
} from 'src/lib';
import { RedisService } from '../redis/redis.service';
import {
  UnauthorizedException,
  InternalServerErrorException,
  BadRequestException,
} from '@nestjs/common';
import * as speakeasy from "speakeasy";
import { UserProxyService } from './proxy/user-proxy.service';

/**
 * Abstract AuthService containing core JWT/Redis logic.
 * 
 * - Always uses RS256 (asymmetric signing with private/public key pair).
 * - Handles issuing token pairs (access + refresh).
 * - Stores refresh tokens in Redis with TTL.
 * - Provides verification helpers for refresh tokens.
 */
export abstract class AuthServiceAbstract {
  constructor(
    protected readonly jwt: JwtService,
    protected readonly redis: RedisService,
    protected readonly userClient: UserProxyService,
    protected readonly eventBus: IEventBus
  ) { }

  // ---------- JWT Signing Helpers ----------

  /**
   * Returns signing options for access/refresh tokens.
   * Always uses RS256 (private key for signing).
   * @param isRefresh Whether the token is a refresh token.
   */
  protected getSignKeyAndOpts(isRefresh: boolean): JwtSignOptions {
    const privateKey = normalizeKeyFromEnv(process.env.JWT_PRIVATE_KEY);
    if (!privateKey) {
      throw new InternalServerErrorException('Missing JWT_PRIVATE_KEY for RS256');
    }

    return {
      algorithm: 'RS256',
      privateKey,
      expiresIn: isRefresh ? getRefreshTtl() : getAccessTtl(),
    };
  }

  /**
   * Sign and return an access token.
   */
  protected async signAccess(payload: AccessPayload): Promise<string> {
    const opts = this.getSignKeyAndOpts(false);
    return this.jwt.signAsync(payload, opts);
  }

  /**
   * Sign and return a refresh token.
   */
  protected async signRefresh(payload: RefreshPayload): Promise<string> {
    const opts = this.getSignKeyAndOpts(true);
    return this.jwt.signAsync(payload, opts);
  }

  // ---------- Token Issuing ----------

  /**
   * Issues a new pair of tokens (access + refresh) for the given user.
   * 
   * - Access token: short-lived (e.g. 15m).
   * - Refresh token: longer-lived (e.g. 7d).
   * - Refresh is stored in Redis with TTL to allow revocation.
   */
  protected async issuePair(user: UserPayload, expiresIn = getAccessTtl()) {
    const aid = newJti();
    const rid = newJti();

    const accessPayload: AccessPayload = { ...user, type: 'access', jti: aid };
    const refreshPayload: RefreshPayload = { ...user, type: 'refresh', jti: rid, aid };

    const [accessToken, refreshToken] = await Promise.all([
      this.signAccess(accessPayload),
      this.signRefresh(refreshPayload),
    ]);


    return {
      payload: {
        accessPayload,
        refreshPayload
      },
      pair: {
        accessToken,
        refreshToken,
        tokenType: 'Bearer',
        expiresIn: expiresIn,
      }
    };
  }

  // ---------- Verification ----------

  /**
   * Verifies a refresh token with RS256 public key.
   * Ensures:
   * - Signature is valid.
   * - Token is not expired.
   * - Token is of type "refresh".
   * 
   * @throws UnauthorizedException if verification fails.
   */
  protected async verifyRefresh(token: string): Promise<RefreshPayload> {
    const publicKey = normalizeKeyFromEnv(process.env.JWT_PUBLIC_KEY);
    if (!publicKey) {
      throw new InternalServerErrorException('Missing JWT_PUBLIC_KEY for RS256');
    }

    let decoded: RefreshPayload;
    try {
      decoded = await this.jwt.verifyAsync<RefreshPayload>(token, {
        algorithms: ['RS256'],
        publicKey,
      });
    } catch {
      throw new UnauthorizedException('Invalid or expired refresh token');
    }

    if (decoded.type !== 'refresh') {
      throw new BadRequestException('Invalid token type: expected refresh');
    }

    return decoded;
  }

  /**
   * Generates a JWT token specifically for bot authentication
   * @param data - Object containing bot ID and optional roles
   * @param data.id - The bot's unique identifier
   * @param data.roles - Optional array or string of role permissions
   * @returns Promise resolving to authentication token response object
   */
  protected async generateJwtForBot(data: { id: string, roles?: string[] | string }): Promise<any> {
    const jti = newJti();
    const ttl = getBotAccessTtl();
    const redis = this.redis.getClient();

    const payload: AccessPayload = {
      sub: data.id,
      client: 'bot',
      type: 'access',
      jti: jti,
      roles: data.roles,
    };

    // Step 1: Generate a fresh token
    const issuePair = await this.issuePair(payload, ttl);
    const accessToken = issuePair.pair.accessToken;
    // can be ignore other information

    // Step 2: (Delete/ Save) replace all previous sessions for this bot
    await this.redis.replaceBotSession(payload.client, payload.sub, jti, ttl)
    return {
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: ttl,
    };
  }


  // ---------- Send Email helper ----------
  protected async sendEmailConfirmation(id: Snowflake, email: string) {
    const TTL = 1000 * 60 * 60 * 24; // 1d
    const confirmToken = this.jwt.sign(
      { sub: String(id), email: email, action: "confirm_email" },
      { expiresIn: TTL, secret: process.env.JWT_SECRET }
    );

    await this.eventBus.publish("notification.send.email", {
      type: "CONFIRM_EMAIL",
      to: email,
      data: {
        token: confirmToken,
        confirmUrl: `${process.env.FRONTEND_URL}/auth/confirm/${confirmToken}`,
      },
    });
  }

  protected async confirmEmailRegister(token: string) {
    try {
      // 1. Verify token
      const payload = this.jwt.verify(token, { secret: process.env.JWT_SECRET });

      if (payload.action !== "confirm_email") throw new UnauthorizedException();

      // 2. Publish event
      await this.eventBus.publish("user.email.confirmed", {
        userId: payload.sub,
        email: payload.email,
      });

      return { message: "Email confirmed." };
    } catch (e) {
      throw new UnauthorizedException("Invalid or expired confirmation token");
    }
  }
  // ----- OTP
  protected async sendEmailResetPassword(id: Snowflake, email: string) {
    const TTL = 60 * 15; // 15 min
    // Generate code
    const code = speakeasy.totp({
      secret: process.env.OTP_SECRET_CODE,
      digits: 6,
      step: process.env.OTP_STEP_TIME ?? 1800,
      encoding: "base32",
    });

    // Send reset email
    await this.eventBus.publish("notification.send.email", {
      type: "RESET_PASSWORD",
      to: email,
      data: { code },
    });
  }
  protected async checkOTP(code: string) {
    return speakeasy.totp.verify({
      secret: process.env.OTP_SECRET_CODE,
      token: code,
      digits: 6,
      step: process.env.OTP_STEP_TIME ?? 1800, 
      encoding: "base32",
    });
  }

}

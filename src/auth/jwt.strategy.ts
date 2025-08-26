import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { normalizeKeyFromEnv } from '../common/tokens.util';

/**
 * JwtStrategy
 *
 * This strategy is used by Passport to validate JWTs sent by clients.
 * It extracts the token from the `Authorization: Bearer <token>` header,
 * verifies its signature using the public RSA key (RS256 only),
 * and attaches the decoded payload to the request context.
 */
@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor() {
    // Load the public RSA key for verifying JWTs
    const publicKey = normalizeKeyFromEnv(process.env.JWT_PUBLIC_KEY);

    if (!publicKey) {
      throw new Error('Missing JWT_PUBLIC_KEY for RS256 verification');
    }

    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey: publicKey,
      algorithms: ['RS256'],
      ignoreExpiration: false, // reject expired tokens automatically
    });
  }

  /**
   * Validate method
   *
   * If the token is valid, this method is called with the decoded payload.
   * It should return a value that will be attached to `req.user`.
   */
  async validate(payload: any) {
    console.log('-- JwtStrategy active via Cerberus');
    return payload;
  }
}

import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { getAlg, normalizeKeyFromEnv } from '../common/tokens.util';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor() {
    const alg = getAlg();
    console.log("---alg", alg)

    // clé/secret pour vérif
    const secretOrKey =
      alg === 'RS256'
        ? normalizeKeyFromEnv(process.env.JWT_PUBLIC_KEY)
        : process.env.JWT_PRIVATE_KEY || '';

    if (!secretOrKey) {
      throw new Error(
        alg === 'RS256'
          ? 'JWT_PUBLIC_KEY manquant pour RS256'
          : 'JWT_PRIVATE_KEY manquant pour HS256',
      );
    }

    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      secretOrKey,
      algorithms: [alg],
      ignoreExpiration: false,
    });
  }

  async validate(payload: any) {
    console.log("--jwt strategy active depuis cerberus")
    return payload;
  }
}

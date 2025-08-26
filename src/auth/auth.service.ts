import { Inject, Injectable } from '@nestjs/common';
import { JwtService, JwtSignOptions } from '@nestjs/jwt';
import { ClientProxy } from '@nestjs/microservices';
import {
    AccessPayload, RefreshPayload, UserPayload,
    getAccessTtl, getRefreshTtl, getAlg, normalizeKeyFromEnv, newJti
} from '../common/tokens.util';
import { RedisService } from '../redis/redis.service';
import { AuthServiceAbstract } from './auth.service.abstract';

@Injectable()
export class AuthService extends AuthServiceAbstract {
    constructor(
        private readonly _jwt: JwtService,
        private readonly _redis: RedisService,
        @Inject("USER_SERVICE") private readonly _userClient: ClientProxy,
    ) {
        super(_jwt, _redis, _userClient);
    }

    /** Register : délègue la création d’utilisateur au USER_SERVICE, puis émet les tokens */
    async register(email: string, password: string, role?: string) {
        const user = await this.userClient
            .send('user.register', { email, password, role }) as any; // todo : make user interface

        const payload: UserPayload = { sub: String(user.id), email: user.email, roles: user.roles };
        return this.issuePair(payload);
    }

    /** Login : délègue la vérif au USER_SERVICE (pwd), puis émet les tokens */
    async login(email: string, password: string) {
        const user = await this.userClient
            .send('user.validate', { email, password }) as any; // todo : make a user interface

        const payload: UserPayload = { sub: String(user.id), email: user.email, roles: user.roles };
        return this.issuePair(payload);
    }

    /** Refresh : vérifie le refresh token, contrôle Redis, puis ROTATION complète (old → new) */
    async refresh(refreshToken: string) {
        const decoded = await this.verifyRefresh(refreshToken);

        // Vérifie présence en Redis (session valide)
        const key = `refresh:${decoded.jti}`;
        const entry = await this.redis.getJSON<{ uid: string }>(key);
        if (!entry || entry.uid !== decoded.sub) {
            throw new Error('Refresh token invalide ou révoqué');
        }

        // Rotation : révoquer l'ancien, émettre un nouveau couple
        await this.redis.del(key);

        const payload: UserPayload = { sub: decoded.sub, email: decoded.email, roles: decoded.roles };
        return this.issuePair(payload);
    }

    /** Logout : révoque le refresh et, optionnellement, blacklist l’access courant */
    async logout(refreshToken: string, accessTokenJti?: string) {
        // todo : supprimer le bon token de session
        
        return { ok: true };
    }
}

import { JwtService, JwtSignOptions } from '@nestjs/jwt';
import { ClientProxy } from '@nestjs/microservices';
import {
    AccessPayload, RefreshPayload, UserPayload,
    getAccessTtl, getRefreshTtl, getAlg, normalizeKeyFromEnv, newJti
} from '../common/tokens.util';
import { RedisService } from '../redis/redis.service';

export abstract class AuthServiceAbstract {
    constructor(
        protected readonly jwt: JwtService,
        protected readonly redis: RedisService,
        protected readonly userClient: ClientProxy,
    ) { }

    // ---------- Helpers JWT signing keys/options ----------
    protected getSignKeyAndOpts(isRefresh: boolean): JwtSignOptions {
        const alg = getAlg();

        if (alg === 'RS256') {
            const privateKey = normalizeKeyFromEnv(process.env.JWT_PRIVATE_KEY);
            if (!privateKey) throw new Error('JWT_PRIVATE_KEY manquant pour RS256');
            return {
                algorithm: 'RS256',
                privateKey,
                expiresIn: isRefresh ? getRefreshTtl() : getAccessTtl(),
            };
        } else {
            const secret = process.env.JWT_SECRET || '';
            if (!secret) throw new Error('JWT_SECRET manquant pour HS256');
            return {
                algorithm: 'HS256',
                secret,
                expiresIn: isRefresh ? getRefreshTtl() : getAccessTtl(),
            };
        }
    }

    protected async signAccess(payload: AccessPayload): Promise<string> {
        const opts = this.getSignKeyAndOpts(false);
        return this.jwt.signAsync(payload, opts);
    }

    protected async signRefresh(payload: RefreshPayload): Promise<string> {
        const opts = this.getSignKeyAndOpts(true);
        return this.jwt.signAsync(payload, opts);
    }

    // ---------- Internals ----------
    protected async issuePair(user: UserPayload) {
        const aid = newJti();
        const rid = newJti();

        const accessPayload: AccessPayload = { ...user, type: 'access', jti: aid };
        const refreshPayload: RefreshPayload = { ...user, type: 'refresh', jti: rid, aid };

        const [accessToken, refreshToken] = await Promise.all([
            this.signAccess(accessPayload),
            this.signRefresh(refreshPayload),
        ]);

        // Stocker le refresh en Redis (clé → userId); TTL = durée du refresh
        await this.redis.setJSON(`refresh:${rid}`, { uid: user.sub }, getRefreshTtl());

        return {
            accessToken,
            refreshToken,
            tokenType: 'Bearer',
            expiresIn: getAccessTtl(),
        };
    }

    protected async verifyRefresh(token: string): Promise<RefreshPayload> {
        const alg = getAlg();
        const verifyOpts: any = { algorithms: [alg] };

        let key: string;
        if (alg === 'RS256') {
            key = normalizeKeyFromEnv(process.env.JWT_PUBLIC_KEY);
            if (!key) throw new Error('JWT_PUBLIC_KEY manquant');
            verifyOpts.publicKey = key;
        } else {
            key = process.env.JWT_SECRET || '';
            if (!key) throw new Error('JWT_SECRET manquant');
            verifyOpts.secret = key;
        }

        const decoded = await this.jwt.verifyAsync<RefreshPayload>(token, {
            ...verifyOpts,
        });

        if (decoded.type !== 'refresh') {
            throw new Error('Mauvais type de token');
        }
        return decoded;
    }
}

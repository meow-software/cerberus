import { Inject, Injectable, BadRequestException, UnauthorizedException, ForbiddenException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ClientProxy } from '@nestjs/microservices';
import {
    AccessPayload,
    RefreshPayload,
    UserPayload,
    getAccessTtl,
    getRefreshWindowSeconds
} from '../common/tokens.util';
import { RedisService } from '../redis/redis.service';
import { AuthServiceAbstract } from './auth.service.abstract';
import { redisCacheKeyPutUserSession } from 'src/lib';

@Injectable()
export class AuthService extends AuthServiceAbstract {
    constructor(
        protected readonly jwt: JwtService,
        protected readonly redis: RedisService,
        @Inject("USER_SERVICE") protected readonly userClient: ClientProxy,
    ) {
        super(jwt, redis, userClient);
    }

    /**
     * Register: delegates user creation to the USER_SERVICE,
     * then issues an access/refresh token pair.
     */
    async register(email: string, password: string, role?: string) {
        const user = await this.userClient
            .send('user.register', { email, password, role }) as any; // TODO: replace with a User interface

        const payload: UserPayload = { sub: String(user.id), email: user.email, roles: user.roles, client: 'user' };
        return this.issuePair(payload);
    }

    /**
     * Login: delegates validation to the USER_SERVICE (check password),
     * then issues an access/refresh token pair.
     */
    async login(email: string, password: string) {
        // const user = await this.userClient
        //     .send('user.validate', { email, password }) as any; // TODO: replace with a User interface

        const user = {
            id: "485124851845",
            email,
            roles: ["user", "admin"],
        }

        if (!user) {
            throw new UnauthorizedException('Invalid credentials.');
        }

        const payload: UserPayload = { sub: String(user.id), email: user.email, roles: user.roles, client: 'user' };
        const issuePair = await this.issuePair(payload);
        const rp = issuePair.payload.refreshPayload;
        const pair = issuePair.pair;

        // Store refresh in Redis (key = session, value = userId), TTL = refresh duration
        await this.redis.setJSON(redisCacheKeyPutUserSession(rp.sub, rp.client, rp.jti), { uid: rp.sub }, pair.expiresIn);
        return pair;
    }

    /**
     * Refresh: requires both refresh token and (optionally) access token.
     * Rules:
     *  - Access token must be expired, but within REFRESH_WINDOW_SECONDS (default: 300s = 5 min).
     *  - Refresh token must still be valid.
     *  - If refresh is expired but access expired just recently (grace period),
     *    allow re-issuing tokens based on access claims.
     */
    async refresh(refreshToken: string, accessToken?: string) {
        const nowSec = Math.floor(Date.now() / 1000);

        // 1) Access token is mandatory for refresh.
        if (!accessToken) {
            throw new BadRequestException('Access token required for refresh.');
        }

        const decodedAccess: any = this.jwt.decode(accessToken);
        if (!decodedAccess || typeof decodedAccess.exp !== 'number') {
            throw new UnauthorizedException('Invalid access token provided.');
        }

        const exp = decodedAccess.exp as number;
        const expiredSince = nowSec - exp;

        // 2) Try to verify refresh token
        let decodedRefresh: RefreshPayload | null = null;
        try {
            decodedRefresh = await this.verifyRefresh(refreshToken);
        } catch {
            // Refresh invalid or expired → continue to fallback
        }

        // Case A: Refresh valid → normal workflow
        if (decodedRefresh) {
            if (exp > nowSec) {
                throw new ForbiddenException('Access token still valid — too early to refresh.');
            }
            if (expiredSince > getRefreshWindowSeconds()) {
                throw new ForbiddenException('Access expired too long ago — refresh window exceeded.');
            }

            // 1. Invalidate the old refresh token (rotation)
            await this.redis.del(redisCacheKeyPutUserSession(decodedRefresh.sub, decodedRefresh.client, decodedRefresh.jti));

            // 2. Put new key
            const payload: UserPayload = { sub: String(decodedRefresh.sub), email: decodedRefresh.email, roles: decodedRefresh.roles, client: decodedRefresh.client };
            const issuePair = await this.issuePair(payload);
            const rp = issuePair.payload.refreshPayload;
            const pair = issuePair.pair;

            // Store refresh in Redis (key = session, value = userId), TTL = refresh duration
            await this.redis.setJSON(redisCacheKeyPutUserSession(rp.sub, rp.client, rp.jti), { uid: rp.sub }, pair.expiresIn);
            return pair;
        }

        // Case B: Refresh expired, but access just expired (grace period)
        if (expiredSince > 0 && expiredSince <= getRefreshWindowSeconds()) {
            const payload: UserPayload = { sub: String(decodedAccess.sub), email: decodedAccess.email, roles: decodedAccess.roles, client: decodedAccess.client };
            const issuePair = await this.issuePair(payload);
            const rp = issuePair.payload.refreshPayload;
            const pair = issuePair.pair;

            // Store refresh in Redis (key = session, value = userId), TTL = refresh duration
            await this.redis.setJSON(redisCacheKeyPutUserSession(rp.sub, rp.client, rp.jti), { uid: rp.sub }, pair.expiresIn);
            return pair;
        }

        // Case C: Both tokens invalid or outside allowed window
        throw new UnauthorizedException('Session expired — please log in again.');
    }

    /**
     * Logout: revokes the refresh token (deletes from Redis),
     * and optionally blacklists the current access token until its expiry.
     */
    async logout(refreshToken: string, accessTokenJti?: string) {
        try {
            const decoded = await this.verifyRefresh(refreshToken);
            await this.redis.del(`refresh:${decoded.jti}`);
        } catch {
            // Refresh already invalid → ignore
        }

        if (accessTokenJti) {
            // Blacklist access until its expiry
            const ttl = getAccessTtl();
            await this.redis.setNX(`bl:access:${accessTokenJti}`, '1', ttl);
        }

        return { ok: true };
    }

    /**
     * Validates bot credentials and generates a JWT access token for authenticated bots
     * @param clientId - The bot's client ID
     * @param clientSecret - The bot's client secret
     * @returns Promise resolving to an authentication token response
     * @throws UnauthorizedException if bot credentials are invalid
     */
    async getBotToken(clientId: string, clientSecret: string) {
        // const bot = await this.userClient
        //     .send('bot.validate', { clientId, clientSecret }) as any; // TODO: replace with a User interface

        const bot = {
            id : clientId,
            clientSecret,
            roles: ["user", "admin"],
        }

        if (!bot) throw new UnauthorizedException('Invalid bot credentials');
        return this.generateJwtForBot({
            id: bot.id,
            roles: bot.roles,
        });
    }
}

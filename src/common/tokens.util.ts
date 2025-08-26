import { randomUUID } from 'crypto';

export type JwtAlg = 'HS256' | 'RS256';

export function getAlg(): JwtAlg {
    return (process.env.JWT_ALG as JwtAlg) || 'HS256';
}

export function getAccessTtl(): number {
    return parseInt(process.env.ACCESS_TOKEN_TTL ?? '900', 10);
}

export function getRefreshTtl(): number {
    return parseInt(process.env.REFRESH_TOKEN_TTL ?? '2592000', 10);
}

export function normalizeKeyFromEnv(key: string | undefined): string {
    if (!key) return '';
    return key.replace(/\\n/g, '\n');
}

export function newJti(): string {
    return randomUUID();
}

export type UserPayload = {
    sub: string;           // user id
    email?: string;
    role?: string;
};

export type AccessPayload = UserPayload & {
    type: 'access';
    jti: string;
};

export type RefreshPayload = UserPayload & {
    type: 'refresh';
    jti: string;
    aid: string;
};

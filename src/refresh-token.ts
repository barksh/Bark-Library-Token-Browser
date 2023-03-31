/**
 * @author WMXPY
 * @namespace Token
 * @description Refresh Token
 */

import { JWTToken } from "@sudoo/jwt-web";
import { JWTRefreshToken } from "./declare";
import { ERROR_CODE } from "./error/code";
import { panic } from "./error/panic";

export class BarkRefreshToken {

    public static fromTokenOrNull(token: string): BarkRefreshToken | null {

        const parsedToken: JWTRefreshToken | null = JWTToken.fromTokenOrNull(token);

        if (parsedToken === null) {
            return null;
        }
        return new BarkRefreshToken(token, parsedToken);
    }

    public static fromTokenOrUndefined(token: string): BarkRefreshToken | undefined {

        const refreshToken: BarkRefreshToken | null = BarkRefreshToken.fromTokenOrNull(token);

        if (refreshToken === null) {
            return undefined;
        }
        return refreshToken;
    }

    public static fromTokenOrThrow(token: string, error?: Error): BarkRefreshToken {

        const refreshToken: BarkRefreshToken | null = BarkRefreshToken.fromTokenOrNull(token);

        if (refreshToken === null) {
            if (error) {
                throw error;
            }
            throw panic.code(ERROR_CODE.INVALID_AUTHENTICATION_TOKEN_1, token);
        }
        return refreshToken;
    }

    private readonly _rawToken: string;
    private readonly _parsedToken: JWTRefreshToken;

    private constructor(rawToken: string, parsedToken: JWTRefreshToken) {

        this._rawToken = rawToken;
        this._parsedToken = parsedToken;
    }

    public getRawToken(): string {
        return this._rawToken;
    }
    public getParsedToken(): JWTRefreshToken {
        return this._parsedToken;
    }

    public verifyExpiration(currentDate: Date = new Date()): boolean {

        return this._parsedToken.verifyExpiration(currentDate);
    }

    /**
     * @returns {string} self domain - the domain name of the token consumer
     */
    public getSelfDomain(): string {
        return this._parsedToken.header.aud;
    }
    /**
     * @returns {string} target domain - the domain name of the token issuer
     */
    public getTargetDomain(): string {
        return this._parsedToken.header.iss;
    }

    public getExpireAtDate(): Date {

        const expireAt: number = this._parsedToken.header.exp;
        if (typeof expireAt !== 'number') {
            throw panic.code(ERROR_CODE.TIME_NOT_EXIST_1, "exp");
        }
        return new Date(expireAt * 1000);
    }
    public getIssueAtDate(): Date {

        const issuedAt: number = this._parsedToken.header.iat;
        if (typeof issuedAt !== 'number') {
            throw panic.code(ERROR_CODE.TIME_NOT_EXIST_1, "iat");
        }
        return new Date(issuedAt * 1000);
    }

    public getTokenIdentifier(): string {
        return this._parsedToken.header.jti;
    }
    public getInquiryIdentifier(): string {
        return this._parsedToken.body.inquiry;
    }
    public getAccountIdentifier(): string {
        return this._parsedToken.body.identifier;
    }
}

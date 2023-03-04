/**
 * @author WMXPY
 * @namespace Token
 * @description Authentication Token
 */

import { JWTToken } from "@sudoo/jwt-web";
import { JWTAuthenticationToken } from "./declare";
import { ERROR_CODE } from "./error/code";
import { panic } from "./error/panic";

export class BarkAuthenticationToken {

    public static fromString(token: string): BarkAuthenticationToken {

        const parsedToken: JWTAuthenticationToken | null = JWTToken.fromTokenOrNull(token);

        if (!parsedToken) {
            throw panic.code(ERROR_CODE.INVALID_AUTHENTICATION_TOKEN_1, token);
        }

        return new BarkAuthenticationToken(token, parsedToken);
    }

    private readonly _rawToken: string;
    private readonly _parsedToken: JWTAuthenticationToken;

    private constructor(rawToken: string, parsedToken: JWTAuthenticationToken) {

        this._rawToken = rawToken;
        this._parsedToken = parsedToken;
    }

    public getRawToken(): string {
        return this._rawToken;
    }
    public getParsedToken(): JWTAuthenticationToken {
        return this._parsedToken;
    }

    public verifyExpiration(currentDate: Date = new Date()): boolean {

        return this._parsedToken.verifyExpiration(currentDate);
    }

    public getSelfDomain(): string {
        return this._parsedToken.header.aud;
    }
    public getTargetDomain(): string {
        return this._parsedToken.header.iss;
    }
    public getTokenIdentifier(): string {
        return this._parsedToken.header.jti;
    }
    public getAccountIdentifier(): string {
        return this._parsedToken.body.identifier;
    }
}

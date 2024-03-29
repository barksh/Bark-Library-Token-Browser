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

    public static fromTokenOrNull(token: string): BarkAuthenticationToken | null {

        const parsedToken: JWTAuthenticationToken | null = JWTToken.fromTokenOrNull(token);

        if (parsedToken === null) {
            return null;
        }
        return new BarkAuthenticationToken(token, parsedToken);
    }

    public static fromTokenOrUndefined(token: string): BarkAuthenticationToken | undefined {

        const authenticationToken: BarkAuthenticationToken | null = BarkAuthenticationToken.fromTokenOrNull(token);

        if (authenticationToken === null) {
            return undefined;
        }
        return authenticationToken;
    }

    public static fromTokenOrThrow(token: string, error?: Error): BarkAuthenticationToken {

        const authenticationToken: BarkAuthenticationToken | null = BarkAuthenticationToken.fromTokenOrNull(token);

        if (authenticationToken === null) {
            if (error) {
                throw error;
            }
            throw panic.code(ERROR_CODE.INVALID_AUTHENTICATION_TOKEN_1, token);
        }
        return authenticationToken;
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

    public verifyIssueDate(currentDate: Date = new Date()): boolean {
        return this._parsedToken.verifyIssueDate(currentDate);
    }
    public verifyNotBefore(currentDate: Date = new Date()): boolean {
        return this._parsedToken.verifyNotBefore(currentDate);
    }
    public verifyExpiration(currentDate: Date = new Date()): boolean {
        return this._parsedToken.verifyExpiration(currentDate);
    }
    public verifyTime(currentDate: Date = new Date()): boolean {
        return this._parsedToken.verifyTime(currentDate);
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
    public getTokenIdentifier(): string {
        return this._parsedToken.header.jti;
    }

    public getNotBeforeDate(): Date {

        const notBefore: number | undefined = this._parsedToken.header.nbf;
        if (typeof notBefore !== 'number') {
            throw panic.code(ERROR_CODE.TIME_NOT_EXIST_1, "nbf");
        }
        return new Date(notBefore * 1000);
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

    public getAccountIdentifier(): string {
        return this._parsedToken.body.identifier;
    }
    public isAutomation(): boolean {
        return this._parsedToken.body.automation;
    }
    public isAdministrator(): boolean {
        return this._parsedToken.body.administrator;
    }
}

/**
 * @author WMXPY
 * @namespace Token
 * @description Declare
 */

import { JWTToken } from "@sudoo/jwt-web";

export type JWTRefreshTokenHeader = {

    readonly alg: "RS256";
    readonly typ: "JWT";
    readonly aud: string;
    readonly exp: number;
    readonly jti: string;
    readonly kty: "Bark";
    readonly iat: number;
    readonly iss: string;
    readonly purpose: "Refresh";
};

export type JWTRefreshTokenBody = {

    readonly identifier: string;
    readonly inquiry: string;
};

export type JWTRefreshToken = JWTToken<JWTRefreshTokenHeader, JWTRefreshTokenBody>;

export type JWTAuthenticationTokenHeader = {

    readonly alg: "RS256";
    readonly typ: "JWT";
    readonly aud: string;
    readonly exp: number;
    readonly jti: string;
    readonly kty: "Bark";
    readonly iat: number;
    readonly iss: string;
    readonly purpose: "Authentication";
};

export type JWTAuthenticationTokenBody = {

    readonly identifier: string;

    readonly automation: boolean;
    readonly administrator: boolean;
};

export type JWTAuthenticationToken = JWTToken<JWTAuthenticationTokenHeader, JWTAuthenticationTokenBody>;

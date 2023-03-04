/**
 * @author WMXPY
 * @namespace Error
 * @description List
 */

import { ERROR_CODE } from "./code";

export const ERROR_LIST: Record<ERROR_CODE, string> = {

    [ERROR_CODE.INVALID_REFRESH_TOKEN_1]: "Invalid refresh token: {}",
    [ERROR_CODE.INVALID_AUTHENTICATION_TOKEN_1]: "Invalid authentication token: {}",
};

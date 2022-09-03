/******/ (() => { // webpackBootstrap
/******/ 	var __webpack_modules__ = ({

/***/ "./node_modules/@supabase/functions-js/dist/module/helper.js":
/*!*******************************************************************!*\
  !*** ./node_modules/@supabase/functions-js/dist/module/helper.js ***!
  \*******************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "resolveFetch": () => (/* binding */ resolveFetch)
/* harmony export */ });
var __awaiter = (undefined && undefined.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
const resolveFetch = (customFetch) => {
    let _fetch;
    if (customFetch) {
        _fetch = customFetch;
    }
    else if (typeof fetch === 'undefined') {
        _fetch = (...args) => __awaiter(void 0, void 0, void 0, function* () { return yield (yield __webpack_require__.e(/*! import() */ "vendors-node_modules_cross-fetch_dist_browser-ponyfill_js").then(__webpack_require__.t.bind(__webpack_require__, /*! cross-fetch */ "./node_modules/cross-fetch/dist/browser-ponyfill.js", 23))).fetch(...args); });
    }
    else {
        _fetch = fetch;
    }
    return (...args) => _fetch(...args);
};
//# sourceMappingURL=helper.js.map

/***/ }),

/***/ "./node_modules/@supabase/functions-js/dist/module/index.js":
/*!******************************************************************!*\
  !*** ./node_modules/@supabase/functions-js/dist/module/index.js ***!
  \******************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "FunctionsClient": () => (/* binding */ FunctionsClient)
/* harmony export */ });
/* harmony import */ var _helper__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./helper */ "./node_modules/@supabase/functions-js/dist/module/helper.js");
var __awaiter = (undefined && undefined.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};

class FunctionsClient {
    constructor(url, { headers = {}, customFetch, } = {}) {
        this.url = url;
        this.headers = headers;
        this.fetch = (0,_helper__WEBPACK_IMPORTED_MODULE_0__.resolveFetch)(customFetch);
    }
    /**
     * Updates the authorization header
     * @params token - the new jwt token sent in the authorisation header
     */
    setAuth(token) {
        this.headers.Authorization = `Bearer ${token}`;
    }
    /**
     * Invokes a function
     * @param functionName - the name of the function to invoke
     * @param invokeOptions - object with the following properties
     * `headers`: object representing the headers to send with the request
     * `body`: the body of the request
     * `responseType`: how the response should be parsed. The default is `json`
     */
    invoke(functionName, invokeOptions) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                const { headers, body } = invokeOptions !== null && invokeOptions !== void 0 ? invokeOptions : {};
                const response = yield this.fetch(`${this.url}/${functionName}`, {
                    method: 'POST',
                    headers: Object.assign({}, this.headers, headers),
                    body,
                });
                const isRelayError = response.headers.get('x-relay-error');
                if (isRelayError && isRelayError === 'true') {
                    return { data: null, error: new Error(yield response.text()) };
                }
                let data;
                const { responseType } = invokeOptions !== null && invokeOptions !== void 0 ? invokeOptions : {};
                if (!responseType || responseType === 'json') {
                    data = yield response.json();
                }
                else if (responseType === 'arrayBuffer') {
                    data = yield response.arrayBuffer();
                }
                else if (responseType === 'blob') {
                    data = yield response.blob();
                }
                else {
                    data = yield response.text();
                }
                return { data, error: null };
            }
            catch (error) {
                return { data: null, error };
            }
        });
    }
}
//# sourceMappingURL=index.js.map

/***/ }),

/***/ "./node_modules/@supabase/gotrue-js/dist/module/GoTrueApi.js":
/*!*******************************************************************!*\
  !*** ./node_modules/@supabase/gotrue-js/dist/module/GoTrueApi.js ***!
  \*******************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "default": () => (/* binding */ GoTrueApi)
/* harmony export */ });
/* harmony import */ var _lib_fetch__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./lib/fetch */ "./node_modules/@supabase/gotrue-js/dist/module/lib/fetch.js");
/* harmony import */ var _lib_constants__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ./lib/constants */ "./node_modules/@supabase/gotrue-js/dist/module/lib/constants.js");
/* harmony import */ var _lib_cookies__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ./lib/cookies */ "./node_modules/@supabase/gotrue-js/dist/module/lib/cookies.js");
/* harmony import */ var _lib_helpers__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ./lib/helpers */ "./node_modules/@supabase/gotrue-js/dist/module/lib/helpers.js");
var __awaiter = (undefined && undefined.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};




class GoTrueApi {
    constructor({ url = '', headers = {}, cookieOptions, fetch, }) {
        this.url = url;
        this.headers = headers;
        this.cookieOptions = Object.assign(Object.assign({}, _lib_constants__WEBPACK_IMPORTED_MODULE_1__.COOKIE_OPTIONS), cookieOptions);
        this.fetch = (0,_lib_helpers__WEBPACK_IMPORTED_MODULE_3__.resolveFetch)(fetch);
    }
    /**
     * Create a temporary object with all configured headers and
     * adds the Authorization token to be used on request methods
     * @param jwt A valid, logged-in JWT.
     */
    _createRequestHeaders(jwt) {
        const headers = Object.assign({}, this.headers);
        headers['Authorization'] = `Bearer ${jwt}`;
        return headers;
    }
    cookieName() {
        var _a;
        return (_a = this.cookieOptions.name) !== null && _a !== void 0 ? _a : '';
    }
    /**
     * Generates the relevant login URL for a third-party provider.
     * @param provider One of the providers supported by GoTrue.
     * @param redirectTo A URL or mobile address to send the user to after they are confirmed.
     * @param scopes A space-separated list of scopes granted to the OAuth application.
     */
    getUrlForProvider(provider, options) {
        const urlParams = [`provider=${encodeURIComponent(provider)}`];
        if (options === null || options === void 0 ? void 0 : options.redirectTo) {
            urlParams.push(`redirect_to=${encodeURIComponent(options.redirectTo)}`);
        }
        if (options === null || options === void 0 ? void 0 : options.scopes) {
            urlParams.push(`scopes=${encodeURIComponent(options.scopes)}`);
        }
        if (options === null || options === void 0 ? void 0 : options.queryParams) {
            const query = new URLSearchParams(options.queryParams);
            urlParams.push(`${query}`);
        }
        return `${this.url}/authorize?${urlParams.join('&')}`;
    }
    /**
     * Creates a new user using their email address.
     * @param email The email address of the user.
     * @param password The password of the user.
     * @param redirectTo A URL or mobile address to send the user to after they are confirmed.
     * @param data Optional user metadata.
     * @param captchaToken Verification token received when the user completes the captcha on your site.
     *
     * @returns A logged-in session if the server has "autoconfirm" ON
     * @returns A user if the server has "autoconfirm" OFF
     */
    signUpWithEmail(email, password, options = {}) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                const headers = Object.assign({}, this.headers);
                let queryString = '';
                if (options.redirectTo) {
                    queryString = '?redirect_to=' + encodeURIComponent(options.redirectTo);
                }
                const data = yield (0,_lib_fetch__WEBPACK_IMPORTED_MODULE_0__.post)(this.fetch, `${this.url}/signup${queryString}`, {
                    email,
                    password,
                    data: options.data,
                    gotrue_meta_security: { captcha_token: options.captchaToken },
                }, { headers });
                const session = Object.assign({}, data);
                if (session.expires_in)
                    session.expires_at = (0,_lib_helpers__WEBPACK_IMPORTED_MODULE_3__.expiresAt)(data.expires_in);
                return { data: session, error: null };
            }
            catch (e) {
                return { data: null, error: e };
            }
        });
    }
    /**
     * Logs in an existing user using their email address.
     * @param email The email address of the user.
     * @param password The password of the user.
     * @param redirectTo A URL or mobile address to send the user to after they are confirmed.
     * @param captchaToken Verification token received when the user completes the captcha on your site.
     */
    signInWithEmail(email, password, options = {}) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                const headers = Object.assign({}, this.headers);
                let queryString = '?grant_type=password';
                if (options.redirectTo) {
                    queryString += '&redirect_to=' + encodeURIComponent(options.redirectTo);
                }
                const data = yield (0,_lib_fetch__WEBPACK_IMPORTED_MODULE_0__.post)(this.fetch, `${this.url}/token${queryString}`, { email, password, gotrue_meta_security: { captcha_token: options.captchaToken } }, { headers });
                const session = Object.assign({}, data);
                if (session.expires_in)
                    session.expires_at = (0,_lib_helpers__WEBPACK_IMPORTED_MODULE_3__.expiresAt)(data.expires_in);
                return { data: session, error: null };
            }
            catch (e) {
                return { data: null, error: e };
            }
        });
    }
    /**
     * Signs up a new user using their phone number and a password.
     * @param phone The phone number of the user.
     * @param password The password of the user.
     * @param data Optional user metadata.
     * @param captchaToken Verification token received when the user completes the captcha on your site.
     */
    signUpWithPhone(phone, password, options = {}) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                const headers = Object.assign({}, this.headers);
                const data = yield (0,_lib_fetch__WEBPACK_IMPORTED_MODULE_0__.post)(this.fetch, `${this.url}/signup`, {
                    phone,
                    password,
                    data: options.data,
                    gotrue_meta_security: { captcha_token: options.captchaToken },
                }, { headers });
                const session = Object.assign({}, data);
                if (session.expires_in)
                    session.expires_at = (0,_lib_helpers__WEBPACK_IMPORTED_MODULE_3__.expiresAt)(data.expires_in);
                return { data: session, error: null };
            }
            catch (e) {
                return { data: null, error: e };
            }
        });
    }
    /**
     * Logs in an existing user using their phone number and password.
     * @param phone The phone number of the user.
     * @param password The password of the user.
     * @param captchaToken Verification token received when the user completes the captcha on your site.
     */
    signInWithPhone(phone, password, options = {}) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                const headers = Object.assign({}, this.headers);
                const queryString = '?grant_type=password';
                const data = yield (0,_lib_fetch__WEBPACK_IMPORTED_MODULE_0__.post)(this.fetch, `${this.url}/token${queryString}`, { phone, password, gotrue_meta_security: { captcha_token: options.captchaToken } }, { headers });
                const session = Object.assign({}, data);
                if (session.expires_in)
                    session.expires_at = (0,_lib_helpers__WEBPACK_IMPORTED_MODULE_3__.expiresAt)(data.expires_in);
                return { data: session, error: null };
            }
            catch (e) {
                return { data: null, error: e };
            }
        });
    }
    /**
     * Logs in an OpenID Connect user using their id_token.
     * @param id_token The IDToken of the user.
     * @param nonce The nonce of the user. The nonce is a random value generated by the developer (= yourself) before the initial grant is started. You should check the OpenID Connect specification for details. https://openid.net/developers/specs/
     * @param provider The provider of the user.
     * @param client_id The clientID of the user.
     * @param issuer The issuer of the user.
     */
    signInWithOpenIDConnect({ id_token, nonce, client_id, issuer, provider, }) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                const headers = Object.assign({}, this.headers);
                const queryString = '?grant_type=id_token';
                const data = yield (0,_lib_fetch__WEBPACK_IMPORTED_MODULE_0__.post)(this.fetch, `${this.url}/token${queryString}`, { id_token, nonce, client_id, issuer, provider }, { headers });
                const session = Object.assign({}, data);
                if (session.expires_in)
                    session.expires_at = (0,_lib_helpers__WEBPACK_IMPORTED_MODULE_3__.expiresAt)(data.expires_in);
                return { data: session, error: null };
            }
            catch (e) {
                return { data: null, error: e };
            }
        });
    }
    /**
     * Sends a magic login link to an email address.
     * @param email The email address of the user.
     * @param shouldCreateUser A boolean flag to indicate whether to automatically create a user on magiclink / otp sign-ins if the user doesn't exist. Defaults to true.
     * @param redirectTo A URL or mobile address to send the user to after they are confirmed.
     * @param captchaToken Verification token received when the user completes the captcha on your site.
     */
    sendMagicLinkEmail(email, options = {}) {
        var _a;
        return __awaiter(this, void 0, void 0, function* () {
            try {
                const headers = Object.assign({}, this.headers);
                let queryString = '';
                if (options.redirectTo) {
                    queryString += '?redirect_to=' + encodeURIComponent(options.redirectTo);
                }
                const shouldCreateUser = (_a = options.shouldCreateUser) !== null && _a !== void 0 ? _a : true;
                const data = yield (0,_lib_fetch__WEBPACK_IMPORTED_MODULE_0__.post)(this.fetch, `${this.url}/otp${queryString}`, {
                    email,
                    create_user: shouldCreateUser,
                    gotrue_meta_security: { captcha_token: options.captchaToken },
                }, { headers });
                return { data, error: null };
            }
            catch (e) {
                return { data: null, error: e };
            }
        });
    }
    /**
     * Sends a mobile OTP via SMS. Will register the account if it doesn't already exist
     * @param phone The user's phone number WITH international prefix
     * @param shouldCreateUser A boolean flag to indicate whether to automatically create a user on magiclink / otp sign-ins if the user doesn't exist. Defaults to true.
     * @param captchaToken Verification token received when the user completes the captcha on your site.
     */
    sendMobileOTP(phone, options = {}) {
        var _a;
        return __awaiter(this, void 0, void 0, function* () {
            try {
                const shouldCreateUser = (_a = options.shouldCreateUser) !== null && _a !== void 0 ? _a : true;
                const headers = Object.assign({}, this.headers);
                const data = yield (0,_lib_fetch__WEBPACK_IMPORTED_MODULE_0__.post)(this.fetch, `${this.url}/otp`, {
                    phone,
                    create_user: shouldCreateUser,
                    gotrue_meta_security: { captcha_token: options.captchaToken },
                }, { headers });
                return { data, error: null };
            }
            catch (e) {
                return { data: null, error: e };
            }
        });
    }
    /**
     * Removes a logged-in session.
     * @param jwt A valid, logged-in JWT.
     */
    signOut(jwt) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                yield (0,_lib_fetch__WEBPACK_IMPORTED_MODULE_0__.post)(this.fetch, `${this.url}/logout`, {}, { headers: this._createRequestHeaders(jwt), noResolveJson: true });
                return { error: null };
            }
            catch (e) {
                return { error: e };
            }
        });
    }
    /**
     * @deprecated Use `verifyOTP` instead!
     * @param phone The user's phone number WITH international prefix
     * @param token token that user was sent to their mobile phone
     * @param redirectTo A URL or mobile address to send the user to after they are confirmed.
     */
    verifyMobileOTP(phone, token, options = {}) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                const headers = Object.assign({}, this.headers);
                const data = yield (0,_lib_fetch__WEBPACK_IMPORTED_MODULE_0__.post)(this.fetch, `${this.url}/verify`, { phone, token, type: 'sms', redirect_to: options.redirectTo }, { headers });
                const session = Object.assign({}, data);
                if (session.expires_in)
                    session.expires_at = (0,_lib_helpers__WEBPACK_IMPORTED_MODULE_3__.expiresAt)(data.expires_in);
                return { data: session, error: null };
            }
            catch (e) {
                return { data: null, error: e };
            }
        });
    }
    /**
     * Send User supplied Email / Mobile OTP to be verified
     * @param email The user's email address
     * @param phone The user's phone number WITH international prefix
     * @param token token that user was sent to their mobile phone
     * @param type verification type that the otp is generated for
     * @param redirectTo A URL or mobile address to send the user to after they are confirmed.
     */
    verifyOTP({ email, phone, token, type = 'sms' }, options = {}) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                const headers = Object.assign({}, this.headers);
                const data = yield (0,_lib_fetch__WEBPACK_IMPORTED_MODULE_0__.post)(this.fetch, `${this.url}/verify`, { email, phone, token, type, redirect_to: options.redirectTo }, { headers });
                const session = Object.assign({}, data);
                if (session.expires_in)
                    session.expires_at = (0,_lib_helpers__WEBPACK_IMPORTED_MODULE_3__.expiresAt)(data.expires_in);
                return { data: session, error: null };
            }
            catch (e) {
                return { data: null, error: e };
            }
        });
    }
    /**
     * Sends an invite link to an email address.
     * @param email The email address of the user.
     * @param redirectTo A URL or mobile address to send the user to after they are confirmed.
     * @param data Optional user metadata
     */
    inviteUserByEmail(email, options = {}) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                const headers = Object.assign({}, this.headers);
                let queryString = '';
                if (options.redirectTo) {
                    queryString += '?redirect_to=' + encodeURIComponent(options.redirectTo);
                }
                const data = yield (0,_lib_fetch__WEBPACK_IMPORTED_MODULE_0__.post)(this.fetch, `${this.url}/invite${queryString}`, { email, data: options.data }, { headers });
                return { data, error: null };
            }
            catch (e) {
                return { data: null, error: e };
            }
        });
    }
    /**
     * Sends a reset request to an email address.
     * @param email The email address of the user.
     * @param redirectTo A URL or mobile address to send the user to after they are confirmed.
     * @param captchaToken Verification token received when the user completes the captcha on your site.
     */
    resetPasswordForEmail(email, options = {}) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                const headers = Object.assign({}, this.headers);
                let queryString = '';
                if (options.redirectTo) {
                    queryString += '?redirect_to=' + encodeURIComponent(options.redirectTo);
                }
                const data = yield (0,_lib_fetch__WEBPACK_IMPORTED_MODULE_0__.post)(this.fetch, `${this.url}/recover${queryString}`, { email, gotrue_meta_security: { captcha_token: options.captchaToken } }, { headers });
                return { data, error: null };
            }
            catch (e) {
                return { data: null, error: e };
            }
        });
    }
    /**
     * Generates a new JWT.
     * @param refreshToken A valid refresh token that was returned on login.
     */
    refreshAccessToken(refreshToken) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                const data = yield (0,_lib_fetch__WEBPACK_IMPORTED_MODULE_0__.post)(this.fetch, `${this.url}/token?grant_type=refresh_token`, { refresh_token: refreshToken }, { headers: this.headers });
                const session = Object.assign({}, data);
                if (session.expires_in)
                    session.expires_at = (0,_lib_helpers__WEBPACK_IMPORTED_MODULE_3__.expiresAt)(data.expires_in);
                return { data: session, error: null };
            }
            catch (e) {
                return { data: null, error: e };
            }
        });
    }
    /**
     * Set/delete the auth cookie based on the AuthChangeEvent.
     * Works for Next.js & Express (requires cookie-parser middleware).
     * @param req The request object.
     * @param res The response object.
     */
    setAuthCookie(req, res) {
        if (req.method !== 'POST') {
            res.setHeader('Allow', 'POST');
            res.status(405).end('Method Not Allowed');
        }
        const { event, session } = req.body;
        if (!event)
            throw new Error('Auth event missing!');
        if (event === 'SIGNED_IN') {
            if (!session)
                throw new Error('Auth session missing!');
            (0,_lib_cookies__WEBPACK_IMPORTED_MODULE_2__.setCookies)(req, res, [
                { key: 'access-token', value: session.access_token },
                { key: 'refresh-token', value: session.refresh_token },
            ].map((token) => {
                var _a;
                return ({
                    name: `${this.cookieName()}-${token.key}`,
                    value: token.value,
                    domain: this.cookieOptions.domain,
                    maxAge: (_a = this.cookieOptions.lifetime) !== null && _a !== void 0 ? _a : 0,
                    path: this.cookieOptions.path,
                    sameSite: this.cookieOptions.sameSite,
                });
            }));
        }
        if (event === 'SIGNED_OUT') {
            (0,_lib_cookies__WEBPACK_IMPORTED_MODULE_2__.setCookies)(req, res, ['access-token', 'refresh-token'].map((key) => ({
                name: `${this.cookieName()}-${key}`,
                value: '',
                maxAge: -1,
            })));
        }
        res.status(200).json({});
    }
    /**
     * Deletes the Auth Cookies and redirects to the
     * @param req The request object.
     * @param res The response object.
     * @param options Optionally specify a `redirectTo` URL in the options.
     */
    deleteAuthCookie(req, res, { redirectTo = '/' }) {
        (0,_lib_cookies__WEBPACK_IMPORTED_MODULE_2__.setCookies)(req, res, ['access-token', 'refresh-token'].map((key) => ({
            name: `${this.cookieName()}-${key}`,
            value: '',
            maxAge: -1,
        })));
        return res.redirect(307, redirectTo);
    }
    /**
     * Helper method to generate the Auth Cookie string for you in case you can't use `setAuthCookie`.
     * @param req The request object.
     * @param res The response object.
     * @returns The Cookie string that needs to be set as the value for the `Set-Cookie` header.
     */
    getAuthCookieString(req, res) {
        if (req.method !== 'POST') {
            res.setHeader('Allow', 'POST');
            res.status(405).end('Method Not Allowed');
        }
        const { event, session } = req.body;
        if (!event)
            throw new Error('Auth event missing!');
        if (event === 'SIGNED_IN') {
            if (!session)
                throw new Error('Auth session missing!');
            return (0,_lib_cookies__WEBPACK_IMPORTED_MODULE_2__.getCookieString)(req, res, [
                { key: 'access-token', value: session.access_token },
                { key: 'refresh-token', value: session.refresh_token },
            ].map((token) => {
                var _a;
                return ({
                    name: `${this.cookieName()}-${token.key}`,
                    value: token.value,
                    domain: this.cookieOptions.domain,
                    maxAge: (_a = this.cookieOptions.lifetime) !== null && _a !== void 0 ? _a : 0,
                    path: this.cookieOptions.path,
                    sameSite: this.cookieOptions.sameSite,
                });
            }));
        }
        if (event === 'SIGNED_OUT') {
            return (0,_lib_cookies__WEBPACK_IMPORTED_MODULE_2__.getCookieString)(req, res, ['access-token', 'refresh-token'].map((key) => ({
                name: `${this.cookieName()}-${key}`,
                value: '',
                maxAge: -1,
            })));
        }
        return res.getHeader('Set-Cookie');
    }
    /**
     * Generates links to be sent via email or other.
     * @param type The link type ("signup" or "magiclink" or "recovery" or "invite").
     * @param email The user's email.
     * @param password User password. For signup only.
     * @param data Optional user metadata. For signup only.
     * @param redirectTo The link type ("signup" or "magiclink" or "recovery" or "invite").
     */
    generateLink(type, email, options = {}) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                const data = yield (0,_lib_fetch__WEBPACK_IMPORTED_MODULE_0__.post)(this.fetch, `${this.url}/admin/generate_link`, {
                    type,
                    email,
                    password: options.password,
                    data: options.data,
                    redirect_to: options.redirectTo,
                }, { headers: this.headers });
                return { data, error: null };
            }
            catch (e) {
                return { data: null, error: e };
            }
        });
    }
    // User Admin API
    /**
     * Creates a new user.
     *
     * This function should only be called on a server. Never expose your `service_role` key in the browser.
     *
     * @param attributes The data you want to create the user with.
     */
    createUser(attributes) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                const data = yield (0,_lib_fetch__WEBPACK_IMPORTED_MODULE_0__.post)(this.fetch, `${this.url}/admin/users`, attributes, {
                    headers: this.headers,
                });
                return { user: data, data, error: null };
            }
            catch (e) {
                return { user: null, data: null, error: e };
            }
        });
    }
    /**
     * Get a list of users.
     *
     * This function should only be called on a server. Never expose your `service_role` key in the browser.
     */
    listUsers() {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                const data = yield (0,_lib_fetch__WEBPACK_IMPORTED_MODULE_0__.get)(this.fetch, `${this.url}/admin/users`, {
                    headers: this.headers,
                });
                return { data: data.users, error: null };
            }
            catch (e) {
                return { data: null, error: e };
            }
        });
    }
    /**
     * Get user by id.
     *
     * @param uid The user's unique identifier
     *
     * This function should only be called on a server. Never expose your `service_role` key in the browser.
     */
    getUserById(uid) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                const data = yield (0,_lib_fetch__WEBPACK_IMPORTED_MODULE_0__.get)(this.fetch, `${this.url}/admin/users/${uid}`, {
                    headers: this.headers,
                });
                return { data, error: null };
            }
            catch (e) {
                return { data: null, error: e };
            }
        });
    }
    /**
     * Get user by reading the cookie from the request.
     * Works for Next.js & Express (requires cookie-parser middleware).
     */
    getUserByCookie(req, res) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                if (!req.cookies) {
                    throw new Error('Not able to parse cookies! When using Express make sure the cookie-parser middleware is in use!');
                }
                const access_token = req.cookies[`${this.cookieName()}-access-token`];
                const refresh_token = req.cookies[`${this.cookieName()}-refresh-token`];
                if (!access_token) {
                    throw new Error('No cookie found!');
                }
                const { user, error: getUserError } = yield this.getUser(access_token);
                if (getUserError) {
                    if (!refresh_token)
                        throw new Error('No refresh_token cookie found!');
                    if (!res)
                        throw new Error('You need to pass the res object to automatically refresh the session!');
                    const { data, error } = yield this.refreshAccessToken(refresh_token);
                    if (error) {
                        throw error;
                    }
                    else if (data) {
                        (0,_lib_cookies__WEBPACK_IMPORTED_MODULE_2__.setCookies)(req, res, [
                            { key: 'access-token', value: data.access_token },
                            { key: 'refresh-token', value: data.refresh_token },
                        ].map((token) => {
                            var _a;
                            return ({
                                name: `${this.cookieName()}-${token.key}`,
                                value: token.value,
                                domain: this.cookieOptions.domain,
                                maxAge: (_a = this.cookieOptions.lifetime) !== null && _a !== void 0 ? _a : 0,
                                path: this.cookieOptions.path,
                                sameSite: this.cookieOptions.sameSite,
                            });
                        }));
                        return { token: data.access_token, user: data.user, data: data.user, error: null };
                    }
                }
                return { token: access_token, user: user, data: user, error: null };
            }
            catch (e) {
                return { token: null, user: null, data: null, error: e };
            }
        });
    }
    /**
     * Updates the user data.
     *
     * @param attributes The data you want to update.
     *
     * This function should only be called on a server. Never expose your `service_role` key in the browser.
     */
    updateUserById(uid, attributes) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                this; //
                const data = yield (0,_lib_fetch__WEBPACK_IMPORTED_MODULE_0__.put)(this.fetch, `${this.url}/admin/users/${uid}`, attributes, {
                    headers: this.headers,
                });
                return { user: data, data, error: null };
            }
            catch (e) {
                return { user: null, data: null, error: e };
            }
        });
    }
    /**
     * Delete a user. Requires a `service_role` key.
     *
     * This function should only be called on a server. Never expose your `service_role` key in the browser.
     *
     * @param uid The user uid you want to remove.
     */
    deleteUser(uid) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                const data = yield (0,_lib_fetch__WEBPACK_IMPORTED_MODULE_0__.remove)(this.fetch, `${this.url}/admin/users/${uid}`, {}, {
                    headers: this.headers,
                });
                return { user: data, data, error: null };
            }
            catch (e) {
                return { user: null, data: null, error: e };
            }
        });
    }
    /**
     * Gets the current user details.
     *
     * This method is called by the GoTrueClient `update` where
     * the jwt is set to this.currentSession.access_token
     * and therefore, acts like getting the currently authenticated user
     *
     * @param jwt A valid, logged-in JWT. Typically, the access_token for the currentSession
     */
    getUser(jwt) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                const data = yield (0,_lib_fetch__WEBPACK_IMPORTED_MODULE_0__.get)(this.fetch, `${this.url}/user`, {
                    headers: this._createRequestHeaders(jwt),
                });
                return { user: data, data, error: null };
            }
            catch (e) {
                return { user: null, data: null, error: e };
            }
        });
    }
    /**
     * Updates the user data.
     * @param jwt A valid, logged-in JWT.
     * @param attributes The data you want to update.
     */
    updateUser(jwt, attributes) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                const data = yield (0,_lib_fetch__WEBPACK_IMPORTED_MODULE_0__.put)(this.fetch, `${this.url}/user`, attributes, {
                    headers: this._createRequestHeaders(jwt),
                });
                return { user: data, data, error: null };
            }
            catch (e) {
                return { user: null, data: null, error: e };
            }
        });
    }
}
//# sourceMappingURL=GoTrueApi.js.map

/***/ }),

/***/ "./node_modules/@supabase/gotrue-js/dist/module/GoTrueClient.js":
/*!**********************************************************************!*\
  !*** ./node_modules/@supabase/gotrue-js/dist/module/GoTrueClient.js ***!
  \**********************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "default": () => (/* binding */ GoTrueClient)
/* harmony export */ });
/* harmony import */ var _GoTrueApi__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./GoTrueApi */ "./node_modules/@supabase/gotrue-js/dist/module/GoTrueApi.js");
/* harmony import */ var _lib_helpers__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ./lib/helpers */ "./node_modules/@supabase/gotrue-js/dist/module/lib/helpers.js");
/* harmony import */ var _lib_constants__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ./lib/constants */ "./node_modules/@supabase/gotrue-js/dist/module/lib/constants.js");
/* harmony import */ var _lib_polyfills__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ./lib/polyfills */ "./node_modules/@supabase/gotrue-js/dist/module/lib/polyfills.js");
var __awaiter = (undefined && undefined.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};




(0,_lib_polyfills__WEBPACK_IMPORTED_MODULE_3__.polyfillGlobalThis)(); // Make "globalThis" available
const DEFAULT_OPTIONS = {
    url: _lib_constants__WEBPACK_IMPORTED_MODULE_2__.GOTRUE_URL,
    autoRefreshToken: true,
    persistSession: true,
    detectSessionInUrl: true,
    multiTab: true,
    headers: _lib_constants__WEBPACK_IMPORTED_MODULE_2__.DEFAULT_HEADERS,
};
class GoTrueClient {
    /**
     * Create a new client for use in the browser.
     * @param options.url The URL of the GoTrue server.
     * @param options.headers Any additional headers to send to the GoTrue server.
     * @param options.detectSessionInUrl Set to "true" if you want to automatically detects OAuth grants in the URL and signs in the user.
     * @param options.autoRefreshToken Set to "true" if you want to automatically refresh the token before expiring.
     * @param options.persistSession Set to "true" if you want to automatically save the user session into local storage.
     * @param options.localStorage Provide your own local storage implementation to use instead of the browser's local storage.
     * @param options.multiTab Set to "false" if you want to disable multi-tab/window events.
     * @param options.cookieOptions
     * @param options.fetch A custom fetch implementation.
     */
    constructor(options) {
        this.stateChangeEmitters = new Map();
        this.networkRetries = 0;
        const settings = Object.assign(Object.assign({}, DEFAULT_OPTIONS), options);
        this.currentUser = null;
        this.currentSession = null;
        this.autoRefreshToken = settings.autoRefreshToken;
        this.persistSession = settings.persistSession;
        this.multiTab = settings.multiTab;
        this.localStorage = settings.localStorage || globalThis.localStorage;
        this.api = new _GoTrueApi__WEBPACK_IMPORTED_MODULE_0__["default"]({
            url: settings.url,
            headers: settings.headers,
            cookieOptions: settings.cookieOptions,
            fetch: settings.fetch,
        });
        this._recoverSession();
        this._recoverAndRefresh();
        this._listenForMultiTabEvents();
        this._handleVisibilityChange();
        if (settings.detectSessionInUrl && (0,_lib_helpers__WEBPACK_IMPORTED_MODULE_1__.isBrowser)() && !!(0,_lib_helpers__WEBPACK_IMPORTED_MODULE_1__.getParameterByName)('access_token')) {
            // Handle the OAuth redirect
            this.getSessionFromUrl({ storeSession: true }).then(({ error }) => {
                if (error) {
                    throw new Error('Error getting session from URL.');
                }
            });
        }
    }
    /**
     * Creates a new user.
     * @type UserCredentials
     * @param email The user's email address.
     * @param password The user's password.
     * @param phone The user's phone number.
     * @param redirectTo The redirect URL attached to the signup confirmation link. Does not redirect the user if it's a mobile signup.
     * @param data Optional user metadata.
     */
    signUp({ email, password, phone }, options = {}) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                this._removeSession();
                const { data, error } = phone && password
                    ? yield this.api.signUpWithPhone(phone, password, {
                        data: options.data,
                        captchaToken: options.captchaToken,
                    })
                    : yield this.api.signUpWithEmail(email, password, {
                        redirectTo: options.redirectTo,
                        data: options.data,
                        captchaToken: options.captchaToken,
                    });
                if (error) {
                    throw error;
                }
                if (!data) {
                    throw 'An error occurred on sign up.';
                }
                let session = null;
                let user = null;
                if (data.access_token) {
                    session = data;
                    user = session.user;
                    this._saveSession(session);
                    this._notifyAllSubscribers('SIGNED_IN');
                }
                if (data.id) {
                    user = data;
                }
                return { user, session, error: null };
            }
            catch (e) {
                return { user: null, session: null, error: e };
            }
        });
    }
    /**
     * Log in an existing user, or login via a third-party provider.
     * @type UserCredentials
     * @param email The user's email address.
     * @param phone The user's phone number.
     * @param password The user's password.
     * @param refreshToken A valid refresh token that was returned on login.
     * @param provider One of the providers supported by GoTrue.
     * @param redirectTo A URL to send the user to after they are confirmed (OAuth logins only).
     * @param shouldCreateUser A boolean flag to indicate whether to automatically create a user on magiclink / otp sign-ins if the user doesn't exist. Defaults to true.
     * @param scopes A space-separated list of scopes granted to the OAuth application.
     */
    signIn({ email, phone, password, refreshToken, provider, oidc }, options = {}) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                this._removeSession();
                if (email && !password) {
                    const { error } = yield this.api.sendMagicLinkEmail(email, {
                        redirectTo: options.redirectTo,
                        shouldCreateUser: options.shouldCreateUser,
                        captchaToken: options.captchaToken,
                    });
                    return { user: null, session: null, error };
                }
                if (email && password) {
                    return this._handleEmailSignIn(email, password, {
                        redirectTo: options.redirectTo,
                        captchaToken: options.captchaToken,
                    });
                }
                if (phone && !password) {
                    const { error } = yield this.api.sendMobileOTP(phone, {
                        shouldCreateUser: options.shouldCreateUser,
                        captchaToken: options.captchaToken,
                    });
                    return { user: null, session: null, error };
                }
                if (phone && password) {
                    return this._handlePhoneSignIn(phone, password);
                }
                if (refreshToken) {
                    // currentSession and currentUser will be updated to latest on _callRefreshToken using the passed refreshToken
                    const { error } = yield this._callRefreshToken(refreshToken);
                    if (error)
                        throw error;
                    return {
                        user: this.currentUser,
                        session: this.currentSession,
                        error: null,
                    };
                }
                if (provider) {
                    return this._handleProviderSignIn(provider, {
                        redirectTo: options.redirectTo,
                        scopes: options.scopes,
                        queryParams: options.queryParams,
                    });
                }
                if (oidc) {
                    return this._handleOpenIDConnectSignIn(oidc);
                }
                throw new Error(`You must provide either an email, phone number, a third-party provider or OpenID Connect.`);
            }
            catch (e) {
                return { user: null, session: null, error: e };
            }
        });
    }
    /**
     * Log in a user given a User supplied OTP received via mobile.
     * @param email The user's email address.
     * @param phone The user's phone number.
     * @param token The user's password.
     * @param type The user's verification type.
     * @param redirectTo A URL or mobile address to send the user to after they are confirmed.
     */
    verifyOTP(params, options = {}) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                this._removeSession();
                const { data, error } = yield this.api.verifyOTP(params, options);
                if (error) {
                    throw error;
                }
                if (!data) {
                    throw 'An error occurred on token verification.';
                }
                let session = null;
                let user = null;
                if (data.access_token) {
                    session = data;
                    user = session.user;
                    this._saveSession(session);
                    this._notifyAllSubscribers('SIGNED_IN');
                }
                if (data.id) {
                    user = data;
                }
                return { user, session, error: null };
            }
            catch (e) {
                return { user: null, session: null, error: e };
            }
        });
    }
    /**
     * Inside a browser context, `user()` will return the user data, if there is a logged in user.
     *
     * For server-side management, you can get a user through `auth.api.getUserByCookie()`
     */
    user() {
        return this.currentUser;
    }
    /**
     * Returns the session data, if there is an active session.
     */
    session() {
        return this.currentSession;
    }
    /**
     * Force refreshes the session including the user data in case it was updated in a different session.
     */
    refreshSession() {
        var _a;
        return __awaiter(this, void 0, void 0, function* () {
            try {
                if (!((_a = this.currentSession) === null || _a === void 0 ? void 0 : _a.access_token))
                    throw new Error('Not logged in.');
                // currentSession and currentUser will be updated to latest on _callRefreshToken
                const { error } = yield this._callRefreshToken();
                if (error)
                    throw error;
                return { data: this.currentSession, user: this.currentUser, error: null };
            }
            catch (e) {
                return { data: null, user: null, error: e };
            }
        });
    }
    /**
     * Updates user data, if there is a logged in user.
     */
    update(attributes) {
        var _a;
        return __awaiter(this, void 0, void 0, function* () {
            try {
                if (!((_a = this.currentSession) === null || _a === void 0 ? void 0 : _a.access_token))
                    throw new Error('Not logged in.');
                const { user, error } = yield this.api.updateUser(this.currentSession.access_token, attributes);
                if (error)
                    throw error;
                if (!user)
                    throw Error('Invalid user data.');
                const session = Object.assign(Object.assign({}, this.currentSession), { user });
                this._saveSession(session);
                this._notifyAllSubscribers('USER_UPDATED');
                return { data: user, user, error: null };
            }
            catch (e) {
                return { data: null, user: null, error: e };
            }
        });
    }
    /**
     * Sets the session data from refresh_token and returns current Session and Error
     * @param refresh_token a JWT token
     */
    setSession(refresh_token) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                if (!refresh_token) {
                    throw new Error('No current session.');
                }
                const { data, error } = yield this.api.refreshAccessToken(refresh_token);
                if (error) {
                    return { session: null, error: error };
                }
                this._saveSession(data);
                this._notifyAllSubscribers('SIGNED_IN');
                return { session: data, error: null };
            }
            catch (e) {
                return { error: e, session: null };
            }
        });
    }
    /**
     * Overrides the JWT on the current client. The JWT will then be sent in all subsequent network requests.
     * @param access_token a jwt access token
     */
    setAuth(access_token) {
        this.currentSession = Object.assign(Object.assign({}, this.currentSession), { access_token, token_type: 'bearer', user: this.user() });
        this._notifyAllSubscribers('TOKEN_REFRESHED');
        return this.currentSession;
    }
    /**
     * Gets the session data from a URL string
     * @param options.storeSession Optionally store the session in the browser
     */
    getSessionFromUrl(options) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                if (!(0,_lib_helpers__WEBPACK_IMPORTED_MODULE_1__.isBrowser)())
                    throw new Error('No browser detected.');
                const error_description = (0,_lib_helpers__WEBPACK_IMPORTED_MODULE_1__.getParameterByName)('error_description');
                if (error_description)
                    throw new Error(error_description);
                const provider_token = (0,_lib_helpers__WEBPACK_IMPORTED_MODULE_1__.getParameterByName)('provider_token');
                const access_token = (0,_lib_helpers__WEBPACK_IMPORTED_MODULE_1__.getParameterByName)('access_token');
                if (!access_token)
                    throw new Error('No access_token detected.');
                const expires_in = (0,_lib_helpers__WEBPACK_IMPORTED_MODULE_1__.getParameterByName)('expires_in');
                if (!expires_in)
                    throw new Error('No expires_in detected.');
                const refresh_token = (0,_lib_helpers__WEBPACK_IMPORTED_MODULE_1__.getParameterByName)('refresh_token');
                if (!refresh_token)
                    throw new Error('No refresh_token detected.');
                const token_type = (0,_lib_helpers__WEBPACK_IMPORTED_MODULE_1__.getParameterByName)('token_type');
                if (!token_type)
                    throw new Error('No token_type detected.');
                const timeNow = Math.round(Date.now() / 1000);
                const expires_at = timeNow + parseInt(expires_in);
                const { user, error } = yield this.api.getUser(access_token);
                if (error)
                    throw error;
                const session = {
                    provider_token,
                    access_token,
                    expires_in: parseInt(expires_in),
                    expires_at,
                    refresh_token,
                    token_type,
                    user: user,
                };
                if (options === null || options === void 0 ? void 0 : options.storeSession) {
                    this._saveSession(session);
                    const recoveryMode = (0,_lib_helpers__WEBPACK_IMPORTED_MODULE_1__.getParameterByName)('type');
                    this._notifyAllSubscribers('SIGNED_IN');
                    if (recoveryMode === 'recovery') {
                        this._notifyAllSubscribers('PASSWORD_RECOVERY');
                    }
                }
                // Remove tokens from URL
                window.location.hash = '';
                return { data: session, error: null };
            }
            catch (e) {
                return { data: null, error: e };
            }
        });
    }
    /**
     * Inside a browser context, `signOut()` will remove the logged in user from the browser session
     * and log them out - removing all items from localstorage and then trigger a "SIGNED_OUT" event.
     *
     * For server-side management, you can revoke all refresh tokens for a user by passing a user's JWT through to `auth.api.signOut(JWT: string)`. There is no way to revoke a user's session JWT before it automatically expires
     */
    signOut() {
        var _a;
        return __awaiter(this, void 0, void 0, function* () {
            const accessToken = (_a = this.currentSession) === null || _a === void 0 ? void 0 : _a.access_token;
            this._removeSession();
            this._notifyAllSubscribers('SIGNED_OUT');
            if (accessToken) {
                const { error } = yield this.api.signOut(accessToken);
                if (error)
                    return { error };
            }
            return { error: null };
        });
    }
    /**
     * Receive a notification every time an auth event happens.
     * @returns {Subscription} A subscription object which can be used to unsubscribe itself.
     */
    onAuthStateChange(callback) {
        try {
            const id = (0,_lib_helpers__WEBPACK_IMPORTED_MODULE_1__.uuid)();
            const subscription = {
                id,
                callback,
                unsubscribe: () => {
                    this.stateChangeEmitters.delete(id);
                },
            };
            this.stateChangeEmitters.set(id, subscription);
            return { data: subscription, error: null };
        }
        catch (e) {
            return { data: null, error: e };
        }
    }
    _handleEmailSignIn(email, password, options = {}) {
        var _a, _b;
        return __awaiter(this, void 0, void 0, function* () {
            try {
                const { data, error } = yield this.api.signInWithEmail(email, password, {
                    redirectTo: options.redirectTo,
                    captchaToken: options.captchaToken,
                });
                if (error || !data)
                    return { data: null, user: null, session: null, error };
                if (((_a = data === null || data === void 0 ? void 0 : data.user) === null || _a === void 0 ? void 0 : _a.confirmed_at) || ((_b = data === null || data === void 0 ? void 0 : data.user) === null || _b === void 0 ? void 0 : _b.email_confirmed_at)) {
                    this._saveSession(data);
                    this._notifyAllSubscribers('SIGNED_IN');
                }
                return { data, user: data.user, session: data, error: null };
            }
            catch (e) {
                return { data: null, user: null, session: null, error: e };
            }
        });
    }
    _handlePhoneSignIn(phone, password, options = {}) {
        var _a;
        return __awaiter(this, void 0, void 0, function* () {
            try {
                const { data, error } = yield this.api.signInWithPhone(phone, password, options);
                if (error || !data)
                    return { data: null, user: null, session: null, error };
                if ((_a = data === null || data === void 0 ? void 0 : data.user) === null || _a === void 0 ? void 0 : _a.phone_confirmed_at) {
                    this._saveSession(data);
                    this._notifyAllSubscribers('SIGNED_IN');
                }
                return { data, user: data.user, session: data, error: null };
            }
            catch (e) {
                return { data: null, user: null, session: null, error: e };
            }
        });
    }
    _handleProviderSignIn(provider, options = {}) {
        const url = this.api.getUrlForProvider(provider, {
            redirectTo: options.redirectTo,
            scopes: options.scopes,
            queryParams: options.queryParams,
        });
        try {
            // try to open on the browser
            if ((0,_lib_helpers__WEBPACK_IMPORTED_MODULE_1__.isBrowser)()) {
                window.location.href = url;
            }
            return { provider, url, data: null, session: null, user: null, error: null };
        }
        catch (e) {
            // fallback to returning the URL
            if (url)
                return { provider, url, data: null, session: null, user: null, error: null };
            return { data: null, user: null, session: null, error: e };
        }
    }
    _handleOpenIDConnectSignIn({ id_token, nonce, client_id, issuer, provider, }) {
        return __awaiter(this, void 0, void 0, function* () {
            if (id_token && nonce && ((client_id && issuer) || provider)) {
                try {
                    const { data, error } = yield this.api.signInWithOpenIDConnect({
                        id_token,
                        nonce,
                        client_id,
                        issuer,
                        provider,
                    });
                    if (error || !data)
                        return { user: null, session: null, error };
                    this._saveSession(data);
                    this._notifyAllSubscribers('SIGNED_IN');
                    return { user: data.user, session: data, error: null };
                }
                catch (e) {
                    return { user: null, session: null, error: e };
                }
            }
            throw new Error(`You must provide a OpenID Connect provider with your id token and nonce.`);
        });
    }
    /**
     * Attempts to get the session from LocalStorage
     * Note: this should never be async (even for React Native), as we need it to return immediately in the constructor.
     */
    _recoverSession() {
        try {
            const data = (0,_lib_helpers__WEBPACK_IMPORTED_MODULE_1__.getItemSynchronously)(this.localStorage, _lib_constants__WEBPACK_IMPORTED_MODULE_2__.STORAGE_KEY);
            if (!data)
                return null;
            const { currentSession, expiresAt } = data;
            const timeNow = Math.round(Date.now() / 1000);
            if (expiresAt >= timeNow + _lib_constants__WEBPACK_IMPORTED_MODULE_2__.EXPIRY_MARGIN && (currentSession === null || currentSession === void 0 ? void 0 : currentSession.user)) {
                this._saveSession(currentSession);
                this._notifyAllSubscribers('SIGNED_IN');
            }
        }
        catch (error) {
            console.log('error', error);
        }
    }
    /**
     * Recovers the session from LocalStorage and refreshes
     * Note: this method is async to accommodate for AsyncStorage e.g. in React native.
     */
    _recoverAndRefresh() {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                const data = yield (0,_lib_helpers__WEBPACK_IMPORTED_MODULE_1__.getItemAsync)(this.localStorage, _lib_constants__WEBPACK_IMPORTED_MODULE_2__.STORAGE_KEY);
                if (!data)
                    return null;
                const { currentSession, expiresAt } = data;
                const timeNow = Math.round(Date.now() / 1000);
                if (expiresAt < timeNow + _lib_constants__WEBPACK_IMPORTED_MODULE_2__.EXPIRY_MARGIN) {
                    if (this.autoRefreshToken && currentSession.refresh_token) {
                        this.networkRetries++;
                        const { error } = yield this._callRefreshToken(currentSession.refresh_token);
                        if (error) {
                            console.log(error.message);
                            if (error.message === _lib_constants__WEBPACK_IMPORTED_MODULE_2__.NETWORK_FAILURE.ERROR_MESSAGE &&
                                this.networkRetries < _lib_constants__WEBPACK_IMPORTED_MODULE_2__.NETWORK_FAILURE.MAX_RETRIES) {
                                if (this.refreshTokenTimer)
                                    clearTimeout(this.refreshTokenTimer);
                                this.refreshTokenTimer = setTimeout(() => this._recoverAndRefresh(), Math.pow(_lib_constants__WEBPACK_IMPORTED_MODULE_2__.NETWORK_FAILURE.RETRY_INTERVAL, this.networkRetries) * 100 // exponential backoff
                                );
                                return;
                            }
                            yield this._removeSession();
                        }
                        this.networkRetries = 0;
                    }
                    else {
                        this._removeSession();
                    }
                }
                else if (!currentSession) {
                    console.log('Current session is missing data.');
                    this._removeSession();
                }
                else {
                    // should be handled on _recoverSession method already
                    // But we still need the code here to accommodate for AsyncStorage e.g. in React native
                    this._saveSession(currentSession);
                    this._notifyAllSubscribers('SIGNED_IN');
                }
            }
            catch (err) {
                console.error(err);
                return null;
            }
        });
    }
    _callRefreshToken(refresh_token) {
        var _a;
        if (refresh_token === void 0) { refresh_token = (_a = this.currentSession) === null || _a === void 0 ? void 0 : _a.refresh_token; }
        return __awaiter(this, void 0, void 0, function* () {
            try {
                if (!refresh_token) {
                    throw new Error('No current session.');
                }
                const { data, error } = yield this.api.refreshAccessToken(refresh_token);
                if (error)
                    throw error;
                if (!data)
                    throw Error('Invalid session data.');
                this._saveSession(data);
                this._notifyAllSubscribers('TOKEN_REFRESHED');
                this._notifyAllSubscribers('SIGNED_IN');
                return { data, error: null };
            }
            catch (e) {
                return { data: null, error: e };
            }
        });
    }
    _notifyAllSubscribers(event) {
        this.stateChangeEmitters.forEach((x) => x.callback(event, this.currentSession));
    }
    /**
     * set currentSession and currentUser
     * process to _startAutoRefreshToken if possible
     */
    _saveSession(session) {
        this.currentSession = session;
        this.currentUser = session.user;
        const expiresAt = session.expires_at;
        if (expiresAt) {
            const timeNow = Math.round(Date.now() / 1000);
            const expiresIn = expiresAt - timeNow;
            const refreshDurationBeforeExpires = expiresIn > _lib_constants__WEBPACK_IMPORTED_MODULE_2__.EXPIRY_MARGIN ? _lib_constants__WEBPACK_IMPORTED_MODULE_2__.EXPIRY_MARGIN : 0.5;
            this._startAutoRefreshToken((expiresIn - refreshDurationBeforeExpires) * 1000);
        }
        // Do we need any extra check before persist session
        // access_token or user ?
        if (this.persistSession && session.expires_at) {
            this._persistSession(this.currentSession);
        }
    }
    _persistSession(currentSession) {
        const data = { currentSession, expiresAt: currentSession.expires_at };
        (0,_lib_helpers__WEBPACK_IMPORTED_MODULE_1__.setItemAsync)(this.localStorage, _lib_constants__WEBPACK_IMPORTED_MODULE_2__.STORAGE_KEY, data);
    }
    _removeSession() {
        return __awaiter(this, void 0, void 0, function* () {
            this.currentSession = null;
            this.currentUser = null;
            if (this.refreshTokenTimer)
                clearTimeout(this.refreshTokenTimer);
            (0,_lib_helpers__WEBPACK_IMPORTED_MODULE_1__.removeItemAsync)(this.localStorage, _lib_constants__WEBPACK_IMPORTED_MODULE_2__.STORAGE_KEY);
        });
    }
    /**
     * Clear and re-create refresh token timer
     * @param value time intervals in milliseconds
     */
    _startAutoRefreshToken(value) {
        if (this.refreshTokenTimer)
            clearTimeout(this.refreshTokenTimer);
        if (value <= 0 || !this.autoRefreshToken)
            return;
        this.refreshTokenTimer = setTimeout(() => __awaiter(this, void 0, void 0, function* () {
            this.networkRetries++;
            const { error } = yield this._callRefreshToken();
            if (!error)
                this.networkRetries = 0;
            if ((error === null || error === void 0 ? void 0 : error.message) === _lib_constants__WEBPACK_IMPORTED_MODULE_2__.NETWORK_FAILURE.ERROR_MESSAGE &&
                this.networkRetries < _lib_constants__WEBPACK_IMPORTED_MODULE_2__.NETWORK_FAILURE.MAX_RETRIES)
                this._startAutoRefreshToken(Math.pow(_lib_constants__WEBPACK_IMPORTED_MODULE_2__.NETWORK_FAILURE.RETRY_INTERVAL, this.networkRetries) * 100); // exponential backoff
        }), value);
        if (typeof this.refreshTokenTimer.unref === 'function')
            this.refreshTokenTimer.unref();
    }
    /**
     * Listens for changes to LocalStorage and updates the current session.
     */
    _listenForMultiTabEvents() {
        if (!this.multiTab || !(0,_lib_helpers__WEBPACK_IMPORTED_MODULE_1__.isBrowser)() || !(window === null || window === void 0 ? void 0 : window.addEventListener)) {
            return false;
        }
        try {
            window === null || window === void 0 ? void 0 : window.addEventListener('storage', (e) => {
                var _a;
                if (e.key === _lib_constants__WEBPACK_IMPORTED_MODULE_2__.STORAGE_KEY) {
                    const newSession = JSON.parse(String(e.newValue));
                    if ((_a = newSession === null || newSession === void 0 ? void 0 : newSession.currentSession) === null || _a === void 0 ? void 0 : _a.access_token) {
                        this._saveSession(newSession.currentSession);
                        this._notifyAllSubscribers('SIGNED_IN');
                    }
                    else {
                        this._removeSession();
                        this._notifyAllSubscribers('SIGNED_OUT');
                    }
                }
            });
        }
        catch (error) {
            console.error('_listenForMultiTabEvents', error);
        }
    }
    _handleVisibilityChange() {
        if (!this.multiTab || !(0,_lib_helpers__WEBPACK_IMPORTED_MODULE_1__.isBrowser)() || !(window === null || window === void 0 ? void 0 : window.addEventListener)) {
            return false;
        }
        try {
            window === null || window === void 0 ? void 0 : window.addEventListener('visibilitychange', () => {
                if (document.visibilityState === 'visible') {
                    this._recoverAndRefresh();
                }
            });
        }
        catch (error) {
            console.error('_handleVisibilityChange', error);
        }
    }
}
//# sourceMappingURL=GoTrueClient.js.map

/***/ }),

/***/ "./node_modules/@supabase/gotrue-js/dist/module/index.js":
/*!***************************************************************!*\
  !*** ./node_modules/@supabase/gotrue-js/dist/module/index.js ***!
  \***************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "GoTrueApi": () => (/* reexport safe */ _GoTrueApi__WEBPACK_IMPORTED_MODULE_0__["default"]),
/* harmony export */   "GoTrueClient": () => (/* reexport safe */ _GoTrueClient__WEBPACK_IMPORTED_MODULE_1__["default"])
/* harmony export */ });
/* harmony import */ var _GoTrueApi__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./GoTrueApi */ "./node_modules/@supabase/gotrue-js/dist/module/GoTrueApi.js");
/* harmony import */ var _GoTrueClient__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ./GoTrueClient */ "./node_modules/@supabase/gotrue-js/dist/module/GoTrueClient.js");
/* harmony import */ var _lib_types__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ./lib/types */ "./node_modules/@supabase/gotrue-js/dist/module/lib/types.js");




//# sourceMappingURL=index.js.map

/***/ }),

/***/ "./node_modules/@supabase/gotrue-js/dist/module/lib/constants.js":
/*!***********************************************************************!*\
  !*** ./node_modules/@supabase/gotrue-js/dist/module/lib/constants.js ***!
  \***********************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "AUDIENCE": () => (/* binding */ AUDIENCE),
/* harmony export */   "COOKIE_OPTIONS": () => (/* binding */ COOKIE_OPTIONS),
/* harmony export */   "DEFAULT_HEADERS": () => (/* binding */ DEFAULT_HEADERS),
/* harmony export */   "EXPIRY_MARGIN": () => (/* binding */ EXPIRY_MARGIN),
/* harmony export */   "GOTRUE_URL": () => (/* binding */ GOTRUE_URL),
/* harmony export */   "NETWORK_FAILURE": () => (/* binding */ NETWORK_FAILURE),
/* harmony export */   "STORAGE_KEY": () => (/* binding */ STORAGE_KEY)
/* harmony export */ });
/* harmony import */ var _version__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./version */ "./node_modules/@supabase/gotrue-js/dist/module/lib/version.js");

const GOTRUE_URL = 'http://localhost:9999';
const AUDIENCE = '';
const DEFAULT_HEADERS = { 'X-Client-Info': `gotrue-js/${_version__WEBPACK_IMPORTED_MODULE_0__.version}` };
const EXPIRY_MARGIN = 10; // in seconds
const NETWORK_FAILURE = {
    ERROR_MESSAGE: 'Request Failed',
    MAX_RETRIES: 10,
    RETRY_INTERVAL: 2, // in deciseconds
};
const STORAGE_KEY = 'supabase.auth.token';
const COOKIE_OPTIONS = {
    name: 'sb',
    lifetime: 60 * 60 * 8,
    domain: '',
    path: '/',
    sameSite: 'lax',
};
//# sourceMappingURL=constants.js.map

/***/ }),

/***/ "./node_modules/@supabase/gotrue-js/dist/module/lib/cookies.js":
/*!*********************************************************************!*\
  !*** ./node_modules/@supabase/gotrue-js/dist/module/lib/cookies.js ***!
  \*********************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "deleteCookie": () => (/* binding */ deleteCookie),
/* harmony export */   "getCookieString": () => (/* binding */ getCookieString),
/* harmony export */   "setCookie": () => (/* binding */ setCookie),
/* harmony export */   "setCookies": () => (/* binding */ setCookies)
/* harmony export */ });
/**
 * Serialize data into a cookie header.
 */
function serialize(name, val, options) {
    const opt = options || {};
    const enc = encodeURIComponent;
    /* eslint-disable-next-line no-control-regex */
    const fieldContentRegExp = /^[\u0009\u0020-\u007e\u0080-\u00ff]+$/;
    if (typeof enc !== 'function') {
        throw new TypeError('option encode is invalid');
    }
    if (!fieldContentRegExp.test(name)) {
        throw new TypeError('argument name is invalid');
    }
    const value = enc(val);
    if (value && !fieldContentRegExp.test(value)) {
        throw new TypeError('argument val is invalid');
    }
    let str = name + '=' + value;
    if (null != opt.maxAge) {
        const maxAge = opt.maxAge - 0;
        if (isNaN(maxAge) || !isFinite(maxAge)) {
            throw new TypeError('option maxAge is invalid');
        }
        str += '; Max-Age=' + Math.floor(maxAge);
    }
    if (opt.domain) {
        if (!fieldContentRegExp.test(opt.domain)) {
            throw new TypeError('option domain is invalid');
        }
        str += '; Domain=' + opt.domain;
    }
    if (opt.path) {
        if (!fieldContentRegExp.test(opt.path)) {
            throw new TypeError('option path is invalid');
        }
        str += '; Path=' + opt.path;
    }
    if (opt.expires) {
        if (typeof opt.expires.toUTCString !== 'function') {
            throw new TypeError('option expires is invalid');
        }
        str += '; Expires=' + opt.expires.toUTCString();
    }
    if (opt.httpOnly) {
        str += '; HttpOnly';
    }
    if (opt.secure) {
        str += '; Secure';
    }
    if (opt.sameSite) {
        const sameSite = typeof opt.sameSite === 'string' ? opt.sameSite.toLowerCase() : opt.sameSite;
        switch (sameSite) {
            case 'lax':
                str += '; SameSite=Lax';
                break;
            case 'strict':
                str += '; SameSite=Strict';
                break;
            case 'none':
                str += '; SameSite=None';
                break;
            default:
                throw new TypeError('option sameSite is invalid');
        }
    }
    return str;
}
/**
 * Based on the environment and the request we know if a secure cookie can be set.
 */
function isSecureEnvironment(req) {
    if (!req || !req.headers || !req.headers.host) {
        throw new Error('The "host" request header is not available');
    }
    const host = (req.headers.host.indexOf(':') > -1 && req.headers.host.split(':')[0]) || req.headers.host;
    if (['localhost', '127.0.0.1'].indexOf(host) > -1 || host.endsWith('.local')) {
        return false;
    }
    return true;
}
/**
 * Serialize a cookie to a string.
 */
function serializeCookie(cookie, secure) {
    var _a, _b, _c;
    return serialize(cookie.name, cookie.value, {
        maxAge: cookie.maxAge,
        expires: new Date(Date.now() + cookie.maxAge * 1000),
        httpOnly: true,
        secure,
        path: (_a = cookie.path) !== null && _a !== void 0 ? _a : '/',
        domain: (_b = cookie.domain) !== null && _b !== void 0 ? _b : '',
        sameSite: (_c = cookie.sameSite) !== null && _c !== void 0 ? _c : 'lax',
    });
}
/**
 * Get Cookie Header strings.
 */
function getCookieString(req, res, cookies) {
    const strCookies = cookies.map((c) => serializeCookie(c, isSecureEnvironment(req)));
    const previousCookies = res.getHeader('Set-Cookie');
    if (previousCookies) {
        if (previousCookies instanceof Array) {
            Array.prototype.push.apply(strCookies, previousCookies);
        }
        else if (typeof previousCookies === 'string') {
            strCookies.push(previousCookies);
        }
    }
    return strCookies;
}
/**
 * Set one or more cookies.
 */
function setCookies(req, res, cookies) {
    res.setHeader('Set-Cookie', getCookieString(req, res, cookies));
}
/**
 * Set one or more cookies.
 */
function setCookie(req, res, cookie) {
    setCookies(req, res, [cookie]);
}
function deleteCookie(req, res, name) {
    setCookie(req, res, {
        name,
        value: '',
        maxAge: -1,
    });
}
//# sourceMappingURL=cookies.js.map

/***/ }),

/***/ "./node_modules/@supabase/gotrue-js/dist/module/lib/fetch.js":
/*!*******************************************************************!*\
  !*** ./node_modules/@supabase/gotrue-js/dist/module/lib/fetch.js ***!
  \*******************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "get": () => (/* binding */ get),
/* harmony export */   "post": () => (/* binding */ post),
/* harmony export */   "put": () => (/* binding */ put),
/* harmony export */   "remove": () => (/* binding */ remove)
/* harmony export */ });
/* harmony import */ var _constants__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./constants */ "./node_modules/@supabase/gotrue-js/dist/module/lib/constants.js");
var __awaiter = (undefined && undefined.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};

const _getErrorMessage = (err) => err.msg || err.message || err.error_description || err.error || JSON.stringify(err);
const handleError = (error, reject) => {
    if (!(error === null || error === void 0 ? void 0 : error.status)) {
        return reject({ message: _constants__WEBPACK_IMPORTED_MODULE_0__.NETWORK_FAILURE.ERROR_MESSAGE });
    }
    if (typeof error.json !== 'function') {
        return reject(error);
    }
    error.json().then((err) => {
        return reject({
            message: _getErrorMessage(err),
            status: (error === null || error === void 0 ? void 0 : error.status) || 500,
        });
    });
};
const _getRequestParams = (method, options, body) => {
    const params = { method, headers: (options === null || options === void 0 ? void 0 : options.headers) || {} };
    if (method === 'GET') {
        return params;
    }
    params.headers = Object.assign({ 'Content-Type': 'text/plain;charset=UTF-8' }, options === null || options === void 0 ? void 0 : options.headers);
    params.body = JSON.stringify(body);
    return params;
};
function _handleRequest(fetcher, method, url, options, body) {
    return __awaiter(this, void 0, void 0, function* () {
        return new Promise((resolve, reject) => {
            fetcher(url, _getRequestParams(method, options, body))
                .then((result) => {
                if (!result.ok)
                    throw result;
                if (options === null || options === void 0 ? void 0 : options.noResolveJson)
                    return resolve;
                return result.json();
            })
                .then((data) => resolve(data))
                .catch((error) => handleError(error, reject));
        });
    });
}
function get(fetcher, url, options) {
    return __awaiter(this, void 0, void 0, function* () {
        return _handleRequest(fetcher, 'GET', url, options);
    });
}
function post(fetcher, url, body, options) {
    return __awaiter(this, void 0, void 0, function* () {
        return _handleRequest(fetcher, 'POST', url, options, body);
    });
}
function put(fetcher, url, body, options) {
    return __awaiter(this, void 0, void 0, function* () {
        return _handleRequest(fetcher, 'PUT', url, options, body);
    });
}
function remove(fetcher, url, body, options) {
    return __awaiter(this, void 0, void 0, function* () {
        return _handleRequest(fetcher, 'DELETE', url, options, body);
    });
}
//# sourceMappingURL=fetch.js.map

/***/ }),

/***/ "./node_modules/@supabase/gotrue-js/dist/module/lib/helpers.js":
/*!*********************************************************************!*\
  !*** ./node_modules/@supabase/gotrue-js/dist/module/lib/helpers.js ***!
  \*********************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "expiresAt": () => (/* binding */ expiresAt),
/* harmony export */   "getItemAsync": () => (/* binding */ getItemAsync),
/* harmony export */   "getItemSynchronously": () => (/* binding */ getItemSynchronously),
/* harmony export */   "getParameterByName": () => (/* binding */ getParameterByName),
/* harmony export */   "isBrowser": () => (/* binding */ isBrowser),
/* harmony export */   "removeItemAsync": () => (/* binding */ removeItemAsync),
/* harmony export */   "resolveFetch": () => (/* binding */ resolveFetch),
/* harmony export */   "setItemAsync": () => (/* binding */ setItemAsync),
/* harmony export */   "uuid": () => (/* binding */ uuid)
/* harmony export */ });
var __awaiter = (undefined && undefined.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
function expiresAt(expiresIn) {
    const timeNow = Math.round(Date.now() / 1000);
    return timeNow + expiresIn;
}
function uuid() {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
        const r = (Math.random() * 16) | 0, v = c == 'x' ? r : (r & 0x3) | 0x8;
        return v.toString(16);
    });
}
const isBrowser = () => typeof window !== 'undefined';
function getParameterByName(name, url) {
    var _a;
    if (!url)
        url = ((_a = window === null || window === void 0 ? void 0 : window.location) === null || _a === void 0 ? void 0 : _a.href) || '';
    // eslint-disable-next-line no-useless-escape
    name = name.replace(/[\[\]]/g, '\\$&');
    const regex = new RegExp('[?&#]' + name + '(=([^&#]*)|&|#|$)'), results = regex.exec(url);
    if (!results)
        return null;
    if (!results[2])
        return '';
    return decodeURIComponent(results[2].replace(/\+/g, ' '));
}
const resolveFetch = (customFetch) => {
    let _fetch;
    if (customFetch) {
        _fetch = customFetch;
    }
    else if (typeof fetch === 'undefined') {
        _fetch = (...args) => __awaiter(void 0, void 0, void 0, function* () { return yield (yield __webpack_require__.e(/*! import() */ "vendors-node_modules_cross-fetch_dist_browser-ponyfill_js").then(__webpack_require__.t.bind(__webpack_require__, /*! cross-fetch */ "./node_modules/cross-fetch/dist/browser-ponyfill.js", 23))).fetch(...args); });
    }
    else {
        _fetch = fetch;
    }
    return (...args) => _fetch(...args);
};
// LocalStorage helpers
const setItemAsync = (storage, key, data) => __awaiter(void 0, void 0, void 0, function* () {
    isBrowser() && (yield (storage === null || storage === void 0 ? void 0 : storage.setItem(key, JSON.stringify(data))));
});
const getItemAsync = (storage, key) => __awaiter(void 0, void 0, void 0, function* () {
    const value = isBrowser() && (yield (storage === null || storage === void 0 ? void 0 : storage.getItem(key)));
    if (!value)
        return null;
    try {
        return JSON.parse(value);
    }
    catch (_a) {
        return value;
    }
});
const getItemSynchronously = (storage, key) => {
    const value = isBrowser() && (storage === null || storage === void 0 ? void 0 : storage.getItem(key));
    if (!value || typeof value !== 'string') {
        return null;
    }
    try {
        return JSON.parse(value);
    }
    catch (_a) {
        return value;
    }
};
const removeItemAsync = (storage, key) => __awaiter(void 0, void 0, void 0, function* () {
    isBrowser() && (yield (storage === null || storage === void 0 ? void 0 : storage.removeItem(key)));
});
//# sourceMappingURL=helpers.js.map

/***/ }),

/***/ "./node_modules/@supabase/gotrue-js/dist/module/lib/polyfills.js":
/*!***********************************************************************!*\
  !*** ./node_modules/@supabase/gotrue-js/dist/module/lib/polyfills.js ***!
  \***********************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "polyfillGlobalThis": () => (/* binding */ polyfillGlobalThis)
/* harmony export */ });
/**
 * https://mathiasbynens.be/notes/globalthis
 */
function polyfillGlobalThis() {
    if (typeof globalThis === 'object')
        return;
    try {
        Object.defineProperty(Object.prototype, '__magic__', {
            get: function () {
                return this;
            },
            configurable: true,
        });
        // @ts-expect-error 'Allow access to magic'
        __magic__.globalThis = __magic__;
        // @ts-expect-error 'Allow access to magic'
        delete Object.prototype.__magic__;
    }
    catch (e) {
        if (typeof self !== 'undefined') {
            // @ts-expect-error 'Allow access to globals'
            self.globalThis = self;
        }
    }
}
//# sourceMappingURL=polyfills.js.map

/***/ }),

/***/ "./node_modules/@supabase/gotrue-js/dist/module/lib/types.js":
/*!*******************************************************************!*\
  !*** ./node_modules/@supabase/gotrue-js/dist/module/lib/types.js ***!
  \*******************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);

//# sourceMappingURL=types.js.map

/***/ }),

/***/ "./node_modules/@supabase/gotrue-js/dist/module/lib/version.js":
/*!*********************************************************************!*\
  !*** ./node_modules/@supabase/gotrue-js/dist/module/lib/version.js ***!
  \*********************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "version": () => (/* binding */ version)
/* harmony export */ });
// generated by genversion
const version = '1.22.22';
//# sourceMappingURL=version.js.map

/***/ }),

/***/ "./node_modules/@supabase/postgrest-js/dist/module/PostgrestClient.js":
/*!****************************************************************************!*\
  !*** ./node_modules/@supabase/postgrest-js/dist/module/PostgrestClient.js ***!
  \****************************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "default": () => (/* binding */ PostgrestClient)
/* harmony export */ });
/* harmony import */ var _lib_PostgrestQueryBuilder__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./lib/PostgrestQueryBuilder */ "./node_modules/@supabase/postgrest-js/dist/module/lib/PostgrestQueryBuilder.js");
/* harmony import */ var _lib_PostgrestRpcBuilder__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ./lib/PostgrestRpcBuilder */ "./node_modules/@supabase/postgrest-js/dist/module/lib/PostgrestRpcBuilder.js");
/* harmony import */ var _lib_constants__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ./lib/constants */ "./node_modules/@supabase/postgrest-js/dist/module/lib/constants.js");



class PostgrestClient {
    /**
     * Creates a PostgREST client.
     *
     * @param url  URL of the PostgREST endpoint.
     * @param headers  Custom headers.
     * @param schema  Postgres schema to switch to.
     */
    constructor(url, { headers = {}, schema, fetch, throwOnError, } = {}) {
        this.url = url;
        this.headers = Object.assign(Object.assign({}, _lib_constants__WEBPACK_IMPORTED_MODULE_2__.DEFAULT_HEADERS), headers);
        this.schema = schema;
        this.fetch = fetch;
        this.shouldThrowOnError = throwOnError;
    }
    /**
     * Authenticates the request with JWT.
     *
     * @param token  The JWT token to use.
     */
    auth(token) {
        this.headers['Authorization'] = `Bearer ${token}`;
        return this;
    }
    /**
     * Perform a table operation.
     *
     * @param table  The table name to operate on.
     */
    from(table) {
        const url = `${this.url}/${table}`;
        return new _lib_PostgrestQueryBuilder__WEBPACK_IMPORTED_MODULE_0__["default"](url, {
            headers: this.headers,
            schema: this.schema,
            fetch: this.fetch,
            shouldThrowOnError: this.shouldThrowOnError,
        });
    }
    /**
     * Perform a function call.
     *
     * @param fn  The function name to call.
     * @param params  The parameters to pass to the function call.
     * @param head  When set to true, no data will be returned.
     * @param count  Count algorithm to use to count rows in a table.
     */
    rpc(fn, params, { head = false, count = null, } = {}) {
        const url = `${this.url}/rpc/${fn}`;
        return new _lib_PostgrestRpcBuilder__WEBPACK_IMPORTED_MODULE_1__["default"](url, {
            headers: this.headers,
            schema: this.schema,
            fetch: this.fetch,
            shouldThrowOnError: this.shouldThrowOnError,
        }).rpc(params, { head, count });
    }
}
//# sourceMappingURL=PostgrestClient.js.map

/***/ }),

/***/ "./node_modules/@supabase/postgrest-js/dist/module/index.js":
/*!******************************************************************!*\
  !*** ./node_modules/@supabase/postgrest-js/dist/module/index.js ***!
  \******************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "PostgrestBuilder": () => (/* reexport safe */ _lib_types__WEBPACK_IMPORTED_MODULE_3__.PostgrestBuilder),
/* harmony export */   "PostgrestClient": () => (/* reexport safe */ _PostgrestClient__WEBPACK_IMPORTED_MODULE_0__["default"]),
/* harmony export */   "PostgrestFilterBuilder": () => (/* reexport safe */ _lib_PostgrestFilterBuilder__WEBPACK_IMPORTED_MODULE_1__["default"]),
/* harmony export */   "PostgrestQueryBuilder": () => (/* reexport safe */ _lib_PostgrestQueryBuilder__WEBPACK_IMPORTED_MODULE_2__["default"])
/* harmony export */ });
/* harmony import */ var _PostgrestClient__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./PostgrestClient */ "./node_modules/@supabase/postgrest-js/dist/module/PostgrestClient.js");
/* harmony import */ var _lib_PostgrestFilterBuilder__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ./lib/PostgrestFilterBuilder */ "./node_modules/@supabase/postgrest-js/dist/module/lib/PostgrestFilterBuilder.js");
/* harmony import */ var _lib_PostgrestQueryBuilder__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ./lib/PostgrestQueryBuilder */ "./node_modules/@supabase/postgrest-js/dist/module/lib/PostgrestQueryBuilder.js");
/* harmony import */ var _lib_types__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ./lib/types */ "./node_modules/@supabase/postgrest-js/dist/module/lib/types.js");





//# sourceMappingURL=index.js.map

/***/ }),

/***/ "./node_modules/@supabase/postgrest-js/dist/module/lib/PostgrestFilterBuilder.js":
/*!***************************************************************************************!*\
  !*** ./node_modules/@supabase/postgrest-js/dist/module/lib/PostgrestFilterBuilder.js ***!
  \***************************************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "default": () => (/* binding */ PostgrestFilterBuilder)
/* harmony export */ });
/* harmony import */ var _PostgrestTransformBuilder__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./PostgrestTransformBuilder */ "./node_modules/@supabase/postgrest-js/dist/module/lib/PostgrestTransformBuilder.js");

class PostgrestFilterBuilder extends _PostgrestTransformBuilder__WEBPACK_IMPORTED_MODULE_0__["default"] {
    constructor() {
        super(...arguments);
        /** @deprecated Use `contains()` instead. */
        this.cs = this.contains;
        /** @deprecated Use `containedBy()` instead. */
        this.cd = this.containedBy;
        /** @deprecated Use `rangeLt()` instead. */
        this.sl = this.rangeLt;
        /** @deprecated Use `rangeGt()` instead. */
        this.sr = this.rangeGt;
        /** @deprecated Use `rangeGte()` instead. */
        this.nxl = this.rangeGte;
        /** @deprecated Use `rangeLte()` instead. */
        this.nxr = this.rangeLte;
        /** @deprecated Use `rangeAdjacent()` instead. */
        this.adj = this.rangeAdjacent;
        /** @deprecated Use `overlaps()` instead. */
        this.ov = this.overlaps;
    }
    /**
     * Finds all rows which doesn't satisfy the filter.
     *
     * @param column  The column to filter on.
     * @param operator  The operator to filter with.
     * @param value  The value to filter with.
     */
    not(column, operator, value) {
        this.url.searchParams.append(`${column}`, `not.${operator}.${value}`);
        return this;
    }
    /**
     * Finds all rows satisfying at least one of the filters.
     *
     * @param filters  The filters to use, separated by commas.
     * @param foreignTable  The foreign table to use (if `column` is a foreign column).
     */
    or(filters, { foreignTable } = {}) {
        const key = typeof foreignTable === 'undefined' ? 'or' : `${foreignTable}.or`;
        this.url.searchParams.append(key, `(${filters})`);
        return this;
    }
    /**
     * Finds all rows whose value on the stated `column` exactly matches the
     * specified `value`.
     *
     * @param column  The column to filter on.
     * @param value  The value to filter with.
     */
    eq(column, value) {
        this.url.searchParams.append(`${column}`, `eq.${value}`);
        return this;
    }
    /**
     * Finds all rows whose value on the stated `column` doesn't match the
     * specified `value`.
     *
     * @param column  The column to filter on.
     * @param value  The value to filter with.
     */
    neq(column, value) {
        this.url.searchParams.append(`${column}`, `neq.${value}`);
        return this;
    }
    /**
     * Finds all rows whose value on the stated `column` is greater than the
     * specified `value`.
     *
     * @param column  The column to filter on.
     * @param value  The value to filter with.
     */
    gt(column, value) {
        this.url.searchParams.append(`${column}`, `gt.${value}`);
        return this;
    }
    /**
     * Finds all rows whose value on the stated `column` is greater than or
     * equal to the specified `value`.
     *
     * @param column  The column to filter on.
     * @param value  The value to filter with.
     */
    gte(column, value) {
        this.url.searchParams.append(`${column}`, `gte.${value}`);
        return this;
    }
    /**
     * Finds all rows whose value on the stated `column` is less than the
     * specified `value`.
     *
     * @param column  The column to filter on.
     * @param value  The value to filter with.
     */
    lt(column, value) {
        this.url.searchParams.append(`${column}`, `lt.${value}`);
        return this;
    }
    /**
     * Finds all rows whose value on the stated `column` is less than or equal
     * to the specified `value`.
     *
     * @param column  The column to filter on.
     * @param value  The value to filter with.
     */
    lte(column, value) {
        this.url.searchParams.append(`${column}`, `lte.${value}`);
        return this;
    }
    /**
     * Finds all rows whose value in the stated `column` matches the supplied
     * `pattern` (case sensitive).
     *
     * @param column  The column to filter on.
     * @param pattern  The pattern to filter with.
     */
    like(column, pattern) {
        this.url.searchParams.append(`${column}`, `like.${pattern}`);
        return this;
    }
    /**
     * Finds all rows whose value in the stated `column` matches the supplied
     * `pattern` (case insensitive).
     *
     * @param column  The column to filter on.
     * @param pattern  The pattern to filter with.
     */
    ilike(column, pattern) {
        this.url.searchParams.append(`${column}`, `ilike.${pattern}`);
        return this;
    }
    /**
     * A check for exact equality (null, true, false), finds all rows whose
     * value on the stated `column` exactly match the specified `value`.
     *
     * @param column  The column to filter on.
     * @param value  The value to filter with.
     */
    is(column, value) {
        this.url.searchParams.append(`${column}`, `is.${value}`);
        return this;
    }
    /**
     * Finds all rows whose value on the stated `column` is found on the
     * specified `values`.
     *
     * @param column  The column to filter on.
     * @param values  The values to filter with.
     */
    in(column, values) {
        const cleanedValues = values
            .map((s) => {
            // handle postgrest reserved characters
            // https://postgrest.org/en/v7.0.0/api.html#reserved-characters
            if (typeof s === 'string' && new RegExp('[,()]').test(s))
                return `"${s}"`;
            else
                return `${s}`;
        })
            .join(',');
        this.url.searchParams.append(`${column}`, `in.(${cleanedValues})`);
        return this;
    }
    /**
     * Finds all rows whose json, array, or range value on the stated `column`
     * contains the values specified in `value`.
     *
     * @param column  The column to filter on.
     * @param value  The value to filter with.
     */
    contains(column, value) {
        if (typeof value === 'string') {
            // range types can be inclusive '[', ']' or exclusive '(', ')' so just
            // keep it simple and accept a string
            this.url.searchParams.append(`${column}`, `cs.${value}`);
        }
        else if (Array.isArray(value)) {
            // array
            this.url.searchParams.append(`${column}`, `cs.{${value.join(',')}}`);
        }
        else {
            // json
            this.url.searchParams.append(`${column}`, `cs.${JSON.stringify(value)}`);
        }
        return this;
    }
    /**
     * Finds all rows whose json, array, or range value on the stated `column` is
     * contained by the specified `value`.
     *
     * @param column  The column to filter on.
     * @param value  The value to filter with.
     */
    containedBy(column, value) {
        if (typeof value === 'string') {
            // range
            this.url.searchParams.append(`${column}`, `cd.${value}`);
        }
        else if (Array.isArray(value)) {
            // array
            this.url.searchParams.append(`${column}`, `cd.{${value.join(',')}}`);
        }
        else {
            // json
            this.url.searchParams.append(`${column}`, `cd.${JSON.stringify(value)}`);
        }
        return this;
    }
    /**
     * Finds all rows whose range value on the stated `column` is strictly to the
     * left of the specified `range`.
     *
     * @param column  The column to filter on.
     * @param range  The range to filter with.
     */
    rangeLt(column, range) {
        this.url.searchParams.append(`${column}`, `sl.${range}`);
        return this;
    }
    /**
     * Finds all rows whose range value on the stated `column` is strictly to
     * the right of the specified `range`.
     *
     * @param column  The column to filter on.
     * @param range  The range to filter with.
     */
    rangeGt(column, range) {
        this.url.searchParams.append(`${column}`, `sr.${range}`);
        return this;
    }
    /**
     * Finds all rows whose range value on the stated `column` does not extend
     * to the left of the specified `range`.
     *
     * @param column  The column to filter on.
     * @param range  The range to filter with.
     */
    rangeGte(column, range) {
        this.url.searchParams.append(`${column}`, `nxl.${range}`);
        return this;
    }
    /**
     * Finds all rows whose range value on the stated `column` does not extend
     * to the right of the specified `range`.
     *
     * @param column  The column to filter on.
     * @param range  The range to filter with.
     */
    rangeLte(column, range) {
        this.url.searchParams.append(`${column}`, `nxr.${range}`);
        return this;
    }
    /**
     * Finds all rows whose range value on the stated `column` is adjacent to
     * the specified `range`.
     *
     * @param column  The column to filter on.
     * @param range  The range to filter with.
     */
    rangeAdjacent(column, range) {
        this.url.searchParams.append(`${column}`, `adj.${range}`);
        return this;
    }
    /**
     * Finds all rows whose array or range value on the stated `column` overlaps
     * (has a value in common) with the specified `value`.
     *
     * @param column  The column to filter on.
     * @param value  The value to filter with.
     */
    overlaps(column, value) {
        if (typeof value === 'string') {
            // range
            this.url.searchParams.append(`${column}`, `ov.${value}`);
        }
        else {
            // array
            this.url.searchParams.append(`${column}`, `ov.{${value.join(',')}}`);
        }
        return this;
    }
    /**
     * Finds all rows whose text or tsvector value on the stated `column` matches
     * the tsquery in `query`.
     *
     * @param column  The column to filter on.
     * @param query  The Postgres tsquery string to filter with.
     * @param config  The text search configuration to use.
     * @param type  The type of tsquery conversion to use on `query`.
     */
    textSearch(column, query, { config, type = null, } = {}) {
        let typePart = '';
        if (type === 'plain') {
            typePart = 'pl';
        }
        else if (type === 'phrase') {
            typePart = 'ph';
        }
        else if (type === 'websearch') {
            typePart = 'w';
        }
        const configPart = config === undefined ? '' : `(${config})`;
        this.url.searchParams.append(`${column}`, `${typePart}fts${configPart}.${query}`);
        return this;
    }
    /**
     * Finds all rows whose tsvector value on the stated `column` matches
     * to_tsquery(`query`).
     *
     * @param column  The column to filter on.
     * @param query  The Postgres tsquery string to filter with.
     * @param config  The text search configuration to use.
     *
     * @deprecated Use `textSearch()` instead.
     */
    fts(column, query, { config } = {}) {
        const configPart = typeof config === 'undefined' ? '' : `(${config})`;
        this.url.searchParams.append(`${column}`, `fts${configPart}.${query}`);
        return this;
    }
    /**
     * Finds all rows whose tsvector value on the stated `column` matches
     * plainto_tsquery(`query`).
     *
     * @param column  The column to filter on.
     * @param query  The Postgres tsquery string to filter with.
     * @param config  The text search configuration to use.
     *
     * @deprecated Use `textSearch()` with `type: 'plain'` instead.
     */
    plfts(column, query, { config } = {}) {
        const configPart = typeof config === 'undefined' ? '' : `(${config})`;
        this.url.searchParams.append(`${column}`, `plfts${configPart}.${query}`);
        return this;
    }
    /**
     * Finds all rows whose tsvector value on the stated `column` matches
     * phraseto_tsquery(`query`).
     *
     * @param column  The column to filter on.
     * @param query  The Postgres tsquery string to filter with.
     * @param config  The text search configuration to use.
     *
     * @deprecated Use `textSearch()` with `type: 'phrase'` instead.
     */
    phfts(column, query, { config } = {}) {
        const configPart = typeof config === 'undefined' ? '' : `(${config})`;
        this.url.searchParams.append(`${column}`, `phfts${configPart}.${query}`);
        return this;
    }
    /**
     * Finds all rows whose tsvector value on the stated `column` matches
     * websearch_to_tsquery(`query`).
     *
     * @param column  The column to filter on.
     * @param query  The Postgres tsquery string to filter with.
     * @param config  The text search configuration to use.
     *
     * @deprecated Use `textSearch()` with `type: 'websearch'` instead.
     */
    wfts(column, query, { config } = {}) {
        const configPart = typeof config === 'undefined' ? '' : `(${config})`;
        this.url.searchParams.append(`${column}`, `wfts${configPart}.${query}`);
        return this;
    }
    /**
     * Finds all rows whose `column` satisfies the filter.
     *
     * @param column  The column to filter on.
     * @param operator  The operator to filter with.
     * @param value  The value to filter with.
     */
    filter(column, operator, value) {
        this.url.searchParams.append(`${column}`, `${operator}.${value}`);
        return this;
    }
    /**
     * Finds all rows whose columns match the specified `query` object.
     *
     * @param query  The object to filter with, with column names as keys mapped
     *               to their filter values.
     */
    match(query) {
        Object.keys(query).forEach((key) => {
            this.url.searchParams.append(`${key}`, `eq.${query[key]}`);
        });
        return this;
    }
}
//# sourceMappingURL=PostgrestFilterBuilder.js.map

/***/ }),

/***/ "./node_modules/@supabase/postgrest-js/dist/module/lib/PostgrestQueryBuilder.js":
/*!**************************************************************************************!*\
  !*** ./node_modules/@supabase/postgrest-js/dist/module/lib/PostgrestQueryBuilder.js ***!
  \**************************************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "default": () => (/* binding */ PostgrestQueryBuilder)
/* harmony export */ });
/* harmony import */ var _types__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./types */ "./node_modules/@supabase/postgrest-js/dist/module/lib/types.js");
/* harmony import */ var _PostgrestFilterBuilder__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ./PostgrestFilterBuilder */ "./node_modules/@supabase/postgrest-js/dist/module/lib/PostgrestFilterBuilder.js");


class PostgrestQueryBuilder extends _types__WEBPACK_IMPORTED_MODULE_0__.PostgrestBuilder {
    constructor(url, { headers = {}, schema, fetch, shouldThrowOnError, } = {}) {
        super({ fetch, shouldThrowOnError });
        this.url = new URL(url);
        this.headers = Object.assign({}, headers);
        this.schema = schema;
    }
    /**
     * Performs vertical filtering with SELECT.
     *
     * @param columns  The columns to retrieve, separated by commas.
     * @param head  When set to true, select will void data.
     * @param count  Count algorithm to use to count rows in a table.
     */
    select(columns = '*', { head = false, count = null, } = {}) {
        this.method = 'GET';
        // Remove whitespaces except when quoted
        let quoted = false;
        const cleanedColumns = columns
            .split('')
            .map((c) => {
            if (/\s/.test(c) && !quoted) {
                return '';
            }
            if (c === '"') {
                quoted = !quoted;
            }
            return c;
        })
            .join('');
        this.url.searchParams.set('select', cleanedColumns);
        if (count) {
            this.headers['Prefer'] = `count=${count}`;
        }
        if (head) {
            this.method = 'HEAD';
        }
        return new _PostgrestFilterBuilder__WEBPACK_IMPORTED_MODULE_1__["default"](this);
    }
    insert(values, { upsert = false, onConflict, returning = 'representation', count = null, } = {}) {
        this.method = 'POST';
        const prefersHeaders = [`return=${returning}`];
        if (upsert)
            prefersHeaders.push('resolution=merge-duplicates');
        if (upsert && onConflict !== undefined)
            this.url.searchParams.set('on_conflict', onConflict);
        this.body = values;
        if (count) {
            prefersHeaders.push(`count=${count}`);
        }
        if (this.headers['Prefer']) {
            prefersHeaders.unshift(this.headers['Prefer']);
        }
        this.headers['Prefer'] = prefersHeaders.join(',');
        if (Array.isArray(values)) {
            const columns = values.reduce((acc, x) => acc.concat(Object.keys(x)), []);
            if (columns.length > 0) {
                const uniqueColumns = [...new Set(columns)].map((column) => `"${column}"`);
                this.url.searchParams.set('columns', uniqueColumns.join(','));
            }
        }
        return new _PostgrestFilterBuilder__WEBPACK_IMPORTED_MODULE_1__["default"](this);
    }
    /**
     * Performs an UPSERT into the table.
     *
     * @param values  The values to insert.
     * @param onConflict  By specifying the `on_conflict` query parameter, you can make UPSERT work on a column(s) that has a UNIQUE constraint.
     * @param returning  By default the new record is returned. Set this to 'minimal' if you don't need this value.
     * @param count  Count algorithm to use to count rows in a table.
     * @param ignoreDuplicates  Specifies if duplicate rows should be ignored and not inserted.
     */
    upsert(values, { onConflict, returning = 'representation', count = null, ignoreDuplicates = false, } = {}) {
        this.method = 'POST';
        const prefersHeaders = [
            `resolution=${ignoreDuplicates ? 'ignore' : 'merge'}-duplicates`,
            `return=${returning}`,
        ];
        if (onConflict !== undefined)
            this.url.searchParams.set('on_conflict', onConflict);
        this.body = values;
        if (count) {
            prefersHeaders.push(`count=${count}`);
        }
        if (this.headers['Prefer']) {
            prefersHeaders.unshift(this.headers['Prefer']);
        }
        this.headers['Prefer'] = prefersHeaders.join(',');
        return new _PostgrestFilterBuilder__WEBPACK_IMPORTED_MODULE_1__["default"](this);
    }
    /**
     * Performs an UPDATE on the table.
     *
     * @param values  The values to update.
     * @param returning  By default the updated record is returned. Set this to 'minimal' if you don't need this value.
     * @param count  Count algorithm to use to count rows in a table.
     */
    update(values, { returning = 'representation', count = null, } = {}) {
        this.method = 'PATCH';
        const prefersHeaders = [`return=${returning}`];
        this.body = values;
        if (count) {
            prefersHeaders.push(`count=${count}`);
        }
        if (this.headers['Prefer']) {
            prefersHeaders.unshift(this.headers['Prefer']);
        }
        this.headers['Prefer'] = prefersHeaders.join(',');
        return new _PostgrestFilterBuilder__WEBPACK_IMPORTED_MODULE_1__["default"](this);
    }
    /**
     * Performs a DELETE on the table.
     *
     * @param returning  If `true`, return the deleted row(s) in the response.
     * @param count  Count algorithm to use to count rows in a table.
     */
    delete({ returning = 'representation', count = null, } = {}) {
        this.method = 'DELETE';
        const prefersHeaders = [`return=${returning}`];
        if (count) {
            prefersHeaders.push(`count=${count}`);
        }
        if (this.headers['Prefer']) {
            prefersHeaders.unshift(this.headers['Prefer']);
        }
        this.headers['Prefer'] = prefersHeaders.join(',');
        return new _PostgrestFilterBuilder__WEBPACK_IMPORTED_MODULE_1__["default"](this);
    }
}
//# sourceMappingURL=PostgrestQueryBuilder.js.map

/***/ }),

/***/ "./node_modules/@supabase/postgrest-js/dist/module/lib/PostgrestRpcBuilder.js":
/*!************************************************************************************!*\
  !*** ./node_modules/@supabase/postgrest-js/dist/module/lib/PostgrestRpcBuilder.js ***!
  \************************************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "default": () => (/* binding */ PostgrestRpcBuilder)
/* harmony export */ });
/* harmony import */ var _types__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./types */ "./node_modules/@supabase/postgrest-js/dist/module/lib/types.js");
/* harmony import */ var _PostgrestFilterBuilder__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ./PostgrestFilterBuilder */ "./node_modules/@supabase/postgrest-js/dist/module/lib/PostgrestFilterBuilder.js");


class PostgrestRpcBuilder extends _types__WEBPACK_IMPORTED_MODULE_0__.PostgrestBuilder {
    constructor(url, { headers = {}, schema, fetch, shouldThrowOnError, } = {}) {
        super({ fetch, shouldThrowOnError });
        this.url = new URL(url);
        this.headers = Object.assign({}, headers);
        this.schema = schema;
    }
    /**
     * Perform a function call.
     */
    rpc(params, { head = false, count = null, } = {}) {
        if (head) {
            this.method = 'HEAD';
            if (params) {
                Object.entries(params).forEach(([name, value]) => {
                    this.url.searchParams.append(name, value);
                });
            }
        }
        else {
            this.method = 'POST';
            this.body = params;
        }
        if (count) {
            if (this.headers['Prefer'] !== undefined)
                this.headers['Prefer'] += `,count=${count}`;
            else
                this.headers['Prefer'] = `count=${count}`;
        }
        return new _PostgrestFilterBuilder__WEBPACK_IMPORTED_MODULE_1__["default"](this);
    }
}
//# sourceMappingURL=PostgrestRpcBuilder.js.map

/***/ }),

/***/ "./node_modules/@supabase/postgrest-js/dist/module/lib/PostgrestTransformBuilder.js":
/*!******************************************************************************************!*\
  !*** ./node_modules/@supabase/postgrest-js/dist/module/lib/PostgrestTransformBuilder.js ***!
  \******************************************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "default": () => (/* binding */ PostgrestTransformBuilder)
/* harmony export */ });
/* harmony import */ var _types__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./types */ "./node_modules/@supabase/postgrest-js/dist/module/lib/types.js");

/**
 * Post-filters (transforms)
 */
class PostgrestTransformBuilder extends _types__WEBPACK_IMPORTED_MODULE_0__.PostgrestBuilder {
    /**
     * Performs vertical filtering with SELECT.
     *
     * @param columns  The columns to retrieve, separated by commas.
     */
    select(columns = '*') {
        // Remove whitespaces except when quoted
        let quoted = false;
        const cleanedColumns = columns
            .split('')
            .map((c) => {
            if (/\s/.test(c) && !quoted) {
                return '';
            }
            if (c === '"') {
                quoted = !quoted;
            }
            return c;
        })
            .join('');
        this.url.searchParams.set('select', cleanedColumns);
        return this;
    }
    /**
     * Orders the result with the specified `column`.
     *
     * @param column  The column to order on.
     * @param ascending  If `true`, the result will be in ascending order.
     * @param nullsFirst  If `true`, `null`s appear first.
     * @param foreignTable  The foreign table to use (if `column` is a foreign column).
     */
    order(column, { ascending = true, nullsFirst = false, foreignTable, } = {}) {
        const key = typeof foreignTable === 'undefined' ? 'order' : `${foreignTable}.order`;
        const existingOrder = this.url.searchParams.get(key);
        this.url.searchParams.set(key, `${existingOrder ? `${existingOrder},` : ''}${column}.${ascending ? 'asc' : 'desc'}.${nullsFirst ? 'nullsfirst' : 'nullslast'}`);
        return this;
    }
    /**
     * Limits the result with the specified `count`.
     *
     * @param count  The maximum no. of rows to limit to.
     * @param foreignTable  The foreign table to use (for foreign columns).
     */
    limit(count, { foreignTable } = {}) {
        const key = typeof foreignTable === 'undefined' ? 'limit' : `${foreignTable}.limit`;
        this.url.searchParams.set(key, `${count}`);
        return this;
    }
    /**
     * Limits the result to rows within the specified range, inclusive.
     *
     * @param from  The starting index from which to limit the result, inclusive.
     * @param to  The last index to which to limit the result, inclusive.
     * @param foreignTable  The foreign table to use (for foreign columns).
     */
    range(from, to, { foreignTable } = {}) {
        const keyOffset = typeof foreignTable === 'undefined' ? 'offset' : `${foreignTable}.offset`;
        const keyLimit = typeof foreignTable === 'undefined' ? 'limit' : `${foreignTable}.limit`;
        this.url.searchParams.set(keyOffset, `${from}`);
        // Range is inclusive, so add 1
        this.url.searchParams.set(keyLimit, `${to - from + 1}`);
        return this;
    }
    /**
     * Sets the AbortSignal for the fetch request.
     */
    abortSignal(signal) {
        this.signal = signal;
        return this;
    }
    /**
     * Retrieves only one row from the result. Result must be one row (e.g. using
     * `limit`), otherwise this will result in an error.
     */
    single() {
        this.headers['Accept'] = 'application/vnd.pgrst.object+json';
        return this;
    }
    /**
     * Retrieves at most one row from the result. Result must be at most one row
     * (e.g. using `eq` on a UNIQUE column), otherwise this will result in an
     * error.
     */
    maybeSingle() {
        this.headers['Accept'] = 'application/vnd.pgrst.object+json';
        this.allowEmpty = true;
        return this;
    }
    /**
     * Set the response type to CSV.
     */
    csv() {
        this.headers['Accept'] = 'text/csv';
        return this;
    }
}
//# sourceMappingURL=PostgrestTransformBuilder.js.map

/***/ }),

/***/ "./node_modules/@supabase/postgrest-js/dist/module/lib/constants.js":
/*!**************************************************************************!*\
  !*** ./node_modules/@supabase/postgrest-js/dist/module/lib/constants.js ***!
  \**************************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "DEFAULT_HEADERS": () => (/* binding */ DEFAULT_HEADERS)
/* harmony export */ });
/* harmony import */ var _version__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./version */ "./node_modules/@supabase/postgrest-js/dist/module/lib/version.js");

const DEFAULT_HEADERS = { 'X-Client-Info': `postgrest-js/${_version__WEBPACK_IMPORTED_MODULE_0__.version}` };
//# sourceMappingURL=constants.js.map

/***/ }),

/***/ "./node_modules/@supabase/postgrest-js/dist/module/lib/types.js":
/*!**********************************************************************!*\
  !*** ./node_modules/@supabase/postgrest-js/dist/module/lib/types.js ***!
  \**********************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "PostgrestBuilder": () => (/* binding */ PostgrestBuilder)
/* harmony export */ });
var __awaiter = (undefined && undefined.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
class PostgrestBuilder {
    constructor(builder) {
        Object.assign(this, builder);
        let _fetch;
        if (builder.fetch) {
            _fetch = builder.fetch;
        }
        else if (typeof fetch === 'undefined') {
            _fetch = (...args) => __awaiter(this, void 0, void 0, function* () { return yield (yield __webpack_require__.e(/*! import() */ "vendors-node_modules_cross-fetch_dist_browser-ponyfill_js").then(__webpack_require__.t.bind(__webpack_require__, /*! cross-fetch */ "./node_modules/cross-fetch/dist/browser-ponyfill.js", 23))).fetch(...args); });
        }
        else {
            _fetch = fetch;
        }
        this.fetch = (...args) => _fetch(...args);
        this.shouldThrowOnError = builder.shouldThrowOnError || false;
        this.allowEmpty = builder.allowEmpty || false;
    }
    /**
     * If there's an error with the query, throwOnError will reject the promise by
     * throwing the error instead of returning it as part of a successful response.
     *
     * {@link https://github.com/supabase/supabase-js/issues/92}
     */
    throwOnError(throwOnError) {
        if (throwOnError === null || throwOnError === undefined) {
            throwOnError = true;
        }
        this.shouldThrowOnError = throwOnError;
        return this;
    }
    then(onfulfilled, onrejected) {
        // https://postgrest.org/en/stable/api.html#switching-schemas
        if (typeof this.schema === 'undefined') {
            // skip
        }
        else if (['GET', 'HEAD'].includes(this.method)) {
            this.headers['Accept-Profile'] = this.schema;
        }
        else {
            this.headers['Content-Profile'] = this.schema;
        }
        if (this.method !== 'GET' && this.method !== 'HEAD') {
            this.headers['Content-Type'] = 'application/json';
        }
        let res = this.fetch(this.url.toString(), {
            method: this.method,
            headers: this.headers,
            body: JSON.stringify(this.body),
            signal: this.signal,
        }).then((res) => __awaiter(this, void 0, void 0, function* () {
            var _a, _b, _c, _d;
            let error = null;
            let data = null;
            let count = null;
            let status = res.status;
            let statusText = res.statusText;
            if (res.ok) {
                const isReturnMinimal = (_a = this.headers['Prefer']) === null || _a === void 0 ? void 0 : _a.split(',').includes('return=minimal');
                if (this.method !== 'HEAD' && !isReturnMinimal) {
                    const text = yield res.text();
                    if (!text) {
                        // discard `text`
                    }
                    else if (this.headers['Accept'] === 'text/csv') {
                        data = text;
                    }
                    else {
                        data = JSON.parse(text);
                    }
                }
                const countHeader = (_b = this.headers['Prefer']) === null || _b === void 0 ? void 0 : _b.match(/count=(exact|planned|estimated)/);
                const contentRange = (_c = res.headers.get('content-range')) === null || _c === void 0 ? void 0 : _c.split('/');
                if (countHeader && contentRange && contentRange.length > 1) {
                    count = parseInt(contentRange[1]);
                }
            }
            else {
                const body = yield res.text();
                try {
                    error = JSON.parse(body);
                }
                catch (_e) {
                    error = {
                        message: body,
                    };
                }
                if (error && this.allowEmpty && ((_d = error === null || error === void 0 ? void 0 : error.details) === null || _d === void 0 ? void 0 : _d.includes('Results contain 0 rows'))) {
                    error = null;
                    status = 200;
                    statusText = 'OK';
                }
                if (error && this.shouldThrowOnError) {
                    throw error;
                }
            }
            const postgrestResponse = {
                error,
                data,
                count,
                status,
                statusText,
                body: data,
            };
            return postgrestResponse;
        }));
        if (!this.shouldThrowOnError) {
            res = res.catch((fetchError) => ({
                error: {
                    message: `FetchError: ${fetchError.message}`,
                    details: '',
                    hint: '',
                    code: fetchError.code || '',
                },
                data: null,
                body: null,
                count: null,
                status: 400,
                statusText: 'Bad Request',
            }));
        }
        return res.then(onfulfilled, onrejected);
    }
}
//# sourceMappingURL=types.js.map

/***/ }),

/***/ "./node_modules/@supabase/postgrest-js/dist/module/lib/version.js":
/*!************************************************************************!*\
  !*** ./node_modules/@supabase/postgrest-js/dist/module/lib/version.js ***!
  \************************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "version": () => (/* binding */ version)
/* harmony export */ });
// generated by genversion
const version = '0.37.4';
//# sourceMappingURL=version.js.map

/***/ }),

/***/ "./node_modules/@supabase/realtime-js/dist/module/RealtimeClient.js":
/*!**************************************************************************!*\
  !*** ./node_modules/@supabase/realtime-js/dist/module/RealtimeClient.js ***!
  \**************************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "default": () => (/* binding */ RealtimeClient)
/* harmony export */ });
/* harmony import */ var websocket__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! websocket */ "./node_modules/websocket/lib/browser.js");
/* harmony import */ var websocket__WEBPACK_IMPORTED_MODULE_0___default = /*#__PURE__*/__webpack_require__.n(websocket__WEBPACK_IMPORTED_MODULE_0__);
/* harmony import */ var _lib_constants__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ./lib/constants */ "./node_modules/@supabase/realtime-js/dist/module/lib/constants.js");
/* harmony import */ var _lib_timer__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ./lib/timer */ "./node_modules/@supabase/realtime-js/dist/module/lib/timer.js");
/* harmony import */ var _lib_serializer__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ./lib/serializer */ "./node_modules/@supabase/realtime-js/dist/module/lib/serializer.js");
/* harmony import */ var _RealtimeSubscription__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! ./RealtimeSubscription */ "./node_modules/@supabase/realtime-js/dist/module/RealtimeSubscription.js");
var __awaiter = (undefined && undefined.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};





const noop = () => { };
class RealtimeClient {
    /**
     * Initializes the Socket.
     *
     * @param endPoint The string WebSocket endpoint, ie, "ws://example.com/socket", "wss://example.com", "/socket" (inherited host & protocol)
     * @param options.transport The Websocket Transport, for example WebSocket.
     * @param options.timeout The default timeout in milliseconds to trigger push timeouts.
     * @param options.params The optional params to pass when connecting.
     * @param options.headers The optional headers to pass when connecting.
     * @param options.heartbeatIntervalMs The millisec interval to send a heartbeat message.
     * @param options.logger The optional function for specialized logging, ie: logger: (kind, msg, data) => { console.log(`${kind}: ${msg}`, data) }
     * @param options.encode The function to encode outgoing messages. Defaults to JSON: (payload, callback) => callback(JSON.stringify(payload))
     * @param options.decode The function to decode incoming messages. Defaults to Serializer's decode.
     * @param options.longpollerTimeout The maximum timeout of a long poll AJAX request. Defaults to 20s (double the server long poll timer).
     * @param options.reconnectAfterMs he optional function that returns the millsec reconnect interval. Defaults to stepped backoff off.
     */
    constructor(endPoint, options) {
        this.accessToken = null;
        this.channels = [];
        this.endPoint = '';
        this.headers = _lib_constants__WEBPACK_IMPORTED_MODULE_1__.DEFAULT_HEADERS;
        this.params = {};
        this.timeout = _lib_constants__WEBPACK_IMPORTED_MODULE_1__.DEFAULT_TIMEOUT;
        this.transport = websocket__WEBPACK_IMPORTED_MODULE_0__.w3cwebsocket;
        this.heartbeatIntervalMs = 30000;
        this.longpollerTimeout = 20000;
        this.heartbeatTimer = undefined;
        this.pendingHeartbeatRef = null;
        this.ref = 0;
        this.logger = noop;
        this.conn = null;
        this.sendBuffer = [];
        this.serializer = new _lib_serializer__WEBPACK_IMPORTED_MODULE_3__["default"]();
        this.stateChangeCallbacks = {
            open: [],
            close: [],
            error: [],
            message: [],
        };
        this.endPoint = `${endPoint}/${_lib_constants__WEBPACK_IMPORTED_MODULE_1__.TRANSPORTS.websocket}`;
        if (options === null || options === void 0 ? void 0 : options.params)
            this.params = options.params;
        if (options === null || options === void 0 ? void 0 : options.headers)
            this.headers = Object.assign(Object.assign({}, this.headers), options.headers);
        if (options === null || options === void 0 ? void 0 : options.timeout)
            this.timeout = options.timeout;
        if (options === null || options === void 0 ? void 0 : options.logger)
            this.logger = options.logger;
        if (options === null || options === void 0 ? void 0 : options.transport)
            this.transport = options.transport;
        if (options === null || options === void 0 ? void 0 : options.heartbeatIntervalMs)
            this.heartbeatIntervalMs = options.heartbeatIntervalMs;
        if (options === null || options === void 0 ? void 0 : options.longpollerTimeout)
            this.longpollerTimeout = options.longpollerTimeout;
        this.reconnectAfterMs = (options === null || options === void 0 ? void 0 : options.reconnectAfterMs) ? options.reconnectAfterMs
            : (tries) => {
                return [1000, 2000, 5000, 10000][tries - 1] || 10000;
            };
        this.encode = (options === null || options === void 0 ? void 0 : options.encode) ? options.encode
            : (payload, callback) => {
                return callback(JSON.stringify(payload));
            };
        this.decode = (options === null || options === void 0 ? void 0 : options.decode) ? options.decode
            : this.serializer.decode.bind(this.serializer);
        this.reconnectTimer = new _lib_timer__WEBPACK_IMPORTED_MODULE_2__["default"](() => __awaiter(this, void 0, void 0, function* () {
            yield this.disconnect();
            this.connect();
        }), this.reconnectAfterMs);
    }
    /**
     * Connects the socket, unless already connected.
     */
    connect() {
        if (this.conn) {
            return;
        }
        this.conn = new this.transport(this.endPointURL(), [], null, this.headers);
        if (this.conn) {
            // this.conn.timeout = this.longpollerTimeout // TYPE ERROR
            this.conn.binaryType = 'arraybuffer';
            this.conn.onopen = () => this._onConnOpen();
            this.conn.onerror = (error) => this._onConnError(error);
            this.conn.onmessage = (event) => this.onConnMessage(event);
            this.conn.onclose = (event) => this._onConnClose(event);
        }
    }
    /**
     * Disconnects the socket.
     *
     * @param code A numeric status code to send on disconnect.
     * @param reason A custom reason for the disconnect.
     */
    disconnect(code, reason) {
        return new Promise((resolve, _reject) => {
            try {
                if (this.conn) {
                    this.conn.onclose = function () { }; // noop
                    if (code) {
                        this.conn.close(code, reason || '');
                    }
                    else {
                        this.conn.close();
                    }
                    this.conn = null;
                    // remove open handles
                    this.heartbeatTimer && clearInterval(this.heartbeatTimer);
                    this.reconnectTimer.reset();
                }
                resolve({ error: null, data: true });
            }
            catch (error) {
                resolve({ error: error, data: false });
            }
        });
    }
    /**
     * Logs the message.
     *
     * For customized logging, `this.logger` can be overriden.
     */
    log(kind, msg, data) {
        this.logger(kind, msg, data);
    }
    /**
     * Registers a callback for connection state change event.
     *
     * @param callback A function to be called when the event occurs.
     *
     * @example
     *    socket.onOpen(() => console.log("Socket opened."))
     */
    onOpen(callback) {
        this.stateChangeCallbacks.open.push(callback);
    }
    /**
     * Registers a callback for connection state change events.
     *
     * @param callback A function to be called when the event occurs.
     *
     * @example
     *    socket.onOpen(() => console.log("Socket closed."))
     */
    onClose(callback) {
        this.stateChangeCallbacks.close.push(callback);
    }
    /**
     * Registers a callback for connection state change events.
     *
     * @param callback A function to be called when the event occurs.
     *
     * @example
     *    socket.onOpen((error) => console.log("An error occurred"))
     */
    onError(callback) {
        this.stateChangeCallbacks.error.push(callback);
    }
    /**
     * Calls a function any time a message is received.
     *
     * @param callback A function to be called when the event occurs.
     *
     * @example
     *    socket.onMessage((message) => console.log(message))
     */
    onMessage(callback) {
        this.stateChangeCallbacks.message.push(callback);
    }
    /**
     * Returns the current state of the socket.
     */
    connectionState() {
        switch (this.conn && this.conn.readyState) {
            case _lib_constants__WEBPACK_IMPORTED_MODULE_1__.SOCKET_STATES.connecting:
                return _lib_constants__WEBPACK_IMPORTED_MODULE_1__.CONNECTION_STATE.Connecting;
            case _lib_constants__WEBPACK_IMPORTED_MODULE_1__.SOCKET_STATES.open:
                return _lib_constants__WEBPACK_IMPORTED_MODULE_1__.CONNECTION_STATE.Open;
            case _lib_constants__WEBPACK_IMPORTED_MODULE_1__.SOCKET_STATES.closing:
                return _lib_constants__WEBPACK_IMPORTED_MODULE_1__.CONNECTION_STATE.Closing;
            default:
                return _lib_constants__WEBPACK_IMPORTED_MODULE_1__.CONNECTION_STATE.Closed;
        }
    }
    /**
     * Retuns `true` is the connection is open.
     */
    isConnected() {
        return this.connectionState() === _lib_constants__WEBPACK_IMPORTED_MODULE_1__.CONNECTION_STATE.Open;
    }
    /**
     * Removes a subscription from the socket.
     *
     * @param channel An open subscription.
     */
    remove(channel) {
        this.channels = this.channels.filter((c) => c.joinRef() !== channel.joinRef());
    }
    channel(topic, chanParams = {}) {
        const chan = new _RealtimeSubscription__WEBPACK_IMPORTED_MODULE_4__["default"](topic, chanParams, this);
        this.channels.push(chan);
        return chan;
    }
    /**
     * Push out a message if the socket is connected.
     *
     * If the socket is not connected, the message gets enqueued within a local buffer, and sent out when a connection is next established.
     */
    push(data) {
        const { topic, event, payload, ref } = data;
        let callback = () => {
            this.encode(data, (result) => {
                var _a;
                (_a = this.conn) === null || _a === void 0 ? void 0 : _a.send(result);
            });
        };
        this.log('push', `${topic} ${event} (${ref})`, payload);
        if (this.isConnected()) {
            callback();
        }
        else {
            this.sendBuffer.push(callback);
        }
    }
    onConnMessage(rawMessage) {
        this.decode(rawMessage.data, (msg) => {
            let { topic, event, payload, ref } = msg;
            if ((ref && ref === this.pendingHeartbeatRef) ||
                event === (payload === null || payload === void 0 ? void 0 : payload.type)) {
                this.pendingHeartbeatRef = null;
            }
            this.log('receive', `${payload.status || ''} ${topic} ${event} ${(ref && '(' + ref + ')') || ''}`, payload);
            this.channels
                .filter((channel) => channel.isMember(topic))
                .forEach((channel) => channel.trigger(event, payload, ref));
            this.stateChangeCallbacks.message.forEach((callback) => callback(msg));
        });
    }
    /**
     * Returns the URL of the websocket.
     */
    endPointURL() {
        return this._appendParams(this.endPoint, Object.assign({}, this.params, { vsn: _lib_constants__WEBPACK_IMPORTED_MODULE_1__.VSN }));
    }
    /**
     * Return the next message ref, accounting for overflows
     */
    makeRef() {
        let newRef = this.ref + 1;
        if (newRef === this.ref) {
            this.ref = 0;
        }
        else {
            this.ref = newRef;
        }
        return this.ref.toString();
    }
    /**
     * Sets the JWT access token used for channel subscription authorization and Realtime RLS.
     *
     * @param token A JWT string.
     */
    setAuth(token) {
        this.accessToken = token;
        this.channels.forEach((channel) => {
            token && channel.updateJoinPayload({ user_token: token });
            if (channel.joinedOnce && channel.isJoined()) {
                channel.push(_lib_constants__WEBPACK_IMPORTED_MODULE_1__.CHANNEL_EVENTS.access_token, { access_token: token });
            }
        });
    }
    /**
     * Unsubscribe from channels with the specified topic.
     */
    leaveOpenTopic(topic) {
        let dupChannel = this.channels.find((c) => c.topic === topic && (c.isJoined() || c.isJoining()));
        if (dupChannel) {
            this.log('transport', `leaving duplicate topic "${topic}"`);
            dupChannel.unsubscribe();
        }
    }
    _onConnOpen() {
        this.log('transport', `connected to ${this.endPointURL()}`);
        this._flushSendBuffer();
        this.reconnectTimer.reset();
        this.heartbeatTimer && clearInterval(this.heartbeatTimer);
        this.heartbeatTimer = setInterval(() => this._sendHeartbeat(), this.heartbeatIntervalMs);
        this.stateChangeCallbacks.open.forEach((callback) => callback());
    }
    _onConnClose(event) {
        this.log('transport', 'close', event);
        this._triggerChanError();
        this.heartbeatTimer && clearInterval(this.heartbeatTimer);
        this.reconnectTimer.scheduleTimeout();
        this.stateChangeCallbacks.close.forEach((callback) => callback(event));
    }
    _onConnError(error) {
        this.log('transport', error.message);
        this._triggerChanError();
        this.stateChangeCallbacks.error.forEach((callback) => callback(error));
    }
    _triggerChanError() {
        this.channels.forEach((channel) => channel.trigger(_lib_constants__WEBPACK_IMPORTED_MODULE_1__.CHANNEL_EVENTS.error));
    }
    _appendParams(url, params) {
        if (Object.keys(params).length === 0) {
            return url;
        }
        const prefix = url.match(/\?/) ? '&' : '?';
        const query = new URLSearchParams(params);
        return `${url}${prefix}${query}`;
    }
    _flushSendBuffer() {
        if (this.isConnected() && this.sendBuffer.length > 0) {
            this.sendBuffer.forEach((callback) => callback());
            this.sendBuffer = [];
        }
    }
    _sendHeartbeat() {
        var _a;
        if (!this.isConnected()) {
            return;
        }
        if (this.pendingHeartbeatRef) {
            this.pendingHeartbeatRef = null;
            this.log('transport', 'heartbeat timeout. Attempting to re-establish connection');
            (_a = this.conn) === null || _a === void 0 ? void 0 : _a.close(_lib_constants__WEBPACK_IMPORTED_MODULE_1__.WS_CLOSE_NORMAL, 'hearbeat timeout');
            return;
        }
        this.pendingHeartbeatRef = this.makeRef();
        this.push({
            topic: 'phoenix',
            event: 'heartbeat',
            payload: {},
            ref: this.pendingHeartbeatRef,
        });
        this.setAuth(this.accessToken);
    }
}
//# sourceMappingURL=RealtimeClient.js.map

/***/ }),

/***/ "./node_modules/@supabase/realtime-js/dist/module/RealtimeSubscription.js":
/*!********************************************************************************!*\
  !*** ./node_modules/@supabase/realtime-js/dist/module/RealtimeSubscription.js ***!
  \********************************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "default": () => (/* binding */ RealtimeSubscription)
/* harmony export */ });
/* harmony import */ var _lib_constants__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./lib/constants */ "./node_modules/@supabase/realtime-js/dist/module/lib/constants.js");
/* harmony import */ var _lib_push__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ./lib/push */ "./node_modules/@supabase/realtime-js/dist/module/lib/push.js");
/* harmony import */ var _lib_timer__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ./lib/timer */ "./node_modules/@supabase/realtime-js/dist/module/lib/timer.js");



class RealtimeSubscription {
    constructor(topic, params = {}, socket) {
        this.topic = topic;
        this.params = params;
        this.socket = socket;
        this.bindings = [];
        this.state = _lib_constants__WEBPACK_IMPORTED_MODULE_0__.CHANNEL_STATES.closed;
        this.joinedOnce = false;
        this.pushBuffer = [];
        this.timeout = this.socket.timeout;
        this.joinPush = new _lib_push__WEBPACK_IMPORTED_MODULE_1__["default"](this, _lib_constants__WEBPACK_IMPORTED_MODULE_0__.CHANNEL_EVENTS.join, this.params, this.timeout);
        this.rejoinTimer = new _lib_timer__WEBPACK_IMPORTED_MODULE_2__["default"](() => this.rejoinUntilConnected(), this.socket.reconnectAfterMs);
        this.joinPush.receive('ok', () => {
            this.state = _lib_constants__WEBPACK_IMPORTED_MODULE_0__.CHANNEL_STATES.joined;
            this.rejoinTimer.reset();
            this.pushBuffer.forEach((pushEvent) => pushEvent.send());
            this.pushBuffer = [];
        });
        this.onClose(() => {
            this.rejoinTimer.reset();
            this.socket.log('channel', `close ${this.topic} ${this.joinRef()}`);
            this.state = _lib_constants__WEBPACK_IMPORTED_MODULE_0__.CHANNEL_STATES.closed;
            this.socket.remove(this);
        });
        this.onError((reason) => {
            if (this.isLeaving() || this.isClosed()) {
                return;
            }
            this.socket.log('channel', `error ${this.topic}`, reason);
            this.state = _lib_constants__WEBPACK_IMPORTED_MODULE_0__.CHANNEL_STATES.errored;
            this.rejoinTimer.scheduleTimeout();
        });
        this.joinPush.receive('timeout', () => {
            if (!this.isJoining()) {
                return;
            }
            this.socket.log('channel', `timeout ${this.topic}`, this.joinPush.timeout);
            this.state = _lib_constants__WEBPACK_IMPORTED_MODULE_0__.CHANNEL_STATES.errored;
            this.rejoinTimer.scheduleTimeout();
        });
        this.on(_lib_constants__WEBPACK_IMPORTED_MODULE_0__.CHANNEL_EVENTS.reply, (payload, ref) => {
            this.trigger(this.replyEventName(ref), payload);
        });
    }
    rejoinUntilConnected() {
        this.rejoinTimer.scheduleTimeout();
        if (this.socket.isConnected()) {
            this.rejoin();
        }
    }
    subscribe(timeout = this.timeout) {
        if (this.joinedOnce) {
            throw `tried to subscribe multiple times. 'subscribe' can only be called a single time per channel instance`;
        }
        else {
            this.joinedOnce = true;
            this.rejoin(timeout);
            return this.joinPush;
        }
    }
    onClose(callback) {
        this.on(_lib_constants__WEBPACK_IMPORTED_MODULE_0__.CHANNEL_EVENTS.close, callback);
    }
    onError(callback) {
        this.on(_lib_constants__WEBPACK_IMPORTED_MODULE_0__.CHANNEL_EVENTS.error, (reason) => callback(reason));
    }
    on(event, callback) {
        this.bindings.push({ event, callback });
    }
    off(event) {
        this.bindings = this.bindings.filter((bind) => bind.event !== event);
    }
    canPush() {
        return this.socket.isConnected() && this.isJoined();
    }
    push(event, payload, timeout = this.timeout) {
        if (!this.joinedOnce) {
            throw `tried to push '${event}' to '${this.topic}' before joining. Use channel.subscribe() before pushing events`;
        }
        let pushEvent = new _lib_push__WEBPACK_IMPORTED_MODULE_1__["default"](this, event, payload, timeout);
        if (this.canPush()) {
            pushEvent.send();
        }
        else {
            pushEvent.startTimeout();
            this.pushBuffer.push(pushEvent);
        }
        return pushEvent;
    }
    updateJoinPayload(payload) {
        this.joinPush.updatePayload(payload);
    }
    /**
     * Leaves the channel
     *
     * Unsubscribes from server events, and instructs channel to terminate on server.
     * Triggers onClose() hooks.
     *
     * To receive leave acknowledgements, use the a `receive` hook to bind to the server ack, ie:
     * channel.unsubscribe().receive("ok", () => alert("left!") )
     */
    unsubscribe(timeout = this.timeout) {
        this.state = _lib_constants__WEBPACK_IMPORTED_MODULE_0__.CHANNEL_STATES.leaving;
        let onClose = () => {
            this.socket.log('channel', `leave ${this.topic}`);
            this.trigger(_lib_constants__WEBPACK_IMPORTED_MODULE_0__.CHANNEL_EVENTS.close, 'leave', this.joinRef());
        };
        // Destroy joinPush to avoid connection timeouts during unscription phase
        this.joinPush.destroy();
        let leavePush = new _lib_push__WEBPACK_IMPORTED_MODULE_1__["default"](this, _lib_constants__WEBPACK_IMPORTED_MODULE_0__.CHANNEL_EVENTS.leave, {}, timeout);
        leavePush.receive('ok', () => onClose()).receive('timeout', () => onClose());
        leavePush.send();
        if (!this.canPush()) {
            leavePush.trigger('ok', {});
        }
        return leavePush;
    }
    /**
     * Overridable message hook
     *
     * Receives all events for specialized message handling before dispatching to the channel callbacks.
     * Must return the payload, modified or unmodified.
     */
    onMessage(event, payload, ref) {
        return payload;
    }
    isMember(topic) {
        return this.topic === topic;
    }
    joinRef() {
        return this.joinPush.ref;
    }
    rejoin(timeout = this.timeout) {
        if (this.isLeaving()) {
            return;
        }
        this.socket.leaveOpenTopic(this.topic);
        this.state = _lib_constants__WEBPACK_IMPORTED_MODULE_0__.CHANNEL_STATES.joining;
        this.joinPush.resend(timeout);
    }
    trigger(event, payload, ref) {
        let { close, error, leave, join } = _lib_constants__WEBPACK_IMPORTED_MODULE_0__.CHANNEL_EVENTS;
        let events = [close, error, leave, join];
        if (ref && events.indexOf(event) >= 0 && ref !== this.joinRef()) {
            return;
        }
        let handledPayload = this.onMessage(event, payload, ref);
        if (payload && !handledPayload) {
            throw 'channel onMessage callbacks must return the payload, modified or unmodified';
        }
        this.bindings
            .filter((bind) => {
            // Bind all events if the user specifies a wildcard.
            if (bind.event === '*') {
                return event === (payload === null || payload === void 0 ? void 0 : payload.type);
            }
            else {
                return bind.event === event;
            }
        })
            .map((bind) => bind.callback(handledPayload, ref));
    }
    replyEventName(ref) {
        return `chan_reply_${ref}`;
    }
    isClosed() {
        return this.state === _lib_constants__WEBPACK_IMPORTED_MODULE_0__.CHANNEL_STATES.closed;
    }
    isErrored() {
        return this.state === _lib_constants__WEBPACK_IMPORTED_MODULE_0__.CHANNEL_STATES.errored;
    }
    isJoined() {
        return this.state === _lib_constants__WEBPACK_IMPORTED_MODULE_0__.CHANNEL_STATES.joined;
    }
    isJoining() {
        return this.state === _lib_constants__WEBPACK_IMPORTED_MODULE_0__.CHANNEL_STATES.joining;
    }
    isLeaving() {
        return this.state === _lib_constants__WEBPACK_IMPORTED_MODULE_0__.CHANNEL_STATES.leaving;
    }
}
//# sourceMappingURL=RealtimeSubscription.js.map

/***/ }),

/***/ "./node_modules/@supabase/realtime-js/dist/module/index.js":
/*!*****************************************************************!*\
  !*** ./node_modules/@supabase/realtime-js/dist/module/index.js ***!
  \*****************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "RealtimeClient": () => (/* reexport safe */ _RealtimeClient__WEBPACK_IMPORTED_MODULE_1__["default"]),
/* harmony export */   "RealtimeSubscription": () => (/* reexport safe */ _RealtimeSubscription__WEBPACK_IMPORTED_MODULE_2__["default"]),
/* harmony export */   "Transformers": () => (/* reexport module object */ _lib_transformers__WEBPACK_IMPORTED_MODULE_0__)
/* harmony export */ });
/* harmony import */ var _lib_transformers__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./lib/transformers */ "./node_modules/@supabase/realtime-js/dist/module/lib/transformers.js");
/* harmony import */ var _RealtimeClient__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ./RealtimeClient */ "./node_modules/@supabase/realtime-js/dist/module/RealtimeClient.js");
/* harmony import */ var _RealtimeSubscription__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ./RealtimeSubscription */ "./node_modules/@supabase/realtime-js/dist/module/RealtimeSubscription.js");




//# sourceMappingURL=index.js.map

/***/ }),

/***/ "./node_modules/@supabase/realtime-js/dist/module/lib/constants.js":
/*!*************************************************************************!*\
  !*** ./node_modules/@supabase/realtime-js/dist/module/lib/constants.js ***!
  \*************************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "CHANNEL_EVENTS": () => (/* binding */ CHANNEL_EVENTS),
/* harmony export */   "CHANNEL_STATES": () => (/* binding */ CHANNEL_STATES),
/* harmony export */   "CONNECTION_STATE": () => (/* binding */ CONNECTION_STATE),
/* harmony export */   "DEFAULT_HEADERS": () => (/* binding */ DEFAULT_HEADERS),
/* harmony export */   "DEFAULT_TIMEOUT": () => (/* binding */ DEFAULT_TIMEOUT),
/* harmony export */   "SOCKET_STATES": () => (/* binding */ SOCKET_STATES),
/* harmony export */   "TRANSPORTS": () => (/* binding */ TRANSPORTS),
/* harmony export */   "VSN": () => (/* binding */ VSN),
/* harmony export */   "WS_CLOSE_NORMAL": () => (/* binding */ WS_CLOSE_NORMAL)
/* harmony export */ });
/* harmony import */ var _version__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./version */ "./node_modules/@supabase/realtime-js/dist/module/lib/version.js");

const DEFAULT_HEADERS = { 'X-Client-Info': `realtime-js/${_version__WEBPACK_IMPORTED_MODULE_0__.version}` };
const VSN = '1.0.0';
const DEFAULT_TIMEOUT = 10000;
const WS_CLOSE_NORMAL = 1000;
var SOCKET_STATES;
(function (SOCKET_STATES) {
    SOCKET_STATES[SOCKET_STATES["connecting"] = 0] = "connecting";
    SOCKET_STATES[SOCKET_STATES["open"] = 1] = "open";
    SOCKET_STATES[SOCKET_STATES["closing"] = 2] = "closing";
    SOCKET_STATES[SOCKET_STATES["closed"] = 3] = "closed";
})(SOCKET_STATES || (SOCKET_STATES = {}));
var CHANNEL_STATES;
(function (CHANNEL_STATES) {
    CHANNEL_STATES["closed"] = "closed";
    CHANNEL_STATES["errored"] = "errored";
    CHANNEL_STATES["joined"] = "joined";
    CHANNEL_STATES["joining"] = "joining";
    CHANNEL_STATES["leaving"] = "leaving";
})(CHANNEL_STATES || (CHANNEL_STATES = {}));
var CHANNEL_EVENTS;
(function (CHANNEL_EVENTS) {
    CHANNEL_EVENTS["close"] = "phx_close";
    CHANNEL_EVENTS["error"] = "phx_error";
    CHANNEL_EVENTS["join"] = "phx_join";
    CHANNEL_EVENTS["reply"] = "phx_reply";
    CHANNEL_EVENTS["leave"] = "phx_leave";
    CHANNEL_EVENTS["access_token"] = "access_token";
})(CHANNEL_EVENTS || (CHANNEL_EVENTS = {}));
var TRANSPORTS;
(function (TRANSPORTS) {
    TRANSPORTS["websocket"] = "websocket";
})(TRANSPORTS || (TRANSPORTS = {}));
var CONNECTION_STATE;
(function (CONNECTION_STATE) {
    CONNECTION_STATE["Connecting"] = "connecting";
    CONNECTION_STATE["Open"] = "open";
    CONNECTION_STATE["Closing"] = "closing";
    CONNECTION_STATE["Closed"] = "closed";
})(CONNECTION_STATE || (CONNECTION_STATE = {}));
//# sourceMappingURL=constants.js.map

/***/ }),

/***/ "./node_modules/@supabase/realtime-js/dist/module/lib/push.js":
/*!********************************************************************!*\
  !*** ./node_modules/@supabase/realtime-js/dist/module/lib/push.js ***!
  \********************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "default": () => (/* binding */ Push)
/* harmony export */ });
/* harmony import */ var _lib_constants__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ../lib/constants */ "./node_modules/@supabase/realtime-js/dist/module/lib/constants.js");

class Push {
    /**
     * Initializes the Push
     *
     * @param channel The Channel
     * @param event The event, for example `"phx_join"`
     * @param payload The payload, for example `{user_id: 123}`
     * @param timeout The push timeout in milliseconds
     */
    constructor(channel, event, payload = {}, timeout = _lib_constants__WEBPACK_IMPORTED_MODULE_0__.DEFAULT_TIMEOUT) {
        this.channel = channel;
        this.event = event;
        this.payload = payload;
        this.timeout = timeout;
        this.sent = false;
        this.timeoutTimer = undefined;
        this.ref = '';
        this.receivedResp = null;
        this.recHooks = [];
        this.refEvent = null;
    }
    resend(timeout) {
        this.timeout = timeout;
        this._cancelRefEvent();
        this.ref = '';
        this.refEvent = null;
        this.receivedResp = null;
        this.sent = false;
        this.send();
    }
    send() {
        if (this._hasReceived('timeout')) {
            return;
        }
        this.startTimeout();
        this.sent = true;
        this.channel.socket.push({
            topic: this.channel.topic,
            event: this.event,
            payload: this.payload,
            ref: this.ref,
        });
    }
    updatePayload(payload) {
        this.payload = Object.assign(Object.assign({}, this.payload), payload);
    }
    receive(status, callback) {
        var _a;
        if (this._hasReceived(status)) {
            callback((_a = this.receivedResp) === null || _a === void 0 ? void 0 : _a.response);
        }
        this.recHooks.push({ status, callback });
        return this;
    }
    startTimeout() {
        if (this.timeoutTimer) {
            return;
        }
        this.ref = this.channel.socket.makeRef();
        this.refEvent = this.channel.replyEventName(this.ref);
        const callback = (payload) => {
            this._cancelRefEvent();
            this._cancelTimeout();
            this.receivedResp = payload;
            this._matchReceive(payload);
        };
        this.channel.on(this.refEvent, callback);
        this.timeoutTimer = setTimeout(() => {
            this.trigger('timeout', {});
        }, this.timeout);
    }
    trigger(status, response) {
        if (this.refEvent)
            this.channel.trigger(this.refEvent, { status, response });
    }
    destroy() {
        this._cancelRefEvent();
        this._cancelTimeout();
    }
    _cancelRefEvent() {
        if (!this.refEvent) {
            return;
        }
        this.channel.off(this.refEvent);
    }
    _cancelTimeout() {
        clearTimeout(this.timeoutTimer);
        this.timeoutTimer = undefined;
    }
    _matchReceive({ status, response, }) {
        this.recHooks
            .filter((h) => h.status === status)
            .forEach((h) => h.callback(response));
    }
    _hasReceived(status) {
        return this.receivedResp && this.receivedResp.status === status;
    }
}
//# sourceMappingURL=push.js.map

/***/ }),

/***/ "./node_modules/@supabase/realtime-js/dist/module/lib/serializer.js":
/*!**************************************************************************!*\
  !*** ./node_modules/@supabase/realtime-js/dist/module/lib/serializer.js ***!
  \**************************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "default": () => (/* binding */ Serializer)
/* harmony export */ });
// This file draws heavily from https://github.com/phoenixframework/phoenix/commit/cf098e9cf7a44ee6479d31d911a97d3c7430c6fe
// License: https://github.com/phoenixframework/phoenix/blob/master/LICENSE.md
class Serializer {
    constructor() {
        this.HEADER_LENGTH = 1;
    }
    decode(rawPayload, callback) {
        if (rawPayload.constructor === ArrayBuffer) {
            return callback(this._binaryDecode(rawPayload));
        }
        if (typeof rawPayload === 'string') {
            return callback(JSON.parse(rawPayload));
        }
        return callback({});
    }
    _binaryDecode(buffer) {
        const view = new DataView(buffer);
        const decoder = new TextDecoder();
        return this._decodeBroadcast(buffer, view, decoder);
    }
    _decodeBroadcast(buffer, view, decoder) {
        const topicSize = view.getUint8(1);
        const eventSize = view.getUint8(2);
        let offset = this.HEADER_LENGTH + 2;
        const topic = decoder.decode(buffer.slice(offset, offset + topicSize));
        offset = offset + topicSize;
        const event = decoder.decode(buffer.slice(offset, offset + eventSize));
        offset = offset + eventSize;
        const data = JSON.parse(decoder.decode(buffer.slice(offset, buffer.byteLength)));
        return { ref: null, topic: topic, event: event, payload: data };
    }
}
//# sourceMappingURL=serializer.js.map

/***/ }),

/***/ "./node_modules/@supabase/realtime-js/dist/module/lib/timer.js":
/*!*********************************************************************!*\
  !*** ./node_modules/@supabase/realtime-js/dist/module/lib/timer.js ***!
  \*********************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "default": () => (/* binding */ Timer)
/* harmony export */ });
/**
 * Creates a timer that accepts a `timerCalc` function to perform calculated timeout retries, such as exponential backoff.
 *
 * @example
 *    let reconnectTimer = new Timer(() => this.connect(), function(tries){
 *      return [1000, 5000, 10000][tries - 1] || 10000
 *    })
 *    reconnectTimer.scheduleTimeout() // fires after 1000
 *    reconnectTimer.scheduleTimeout() // fires after 5000
 *    reconnectTimer.reset()
 *    reconnectTimer.scheduleTimeout() // fires after 1000
 */
class Timer {
    constructor(callback, timerCalc) {
        this.callback = callback;
        this.timerCalc = timerCalc;
        this.timer = undefined;
        this.tries = 0;
        this.callback = callback;
        this.timerCalc = timerCalc;
    }
    reset() {
        this.tries = 0;
        clearTimeout(this.timer);
    }
    // Cancels any previous scheduleTimeout and schedules callback
    scheduleTimeout() {
        clearTimeout(this.timer);
        this.timer = setTimeout(() => {
            this.tries = this.tries + 1;
            this.callback();
        }, this.timerCalc(this.tries + 1));
    }
}
//# sourceMappingURL=timer.js.map

/***/ }),

/***/ "./node_modules/@supabase/realtime-js/dist/module/lib/transformers.js":
/*!****************************************************************************!*\
  !*** ./node_modules/@supabase/realtime-js/dist/module/lib/transformers.js ***!
  \****************************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "PostgresTypes": () => (/* binding */ PostgresTypes),
/* harmony export */   "convertCell": () => (/* binding */ convertCell),
/* harmony export */   "convertChangeData": () => (/* binding */ convertChangeData),
/* harmony export */   "convertColumn": () => (/* binding */ convertColumn),
/* harmony export */   "toArray": () => (/* binding */ toArray),
/* harmony export */   "toBoolean": () => (/* binding */ toBoolean),
/* harmony export */   "toJson": () => (/* binding */ toJson),
/* harmony export */   "toNumber": () => (/* binding */ toNumber),
/* harmony export */   "toTimestampString": () => (/* binding */ toTimestampString)
/* harmony export */ });
/**
 * Helpers to convert the change Payload into native JS types.
 */
// Adapted from epgsql (src/epgsql_binary.erl), this module licensed under
// 3-clause BSD found here: https://raw.githubusercontent.com/epgsql/epgsql/devel/LICENSE
var PostgresTypes;
(function (PostgresTypes) {
    PostgresTypes["abstime"] = "abstime";
    PostgresTypes["bool"] = "bool";
    PostgresTypes["date"] = "date";
    PostgresTypes["daterange"] = "daterange";
    PostgresTypes["float4"] = "float4";
    PostgresTypes["float8"] = "float8";
    PostgresTypes["int2"] = "int2";
    PostgresTypes["int4"] = "int4";
    PostgresTypes["int4range"] = "int4range";
    PostgresTypes["int8"] = "int8";
    PostgresTypes["int8range"] = "int8range";
    PostgresTypes["json"] = "json";
    PostgresTypes["jsonb"] = "jsonb";
    PostgresTypes["money"] = "money";
    PostgresTypes["numeric"] = "numeric";
    PostgresTypes["oid"] = "oid";
    PostgresTypes["reltime"] = "reltime";
    PostgresTypes["text"] = "text";
    PostgresTypes["time"] = "time";
    PostgresTypes["timestamp"] = "timestamp";
    PostgresTypes["timestamptz"] = "timestamptz";
    PostgresTypes["timetz"] = "timetz";
    PostgresTypes["tsrange"] = "tsrange";
    PostgresTypes["tstzrange"] = "tstzrange";
})(PostgresTypes || (PostgresTypes = {}));
/**
 * Takes an array of columns and an object of string values then converts each string value
 * to its mapped type.
 *
 * @param {{name: String, type: String}[]} columns
 * @param {Object} record
 * @param {Object} options The map of various options that can be applied to the mapper
 * @param {Array} options.skipTypes The array of types that should not be converted
 *
 * @example convertChangeData([{name: 'first_name', type: 'text'}, {name: 'age', type: 'int4'}], {first_name: 'Paul', age:'33'}, {})
 * //=>{ first_name: 'Paul', age: 33 }
 */
const convertChangeData = (columns, record, options = {}) => {
    var _a;
    const skipTypes = (_a = options.skipTypes) !== null && _a !== void 0 ? _a : [];
    return Object.keys(record).reduce((acc, rec_key) => {
        acc[rec_key] = convertColumn(rec_key, columns, record, skipTypes);
        return acc;
    }, {});
};
/**
 * Converts the value of an individual column.
 *
 * @param {String} columnName The column that you want to convert
 * @param {{name: String, type: String}[]} columns All of the columns
 * @param {Object} record The map of string values
 * @param {Array} skipTypes An array of types that should not be converted
 * @return {object} Useless information
 *
 * @example convertColumn('age', [{name: 'first_name', type: 'text'}, {name: 'age', type: 'int4'}], {first_name: 'Paul', age: '33'}, [])
 * //=> 33
 * @example convertColumn('age', [{name: 'first_name', type: 'text'}, {name: 'age', type: 'int4'}], {first_name: 'Paul', age: '33'}, ['int4'])
 * //=> "33"
 */
const convertColumn = (columnName, columns, record, skipTypes) => {
    const column = columns.find((x) => x.name === columnName);
    const colType = column === null || column === void 0 ? void 0 : column.type;
    const value = record[columnName];
    if (colType && !skipTypes.includes(colType)) {
        return convertCell(colType, value);
    }
    return noop(value);
};
/**
 * If the value of the cell is `null`, returns null.
 * Otherwise converts the string value to the correct type.
 * @param {String} type A postgres column type
 * @param {String} stringValue The cell value
 *
 * @example convertCell('bool', 't')
 * //=> true
 * @example convertCell('int8', '10')
 * //=> 10
 * @example convertCell('_int4', '{1,2,3,4}')
 * //=> [1,2,3,4]
 */
const convertCell = (type, value) => {
    // if data type is an array
    if (type.charAt(0) === '_') {
        const dataType = type.slice(1, type.length);
        return toArray(value, dataType);
    }
    // If not null, convert to correct type.
    switch (type) {
        case PostgresTypes.bool:
            return toBoolean(value);
        case PostgresTypes.float4:
        case PostgresTypes.float8:
        case PostgresTypes.int2:
        case PostgresTypes.int4:
        case PostgresTypes.int8:
        case PostgresTypes.numeric:
        case PostgresTypes.oid:
            return toNumber(value);
        case PostgresTypes.json:
        case PostgresTypes.jsonb:
            return toJson(value);
        case PostgresTypes.timestamp:
            return toTimestampString(value); // Format to be consistent with PostgREST
        case PostgresTypes.abstime: // To allow users to cast it based on Timezone
        case PostgresTypes.date: // To allow users to cast it based on Timezone
        case PostgresTypes.daterange:
        case PostgresTypes.int4range:
        case PostgresTypes.int8range:
        case PostgresTypes.money:
        case PostgresTypes.reltime: // To allow users to cast it based on Timezone
        case PostgresTypes.text:
        case PostgresTypes.time: // To allow users to cast it based on Timezone
        case PostgresTypes.timestamptz: // To allow users to cast it based on Timezone
        case PostgresTypes.timetz: // To allow users to cast it based on Timezone
        case PostgresTypes.tsrange:
        case PostgresTypes.tstzrange:
            return noop(value);
        default:
            // Return the value for remaining types
            return noop(value);
    }
};
const noop = (value) => {
    return value;
};
const toBoolean = (value) => {
    switch (value) {
        case 't':
            return true;
        case 'f':
            return false;
        default:
            return value;
    }
};
const toNumber = (value) => {
    if (typeof value === 'string') {
        const parsedValue = parseFloat(value);
        if (!Number.isNaN(parsedValue)) {
            return parsedValue;
        }
    }
    return value;
};
const toJson = (value) => {
    if (typeof value === 'string') {
        try {
            return JSON.parse(value);
        }
        catch (error) {
            console.log(`JSON parse error: ${error}`);
            return value;
        }
    }
    return value;
};
/**
 * Converts a Postgres Array into a native JS array
 *
 * @example toArray('{}', 'int4')
 * //=> []
 * @example toArray('{"[2021-01-01,2021-12-31)","(2021-01-01,2021-12-32]"}', 'daterange')
 * //=> ['[2021-01-01,2021-12-31)', '(2021-01-01,2021-12-32]']
 * @example toArray([1,2,3,4], 'int4')
 * //=> [1,2,3,4]
 */
const toArray = (value, type) => {
    if (typeof value !== 'string') {
        return value;
    }
    const lastIdx = value.length - 1;
    const closeBrace = value[lastIdx];
    const openBrace = value[0];
    // Confirm value is a Postgres array by checking curly brackets
    if (openBrace === '{' && closeBrace === '}') {
        let arr;
        const valTrim = value.slice(1, lastIdx);
        // TODO: find a better solution to separate Postgres array data
        try {
            arr = JSON.parse('[' + valTrim + ']');
        }
        catch (_) {
            // WARNING: splitting on comma does not cover all edge cases
            arr = valTrim ? valTrim.split(',') : [];
        }
        return arr.map((val) => convertCell(type, val));
    }
    return value;
};
/**
 * Fixes timestamp to be ISO-8601. Swaps the space between the date and time for a 'T'
 * See https://github.com/supabase/supabase/issues/18
 *
 * @example toTimestampString('2019-09-10 00:00:00')
 * //=> '2019-09-10T00:00:00'
 */
const toTimestampString = (value) => {
    if (typeof value === 'string') {
        return value.replace(' ', 'T');
    }
    return value;
};
//# sourceMappingURL=transformers.js.map

/***/ }),

/***/ "./node_modules/@supabase/realtime-js/dist/module/lib/version.js":
/*!***********************************************************************!*\
  !*** ./node_modules/@supabase/realtime-js/dist/module/lib/version.js ***!
  \***********************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "version": () => (/* binding */ version)
/* harmony export */ });
const version = '1.7.4';
//# sourceMappingURL=version.js.map

/***/ }),

/***/ "./node_modules/@supabase/storage-js/dist/module/StorageClient.js":
/*!************************************************************************!*\
  !*** ./node_modules/@supabase/storage-js/dist/module/StorageClient.js ***!
  \************************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "StorageClient": () => (/* binding */ StorageClient)
/* harmony export */ });
/* harmony import */ var _lib__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./lib */ "./node_modules/@supabase/storage-js/dist/module/lib/StorageBucketApi.js");
/* harmony import */ var _lib__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ./lib */ "./node_modules/@supabase/storage-js/dist/module/lib/StorageFileApi.js");

class StorageClient extends _lib__WEBPACK_IMPORTED_MODULE_0__.StorageBucketApi {
    constructor(url, headers = {}, fetch) {
        super(url, headers, fetch);
    }
    /**
     * Perform file operation in a bucket.
     *
     * @param id The bucket id to operate on.
     */
    from(id) {
        return new _lib__WEBPACK_IMPORTED_MODULE_1__.StorageFileApi(this.url, this.headers, id, this.fetch);
    }
}
//# sourceMappingURL=StorageClient.js.map

/***/ }),

/***/ "./node_modules/@supabase/storage-js/dist/module/lib/StorageBucketApi.js":
/*!*******************************************************************************!*\
  !*** ./node_modules/@supabase/storage-js/dist/module/lib/StorageBucketApi.js ***!
  \*******************************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "StorageBucketApi": () => (/* binding */ StorageBucketApi)
/* harmony export */ });
/* harmony import */ var _constants__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./constants */ "./node_modules/@supabase/storage-js/dist/module/lib/constants.js");
/* harmony import */ var _fetch__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ./fetch */ "./node_modules/@supabase/storage-js/dist/module/lib/fetch.js");
/* harmony import */ var _helpers__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ./helpers */ "./node_modules/@supabase/storage-js/dist/module/lib/helpers.js");
var __awaiter = (undefined && undefined.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};



class StorageBucketApi {
    constructor(url, headers = {}, fetch) {
        this.url = url;
        this.headers = Object.assign(Object.assign({}, _constants__WEBPACK_IMPORTED_MODULE_0__.DEFAULT_HEADERS), headers);
        this.fetch = (0,_helpers__WEBPACK_IMPORTED_MODULE_1__.resolveFetch)(fetch);
    }
    /**
     * Retrieves the details of all Storage buckets within an existing project.
     */
    listBuckets() {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                const data = yield (0,_fetch__WEBPACK_IMPORTED_MODULE_2__.get)(this.fetch, `${this.url}/bucket`, { headers: this.headers });
                return { data, error: null };
            }
            catch (error) {
                return { data: null, error };
            }
        });
    }
    /**
     * Retrieves the details of an existing Storage bucket.
     *
     * @param id The unique identifier of the bucket you would like to retrieve.
     */
    getBucket(id) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                const data = yield (0,_fetch__WEBPACK_IMPORTED_MODULE_2__.get)(this.fetch, `${this.url}/bucket/${id}`, { headers: this.headers });
                return { data, error: null };
            }
            catch (error) {
                return { data: null, error };
            }
        });
    }
    /**
     * Creates a new Storage bucket
     *
     * @param id A unique identifier for the bucket you are creating.
     * @returns newly created bucket id
     */
    createBucket(id, options = { public: false }) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                const data = yield (0,_fetch__WEBPACK_IMPORTED_MODULE_2__.post)(this.fetch, `${this.url}/bucket`, { id, name: id, public: options.public }, { headers: this.headers });
                return { data: data.name, error: null };
            }
            catch (error) {
                return { data: null, error };
            }
        });
    }
    /**
     * Updates a new Storage bucket
     *
     * @param id A unique identifier for the bucket you are updating.
     */
    updateBucket(id, options) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                const data = yield (0,_fetch__WEBPACK_IMPORTED_MODULE_2__.put)(this.fetch, `${this.url}/bucket/${id}`, { id, name: id, public: options.public }, { headers: this.headers });
                return { data, error: null };
            }
            catch (error) {
                return { data: null, error };
            }
        });
    }
    /**
     * Removes all objects inside a single bucket.
     *
     * @param id The unique identifier of the bucket you would like to empty.
     */
    emptyBucket(id) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                const data = yield (0,_fetch__WEBPACK_IMPORTED_MODULE_2__.post)(this.fetch, `${this.url}/bucket/${id}/empty`, {}, { headers: this.headers });
                return { data, error: null };
            }
            catch (error) {
                return { data: null, error };
            }
        });
    }
    /**
     * Deletes an existing bucket. A bucket can't be deleted with existing objects inside it.
     * You must first `empty()` the bucket.
     *
     * @param id The unique identifier of the bucket you would like to delete.
     */
    deleteBucket(id) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                const data = yield (0,_fetch__WEBPACK_IMPORTED_MODULE_2__.remove)(this.fetch, `${this.url}/bucket/${id}`, {}, { headers: this.headers });
                return { data, error: null };
            }
            catch (error) {
                return { data: null, error };
            }
        });
    }
}
//# sourceMappingURL=StorageBucketApi.js.map

/***/ }),

/***/ "./node_modules/@supabase/storage-js/dist/module/lib/StorageFileApi.js":
/*!*****************************************************************************!*\
  !*** ./node_modules/@supabase/storage-js/dist/module/lib/StorageFileApi.js ***!
  \*****************************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "StorageFileApi": () => (/* binding */ StorageFileApi)
/* harmony export */ });
/* harmony import */ var _fetch__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ./fetch */ "./node_modules/@supabase/storage-js/dist/module/lib/fetch.js");
/* harmony import */ var _helpers__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./helpers */ "./node_modules/@supabase/storage-js/dist/module/lib/helpers.js");
var __awaiter = (undefined && undefined.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};


const DEFAULT_SEARCH_OPTIONS = {
    limit: 100,
    offset: 0,
    sortBy: {
        column: 'name',
        order: 'asc',
    },
};
const DEFAULT_FILE_OPTIONS = {
    cacheControl: '3600',
    contentType: 'text/plain;charset=UTF-8',
    upsert: false,
};
class StorageFileApi {
    constructor(url, headers = {}, bucketId, fetch) {
        this.url = url;
        this.headers = headers;
        this.bucketId = bucketId;
        this.fetch = (0,_helpers__WEBPACK_IMPORTED_MODULE_0__.resolveFetch)(fetch);
    }
    /**
     * Uploads a file to an existing bucket or replaces an existing file at the specified path with a new one.
     *
     * @param method HTTP method.
     * @param path The relative file path. Should be of the format `folder/subfolder/filename.png`. The bucket must already exist before attempting to upload.
     * @param fileBody The body of the file to be stored in the bucket.
     * @param fileOptions HTTP headers.
     * `cacheControl`: string, the `Cache-Control: max-age=<seconds>` seconds value.
     * `contentType`: string, the `Content-Type` header value. Should be specified if using a `fileBody` that is neither `Blob` nor `File` nor `FormData`, otherwise will default to `text/plain;charset=UTF-8`.
     * `upsert`: boolean, whether to perform an upsert.
     */
    uploadOrUpdate(method, path, fileBody, fileOptions) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                let body;
                const options = Object.assign(Object.assign({}, DEFAULT_FILE_OPTIONS), fileOptions);
                const headers = Object.assign(Object.assign({}, this.headers), (method === 'POST' && { 'x-upsert': String(options.upsert) }));
                if (typeof Blob !== 'undefined' && fileBody instanceof Blob) {
                    body = new FormData();
                    body.append('cacheControl', options.cacheControl);
                    body.append('', fileBody);
                }
                else if (typeof FormData !== 'undefined' && fileBody instanceof FormData) {
                    body = fileBody;
                    body.append('cacheControl', options.cacheControl);
                }
                else {
                    body = fileBody;
                    headers['cache-control'] = `max-age=${options.cacheControl}`;
                    headers['content-type'] = options.contentType;
                }
                const cleanPath = this._removeEmptyFolders(path);
                const _path = this._getFinalPath(cleanPath);
                const res = yield this.fetch(`${this.url}/object/${_path}`, {
                    method,
                    body: body,
                    headers,
                });
                if (res.ok) {
                    // const data = await res.json()
                    // temporary fix till backend is updated to the latest storage-api version
                    return { data: { Key: _path }, error: null };
                }
                else {
                    const error = yield res.json();
                    return { data: null, error };
                }
            }
            catch (error) {
                return { data: null, error };
            }
        });
    }
    /**
     * Uploads a file to an existing bucket.
     *
     * @param path The relative file path. Should be of the format `folder/subfolder/filename.png`. The bucket must already exist before attempting to upload.
     * @param fileBody The body of the file to be stored in the bucket.
     * @param fileOptions HTTP headers.
     * `cacheControl`: string, the `Cache-Control: max-age=<seconds>` seconds value.
     * `contentType`: string, the `Content-Type` header value. Should be specified if using a `fileBody` that is neither `Blob` nor `File` nor `FormData`, otherwise will default to `text/plain;charset=UTF-8`.
     * `upsert`: boolean, whether to perform an upsert.
     */
    upload(path, fileBody, fileOptions) {
        return __awaiter(this, void 0, void 0, function* () {
            return this.uploadOrUpdate('POST', path, fileBody, fileOptions);
        });
    }
    /**
     * Replaces an existing file at the specified path with a new one.
     *
     * @param path The relative file path. Should be of the format `folder/subfolder/filename.png`. The bucket must already exist before attempting to upload.
     * @param fileBody The body of the file to be stored in the bucket.
     * @param fileOptions HTTP headers.
     * `cacheControl`: string, the `Cache-Control: max-age=<seconds>` seconds value.
     * `contentType`: string, the `Content-Type` header value. Should be specified if using a `fileBody` that is neither `Blob` nor `File` nor `FormData`, otherwise will default to `text/plain;charset=UTF-8`.
     * `upsert`: boolean, whether to perform an upsert.
     */
    update(path, fileBody, fileOptions) {
        return __awaiter(this, void 0, void 0, function* () {
            return this.uploadOrUpdate('PUT', path, fileBody, fileOptions);
        });
    }
    /**
     * Moves an existing file.
     *
     * @param fromPath The original file path, including the current file name. For example `folder/image.png`.
     * @param toPath The new file path, including the new file name. For example `folder/image-new.png`.
     */
    move(fromPath, toPath) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                const data = yield (0,_fetch__WEBPACK_IMPORTED_MODULE_1__.post)(this.fetch, `${this.url}/object/move`, { bucketId: this.bucketId, sourceKey: fromPath, destinationKey: toPath }, { headers: this.headers });
                return { data, error: null };
            }
            catch (error) {
                return { data: null, error };
            }
        });
    }
    /**
     * Copies an existing file.
     *
     * @param fromPath The original file path, including the current file name. For example `folder/image.png`.
     * @param toPath The new file path, including the new file name. For example `folder/image-copy.png`.
     */
    copy(fromPath, toPath) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                const data = yield (0,_fetch__WEBPACK_IMPORTED_MODULE_1__.post)(this.fetch, `${this.url}/object/copy`, { bucketId: this.bucketId, sourceKey: fromPath, destinationKey: toPath }, { headers: this.headers });
                return { data, error: null };
            }
            catch (error) {
                return { data: null, error };
            }
        });
    }
    /**
     * Create signed URL to download file without requiring permissions. This URL can be valid for a set number of seconds.
     *
     * @param path The file path to be downloaded, including the current file name. For example `folder/image.png`.
     * @param expiresIn The number of seconds until the signed URL expires. For example, `60` for a URL which is valid for one minute.
     */
    createSignedUrl(path, expiresIn) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                const _path = this._getFinalPath(path);
                let data = yield (0,_fetch__WEBPACK_IMPORTED_MODULE_1__.post)(this.fetch, `${this.url}/object/sign/${_path}`, { expiresIn }, { headers: this.headers });
                const signedURL = `${this.url}${data.signedURL}`;
                data = { signedURL };
                return { data, error: null, signedURL };
            }
            catch (error) {
                return { data: null, error, signedURL: null };
            }
        });
    }
    /**
     * Create signed URLs to download files without requiring permissions. These URLs can be valid for a set number of seconds.
     *
     * @param paths The file paths to be downloaded, including the current file names. For example `['folder/image.png', 'folder2/image2.png']`.
     * @param expiresIn The number of seconds until the signed URLs expire. For example, `60` for URLs which are valid for one minute.
     */
    createSignedUrls(paths, expiresIn) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                const data = yield (0,_fetch__WEBPACK_IMPORTED_MODULE_1__.post)(this.fetch, `${this.url}/object/sign/${this.bucketId}`, { expiresIn, paths }, { headers: this.headers });
                return {
                    data: data.map((datum) => (Object.assign(Object.assign({}, datum), { signedURL: datum.signedURL ? `${this.url}${datum.signedURL}` : null }))),
                    error: null,
                };
            }
            catch (error) {
                return { data: null, error };
            }
        });
    }
    /**
     * Downloads a file.
     *
     * @param path The file path to be downloaded, including the path and file name. For example `folder/image.png`.
     */
    download(path) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                const _path = this._getFinalPath(path);
                const res = yield (0,_fetch__WEBPACK_IMPORTED_MODULE_1__.get)(this.fetch, `${this.url}/object/${_path}`, {
                    headers: this.headers,
                    noResolveJson: true,
                });
                const data = yield res.blob();
                return { data, error: null };
            }
            catch (error) {
                return { data: null, error };
            }
        });
    }
    /**
     * Retrieve URLs for assets in public buckets
     *
     * @param path The file path to be downloaded, including the path and file name. For example `folder/image.png`.
     */
    getPublicUrl(path) {
        try {
            const _path = this._getFinalPath(path);
            const publicURL = `${this.url}/object/public/${_path}`;
            const data = { publicURL };
            return { data, error: null, publicURL };
        }
        catch (error) {
            return { data: null, error, publicURL: null };
        }
    }
    /**
     * Deletes files within the same bucket
     *
     * @param paths An array of files to be deleted, including the path and file name. For example [`folder/image.png`].
     */
    remove(paths) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                const data = yield (0,_fetch__WEBPACK_IMPORTED_MODULE_1__.remove)(this.fetch, `${this.url}/object/${this.bucketId}`, { prefixes: paths }, { headers: this.headers });
                return { data, error: null };
            }
            catch (error) {
                return { data: null, error };
            }
        });
    }
    /**
     * Get file metadata
     * @param id the file id to retrieve metadata
     */
    // async getMetadata(id: string): Promise<{ data: Metadata | null; error: Error | null }> {
    //   try {
    //     const data = await get(`${this.url}/metadata/${id}`, { headers: this.headers })
    //     return { data, error: null }
    //   } catch (error) {
    //     return { data: null, error }
    //   }
    // }
    /**
     * Update file metadata
     * @param id the file id to update metadata
     * @param meta the new file metadata
     */
    // async updateMetadata(
    //   id: string,
    //   meta: Metadata
    // ): Promise<{ data: Metadata | null; error: Error | null }> {
    //   try {
    //     const data = await post(`${this.url}/metadata/${id}`, { ...meta }, { headers: this.headers })
    //     return { data, error: null }
    //   } catch (error) {
    //     return { data: null, error }
    //   }
    // }
    /**
     * Lists all the files within a bucket.
     * @param path The folder path.
     * @param options Search options, including `limit`, `offset`, `sortBy`, and `search`.
     * @param parameters Fetch parameters, currently only supports `signal`, which is an AbortController's signal
     */
    list(path, options, parameters) {
        return __awaiter(this, void 0, void 0, function* () {
            try {
                const body = Object.assign(Object.assign(Object.assign({}, DEFAULT_SEARCH_OPTIONS), options), { prefix: path || '' });
                const data = yield (0,_fetch__WEBPACK_IMPORTED_MODULE_1__.post)(this.fetch, `${this.url}/object/list/${this.bucketId}`, body, { headers: this.headers }, parameters);
                return { data, error: null };
            }
            catch (error) {
                return { data: null, error };
            }
        });
    }
    _getFinalPath(path) {
        return `${this.bucketId}/${path}`;
    }
    _removeEmptyFolders(path) {
        return path.replace(/^\/|\/$/g, '').replace(/\/+/g, '/');
    }
}
//# sourceMappingURL=StorageFileApi.js.map

/***/ }),

/***/ "./node_modules/@supabase/storage-js/dist/module/lib/constants.js":
/*!************************************************************************!*\
  !*** ./node_modules/@supabase/storage-js/dist/module/lib/constants.js ***!
  \************************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "DEFAULT_HEADERS": () => (/* binding */ DEFAULT_HEADERS)
/* harmony export */ });
/* harmony import */ var _version__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./version */ "./node_modules/@supabase/storage-js/dist/module/lib/version.js");

const DEFAULT_HEADERS = { 'X-Client-Info': `storage-js/${_version__WEBPACK_IMPORTED_MODULE_0__.version}` };
//# sourceMappingURL=constants.js.map

/***/ }),

/***/ "./node_modules/@supabase/storage-js/dist/module/lib/fetch.js":
/*!********************************************************************!*\
  !*** ./node_modules/@supabase/storage-js/dist/module/lib/fetch.js ***!
  \********************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "get": () => (/* binding */ get),
/* harmony export */   "post": () => (/* binding */ post),
/* harmony export */   "put": () => (/* binding */ put),
/* harmony export */   "remove": () => (/* binding */ remove)
/* harmony export */ });
var __awaiter = (undefined && undefined.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
const _getErrorMessage = (err) => err.msg || err.message || err.error_description || err.error || JSON.stringify(err);
const handleError = (error, reject) => {
    if (typeof error.json !== 'function') {
        return reject(error);
    }
    error.json().then((err) => {
        return reject({
            message: _getErrorMessage(err),
            status: (error === null || error === void 0 ? void 0 : error.status) || 500,
        });
    });
};
const _getRequestParams = (method, options, parameters, body) => {
    const params = { method, headers: (options === null || options === void 0 ? void 0 : options.headers) || {} };
    if (method === 'GET') {
        return params;
    }
    params.headers = Object.assign({ 'Content-Type': 'application/json' }, options === null || options === void 0 ? void 0 : options.headers);
    params.body = JSON.stringify(body);
    return Object.assign(Object.assign({}, params), parameters);
};
function _handleRequest(fetcher, method, url, options, parameters, body) {
    return __awaiter(this, void 0, void 0, function* () {
        return new Promise((resolve, reject) => {
            fetcher(url, _getRequestParams(method, options, parameters, body))
                .then((result) => {
                if (!result.ok)
                    throw result;
                if (options === null || options === void 0 ? void 0 : options.noResolveJson)
                    return resolve(result);
                return result.json();
            })
                .then((data) => resolve(data))
                .catch((error) => handleError(error, reject));
        });
    });
}
function get(fetcher, url, options, parameters) {
    return __awaiter(this, void 0, void 0, function* () {
        return _handleRequest(fetcher, 'GET', url, options, parameters);
    });
}
function post(fetcher, url, body, options, parameters) {
    return __awaiter(this, void 0, void 0, function* () {
        return _handleRequest(fetcher, 'POST', url, options, parameters, body);
    });
}
function put(fetcher, url, body, options, parameters) {
    return __awaiter(this, void 0, void 0, function* () {
        return _handleRequest(fetcher, 'PUT', url, options, parameters, body);
    });
}
function remove(fetcher, url, body, options, parameters) {
    return __awaiter(this, void 0, void 0, function* () {
        return _handleRequest(fetcher, 'DELETE', url, options, parameters, body);
    });
}
//# sourceMappingURL=fetch.js.map

/***/ }),

/***/ "./node_modules/@supabase/storage-js/dist/module/lib/helpers.js":
/*!**********************************************************************!*\
  !*** ./node_modules/@supabase/storage-js/dist/module/lib/helpers.js ***!
  \**********************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "resolveFetch": () => (/* binding */ resolveFetch)
/* harmony export */ });
var __awaiter = (undefined && undefined.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
const resolveFetch = (customFetch) => {
    let _fetch;
    if (customFetch) {
        _fetch = customFetch;
    }
    else if (typeof fetch === 'undefined') {
        _fetch = (...args) => __awaiter(void 0, void 0, void 0, function* () { return yield (yield __webpack_require__.e(/*! import() */ "vendors-node_modules_cross-fetch_dist_browser-ponyfill_js").then(__webpack_require__.t.bind(__webpack_require__, /*! cross-fetch */ "./node_modules/cross-fetch/dist/browser-ponyfill.js", 23))).fetch(...args); });
    }
    else {
        _fetch = fetch;
    }
    return (...args) => _fetch(...args);
};
//# sourceMappingURL=helpers.js.map

/***/ }),

/***/ "./node_modules/@supabase/storage-js/dist/module/lib/version.js":
/*!**********************************************************************!*\
  !*** ./node_modules/@supabase/storage-js/dist/module/lib/version.js ***!
  \**********************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "version": () => (/* binding */ version)
/* harmony export */ });
// generated by genversion
const version = '1.7.3';
//# sourceMappingURL=version.js.map

/***/ }),

/***/ "./node_modules/@supabase/supabase-js/dist/module/SupabaseClient.js":
/*!**************************************************************************!*\
  !*** ./node_modules/@supabase/supabase-js/dist/module/SupabaseClient.js ***!
  \**************************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "default": () => (/* binding */ SupabaseClient)
/* harmony export */ });
/* harmony import */ var _lib_constants__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ./lib/constants */ "./node_modules/@supabase/supabase-js/dist/module/lib/constants.js");
/* harmony import */ var _lib_helpers__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! ./lib/helpers */ "./node_modules/@supabase/supabase-js/dist/module/lib/helpers.js");
/* harmony import */ var _lib_SupabaseAuthClient__WEBPACK_IMPORTED_MODULE_7__ = __webpack_require__(/*! ./lib/SupabaseAuthClient */ "./node_modules/@supabase/supabase-js/dist/module/lib/SupabaseAuthClient.js");
/* harmony import */ var _lib_SupabaseQueryBuilder__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(/*! ./lib/SupabaseQueryBuilder */ "./node_modules/@supabase/supabase-js/dist/module/lib/SupabaseQueryBuilder.js");
/* harmony import */ var _supabase_storage_js__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! @supabase/storage-js */ "./node_modules/@supabase/storage-js/dist/module/StorageClient.js");
/* harmony import */ var _supabase_functions_js__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! @supabase/functions-js */ "./node_modules/@supabase/functions-js/dist/module/index.js");
/* harmony import */ var _supabase_postgrest_js__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @supabase/postgrest-js */ "./node_modules/@supabase/postgrest-js/dist/module/index.js");
/* harmony import */ var _supabase_realtime_js__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! @supabase/realtime-js */ "./node_modules/@supabase/realtime-js/dist/module/index.js");
var __awaiter = (undefined && undefined.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};








const DEFAULT_OPTIONS = {
    schema: 'public',
    autoRefreshToken: true,
    persistSession: true,
    detectSessionInUrl: true,
    multiTab: true,
    headers: _lib_constants__WEBPACK_IMPORTED_MODULE_2__.DEFAULT_HEADERS,
};
/**
 * Supabase Client.
 *
 * An isomorphic Javascript client for interacting with Postgres.
 */
class SupabaseClient {
    /**
     * Create a new client for use in the browser.
     * @param supabaseUrl The unique Supabase URL which is supplied when you create a new project in your project dashboard.
     * @param supabaseKey The unique Supabase Key which is supplied when you create a new project in your project dashboard.
     * @param options.schema You can switch in between schemas. The schema needs to be on the list of exposed schemas inside Supabase.
     * @param options.autoRefreshToken Set to "true" if you want to automatically refresh the token before expiring.
     * @param options.persistSession Set to "true" if you want to automatically save the user session into local storage.
     * @param options.detectSessionInUrl Set to "true" if you want to automatically detects OAuth grants in the URL and signs in the user.
     * @param options.headers Any additional headers to send with each network request.
     * @param options.realtime Options passed along to realtime-js constructor.
     * @param options.multiTab Set to "false" if you want to disable multi-tab/window events.
     * @param options.fetch A custom fetch implementation.
     */
    constructor(supabaseUrl, supabaseKey, options) {
        this.supabaseUrl = supabaseUrl;
        this.supabaseKey = supabaseKey;
        if (!supabaseUrl)
            throw new Error('supabaseUrl is required.');
        if (!supabaseKey)
            throw new Error('supabaseKey is required.');
        const _supabaseUrl = (0,_lib_helpers__WEBPACK_IMPORTED_MODULE_3__.stripTrailingSlash)(supabaseUrl);
        const settings = Object.assign(Object.assign({}, DEFAULT_OPTIONS), options);
        this.restUrl = `${_supabaseUrl}/rest/v1`;
        this.realtimeUrl = `${_supabaseUrl}/realtime/v1`.replace('http', 'ws');
        this.authUrl = `${_supabaseUrl}/auth/v1`;
        this.storageUrl = `${_supabaseUrl}/storage/v1`;
        const isPlatform = _supabaseUrl.match(/(supabase\.co)|(supabase\.in)/);
        if (isPlatform) {
            const urlParts = _supabaseUrl.split('.');
            this.functionsUrl = `${urlParts[0]}.functions.${urlParts[1]}.${urlParts[2]}`;
        }
        else {
            this.functionsUrl = `${_supabaseUrl}/functions/v1`;
        }
        this.schema = settings.schema;
        this.multiTab = settings.multiTab;
        this.fetch = settings.fetch;
        this.headers = Object.assign(Object.assign({}, _lib_constants__WEBPACK_IMPORTED_MODULE_2__.DEFAULT_HEADERS), options === null || options === void 0 ? void 0 : options.headers);
        this.shouldThrowOnError = settings.shouldThrowOnError || false;
        this.auth = this._initSupabaseAuthClient(settings);
        this.realtime = this._initRealtimeClient(Object.assign({ headers: this.headers }, settings.realtime));
        this._listenForAuthEvents();
        this._listenForMultiTabEvents();
        // In the future we might allow the user to pass in a logger to receive these events.
        // this.realtime.onOpen(() => console.log('OPEN'))
        // this.realtime.onClose(() => console.log('CLOSED'))
        // this.realtime.onError((e: Error) => console.log('Socket error', e))
    }
    /**
     * Supabase Functions allows you to deploy and invoke edge functions.
     */
    get functions() {
        return new _supabase_functions_js__WEBPACK_IMPORTED_MODULE_4__.FunctionsClient(this.functionsUrl, {
            headers: this._getAuthHeaders(),
            customFetch: this.fetch,
        });
    }
    /**
     * Supabase Storage allows you to manage user-generated content, such as photos or videos.
     */
    get storage() {
        return new _supabase_storage_js__WEBPACK_IMPORTED_MODULE_5__.StorageClient(this.storageUrl, this._getAuthHeaders(), this.fetch);
    }
    /**
     * Perform a table operation.
     *
     * @param table The table name to operate on.
     */
    from(table) {
        const url = `${this.restUrl}/${table}`;
        return new _lib_SupabaseQueryBuilder__WEBPACK_IMPORTED_MODULE_6__.SupabaseQueryBuilder(url, {
            headers: this._getAuthHeaders(),
            schema: this.schema,
            realtime: this.realtime,
            table,
            fetch: this.fetch,
            shouldThrowOnError: this.shouldThrowOnError,
        });
    }
    /**
     * Perform a function call.
     *
     * @param fn  The function name to call.
     * @param params  The parameters to pass to the function call.
     * @param head   When set to true, no data will be returned.
     * @param count  Count algorithm to use to count rows in a table.
     *
     */
    rpc(fn, params, { head = false, count = null, } = {}) {
        const rest = this._initPostgRESTClient();
        return rest.rpc(fn, params, { head, count });
    }
    /**
     * Closes and removes all subscriptions and returns a list of removed
     * subscriptions and their errors.
     */
    removeAllSubscriptions() {
        return __awaiter(this, void 0, void 0, function* () {
            const allSubs = this.getSubscriptions().slice();
            const allSubPromises = allSubs.map((sub) => this.removeSubscription(sub));
            const allRemovedSubs = yield Promise.all(allSubPromises);
            return allRemovedSubs.map(({ error }, i) => {
                return {
                    data: { subscription: allSubs[i] },
                    error,
                };
            });
        });
    }
    /**
     * Closes and removes a subscription and returns the number of open subscriptions.
     *
     * @param subscription The subscription you want to close and remove.
     */
    removeSubscription(subscription) {
        return __awaiter(this, void 0, void 0, function* () {
            const { error } = yield this._closeSubscription(subscription);
            const allSubs = this.getSubscriptions();
            const openSubCount = allSubs.filter((chan) => chan.isJoined()).length;
            if (allSubs.length === 0)
                yield this.realtime.disconnect();
            return { data: { openSubscriptions: openSubCount }, error };
        });
    }
    _closeSubscription(subscription) {
        return __awaiter(this, void 0, void 0, function* () {
            let error = null;
            if (!subscription.isClosed()) {
                const { error: unsubError } = yield this._unsubscribeSubscription(subscription);
                error = unsubError;
            }
            this.realtime.remove(subscription);
            return { error };
        });
    }
    _unsubscribeSubscription(subscription) {
        return new Promise((resolve) => {
            subscription
                .unsubscribe()
                .receive('ok', () => resolve({ error: null }))
                .receive('error', (error) => resolve({ error }))
                .receive('timeout', () => resolve({ error: new Error('timed out') }));
        });
    }
    /**
     * Returns an array of all your subscriptions.
     */
    getSubscriptions() {
        return this.realtime.channels;
    }
    _initSupabaseAuthClient({ autoRefreshToken, persistSession, detectSessionInUrl, localStorage, headers, fetch, cookieOptions, multiTab, }) {
        const authHeaders = {
            Authorization: `Bearer ${this.supabaseKey}`,
            apikey: `${this.supabaseKey}`,
        };
        return new _lib_SupabaseAuthClient__WEBPACK_IMPORTED_MODULE_7__.SupabaseAuthClient({
            url: this.authUrl,
            headers: Object.assign(Object.assign({}, headers), authHeaders),
            autoRefreshToken,
            persistSession,
            detectSessionInUrl,
            localStorage,
            fetch,
            cookieOptions,
            multiTab,
        });
    }
    _initRealtimeClient(options) {
        return new _supabase_realtime_js__WEBPACK_IMPORTED_MODULE_1__.RealtimeClient(this.realtimeUrl, Object.assign(Object.assign({}, options), { params: Object.assign(Object.assign({}, options === null || options === void 0 ? void 0 : options.params), { apikey: this.supabaseKey }) }));
    }
    _initPostgRESTClient() {
        return new _supabase_postgrest_js__WEBPACK_IMPORTED_MODULE_0__.PostgrestClient(this.restUrl, {
            headers: this._getAuthHeaders(),
            schema: this.schema,
            fetch: this.fetch,
            throwOnError: this.shouldThrowOnError,
        });
    }
    _getAuthHeaders() {
        var _a, _b;
        const headers = Object.assign({}, this.headers);
        const authBearer = (_b = (_a = this.auth.session()) === null || _a === void 0 ? void 0 : _a.access_token) !== null && _b !== void 0 ? _b : this.supabaseKey;
        headers['apikey'] = this.supabaseKey;
        headers['Authorization'] = headers['Authorization'] || `Bearer ${authBearer}`;
        return headers;
    }
    _listenForMultiTabEvents() {
        if (!this.multiTab || !(0,_lib_helpers__WEBPACK_IMPORTED_MODULE_3__.isBrowser)() || !(window === null || window === void 0 ? void 0 : window.addEventListener)) {
            return null;
        }
        try {
            return window === null || window === void 0 ? void 0 : window.addEventListener('storage', (e) => {
                var _a, _b, _c;
                if (e.key === _lib_constants__WEBPACK_IMPORTED_MODULE_2__.STORAGE_KEY) {
                    const newSession = JSON.parse(String(e.newValue));
                    const accessToken = (_b = (_a = newSession === null || newSession === void 0 ? void 0 : newSession.currentSession) === null || _a === void 0 ? void 0 : _a.access_token) !== null && _b !== void 0 ? _b : undefined;
                    const previousAccessToken = (_c = this.auth.session()) === null || _c === void 0 ? void 0 : _c.access_token;
                    if (!accessToken) {
                        this._handleTokenChanged('SIGNED_OUT', accessToken, 'STORAGE');
                    }
                    else if (!previousAccessToken && accessToken) {
                        this._handleTokenChanged('SIGNED_IN', accessToken, 'STORAGE');
                    }
                    else if (previousAccessToken !== accessToken) {
                        this._handleTokenChanged('TOKEN_REFRESHED', accessToken, 'STORAGE');
                    }
                }
            });
        }
        catch (error) {
            console.error('_listenForMultiTabEvents', error);
            return null;
        }
    }
    _listenForAuthEvents() {
        let { data } = this.auth.onAuthStateChange((event, session) => {
            this._handleTokenChanged(event, session === null || session === void 0 ? void 0 : session.access_token, 'CLIENT');
        });
        return data;
    }
    _handleTokenChanged(event, token, source) {
        if ((event === 'TOKEN_REFRESHED' || event === 'SIGNED_IN') &&
            this.changedAccessToken !== token) {
            // Token has changed
            this.realtime.setAuth(token);
            // Ideally we should call this.auth.recoverSession() - need to make public
            // to trigger a "SIGNED_IN" event on this client.
            if (source == 'STORAGE')
                this.auth.setAuth(token);
            this.changedAccessToken = token;
        }
        else if (event === 'SIGNED_OUT' || event === 'USER_DELETED') {
            // Token is removed
            this.realtime.setAuth(this.supabaseKey);
            if (source == 'STORAGE')
                this.auth.signOut();
        }
    }
}
//# sourceMappingURL=SupabaseClient.js.map

/***/ }),

/***/ "./node_modules/@supabase/supabase-js/dist/module/index.js":
/*!*****************************************************************!*\
  !*** ./node_modules/@supabase/supabase-js/dist/module/index.js ***!
  \*****************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "GoTrueApi": () => (/* reexport safe */ _supabase_gotrue_js__WEBPACK_IMPORTED_MODULE_0__.GoTrueApi),
/* harmony export */   "GoTrueClient": () => (/* reexport safe */ _supabase_gotrue_js__WEBPACK_IMPORTED_MODULE_0__.GoTrueClient),
/* harmony export */   "RealtimeClient": () => (/* reexport safe */ _supabase_realtime_js__WEBPACK_IMPORTED_MODULE_1__.RealtimeClient),
/* harmony export */   "RealtimeSubscription": () => (/* reexport safe */ _supabase_realtime_js__WEBPACK_IMPORTED_MODULE_1__.RealtimeSubscription),
/* harmony export */   "SupabaseClient": () => (/* reexport safe */ _SupabaseClient__WEBPACK_IMPORTED_MODULE_2__["default"]),
/* harmony export */   "Transformers": () => (/* reexport safe */ _supabase_realtime_js__WEBPACK_IMPORTED_MODULE_1__.Transformers),
/* harmony export */   "createClient": () => (/* binding */ createClient)
/* harmony export */ });
/* harmony import */ var _SupabaseClient__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ./SupabaseClient */ "./node_modules/@supabase/supabase-js/dist/module/SupabaseClient.js");
/* harmony import */ var _supabase_gotrue_js__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @supabase/gotrue-js */ "./node_modules/@supabase/gotrue-js/dist/module/index.js");
/* harmony import */ var _supabase_realtime_js__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! @supabase/realtime-js */ "./node_modules/@supabase/realtime-js/dist/module/index.js");



/**
 * Creates a new Supabase Client.
 */
const createClient = (supabaseUrl, supabaseKey, options) => {
    return new _SupabaseClient__WEBPACK_IMPORTED_MODULE_2__["default"](supabaseUrl, supabaseKey, options);
};

//# sourceMappingURL=index.js.map

/***/ }),

/***/ "./node_modules/@supabase/supabase-js/dist/module/lib/SupabaseAuthClient.js":
/*!**********************************************************************************!*\
  !*** ./node_modules/@supabase/supabase-js/dist/module/lib/SupabaseAuthClient.js ***!
  \**********************************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "SupabaseAuthClient": () => (/* binding */ SupabaseAuthClient)
/* harmony export */ });
/* harmony import */ var _supabase_gotrue_js__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @supabase/gotrue-js */ "./node_modules/@supabase/gotrue-js/dist/module/index.js");

class SupabaseAuthClient extends _supabase_gotrue_js__WEBPACK_IMPORTED_MODULE_0__.GoTrueClient {
    constructor(options) {
        super(options);
    }
}
//# sourceMappingURL=SupabaseAuthClient.js.map

/***/ }),

/***/ "./node_modules/@supabase/supabase-js/dist/module/lib/SupabaseQueryBuilder.js":
/*!************************************************************************************!*\
  !*** ./node_modules/@supabase/supabase-js/dist/module/lib/SupabaseQueryBuilder.js ***!
  \************************************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "SupabaseQueryBuilder": () => (/* binding */ SupabaseQueryBuilder)
/* harmony export */ });
/* harmony import */ var _supabase_postgrest_js__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @supabase/postgrest-js */ "./node_modules/@supabase/postgrest-js/dist/module/index.js");
/* harmony import */ var _SupabaseRealtimeClient__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ./SupabaseRealtimeClient */ "./node_modules/@supabase/supabase-js/dist/module/lib/SupabaseRealtimeClient.js");


class SupabaseQueryBuilder extends _supabase_postgrest_js__WEBPACK_IMPORTED_MODULE_0__.PostgrestQueryBuilder {
    constructor(url, { headers = {}, schema, realtime, table, fetch, shouldThrowOnError, }) {
        super(url, { headers, schema, fetch, shouldThrowOnError });
        this._subscription = null;
        this._realtime = realtime;
        this._headers = headers;
        this._schema = schema;
        this._table = table;
    }
    /**
     * Subscribe to realtime changes in your database.
     * @param event The database event which you would like to receive updates for, or you can use the special wildcard `*` to listen to all changes.
     * @param callback A callback that will handle the payload that is sent whenever your database changes.
     */
    on(event, callback) {
        if (!this._realtime.isConnected()) {
            this._realtime.connect();
        }
        if (!this._subscription) {
            this._subscription = new _SupabaseRealtimeClient__WEBPACK_IMPORTED_MODULE_1__.SupabaseRealtimeClient(this._realtime, this._headers, this._schema, this._table);
        }
        return this._subscription.on(event, callback);
    }
}
//# sourceMappingURL=SupabaseQueryBuilder.js.map

/***/ }),

/***/ "./node_modules/@supabase/supabase-js/dist/module/lib/SupabaseRealtimeClient.js":
/*!**************************************************************************************!*\
  !*** ./node_modules/@supabase/supabase-js/dist/module/lib/SupabaseRealtimeClient.js ***!
  \**************************************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "SupabaseRealtimeClient": () => (/* binding */ SupabaseRealtimeClient)
/* harmony export */ });
/* harmony import */ var _supabase_realtime_js__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! @supabase/realtime-js */ "./node_modules/@supabase/realtime-js/dist/module/index.js");

class SupabaseRealtimeClient {
    constructor(socket, headers, schema, tableName) {
        const chanParams = {};
        const topic = tableName === '*' ? `realtime:${schema}` : `realtime:${schema}:${tableName}`;
        const userToken = headers['Authorization'].split(' ')[1];
        if (userToken) {
            chanParams['user_token'] = userToken;
        }
        this.subscription = socket.channel(topic, chanParams);
    }
    getPayloadRecords(payload) {
        const records = {
            new: {},
            old: {},
        };
        if (payload.type === 'INSERT' || payload.type === 'UPDATE') {
            records.new = _supabase_realtime_js__WEBPACK_IMPORTED_MODULE_0__.Transformers.convertChangeData(payload.columns, payload.record);
        }
        if (payload.type === 'UPDATE' || payload.type === 'DELETE') {
            records.old = _supabase_realtime_js__WEBPACK_IMPORTED_MODULE_0__.Transformers.convertChangeData(payload.columns, payload.old_record);
        }
        return records;
    }
    /**
     * The event you want to listen to.
     *
     * @param event The event
     * @param callback A callback function that is called whenever the event occurs.
     */
    on(event, callback) {
        this.subscription.on(event, (payload) => {
            let enrichedPayload = {
                schema: payload.schema,
                table: payload.table,
                commit_timestamp: payload.commit_timestamp,
                eventType: payload.type,
                new: {},
                old: {},
                errors: payload.errors,
            };
            enrichedPayload = Object.assign(Object.assign({}, enrichedPayload), this.getPayloadRecords(payload));
            callback(enrichedPayload);
        });
        return this;
    }
    /**
     * Enables the subscription.
     */
    subscribe(callback = () => { }) {
        this.subscription.onError((e) => callback('SUBSCRIPTION_ERROR', e));
        this.subscription.onClose(() => callback('CLOSED'));
        this.subscription
            .subscribe()
            .receive('ok', () => callback('SUBSCRIBED'))
            .receive('error', (e) => callback('SUBSCRIPTION_ERROR', e))
            .receive('timeout', () => callback('RETRYING_AFTER_TIMEOUT'));
        return this.subscription;
    }
}
//# sourceMappingURL=SupabaseRealtimeClient.js.map

/***/ }),

/***/ "./node_modules/@supabase/supabase-js/dist/module/lib/constants.js":
/*!*************************************************************************!*\
  !*** ./node_modules/@supabase/supabase-js/dist/module/lib/constants.js ***!
  \*************************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "DEFAULT_HEADERS": () => (/* binding */ DEFAULT_HEADERS),
/* harmony export */   "STORAGE_KEY": () => (/* binding */ STORAGE_KEY)
/* harmony export */ });
/* harmony import */ var _version__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ./version */ "./node_modules/@supabase/supabase-js/dist/module/lib/version.js");
// constants.ts

const DEFAULT_HEADERS = { 'X-Client-Info': `supabase-js/${_version__WEBPACK_IMPORTED_MODULE_0__.version}` };
const STORAGE_KEY = 'supabase.auth.token';
//# sourceMappingURL=constants.js.map

/***/ }),

/***/ "./node_modules/@supabase/supabase-js/dist/module/lib/helpers.js":
/*!***********************************************************************!*\
  !*** ./node_modules/@supabase/supabase-js/dist/module/lib/helpers.js ***!
  \***********************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "isBrowser": () => (/* binding */ isBrowser),
/* harmony export */   "stripTrailingSlash": () => (/* binding */ stripTrailingSlash),
/* harmony export */   "uuid": () => (/* binding */ uuid)
/* harmony export */ });
// helpers.ts
function uuid() {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function (c) {
        var r = (Math.random() * 16) | 0, v = c == 'x' ? r : (r & 0x3) | 0x8;
        return v.toString(16);
    });
}
function stripTrailingSlash(url) {
    return url.replace(/\/$/, '');
}
const isBrowser = () => typeof window !== 'undefined';
//# sourceMappingURL=helpers.js.map

/***/ }),

/***/ "./node_modules/@supabase/supabase-js/dist/module/lib/version.js":
/*!***********************************************************************!*\
  !*** ./node_modules/@supabase/supabase-js/dist/module/lib/version.js ***!
  \***********************************************************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "version": () => (/* binding */ version)
/* harmony export */ });
const version = '1.35.6';
//# sourceMappingURL=version.js.map

/***/ }),

/***/ "./node_modules/cross-fetch/dist/browser-ponyfill.js":
/*!***********************************************************!*\
  !*** ./node_modules/cross-fetch/dist/browser-ponyfill.js ***!
  \***********************************************************/
/***/ (function(module, exports) {

var global = typeof self !== 'undefined' ? self : this;
var __self__ = (function () {
function F() {
this.fetch = false;
this.DOMException = global.DOMException
}
F.prototype = global;
return new F();
})();
(function(self) {

var irrelevant = (function (exports) {

  var support = {
    searchParams: 'URLSearchParams' in self,
    iterable: 'Symbol' in self && 'iterator' in Symbol,
    blob:
      'FileReader' in self &&
      'Blob' in self &&
      (function() {
        try {
          new Blob();
          return true
        } catch (e) {
          return false
        }
      })(),
    formData: 'FormData' in self,
    arrayBuffer: 'ArrayBuffer' in self
  };

  function isDataView(obj) {
    return obj && DataView.prototype.isPrototypeOf(obj)
  }

  if (support.arrayBuffer) {
    var viewClasses = [
      '[object Int8Array]',
      '[object Uint8Array]',
      '[object Uint8ClampedArray]',
      '[object Int16Array]',
      '[object Uint16Array]',
      '[object Int32Array]',
      '[object Uint32Array]',
      '[object Float32Array]',
      '[object Float64Array]'
    ];

    var isArrayBufferView =
      ArrayBuffer.isView ||
      function(obj) {
        return obj && viewClasses.indexOf(Object.prototype.toString.call(obj)) > -1
      };
  }

  function normalizeName(name) {
    if (typeof name !== 'string') {
      name = String(name);
    }
    if (/[^a-z0-9\-#$%&'*+.^_`|~]/i.test(name)) {
      throw new TypeError('Invalid character in header field name')
    }
    return name.toLowerCase()
  }

  function normalizeValue(value) {
    if (typeof value !== 'string') {
      value = String(value);
    }
    return value
  }

  // Build a destructive iterator for the value list
  function iteratorFor(items) {
    var iterator = {
      next: function() {
        var value = items.shift();
        return {done: value === undefined, value: value}
      }
    };

    if (support.iterable) {
      iterator[Symbol.iterator] = function() {
        return iterator
      };
    }

    return iterator
  }

  function Headers(headers) {
    this.map = {};

    if (headers instanceof Headers) {
      headers.forEach(function(value, name) {
        this.append(name, value);
      }, this);
    } else if (Array.isArray(headers)) {
      headers.forEach(function(header) {
        this.append(header[0], header[1]);
      }, this);
    } else if (headers) {
      Object.getOwnPropertyNames(headers).forEach(function(name) {
        this.append(name, headers[name]);
      }, this);
    }
  }

  Headers.prototype.append = function(name, value) {
    name = normalizeName(name);
    value = normalizeValue(value);
    var oldValue = this.map[name];
    this.map[name] = oldValue ? oldValue + ', ' + value : value;
  };

  Headers.prototype['delete'] = function(name) {
    delete this.map[normalizeName(name)];
  };

  Headers.prototype.get = function(name) {
    name = normalizeName(name);
    return this.has(name) ? this.map[name] : null
  };

  Headers.prototype.has = function(name) {
    return this.map.hasOwnProperty(normalizeName(name))
  };

  Headers.prototype.set = function(name, value) {
    this.map[normalizeName(name)] = normalizeValue(value);
  };

  Headers.prototype.forEach = function(callback, thisArg) {
    for (var name in this.map) {
      if (this.map.hasOwnProperty(name)) {
        callback.call(thisArg, this.map[name], name, this);
      }
    }
  };

  Headers.prototype.keys = function() {
    var items = [];
    this.forEach(function(value, name) {
      items.push(name);
    });
    return iteratorFor(items)
  };

  Headers.prototype.values = function() {
    var items = [];
    this.forEach(function(value) {
      items.push(value);
    });
    return iteratorFor(items)
  };

  Headers.prototype.entries = function() {
    var items = [];
    this.forEach(function(value, name) {
      items.push([name, value]);
    });
    return iteratorFor(items)
  };

  if (support.iterable) {
    Headers.prototype[Symbol.iterator] = Headers.prototype.entries;
  }

  function consumed(body) {
    if (body.bodyUsed) {
      return Promise.reject(new TypeError('Already read'))
    }
    body.bodyUsed = true;
  }

  function fileReaderReady(reader) {
    return new Promise(function(resolve, reject) {
      reader.onload = function() {
        resolve(reader.result);
      };
      reader.onerror = function() {
        reject(reader.error);
      };
    })
  }

  function readBlobAsArrayBuffer(blob) {
    var reader = new FileReader();
    var promise = fileReaderReady(reader);
    reader.readAsArrayBuffer(blob);
    return promise
  }

  function readBlobAsText(blob) {
    var reader = new FileReader();
    var promise = fileReaderReady(reader);
    reader.readAsText(blob);
    return promise
  }

  function readArrayBufferAsText(buf) {
    var view = new Uint8Array(buf);
    var chars = new Array(view.length);

    for (var i = 0; i < view.length; i++) {
      chars[i] = String.fromCharCode(view[i]);
    }
    return chars.join('')
  }

  function bufferClone(buf) {
    if (buf.slice) {
      return buf.slice(0)
    } else {
      var view = new Uint8Array(buf.byteLength);
      view.set(new Uint8Array(buf));
      return view.buffer
    }
  }

  function Body() {
    this.bodyUsed = false;

    this._initBody = function(body) {
      this._bodyInit = body;
      if (!body) {
        this._bodyText = '';
      } else if (typeof body === 'string') {
        this._bodyText = body;
      } else if (support.blob && Blob.prototype.isPrototypeOf(body)) {
        this._bodyBlob = body;
      } else if (support.formData && FormData.prototype.isPrototypeOf(body)) {
        this._bodyFormData = body;
      } else if (support.searchParams && URLSearchParams.prototype.isPrototypeOf(body)) {
        this._bodyText = body.toString();
      } else if (support.arrayBuffer && support.blob && isDataView(body)) {
        this._bodyArrayBuffer = bufferClone(body.buffer);
        // IE 10-11 can't handle a DataView body.
        this._bodyInit = new Blob([this._bodyArrayBuffer]);
      } else if (support.arrayBuffer && (ArrayBuffer.prototype.isPrototypeOf(body) || isArrayBufferView(body))) {
        this._bodyArrayBuffer = bufferClone(body);
      } else {
        this._bodyText = body = Object.prototype.toString.call(body);
      }

      if (!this.headers.get('content-type')) {
        if (typeof body === 'string') {
          this.headers.set('content-type', 'text/plain;charset=UTF-8');
        } else if (this._bodyBlob && this._bodyBlob.type) {
          this.headers.set('content-type', this._bodyBlob.type);
        } else if (support.searchParams && URLSearchParams.prototype.isPrototypeOf(body)) {
          this.headers.set('content-type', 'application/x-www-form-urlencoded;charset=UTF-8');
        }
      }
    };

    if (support.blob) {
      this.blob = function() {
        var rejected = consumed(this);
        if (rejected) {
          return rejected
        }

        if (this._bodyBlob) {
          return Promise.resolve(this._bodyBlob)
        } else if (this._bodyArrayBuffer) {
          return Promise.resolve(new Blob([this._bodyArrayBuffer]))
        } else if (this._bodyFormData) {
          throw new Error('could not read FormData body as blob')
        } else {
          return Promise.resolve(new Blob([this._bodyText]))
        }
      };

      this.arrayBuffer = function() {
        if (this._bodyArrayBuffer) {
          return consumed(this) || Promise.resolve(this._bodyArrayBuffer)
        } else {
          return this.blob().then(readBlobAsArrayBuffer)
        }
      };
    }

    this.text = function() {
      var rejected = consumed(this);
      if (rejected) {
        return rejected
      }

      if (this._bodyBlob) {
        return readBlobAsText(this._bodyBlob)
      } else if (this._bodyArrayBuffer) {
        return Promise.resolve(readArrayBufferAsText(this._bodyArrayBuffer))
      } else if (this._bodyFormData) {
        throw new Error('could not read FormData body as text')
      } else {
        return Promise.resolve(this._bodyText)
      }
    };

    if (support.formData) {
      this.formData = function() {
        return this.text().then(decode)
      };
    }

    this.json = function() {
      return this.text().then(JSON.parse)
    };

    return this
  }

  // HTTP methods whose capitalization should be normalized
  var methods = ['DELETE', 'GET', 'HEAD', 'OPTIONS', 'POST', 'PUT'];

  function normalizeMethod(method) {
    var upcased = method.toUpperCase();
    return methods.indexOf(upcased) > -1 ? upcased : method
  }

  function Request(input, options) {
    options = options || {};
    var body = options.body;

    if (input instanceof Request) {
      if (input.bodyUsed) {
        throw new TypeError('Already read')
      }
      this.url = input.url;
      this.credentials = input.credentials;
      if (!options.headers) {
        this.headers = new Headers(input.headers);
      }
      this.method = input.method;
      this.mode = input.mode;
      this.signal = input.signal;
      if (!body && input._bodyInit != null) {
        body = input._bodyInit;
        input.bodyUsed = true;
      }
    } else {
      this.url = String(input);
    }

    this.credentials = options.credentials || this.credentials || 'same-origin';
    if (options.headers || !this.headers) {
      this.headers = new Headers(options.headers);
    }
    this.method = normalizeMethod(options.method || this.method || 'GET');
    this.mode = options.mode || this.mode || null;
    this.signal = options.signal || this.signal;
    this.referrer = null;

    if ((this.method === 'GET' || this.method === 'HEAD') && body) {
      throw new TypeError('Body not allowed for GET or HEAD requests')
    }
    this._initBody(body);
  }

  Request.prototype.clone = function() {
    return new Request(this, {body: this._bodyInit})
  };

  function decode(body) {
    var form = new FormData();
    body
      .trim()
      .split('&')
      .forEach(function(bytes) {
        if (bytes) {
          var split = bytes.split('=');
          var name = split.shift().replace(/\+/g, ' ');
          var value = split.join('=').replace(/\+/g, ' ');
          form.append(decodeURIComponent(name), decodeURIComponent(value));
        }
      });
    return form
  }

  function parseHeaders(rawHeaders) {
    var headers = new Headers();
    // Replace instances of \r\n and \n followed by at least one space or horizontal tab with a space
    // https://tools.ietf.org/html/rfc7230#section-3.2
    var preProcessedHeaders = rawHeaders.replace(/\r?\n[\t ]+/g, ' ');
    preProcessedHeaders.split(/\r?\n/).forEach(function(line) {
      var parts = line.split(':');
      var key = parts.shift().trim();
      if (key) {
        var value = parts.join(':').trim();
        headers.append(key, value);
      }
    });
    return headers
  }

  Body.call(Request.prototype);

  function Response(bodyInit, options) {
    if (!options) {
      options = {};
    }

    this.type = 'default';
    this.status = options.status === undefined ? 200 : options.status;
    this.ok = this.status >= 200 && this.status < 300;
    this.statusText = 'statusText' in options ? options.statusText : 'OK';
    this.headers = new Headers(options.headers);
    this.url = options.url || '';
    this._initBody(bodyInit);
  }

  Body.call(Response.prototype);

  Response.prototype.clone = function() {
    return new Response(this._bodyInit, {
      status: this.status,
      statusText: this.statusText,
      headers: new Headers(this.headers),
      url: this.url
    })
  };

  Response.error = function() {
    var response = new Response(null, {status: 0, statusText: ''});
    response.type = 'error';
    return response
  };

  var redirectStatuses = [301, 302, 303, 307, 308];

  Response.redirect = function(url, status) {
    if (redirectStatuses.indexOf(status) === -1) {
      throw new RangeError('Invalid status code')
    }

    return new Response(null, {status: status, headers: {location: url}})
  };

  exports.DOMException = self.DOMException;
  try {
    new exports.DOMException();
  } catch (err) {
    exports.DOMException = function(message, name) {
      this.message = message;
      this.name = name;
      var error = Error(message);
      this.stack = error.stack;
    };
    exports.DOMException.prototype = Object.create(Error.prototype);
    exports.DOMException.prototype.constructor = exports.DOMException;
  }

  function fetch(input, init) {
    return new Promise(function(resolve, reject) {
      var request = new Request(input, init);

      if (request.signal && request.signal.aborted) {
        return reject(new exports.DOMException('Aborted', 'AbortError'))
      }

      var xhr = new XMLHttpRequest();

      function abortXhr() {
        xhr.abort();
      }

      xhr.onload = function() {
        var options = {
          status: xhr.status,
          statusText: xhr.statusText,
          headers: parseHeaders(xhr.getAllResponseHeaders() || '')
        };
        options.url = 'responseURL' in xhr ? xhr.responseURL : options.headers.get('X-Request-URL');
        var body = 'response' in xhr ? xhr.response : xhr.responseText;
        resolve(new Response(body, options));
      };

      xhr.onerror = function() {
        reject(new TypeError('Network request failed'));
      };

      xhr.ontimeout = function() {
        reject(new TypeError('Network request failed'));
      };

      xhr.onabort = function() {
        reject(new exports.DOMException('Aborted', 'AbortError'));
      };

      xhr.open(request.method, request.url, true);

      if (request.credentials === 'include') {
        xhr.withCredentials = true;
      } else if (request.credentials === 'omit') {
        xhr.withCredentials = false;
      }

      if ('responseType' in xhr && support.blob) {
        xhr.responseType = 'blob';
      }

      request.headers.forEach(function(value, name) {
        xhr.setRequestHeader(name, value);
      });

      if (request.signal) {
        request.signal.addEventListener('abort', abortXhr);

        xhr.onreadystatechange = function() {
          // DONE (success or failure)
          if (xhr.readyState === 4) {
            request.signal.removeEventListener('abort', abortXhr);
          }
        };
      }

      xhr.send(typeof request._bodyInit === 'undefined' ? null : request._bodyInit);
    })
  }

  fetch.polyfill = true;

  if (!self.fetch) {
    self.fetch = fetch;
    self.Headers = Headers;
    self.Request = Request;
    self.Response = Response;
  }

  exports.Headers = Headers;
  exports.Request = Request;
  exports.Response = Response;
  exports.fetch = fetch;

  Object.defineProperty(exports, '__esModule', { value: true });

  return exports;

})({});
})(__self__);
__self__.fetch.ponyfill = true;
// Remove "polyfill" property added by whatwg-fetch
delete __self__.fetch.polyfill;
// Choose between native implementation (global) or custom implementation (__self__)
// var ctx = global.fetch ? global : __self__;
var ctx = __self__; // this line disable service worker support temporarily
exports = ctx.fetch // To enable: import fetch from 'cross-fetch'
exports["default"] = ctx.fetch // For TypeScript consumers without esModuleInterop.
exports.fetch = ctx.fetch // To enable: import {fetch} from 'cross-fetch'
exports.Headers = ctx.Headers
exports.Request = ctx.Request
exports.Response = ctx.Response
module.exports = exports


/***/ }),

/***/ "./node_modules/css-loader/dist/cjs.js!./node_modules/postcss-loader/dist/cjs.js!./src/styles.css":
/*!********************************************************************************************************!*\
  !*** ./node_modules/css-loader/dist/cjs.js!./node_modules/postcss-loader/dist/cjs.js!./src/styles.css ***!
  \********************************************************************************************************/
/***/ ((module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "default": () => (__WEBPACK_DEFAULT_EXPORT__)
/* harmony export */ });
/* harmony import */ var _node_modules_css_loader_dist_runtime_sourceMaps_js__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! ../node_modules/css-loader/dist/runtime/sourceMaps.js */ "./node_modules/css-loader/dist/runtime/sourceMaps.js");
/* harmony import */ var _node_modules_css_loader_dist_runtime_sourceMaps_js__WEBPACK_IMPORTED_MODULE_0___default = /*#__PURE__*/__webpack_require__.n(_node_modules_css_loader_dist_runtime_sourceMaps_js__WEBPACK_IMPORTED_MODULE_0__);
/* harmony import */ var _node_modules_css_loader_dist_runtime_api_js__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! ../node_modules/css-loader/dist/runtime/api.js */ "./node_modules/css-loader/dist/runtime/api.js");
/* harmony import */ var _node_modules_css_loader_dist_runtime_api_js__WEBPACK_IMPORTED_MODULE_1___default = /*#__PURE__*/__webpack_require__.n(_node_modules_css_loader_dist_runtime_api_js__WEBPACK_IMPORTED_MODULE_1__);
/* harmony import */ var _node_modules_css_loader_dist_runtime_getUrl_js__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ../node_modules/css-loader/dist/runtime/getUrl.js */ "./node_modules/css-loader/dist/runtime/getUrl.js");
/* harmony import */ var _node_modules_css_loader_dist_runtime_getUrl_js__WEBPACK_IMPORTED_MODULE_2___default = /*#__PURE__*/__webpack_require__.n(_node_modules_css_loader_dist_runtime_getUrl_js__WEBPACK_IMPORTED_MODULE_2__);
// Imports



var ___CSS_LOADER_URL_IMPORT_0___ = new URL(/* asset import */ __webpack_require__(/*! data:image/svg+xml,%3csvg xmlns=%27http://www.w3.org/2000/svg%27 fill=%27none%27 viewBox=%270 0 20 20%27%3e%3cpath stroke=%27%236b7280%27 stroke-linecap=%27round%27 stroke-linejoin=%27round%27 stroke-width=%271.5%27 d=%27M6 8l4 4 4-4%27/%3e%3c/svg%3e */ "data:image/svg+xml,%3csvg xmlns=%27http://www.w3.org/2000/svg%27 fill=%27none%27 viewBox=%270 0 20 20%27%3e%3cpath stroke=%27%236b7280%27 stroke-linecap=%27round%27 stroke-linejoin=%27round%27 stroke-width=%271.5%27 d=%27M6 8l4 4 4-4%27/%3e%3c/svg%3e"), __webpack_require__.b);
var ___CSS_LOADER_URL_IMPORT_1___ = new URL(/* asset import */ __webpack_require__(/*! data:image/svg+xml,%3csvg viewBox=%270 0 16 16%27 fill=%27white%27 xmlns=%27http://www.w3.org/2000/svg%27%3e%3cpath d=%27M12.207 4.793a1 1 0 010 1.414l-5 5a1 1 0 01-1.414 0l-2-2a1 1 0 011.414-1.414L6.5 9.086l4.293-4.293a1 1 0 011.414 0z%27/%3e%3c/svg%3e */ "data:image/svg+xml,%3csvg viewBox=%270 0 16 16%27 fill=%27white%27 xmlns=%27http://www.w3.org/2000/svg%27%3e%3cpath d=%27M12.207 4.793a1 1 0 010 1.414l-5 5a1 1 0 01-1.414 0l-2-2a1 1 0 011.414-1.414L6.5 9.086l4.293-4.293a1 1 0 011.414 0z%27/%3e%3c/svg%3e"), __webpack_require__.b);
var ___CSS_LOADER_URL_IMPORT_2___ = new URL(/* asset import */ __webpack_require__(/*! data:image/svg+xml,%3csvg viewBox=%270 0 16 16%27 fill=%27white%27 xmlns=%27http://www.w3.org/2000/svg%27%3e%3ccircle cx=%278%27 cy=%278%27 r=%273%27/%3e%3c/svg%3e */ "data:image/svg+xml,%3csvg viewBox=%270 0 16 16%27 fill=%27white%27 xmlns=%27http://www.w3.org/2000/svg%27%3e%3ccircle cx=%278%27 cy=%278%27 r=%273%27/%3e%3c/svg%3e"), __webpack_require__.b);
var ___CSS_LOADER_URL_IMPORT_3___ = new URL(/* asset import */ __webpack_require__(/*! data:image/svg+xml,%3csvg xmlns=%27http://www.w3.org/2000/svg%27 fill=%27none%27 viewBox=%270 0 16 16%27%3e%3cpath stroke=%27white%27 stroke-linecap=%27round%27 stroke-linejoin=%27round%27 stroke-width=%272%27 d=%27M4 8h8%27/%3e%3c/svg%3e */ "data:image/svg+xml,%3csvg xmlns=%27http://www.w3.org/2000/svg%27 fill=%27none%27 viewBox=%270 0 16 16%27%3e%3cpath stroke=%27white%27 stroke-linecap=%27round%27 stroke-linejoin=%27round%27 stroke-width=%272%27 d=%27M4 8h8%27/%3e%3c/svg%3e"), __webpack_require__.b);
var ___CSS_LOADER_EXPORT___ = _node_modules_css_loader_dist_runtime_api_js__WEBPACK_IMPORTED_MODULE_1___default()((_node_modules_css_loader_dist_runtime_sourceMaps_js__WEBPACK_IMPORTED_MODULE_0___default()));
var ___CSS_LOADER_URL_REPLACEMENT_0___ = _node_modules_css_loader_dist_runtime_getUrl_js__WEBPACK_IMPORTED_MODULE_2___default()(___CSS_LOADER_URL_IMPORT_0___);
var ___CSS_LOADER_URL_REPLACEMENT_1___ = _node_modules_css_loader_dist_runtime_getUrl_js__WEBPACK_IMPORTED_MODULE_2___default()(___CSS_LOADER_URL_IMPORT_1___);
var ___CSS_LOADER_URL_REPLACEMENT_2___ = _node_modules_css_loader_dist_runtime_getUrl_js__WEBPACK_IMPORTED_MODULE_2___default()(___CSS_LOADER_URL_IMPORT_2___);
var ___CSS_LOADER_URL_REPLACEMENT_3___ = _node_modules_css_loader_dist_runtime_getUrl_js__WEBPACK_IMPORTED_MODULE_2___default()(___CSS_LOADER_URL_IMPORT_3___);
// Module
___CSS_LOADER_EXPORT___.push([module.id, "/*\n! tailwindcss v3.1.8 | MIT License | https://tailwindcss.com\n*/\n\n/*\n1. Prevent padding and border from affecting element width. (https://github.com/mozdevs/cssremedy/issues/4)\n2. Allow adding a border to an element by just adding a border-width. (https://github.com/tailwindcss/tailwindcss/pull/116)\n*/\n\n*,\n::before,\n::after {\n  box-sizing: border-box;\n  /* 1 */\n  border-width: 0;\n  /* 2 */\n  border-style: solid;\n  /* 2 */\n  border-color: #e5e7eb;\n  /* 2 */\n}\n\n::before,\n::after {\n  --tw-content: '';\n}\n\n/*\n1. Use a consistent sensible line-height in all browsers.\n2. Prevent adjustments of font size after orientation changes in iOS.\n3. Use a more readable tab size.\n4. Use the user's configured `sans` font-family by default.\n*/\n\nhtml {\n  line-height: 1.5;\n  /* 1 */\n  -webkit-text-size-adjust: 100%;\n  /* 2 */\n  -moz-tab-size: 4;\n  /* 3 */\n  -o-tab-size: 4;\n     tab-size: 4;\n  /* 3 */\n  font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Ubuntu, Cantarell, Noto Sans, sans-serif, BlinkMacSystemFont, \"Segoe UI\", Roboto, \"Helvetica Neue\", Arial, \"Noto Sans\", sans-serif, \"Apple Color Emoji\", \"Segoe UI Emoji\", \"Segoe UI Symbol\", \"Noto Color Emoji\";\n  /* 4 */\n}\n\n/*\n1. Remove the margin in all browsers.\n2. Inherit line-height from `html` so users can set them as a class directly on the `html` element.\n*/\n\nbody {\n  margin: 0;\n  /* 1 */\n  line-height: inherit;\n  /* 2 */\n}\n\n/*\n1. Add the correct height in Firefox.\n2. Correct the inheritance of border color in Firefox. (https://bugzilla.mozilla.org/show_bug.cgi?id=190655)\n3. Ensure horizontal rules are visible by default.\n*/\n\nhr {\n  height: 0;\n  /* 1 */\n  color: inherit;\n  /* 2 */\n  border-top-width: 1px;\n  /* 3 */\n}\n\n/*\nAdd the correct text decoration in Chrome, Edge, and Safari.\n*/\n\nabbr:where([title]) {\n  -webkit-text-decoration: underline dotted;\n          text-decoration: underline;\n          -webkit-text-decoration: underline dotted currentColor;\n                  text-decoration: underline dotted currentColor;\n}\n\n/*\nRemove the default font size and weight for headings.\n*/\n\nh1,\nh2,\nh3,\nh4,\nh5,\nh6 {\n  font-size: inherit;\n  font-weight: inherit;\n}\n\n/*\nReset links to optimize for opt-in styling instead of opt-out.\n*/\n\na {\n  color: inherit;\n  text-decoration: inherit;\n}\n\n/*\nAdd the correct font weight in Edge and Safari.\n*/\n\nb,\nstrong {\n  font-weight: bolder;\n}\n\n/*\n1. Use the user's configured `mono` font family by default.\n2. Correct the odd `em` font sizing in all browsers.\n*/\n\ncode,\nkbd,\nsamp,\npre {\n  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, \"Liberation Mono\", \"Courier New\", monospace;\n  /* 1 */\n  font-size: 1em;\n  /* 2 */\n}\n\n/*\nAdd the correct font size in all browsers.\n*/\n\nsmall {\n  font-size: 80%;\n}\n\n/*\nPrevent `sub` and `sup` elements from affecting the line height in all browsers.\n*/\n\nsub,\nsup {\n  font-size: 75%;\n  line-height: 0;\n  position: relative;\n  vertical-align: baseline;\n}\n\nsub {\n  bottom: -0.25em;\n}\n\nsup {\n  top: -0.5em;\n}\n\n/*\n1. Remove text indentation from table contents in Chrome and Safari. (https://bugs.chromium.org/p/chromium/issues/detail?id=999088, https://bugs.webkit.org/show_bug.cgi?id=201297)\n2. Correct table border color inheritance in all Chrome and Safari. (https://bugs.chromium.org/p/chromium/issues/detail?id=935729, https://bugs.webkit.org/show_bug.cgi?id=195016)\n3. Remove gaps between table borders by default.\n*/\n\ntable {\n  text-indent: 0;\n  /* 1 */\n  border-color: inherit;\n  /* 2 */\n  border-collapse: collapse;\n  /* 3 */\n}\n\n/*\n1. Change the font styles in all browsers.\n2. Remove the margin in Firefox and Safari.\n3. Remove default padding in all browsers.\n*/\n\nbutton,\ninput,\noptgroup,\nselect,\ntextarea {\n  font-family: inherit;\n  /* 1 */\n  font-size: 100%;\n  /* 1 */\n  font-weight: inherit;\n  /* 1 */\n  line-height: inherit;\n  /* 1 */\n  color: inherit;\n  /* 1 */\n  margin: 0;\n  /* 2 */\n  padding: 0;\n  /* 3 */\n}\n\n/*\nRemove the inheritance of text transform in Edge and Firefox.\n*/\n\nbutton,\nselect {\n  text-transform: none;\n}\n\n/*\n1. Correct the inability to style clickable types in iOS and Safari.\n2. Remove default button styles.\n*/\n\nbutton,\n[type='button'],\n[type='reset'],\n[type='submit'] {\n  -webkit-appearance: button;\n  /* 1 */\n  background-color: transparent;\n  /* 2 */\n  background-image: none;\n  /* 2 */\n}\n\n/*\nUse the modern Firefox focus style for all focusable elements.\n*/\n\n:-moz-focusring {\n  outline: auto;\n}\n\n/*\nRemove the additional `:invalid` styles in Firefox. (https://github.com/mozilla/gecko-dev/blob/2f9eacd9d3d995c937b4251a5557d95d494c9be1/layout/style/res/forms.css#L728-L737)\n*/\n\n:-moz-ui-invalid {\n  box-shadow: none;\n}\n\n/*\nAdd the correct vertical alignment in Chrome and Firefox.\n*/\n\nprogress {\n  vertical-align: baseline;\n}\n\n/*\nCorrect the cursor style of increment and decrement buttons in Safari.\n*/\n\n::-webkit-inner-spin-button,\n::-webkit-outer-spin-button {\n  height: auto;\n}\n\n/*\n1. Correct the odd appearance in Chrome and Safari.\n2. Correct the outline style in Safari.\n*/\n\n[type='search'] {\n  -webkit-appearance: textfield;\n  /* 1 */\n  outline-offset: -2px;\n  /* 2 */\n}\n\n/*\nRemove the inner padding in Chrome and Safari on macOS.\n*/\n\n::-webkit-search-decoration {\n  -webkit-appearance: none;\n}\n\n/*\n1. Correct the inability to style clickable types in iOS and Safari.\n2. Change font properties to `inherit` in Safari.\n*/\n\n::-webkit-file-upload-button {\n  -webkit-appearance: button;\n  /* 1 */\n  font: inherit;\n  /* 2 */\n}\n\n/*\nAdd the correct display in Chrome and Safari.\n*/\n\nsummary {\n  display: list-item;\n}\n\n/*\nRemoves the default spacing and border for appropriate elements.\n*/\n\nblockquote,\ndl,\ndd,\nh1,\nh2,\nh3,\nh4,\nh5,\nh6,\nhr,\nfigure,\np,\npre {\n  margin: 0;\n}\n\nfieldset {\n  margin: 0;\n  padding: 0;\n}\n\nlegend {\n  padding: 0;\n}\n\nol,\nul,\nmenu {\n  list-style: none;\n  margin: 0;\n  padding: 0;\n}\n\n/*\nPrevent resizing textareas horizontally by default.\n*/\n\ntextarea {\n  resize: vertical;\n}\n\n/*\n1. Reset the default placeholder opacity in Firefox. (https://github.com/tailwindlabs/tailwindcss/issues/3300)\n2. Set the default placeholder color to the user's configured gray 400 color.\n*/\n\ninput::-moz-placeholder, textarea::-moz-placeholder {\n  opacity: 1;\n  /* 1 */\n  color: #9ca3af;\n  /* 2 */\n}\n\ninput::placeholder,\ntextarea::placeholder {\n  opacity: 1;\n  /* 1 */\n  color: #9ca3af;\n  /* 2 */\n}\n\n/*\nSet the default cursor for buttons.\n*/\n\nbutton,\n[role=\"button\"] {\n  cursor: pointer;\n}\n\n/*\nMake sure disabled buttons don't get the pointer cursor.\n*/\n\n:disabled {\n  cursor: default;\n}\n\n/*\n1. Make replaced elements `display: block` by default. (https://github.com/mozdevs/cssremedy/issues/14)\n2. Add `vertical-align: middle` to align replaced elements more sensibly by default. (https://github.com/jensimmons/cssremedy/issues/14#issuecomment-634934210)\n   This can trigger a poorly considered lint error in some tools but is included by design.\n*/\n\nimg,\nsvg,\nvideo,\ncanvas,\naudio,\niframe,\nembed,\nobject {\n  display: block;\n  /* 1 */\n  vertical-align: middle;\n  /* 2 */\n}\n\n/*\nConstrain images and videos to the parent width and preserve their intrinsic aspect ratio. (https://github.com/mozdevs/cssremedy/issues/14)\n*/\n\nimg,\nvideo {\n  max-width: 100%;\n  height: auto;\n}\n\n[type='text'],[type='email'],[type='url'],[type='password'],[type='number'],[type='date'],[type='datetime-local'],[type='month'],[type='search'],[type='tel'],[type='time'],[type='week'],[multiple],textarea,select {\n  -webkit-appearance: none;\n     -moz-appearance: none;\n          appearance: none;\n  background-color: #fff;\n  border-color: #6b7280;\n  border-width: 1px;\n  border-radius: 0px;\n  padding-top: 0.5rem;\n  padding-right: 0.75rem;\n  padding-bottom: 0.5rem;\n  padding-left: 0.75rem;\n  font-size: 1rem;\n  line-height: 1.5rem;\n  --tw-shadow: 0 0 rgba(0,0,0,0);\n}\n\n[type='text']:focus, [type='email']:focus, [type='url']:focus, [type='password']:focus, [type='number']:focus, [type='date']:focus, [type='datetime-local']:focus, [type='month']:focus, [type='search']:focus, [type='tel']:focus, [type='time']:focus, [type='week']:focus, [multiple]:focus, textarea:focus, select:focus {\n  outline: 2px solid transparent;\n  outline-offset: 2px;\n  --tw-ring-inset: var(--tw-empty,/*!*/ /*!*/);\n  --tw-ring-offset-width: 0px;\n  --tw-ring-offset-color: #fff;\n  --tw-ring-color: #2563eb;\n  --tw-ring-offset-shadow: var(--tw-ring-inset) 0 0 0 var(--tw-ring-offset-width) var(--tw-ring-offset-color);\n  --tw-ring-shadow: var(--tw-ring-inset) 0 0 0 calc(1px + var(--tw-ring-offset-width)) var(--tw-ring-color);\n  box-shadow: var(--tw-ring-offset-shadow), var(--tw-ring-shadow), var(--tw-shadow);\n  border-color: #2563eb;\n}\n\ninput::-moz-placeholder, textarea::-moz-placeholder {\n  color: #6b7280;\n  opacity: 1;\n}\n\ninput::placeholder,textarea::placeholder {\n  color: #6b7280;\n  opacity: 1;\n}\n\n::-webkit-datetime-edit-fields-wrapper {\n  padding: 0;\n}\n\n::-webkit-date-and-time-value {\n  min-height: 1.5em;\n}\n\n::-webkit-datetime-edit,::-webkit-datetime-edit-year-field,::-webkit-datetime-edit-month-field,::-webkit-datetime-edit-day-field,::-webkit-datetime-edit-hour-field,::-webkit-datetime-edit-minute-field,::-webkit-datetime-edit-second-field,::-webkit-datetime-edit-millisecond-field,::-webkit-datetime-edit-meridiem-field {\n  padding-top: 0;\n  padding-bottom: 0;\n}\n\nselect {\n  background-image: url(" + ___CSS_LOADER_URL_REPLACEMENT_0___ + ");\n  background-position: right 0.5rem center;\n  background-repeat: no-repeat;\n  background-size: 1.5em 1.5em;\n  padding-right: 2.5rem;\n  -webkit-print-color-adjust: exact;\n     color-adjust: exact;\n          print-color-adjust: exact;\n}\n\n[multiple] {\n  background-image: none;\n  background-image: initial;\n  background-position: 0 0;\n  background-position: initial;\n  background-repeat: repeat;\n  background-repeat: initial;\n  background-size: auto auto;\n  background-size: initial;\n  padding-right: 0.75rem;\n  -webkit-print-color-adjust: unset;\n     color-adjust: initial;\n          print-color-adjust: inherit;\n}\n\n[type='checkbox'],[type='radio'] {\n  -webkit-appearance: none;\n     -moz-appearance: none;\n          appearance: none;\n  padding: 0;\n  -webkit-print-color-adjust: exact;\n     color-adjust: exact;\n          print-color-adjust: exact;\n  display: inline-block;\n  vertical-align: middle;\n  background-origin: border-box;\n  -webkit-user-select: none;\n     -moz-user-select: none;\n          user-select: none;\n  flex-shrink: 0;\n  height: 1rem;\n  width: 1rem;\n  color: #2563eb;\n  background-color: #fff;\n  border-color: #6b7280;\n  border-width: 1px;\n  --tw-shadow: 0 0 rgba(0,0,0,0);\n}\n\n[type='checkbox'] {\n  border-radius: 0px;\n}\n\n[type='radio'] {\n  border-radius: 100%;\n}\n\n[type='checkbox']:focus,[type='radio']:focus {\n  outline: 2px solid transparent;\n  outline-offset: 2px;\n  --tw-ring-inset: var(--tw-empty,/*!*/ /*!*/);\n  --tw-ring-offset-width: 2px;\n  --tw-ring-offset-color: #fff;\n  --tw-ring-color: #2563eb;\n  --tw-ring-offset-shadow: var(--tw-ring-inset) 0 0 0 var(--tw-ring-offset-width) var(--tw-ring-offset-color);\n  --tw-ring-shadow: var(--tw-ring-inset) 0 0 0 calc(2px + var(--tw-ring-offset-width)) var(--tw-ring-color);\n  box-shadow: var(--tw-ring-offset-shadow), var(--tw-ring-shadow), var(--tw-shadow);\n}\n\n[type='checkbox']:checked,[type='radio']:checked {\n  border-color: transparent;\n  background-color: currentColor;\n  background-size: 100% 100%;\n  background-position: center;\n  background-repeat: no-repeat;\n}\n\n[type='checkbox']:checked {\n  background-image: url(" + ___CSS_LOADER_URL_REPLACEMENT_1___ + ");\n}\n\n[type='radio']:checked {\n  background-image: url(" + ___CSS_LOADER_URL_REPLACEMENT_2___ + ");\n}\n\n[type='checkbox']:checked:hover,[type='checkbox']:checked:focus,[type='radio']:checked:hover,[type='radio']:checked:focus {\n  border-color: transparent;\n  background-color: currentColor;\n}\n\n[type='checkbox']:indeterminate {\n  background-image: url(" + ___CSS_LOADER_URL_REPLACEMENT_3___ + ");\n  border-color: transparent;\n  background-color: currentColor;\n  background-size: 100% 100%;\n  background-position: center;\n  background-repeat: no-repeat;\n}\n\n[type='checkbox']:indeterminate:hover,[type='checkbox']:indeterminate:focus {\n  border-color: transparent;\n  background-color: currentColor;\n}\n\n[type='file'] {\n  background: transparent none repeat 0 0 / auto auto padding-box border-box scroll;\n  background: initial;\n  border-color: inherit;\n  border-width: 0;\n  border-radius: 0;\n  padding: 0;\n  font-size: inherit;\n  line-height: inherit;\n}\n\n[type='file']:focus {\n  outline: 1px solid ButtonText;\n  outline: 1px auto -webkit-focus-ring-color;\n}\n\n*, ::before, ::after {\n  --tw-border-spacing-x: 0;\n  --tw-border-spacing-y: 0;\n  --tw-translate-x: 0;\n  --tw-translate-y: 0;\n  --tw-rotate: 0;\n  --tw-skew-x: 0;\n  --tw-skew-y: 0;\n  --tw-scale-x: 1;\n  --tw-scale-y: 1;\n  --tw-pan-x:  ;\n  --tw-pan-y:  ;\n  --tw-pinch-zoom:  ;\n  --tw-scroll-snap-strictness: proximity;\n  --tw-ordinal:  ;\n  --tw-slashed-zero:  ;\n  --tw-numeric-figure:  ;\n  --tw-numeric-spacing:  ;\n  --tw-numeric-fraction:  ;\n  --tw-ring-inset:  ;\n  --tw-ring-offset-width: 0px;\n  --tw-ring-offset-color: #fff;\n  --tw-ring-color: rgba(59, 130, 246, 0.5);\n  --tw-ring-offset-shadow: 0 0 rgba(0,0,0,0);\n  --tw-ring-shadow: 0 0 rgba(0,0,0,0);\n  --tw-shadow: 0 0 rgba(0,0,0,0);\n  --tw-shadow-colored: 0 0 rgba(0,0,0,0);\n  --tw-blur:  ;\n  --tw-brightness:  ;\n  --tw-contrast:  ;\n  --tw-grayscale:  ;\n  --tw-hue-rotate:  ;\n  --tw-invert:  ;\n  --tw-saturate:  ;\n  --tw-sepia:  ;\n  --tw-drop-shadow:  ;\n  --tw-backdrop-blur:  ;\n  --tw-backdrop-brightness:  ;\n  --tw-backdrop-contrast:  ;\n  --tw-backdrop-grayscale:  ;\n  --tw-backdrop-hue-rotate:  ;\n  --tw-backdrop-invert:  ;\n  --tw-backdrop-opacity:  ;\n  --tw-backdrop-saturate:  ;\n  --tw-backdrop-sepia:  ;\n}\n\n::-webkit-backdrop {\n  --tw-border-spacing-x: 0;\n  --tw-border-spacing-y: 0;\n  --tw-translate-x: 0;\n  --tw-translate-y: 0;\n  --tw-rotate: 0;\n  --tw-skew-x: 0;\n  --tw-skew-y: 0;\n  --tw-scale-x: 1;\n  --tw-scale-y: 1;\n  --tw-pan-x:  ;\n  --tw-pan-y:  ;\n  --tw-pinch-zoom:  ;\n  --tw-scroll-snap-strictness: proximity;\n  --tw-ordinal:  ;\n  --tw-slashed-zero:  ;\n  --tw-numeric-figure:  ;\n  --tw-numeric-spacing:  ;\n  --tw-numeric-fraction:  ;\n  --tw-ring-inset:  ;\n  --tw-ring-offset-width: 0px;\n  --tw-ring-offset-color: #fff;\n  --tw-ring-color: rgba(59, 130, 246, 0.5);\n  --tw-ring-offset-shadow: 0 0 rgba(0,0,0,0);\n  --tw-ring-shadow: 0 0 rgba(0,0,0,0);\n  --tw-shadow: 0 0 rgba(0,0,0,0);\n  --tw-shadow-colored: 0 0 rgba(0,0,0,0);\n  --tw-blur:  ;\n  --tw-brightness:  ;\n  --tw-contrast:  ;\n  --tw-grayscale:  ;\n  --tw-hue-rotate:  ;\n  --tw-invert:  ;\n  --tw-saturate:  ;\n  --tw-sepia:  ;\n  --tw-drop-shadow:  ;\n  --tw-backdrop-blur:  ;\n  --tw-backdrop-brightness:  ;\n  --tw-backdrop-contrast:  ;\n  --tw-backdrop-grayscale:  ;\n  --tw-backdrop-hue-rotate:  ;\n  --tw-backdrop-invert:  ;\n  --tw-backdrop-opacity:  ;\n  --tw-backdrop-saturate:  ;\n  --tw-backdrop-sepia:  ;\n}\n\n::backdrop {\n  --tw-border-spacing-x: 0;\n  --tw-border-spacing-y: 0;\n  --tw-translate-x: 0;\n  --tw-translate-y: 0;\n  --tw-rotate: 0;\n  --tw-skew-x: 0;\n  --tw-skew-y: 0;\n  --tw-scale-x: 1;\n  --tw-scale-y: 1;\n  --tw-pan-x:  ;\n  --tw-pan-y:  ;\n  --tw-pinch-zoom:  ;\n  --tw-scroll-snap-strictness: proximity;\n  --tw-ordinal:  ;\n  --tw-slashed-zero:  ;\n  --tw-numeric-figure:  ;\n  --tw-numeric-spacing:  ;\n  --tw-numeric-fraction:  ;\n  --tw-ring-inset:  ;\n  --tw-ring-offset-width: 0px;\n  --tw-ring-offset-color: #fff;\n  --tw-ring-color: rgba(59, 130, 246, 0.5);\n  --tw-ring-offset-shadow: 0 0 rgba(0,0,0,0);\n  --tw-ring-shadow: 0 0 rgba(0,0,0,0);\n  --tw-shadow: 0 0 rgba(0,0,0,0);\n  --tw-shadow-colored: 0 0 rgba(0,0,0,0);\n  --tw-blur:  ;\n  --tw-brightness:  ;\n  --tw-contrast:  ;\n  --tw-grayscale:  ;\n  --tw-hue-rotate:  ;\n  --tw-invert:  ;\n  --tw-saturate:  ;\n  --tw-sepia:  ;\n  --tw-drop-shadow:  ;\n  --tw-backdrop-blur:  ;\n  --tw-backdrop-brightness:  ;\n  --tw-backdrop-contrast:  ;\n  --tw-backdrop-grayscale:  ;\n  --tw-backdrop-hue-rotate:  ;\n  --tw-backdrop-invert:  ;\n  --tw-backdrop-opacity:  ;\n  --tw-backdrop-saturate:  ;\n  --tw-backdrop-sepia:  ;\n}\n\n.sr-only {\n  position: absolute;\n  width: 1px;\n  height: 1px;\n  padding: 0;\n  margin: -1px;\n  overflow: hidden;\n  clip: rect(0, 0, 0, 0);\n  white-space: nowrap;\n  border-width: 0;\n}\n\n.col-span-6 {\n  grid-column: span 6 / span 6;\n}\n\n.m-2 {\n  margin: 0.5rem;\n}\n\n.mx-4 {\n  margin-left: 1rem;\n  margin-right: 1rem;\n}\n\n.my-auto {\n  margin-top: auto;\n  margin-bottom: auto;\n}\n\n.mx-auto {\n  margin-left: auto;\n  margin-right: auto;\n}\n\n.my-8 {\n  margin-top: 2rem;\n  margin-bottom: 2rem;\n}\n\n.my-3 {\n  margin-top: 0.75rem;\n  margin-bottom: 0.75rem;\n}\n\n.mt-auto {\n  margin-top: auto;\n}\n\n.mb-5 {\n  margin-bottom: 1.25rem;\n}\n\n.mr-auto {\n  margin-right: auto;\n}\n\n.ml-2 {\n  margin-left: 0.5rem;\n}\n\n.mr-2 {\n  margin-right: 0.5rem;\n}\n\n.ml-4 {\n  margin-left: 1rem;\n}\n\n.mr-4 {\n  margin-right: 1rem;\n}\n\n.mb-0 {\n  margin-bottom: 0px;\n}\n\n.mt-2 {\n  margin-top: 0.5rem;\n}\n\n.mb-2 {\n  margin-bottom: 0.5rem;\n}\n\n.mt-1 {\n  margin-top: 0.25rem;\n}\n\n.mb-1 {\n  margin-bottom: 0.25rem;\n}\n\n.mb-6 {\n  margin-bottom: 1.5rem;\n}\n\n.mb-4 {\n  margin-bottom: 1rem;\n}\n\n.ml-auto {\n  margin-left: auto;\n}\n\n.mt-\\[6px\\] {\n  margin-top: 6px;\n}\n\n.mt-\\[5px\\] {\n  margin-top: 5px;\n}\n\n.mb-3 {\n  margin-bottom: 0.75rem;\n}\n\n.mt-3 {\n  margin-top: 0.75rem;\n}\n\n.mt-5 {\n  margin-top: 1.25rem;\n}\n\n.block {\n  display: block;\n}\n\n.flex {\n  display: flex;\n}\n\n.inline-flex {\n  display: inline-flex;\n}\n\n.grid {\n  display: grid;\n}\n\n.hidden {\n  display: none;\n}\n\n.h-screen {\n  height: 100vh;\n}\n\n.h-20 {\n  height: 5rem;\n}\n\n.w-auto {\n  width: auto;\n}\n\n.w-screen {\n  width: 100vw;\n}\n\n.w-full {\n  width: 100%;\n}\n\n.w-16 {\n  width: 4rem;\n}\n\n.w-20 {\n  width: 5rem;\n}\n\n.max-w-sm {\n  max-width: 24rem;\n}\n\n.grid-cols-2 {\n  grid-template-columns: repeat(2, minmax(0, 1fr));\n}\n\n.flex-row {\n  flex-direction: row;\n}\n\n.flex-col {\n  flex-direction: column;\n}\n\n.content-center {\n  align-content: center;\n}\n\n.items-center {\n  align-items: center;\n}\n\n.justify-center {\n  justify-content: center;\n}\n\n.space-y-0 > :not([hidden]) ~ :not([hidden]) {\n  --tw-space-y-reverse: 0;\n  margin-top: calc(0px * (1 - var(--tw-space-y-reverse)));\n  margin-top: calc(0px * calc(1 - var(--tw-space-y-reverse)));\n  margin-bottom: calc(0px * var(--tw-space-y-reverse));\n}\n\n.overflow-hidden {\n  overflow: hidden;\n}\n\n.overflow-x-auto {\n  overflow-x: auto;\n}\n\n.rounded-lg {\n  border-radius: 0.5rem;\n}\n\n.rounded-none {\n  border-radius: 0px;\n}\n\n.rounded-b-md {\n  border-bottom-right-radius: 0.375rem;\n  border-bottom-left-radius: 0.375rem;\n}\n\n.border {\n  border-width: 1px;\n}\n\n.border-b {\n  border-bottom-width: 1px;\n}\n\n.border-neutral-100 {\n  --tw-border-opacity: 1;\n  border-color: rgba(245, 245, 245, var(--tw-border-opacity));\n}\n\n.border-transparent {\n  border-color: transparent;\n}\n\n.border-neutral-200 {\n  --tw-border-opacity: 1;\n  border-color: rgba(229, 229, 229, var(--tw-border-opacity));\n}\n\n.border-white {\n  --tw-border-opacity: 1;\n  border-color: rgba(255, 255, 255, var(--tw-border-opacity));\n}\n\n.border-gray-300 {\n  --tw-border-opacity: 1;\n  border-color: rgba(209, 213, 219, var(--tw-border-opacity));\n}\n\n.bg-white {\n  --tw-bg-opacity: 1;\n  background-color: rgba(255, 255, 255, var(--tw-bg-opacity));\n}\n\n.bg-blue-500 {\n  --tw-bg-opacity: 1;\n  background-color: rgba(59, 130, 246, var(--tw-bg-opacity));\n}\n\n.bg-gray-50 {\n  --tw-bg-opacity: 1;\n  background-color: rgba(249, 250, 251, var(--tw-bg-opacity));\n}\n\n.bg-blue-600 {\n  --tw-bg-opacity: 1;\n  background-color: rgba(37, 99, 235, var(--tw-bg-opacity));\n}\n\n.bg-neutral-100 {\n  --tw-bg-opacity: 1;\n  background-color: rgba(245, 245, 245, var(--tw-bg-opacity));\n}\n\n.bg-gradient-to-br {\n  background-image: linear-gradient(to bottom right, var(--tw-gradient-stops));\n}\n\n.from-pink-500 {\n  --tw-gradient-from: #ec4899;\n  --tw-gradient-to: rgba(236, 72, 153, 0);\n  --tw-gradient-stops: var(--tw-gradient-from), var(--tw-gradient-to);\n}\n\n.from-violet-500 {\n  --tw-gradient-from: #8b5cf6;\n  --tw-gradient-to: rgba(139, 92, 246, 0);\n  --tw-gradient-stops: var(--tw-gradient-from), var(--tw-gradient-to);\n}\n\n.from-neutral-600 {\n  --tw-gradient-from: #525252;\n  --tw-gradient-to: rgba(82, 82, 82, 0);\n  --tw-gradient-stops: var(--tw-gradient-from), var(--tw-gradient-to);\n}\n\n.from-green-500 {\n  --tw-gradient-from: #22c55e;\n  --tw-gradient-to: rgba(34, 197, 94, 0);\n  --tw-gradient-stops: var(--tw-gradient-from), var(--tw-gradient-to);\n}\n\n.from-blue-500 {\n  --tw-gradient-from: #3b82f6;\n  --tw-gradient-to: rgba(59, 130, 246, 0);\n  --tw-gradient-stops: var(--tw-gradient-from), var(--tw-gradient-to);\n}\n\n.from-red-500 {\n  --tw-gradient-from: #ef4444;\n  --tw-gradient-to: rgba(239, 68, 68, 0);\n  --tw-gradient-stops: var(--tw-gradient-from), var(--tw-gradient-to);\n}\n\n.to-pink-300 {\n  --tw-gradient-to: #f9a8d4;\n}\n\n.to-violet-300 {\n  --tw-gradient-to: #c4b5fd;\n}\n\n.to-neutral-400 {\n  --tw-gradient-to: #a3a3a3;\n}\n\n.to-green-300 {\n  --tw-gradient-to: #86efac;\n}\n\n.to-blue-300 {\n  --tw-gradient-to: #93c5fd;\n}\n\n.to-red-300 {\n  --tw-gradient-to: #fca5a5;\n}\n\n.p-2 {\n  padding: 0.5rem;\n}\n\n.py-2 {\n  padding-top: 0.5rem;\n  padding-bottom: 0.5rem;\n}\n\n.px-4 {\n  padding-left: 1rem;\n  padding-right: 1rem;\n}\n\n.py-\\[6px\\] {\n  padding-top: 6px;\n  padding-bottom: 6px;\n}\n\n.px-0 {\n  padding-left: 0px;\n  padding-right: 0px;\n}\n\n.px-6 {\n  padding-left: 1.5rem;\n  padding-right: 1.5rem;\n}\n\n.py-4 {\n  padding-top: 1rem;\n  padding-bottom: 1rem;\n}\n\n.py-5 {\n  padding-top: 1.25rem;\n  padding-bottom: 1.25rem;\n}\n\n.py-20 {\n  padding-top: 5rem;\n  padding-bottom: 5rem;\n}\n\n.px-3 {\n  padding-left: 0.75rem;\n  padding-right: 0.75rem;\n}\n\n.py-1 {\n  padding-top: 0.25rem;\n  padding-bottom: 0.25rem;\n}\n\n.py-\\[8px\\] {\n  padding-top: 8px;\n  padding-bottom: 8px;\n}\n\n.px-8 {\n  padding-left: 2rem;\n  padding-right: 2rem;\n}\n\n.py-\\[2px\\] {\n  padding-top: 2px;\n  padding-bottom: 2px;\n}\n\n.px-5 {\n  padding-left: 1.25rem;\n  padding-right: 1.25rem;\n}\n\n.pr-3 {\n  padding-right: 0.75rem;\n}\n\n.pr-4 {\n  padding-right: 1rem;\n}\n\n.text-right {\n  text-align: right;\n}\n\n.text-sm {\n  font-size: 0.875rem;\n  line-height: 1.25rem;\n}\n\n.text-lg {\n  font-size: 1.125rem;\n  line-height: 1.75rem;\n}\n\n.text-2xl {\n  font-size: 1.5rem;\n  line-height: 2rem;\n}\n\n.font-medium {\n  font-weight: 500;\n}\n\n.font-semibold {\n  font-weight: 600;\n}\n\n.font-bold {\n  font-weight: 700;\n}\n\n.leading-6 {\n  line-height: 1.5rem;\n}\n\n.text-neutral-600 {\n  --tw-text-opacity: 1;\n  color: rgba(82, 82, 82, var(--tw-text-opacity));\n}\n\n.text-white {\n  --tw-text-opacity: 1;\n  color: rgba(255, 255, 255, var(--tw-text-opacity));\n}\n\n.text-blue-500 {\n  --tw-text-opacity: 1;\n  color: rgba(59, 130, 246, var(--tw-text-opacity));\n}\n\n.text-gray-900 {\n  --tw-text-opacity: 1;\n  color: rgba(17, 24, 39, var(--tw-text-opacity));\n}\n\n.text-neutral-100 {\n  --tw-text-opacity: 1;\n  color: rgba(245, 245, 245, var(--tw-text-opacity));\n}\n\n.text-green-400 {\n  --tw-text-opacity: 1;\n  color: rgba(74, 222, 128, var(--tw-text-opacity));\n}\n\n.text-gray-700 {\n  --tw-text-opacity: 1;\n  color: rgba(55, 65, 81, var(--tw-text-opacity));\n}\n\n.text-gray-500 {\n  --tw-text-opacity: 1;\n  color: rgba(107, 114, 128, var(--tw-text-opacity));\n}\n\n.shadow-lg {\n  --tw-shadow: 0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -4px rgba(0, 0, 0, 0.1);\n  --tw-shadow-colored: 0 10px 15px -3px var(--tw-shadow-color), 0 4px 6px -4px var(--tw-shadow-color);\n  box-shadow: 0 0 rgba(0,0,0,0), 0 0 rgba(0,0,0,0), var(--tw-shadow);\n  box-shadow: 0 0 rgba(0,0,0,0), 0 0 rgba(0,0,0,0), var(--tw-shadow);\n  box-shadow: var(--tw-ring-offset-shadow, 0 0 rgba(0,0,0,0)), var(--tw-ring-shadow, 0 0 rgba(0,0,0,0)), var(--tw-shadow);\n}\n\n.shadow-sm {\n  --tw-shadow: 0 1px 2px 0 rgba(0, 0, 0, 0.05);\n  --tw-shadow-colored: 0 1px 2px 0 var(--tw-shadow-color);\n  box-shadow: 0 0 rgba(0,0,0,0), 0 0 rgba(0,0,0,0), var(--tw-shadow);\n  box-shadow: 0 0 rgba(0,0,0,0), 0 0 rgba(0,0,0,0), var(--tw-shadow);\n  box-shadow: var(--tw-ring-offset-shadow, 0 0 rgba(0,0,0,0)), var(--tw-ring-shadow, 0 0 rgba(0,0,0,0)), var(--tw-shadow);\n}\n\n.shadow {\n  --tw-shadow: 0 1px 3px 0 rgba(0, 0, 0, 0.1), 0 1px 2px -1px rgba(0, 0, 0, 0.1);\n  --tw-shadow-colored: 0 1px 3px 0 var(--tw-shadow-color), 0 1px 2px -1px var(--tw-shadow-color);\n  box-shadow: 0 0 rgba(0,0,0,0), 0 0 rgba(0,0,0,0), var(--tw-shadow);\n  box-shadow: 0 0 rgba(0,0,0,0), 0 0 rgba(0,0,0,0), var(--tw-shadow);\n  box-shadow: var(--tw-ring-offset-shadow, 0 0 rgba(0,0,0,0)), var(--tw-ring-shadow, 0 0 rgba(0,0,0,0)), var(--tw-shadow);\n}\n\n.outline-none {\n  outline: 2px solid transparent;\n  outline-offset: 2px;\n}\n\n.font-jost {\n  font-family: \"Jost\";\n}\n\n.font-inter {\n  font-family: \"Inter\";\n}\n\n.code {\n  font-family: \"Source Code Pro\", monospace;\n  display: block;\n  background-color: white;\n  color: #000000;\n  padding: 1em;\n  word-wrap: break-word;\n  white-space: pre-wrap;\n}\n\n.sidenav {\n  height: 100%;\n  /* 100% Full-height */\n  width: 0;\n  /* 0 width - change this with JavaScript */\n  position: fixed;\n  /* Stay in place */\n  z-index: 1;\n  /* Stay on top */\n  top: 0;\n  /* Stay at the top */\n  left: 0;\n  overflow-x: hidden;\n  /* Disable horizontal scroll */\n  padding-top: 60px;\n  /* Place content 60px from the top */\n  transition: 0.5s;\n  /* 0.5 second transition effect to slide in the sidenav */\n}\n\n/* The navigation menu links */\n\n.sidenav a {\n  display: block;\n}\n\nselect {\n  -webkit-appearance: none;\n     -moz-appearance: none;\n          appearance: none;\n  background-color: #fff;\n  border-color: #6b7280;\n  border-width: 1px;\n  border-radius: 0px;\n  padding-top: 0.5rem;\n  padding-right: 0.75rem;\n  padding-bottom: 0.5rem;\n  padding-left: 0.75rem;\n  font-size: 1rem;\n  line-height: 1.5rem;\n  --tw-shadow: 0 0 rgba(0,0,0,0);\n}\n\n select:focus {\n  outline: 2px solid transparent;\n  outline-offset: 2px;\n  --tw-ring-inset: var(--tw-empty,/*!*/ /*!*/);\n  --tw-ring-offset-width: 0px;\n  --tw-ring-offset-color: #fff;\n  --tw-ring-color: #2563eb;\n  --tw-ring-offset-shadow: var(--tw-ring-inset) 0 0 0 var(--tw-ring-offset-width) var(--tw-ring-offset-color);\n  --tw-ring-shadow: var(--tw-ring-inset) 0 0 0 calc(1px + var(--tw-ring-offset-width)) var(--tw-ring-color);\n  box-shadow: var(--tw-ring-offset-shadow), var(--tw-ring-shadow), var(--tw-shadow);\n  border-color: #2563eb;\n}\n\nselect {\n  background-image: url(" + ___CSS_LOADER_URL_REPLACEMENT_0___ + ");\n  background-position: right 0.5rem center;\n  background-size: 1.5em 1.5em;\n  -webkit-print-color-adjust: exact;\n     color-adjust: exact;\n          print-color-adjust: exact;\n  margin: 0px;\n  margin-top: 0.5rem;\n  display: block;\n  width: 100%;\n  -webkit-appearance: none;\n     -moz-appearance: none;\n          appearance: none;\n  border-radius: 0.25rem;\n  border-width: 1px;\n  border-style: solid;\n  --tw-border-opacity: 1;\n  border-color: rgba(209, 213, 219, var(--tw-border-opacity));\n  --tw-bg-opacity: 1;\n  background-color: rgba(255, 255, 255, var(--tw-bg-opacity));\n  background-clip: padding-box;\n  background-repeat: no-repeat;\n  padding-left: 0.75rem;\n  padding-right: 0.75rem;\n  padding-top: 0.375rem;\n  padding-bottom: 0.375rem;\n  font-size: 1rem;\n  line-height: 1.5rem;\n  font-weight: 400;\n  --tw-text-opacity: 1;\n  color: rgba(55, 65, 81, var(--tw-text-opacity));\n  transition-property: color, background-color, border-color, fill, stroke, opacity, box-shadow, transform, filter, -webkit-text-decoration-color, -webkit-backdrop-filter;\n  transition-property: color, background-color, border-color, text-decoration-color, fill, stroke, opacity, box-shadow, transform, filter, backdrop-filter;\n  transition-property: color, background-color, border-color, text-decoration-color, fill, stroke, opacity, box-shadow, transform, filter, backdrop-filter, -webkit-text-decoration-color, -webkit-backdrop-filter;\n  transition-duration: 150ms;\n  transition-timing-function: cubic-bezier(0.4, 0, 0.2, 1);\n}\n\nselect:focus {\n  --tw-border-opacity: 1;\n  border-color: rgba(37, 99, 235, var(--tw-border-opacity));\n  --tw-bg-opacity: 1;\n  background-color: rgba(255, 255, 255, var(--tw-bg-opacity));\n  --tw-text-opacity: 1;\n  color: rgba(55, 65, 81, var(--tw-text-opacity));\n  outline: 2px solid transparent;\n  outline-offset: 2px;\n}\n\ntable {\n  margin-left: auto;\n  margin-right: auto;\n  margin-top: 2.5rem;\n  margin-bottom: 2.5rem;\n  width: 66.666667%;\n  border-width: 1px;\n  --tw-border-opacity: 1;\n  border-color: rgba(229, 229, 229, var(--tw-border-opacity));\n  font-family: \"Inter\";\n}\n\nth {\n  border-width: 1px;\n  --tw-border-opacity: 1;\n  border-color: rgba(255, 255, 255, var(--tw-border-opacity));\n  --tw-bg-opacity: 1;\n  background-color: rgba(59, 130, 246, var(--tw-bg-opacity));\n  padding: 0.75rem;\n  padding-top: 0.5rem;\n  padding-bottom: 0.5rem;\n  text-align: left;\n  font-weight: 600;\n  --tw-text-opacity: 1;\n  color: rgba(255, 255, 255, var(--tw-text-opacity));\n}\n\ntd {\n  border-width: 1px;\n  --tw-border-opacity: 1;\n  border-color: rgba(229, 229, 229, var(--tw-border-opacity));\n  padding: 0.75rem;\n  padding-top: 0.5rem;\n  padding-bottom: 0.5rem;\n  font-size: 0.875rem;\n  line-height: 1.25rem;\n}\n\n/* Position and style the close button (top right corner) */\n\n.sidenav .closebtn {\n  position: absolute;\n  top: 0;\n  right: 25px;\n  font-size: 28px;\n  margin-left: 50px;\n}\n\n@media screen and (max-height: 450px) {\n  .sidenav {\n    padding-top: 15px;\n  }\n\n  .sidenav a {\n    font-size: 18px;\n  }\n}\n\n.file\\:mr-4::-webkit-file-upload-button {\n  margin-right: 1rem;\n}\n\n.file\\:mr-4::file-selector-button {\n  margin-right: 1rem;\n}\n\n.file\\:rounded-full::-webkit-file-upload-button {\n  border-radius: 9999px;\n}\n\n.file\\:rounded-full::file-selector-button {\n  border-radius: 9999px;\n}\n\n.file\\:border-0::-webkit-file-upload-button {\n  border-width: 0px;\n}\n\n.file\\:border-0::file-selector-button {\n  border-width: 0px;\n}\n\n.file\\:bg-blue-50::-webkit-file-upload-button {\n  --tw-bg-opacity: 1;\n  background-color: rgba(239, 246, 255, var(--tw-bg-opacity));\n}\n\n.file\\:bg-blue-50::file-selector-button {\n  --tw-bg-opacity: 1;\n  background-color: rgba(239, 246, 255, var(--tw-bg-opacity));\n}\n\n.file\\:py-2::-webkit-file-upload-button {\n  padding-top: 0.5rem;\n  padding-bottom: 0.5rem;\n}\n\n.file\\:py-2::file-selector-button {\n  padding-top: 0.5rem;\n  padding-bottom: 0.5rem;\n}\n\n.file\\:px-4::-webkit-file-upload-button {\n  padding-left: 1rem;\n  padding-right: 1rem;\n}\n\n.file\\:px-4::file-selector-button {\n  padding-left: 1rem;\n  padding-right: 1rem;\n}\n\n.file\\:text-sm::-webkit-file-upload-button {\n  font-size: 0.875rem;\n  line-height: 1.25rem;\n}\n\n.file\\:text-sm::file-selector-button {\n  font-size: 0.875rem;\n  line-height: 1.25rem;\n}\n\n.file\\:font-semibold::-webkit-file-upload-button {\n  font-weight: 600;\n}\n\n.file\\:font-semibold::file-selector-button {\n  font-weight: 600;\n}\n\n.file\\:text-blue-700::-webkit-file-upload-button {\n  --tw-text-opacity: 1;\n  color: rgba(29, 78, 216, var(--tw-text-opacity));\n}\n\n.file\\:text-blue-700::file-selector-button {\n  --tw-text-opacity: 1;\n  color: rgba(29, 78, 216, var(--tw-text-opacity));\n}\n\n.hover\\:bg-blue-700:hover {\n  --tw-bg-opacity: 1;\n  background-color: rgba(29, 78, 216, var(--tw-bg-opacity));\n}\n\n.hover\\:bg-blue-400:hover {\n  --tw-bg-opacity: 1;\n  background-color: rgba(96, 165, 250, var(--tw-bg-opacity));\n}\n\n.hover\\:file\\:bg-blue-100::-webkit-file-upload-button:hover {\n  --tw-bg-opacity: 1;\n  background-color: rgba(219, 234, 254, var(--tw-bg-opacity));\n}\n\n.hover\\:file\\:bg-blue-100::file-selector-button:hover {\n  --tw-bg-opacity: 1;\n  background-color: rgba(219, 234, 254, var(--tw-bg-opacity));\n}\n\n.focus\\:border-blue-500:focus {\n  --tw-border-opacity: 1;\n  border-color: rgba(59, 130, 246, var(--tw-border-opacity));\n}\n\n.focus\\:border-indigo-500:focus {\n  --tw-border-opacity: 1;\n  border-color: rgba(99, 102, 241, var(--tw-border-opacity));\n}\n\n.focus\\:outline-none:focus {\n  outline: 2px solid transparent;\n  outline-offset: 2px;\n}\n\n.focus\\:ring-2:focus {\n  --tw-ring-offset-shadow: var(--tw-ring-inset) 0 0 0 var(--tw-ring-offset-width) var(--tw-ring-offset-color);\n  --tw-ring-shadow: var(--tw-ring-inset) 0 0 0 calc(2px + var(--tw-ring-offset-width)) var(--tw-ring-color);\n  box-shadow: var(--tw-ring-offset-shadow), var(--tw-ring-shadow), 0 0 rgba(0,0,0,0);\n  box-shadow: var(--tw-ring-offset-shadow), var(--tw-ring-shadow), 0 0 rgba(0,0,0,0);\n  box-shadow: var(--tw-ring-offset-shadow), var(--tw-ring-shadow), var(--tw-shadow, 0 0 rgba(0,0,0,0));\n}\n\n.focus\\:ring-indigo-500:focus {\n  --tw-ring-opacity: 1;\n  --tw-ring-color: rgba(99, 102, 241, var(--tw-ring-opacity));\n}\n\n.focus\\:ring-blue-500:focus {\n  --tw-ring-opacity: 1;\n  --tw-ring-color: rgba(59, 130, 246, var(--tw-ring-opacity));\n}\n\n.focus\\:ring-offset-2:focus {\n  --tw-ring-offset-width: 2px;\n}\n\n@media (min-width: 640px) {\n  .sm\\:col-span-3 {\n    grid-column: span 3 / span 3;\n  }\n\n  .sm\\:p-6 {\n    padding: 1.5rem;\n  }\n\n  .sm\\:px-4 {\n    padding-left: 1rem;\n    padding-right: 1rem;\n  }\n\n  .sm\\:px-6 {\n    padding-left: 1.5rem;\n    padding-right: 1.5rem;\n  }\n\n  .sm\\:py-0 {\n    padding-top: 0px;\n    padding-bottom: 0px;\n  }\n\n  .sm\\:pr-4 {\n    padding-right: 1rem;\n  }\n\n  .sm\\:pt-2 {\n    padding-top: 0.5rem;\n  }\n\n  .sm\\:text-sm {\n    font-size: 0.875rem;\n    line-height: 1.25rem;\n  }\n\n  .sm\\:font-semibold {\n    font-weight: 600;\n  }\n}\n\n@media (min-width: 768px) {\n  .md\\:mr-0 {\n    margin-right: 0px;\n  }\n\n  .md\\:mb-2 {\n    margin-bottom: 0.5rem;\n  }\n\n  .md\\:ml-0 {\n    margin-left: 0px;\n  }\n\n  .md\\:inline-flex {\n    display: inline-flex;\n  }\n\n  .md\\:grid-cols-3 {\n    grid-template-columns: repeat(3, minmax(0, 1fr));\n  }\n\n  .md\\:flex-col {\n    flex-direction: column;\n  }\n\n  .md\\:items-center {\n    align-items: center;\n  }\n\n  .md\\:space-y-4 > :not([hidden]) ~ :not([hidden]) {\n    --tw-space-y-reverse: 0;\n    margin-top: calc(1rem * (1 - var(--tw-space-y-reverse)));\n    margin-top: calc(1rem * calc(1 - var(--tw-space-y-reverse)));\n    margin-bottom: calc(1rem * var(--tw-space-y-reverse));\n  }\n\n  .md\\:py-\\[6px\\] {\n    padding-top: 6px;\n    padding-bottom: 6px;\n  }\n\n  .md\\:py-8 {\n    padding-top: 2rem;\n    padding-bottom: 2rem;\n  }\n\n  .md\\:text-left {\n    text-align: left;\n  }\n\n  .md\\:text-lg {\n    font-size: 1.125rem;\n    line-height: 1.75rem;\n  }\n\n  .md\\:text-5xl {\n    font-size: 3rem;\n    line-height: 1;\n  }\n}\n\n@media (min-width: 1024px) {\n  .lg\\:mx-auto {\n    margin-left: auto;\n    margin-right: auto;\n  }\n\n  .lg\\:my-auto {\n    margin-top: auto;\n    margin-bottom: auto;\n  }\n\n  .lg\\:my-5 {\n    margin-top: 1.25rem;\n    margin-bottom: 1.25rem;\n  }\n\n  .lg\\:mb-0 {\n    margin-bottom: 0px;\n  }\n\n  .lg\\:mt-2 {\n    margin-top: 0.5rem;\n  }\n\n  .lg\\:mb-5 {\n    margin-bottom: 1.25rem;\n  }\n\n  .lg\\:mb-2 {\n    margin-bottom: 0.5rem;\n  }\n\n  .lg\\:w-1\\/3 {\n    width: 33.333333%;\n  }\n\n  .lg\\:w-1\\/2 {\n    width: 50%;\n  }\n\n  .lg\\:rounded-t-md {\n    border-top-left-radius: 0.375rem;\n    border-top-right-radius: 0.375rem;\n  }\n\n  .lg\\:py-1 {\n    padding-top: 0.25rem;\n    padding-bottom: 0.25rem;\n  }\n\n  .lg\\:py-20 {\n    padding-top: 5rem;\n    padding-bottom: 5rem;\n  }\n\n  .lg\\:px-6 {\n    padding-left: 1.5rem;\n    padding-right: 1.5rem;\n  }\n\n  .lg\\:px-0 {\n    padding-left: 0px;\n    padding-right: 0px;\n  }\n\n  .lg\\:text-lg {\n    font-size: 1.125rem;\n    line-height: 1.75rem;\n  }\n}\n", "",{"version":3,"sources":["webpack://./src/styles.css"],"names":[],"mappings":"AAAA;;CAEC;;AAED;;;CAGC;;AAED;;;EAGE,sBAAsB;EACtB,MAAM;EACN,eAAe;EACf,MAAM;EACN,mBAAmB;EACnB,MAAM;EACN,qBAAqB;EACrB,MAAM;AACR;;AAEA;;EAEE,gBAAgB;AAClB;;AAEA;;;;;CAKC;;AAED;EACE,gBAAgB;EAChB,MAAM;EACN,8BAA8B;EAC9B,MAAM;EACN,gBAAgB;EAChB,MAAM;EACN,cAAc;KACX,WAAW;EACd,MAAM;EACN,wRAA4N;EAC5N,MAAM;AACR;;AAEA;;;CAGC;;AAED;EACE,SAAS;EACT,MAAM;EACN,oBAAoB;EACpB,MAAM;AACR;;AAEA;;;;CAIC;;AAED;EACE,SAAS;EACT,MAAM;EACN,cAAc;EACd,MAAM;EACN,qBAAqB;EACrB,MAAM;AACR;;AAEA;;CAEC;;AAED;EACE,yCAAyC;UACjC,0BAAiC;UAAjC,sDAAiC;kBAAjC,8CAAiC;AAC3C;;AAEA;;CAEC;;AAED;;;;;;EAME,kBAAkB;EAClB,oBAAoB;AACtB;;AAEA;;CAEC;;AAED;EACE,cAAc;EACd,wBAAwB;AAC1B;;AAEA;;CAEC;;AAED;;EAEE,mBAAmB;AACrB;;AAEA;;;CAGC;;AAED;;;;EAIE,+GAA+G;EAC/G,MAAM;EACN,cAAc;EACd,MAAM;AACR;;AAEA;;CAEC;;AAED;EACE,cAAc;AAChB;;AAEA;;CAEC;;AAED;;EAEE,cAAc;EACd,cAAc;EACd,kBAAkB;EAClB,wBAAwB;AAC1B;;AAEA;EACE,eAAe;AACjB;;AAEA;EACE,WAAW;AACb;;AAEA;;;;CAIC;;AAED;EACE,cAAc;EACd,MAAM;EACN,qBAAqB;EACrB,MAAM;EACN,yBAAyB;EACzB,MAAM;AACR;;AAEA;;;;CAIC;;AAED;;;;;EAKE,oBAAoB;EACpB,MAAM;EACN,eAAe;EACf,MAAM;EACN,oBAAoB;EACpB,MAAM;EACN,oBAAoB;EACpB,MAAM;EACN,cAAc;EACd,MAAM;EACN,SAAS;EACT,MAAM;EACN,UAAU;EACV,MAAM;AACR;;AAEA;;CAEC;;AAED;;EAEE,oBAAoB;AACtB;;AAEA;;;CAGC;;AAED;;;;EAIE,0BAA0B;EAC1B,MAAM;EACN,6BAA6B;EAC7B,MAAM;EACN,sBAAsB;EACtB,MAAM;AACR;;AAEA;;CAEC;;AAED;EACE,aAAa;AACf;;AAEA;;CAEC;;AAED;EACE,gBAAgB;AAClB;;AAEA;;CAEC;;AAED;EACE,wBAAwB;AAC1B;;AAEA;;CAEC;;AAED;;EAEE,YAAY;AACd;;AAEA;;;CAGC;;AAED;EACE,6BAA6B;EAC7B,MAAM;EACN,oBAAoB;EACpB,MAAM;AACR;;AAEA;;CAEC;;AAED;EACE,wBAAwB;AAC1B;;AAEA;;;CAGC;;AAED;EACE,0BAA0B;EAC1B,MAAM;EACN,aAAa;EACb,MAAM;AACR;;AAEA;;CAEC;;AAED;EACE,kBAAkB;AACpB;;AAEA;;CAEC;;AAED;;;;;;;;;;;;;EAaE,SAAS;AACX;;AAEA;EACE,SAAS;EACT,UAAU;AACZ;;AAEA;EACE,UAAU;AACZ;;AAEA;;;EAGE,gBAAgB;EAChB,SAAS;EACT,UAAU;AACZ;;AAEA;;CAEC;;AAED;EACE,gBAAgB;AAClB;;AAEA;;;CAGC;;AAED;EACE,UAAU;EACV,MAAM;EACN,cAAc;EACd,MAAM;AACR;;AAEA;;EAEE,UAAU;EACV,MAAM;EACN,cAAc;EACd,MAAM;AACR;;AAEA;;CAEC;;AAED;;EAEE,eAAe;AACjB;;AAEA;;CAEC;;AAED;EACE,eAAe;AACjB;;AAEA;;;;CAIC;;AAED;;;;;;;;EAQE,cAAc;EACd,MAAM;EACN,sBAAsB;EACtB,MAAM;AACR;;AAEA;;CAEC;;AAED;;EAEE,eAAe;EACf,YAAY;AACd;;AAEA;EACE,wBAAwB;KACrB,qBAAqB;UAChB,gBAAgB;EACxB,sBAAsB;EACtB,qBAAqB;EACrB,iBAAiB;EACjB,kBAAkB;EAClB,mBAAmB;EACnB,sBAAsB;EACtB,sBAAsB;EACtB,qBAAqB;EACrB,eAAe;EACf,mBAAmB;EACnB,8BAAsB;AACxB;;AAEA;EACE,8BAA8B;EAC9B,mBAAmB;EACnB,4CAA4C;EAC5C,2BAA2B;EAC3B,4BAA4B;EAC5B,wBAAwB;EACxB,2GAA2G;EAC3G,yGAAyG;EACzG,iFAAiF;EACjF,qBAAqB;AACvB;;AAEA;EACE,cAAc;EACd,UAAU;AACZ;;AAEA;EACE,cAAc;EACd,UAAU;AACZ;;AAEA;EACE,UAAU;AACZ;;AAEA;EACE,iBAAiB;AACnB;;AAEA;EACE,cAAc;EACd,iBAAiB;AACnB;;AAEA;EACE,yDAAmP;EACnP,wCAAwC;EACxC,4BAA4B;EAC5B,4BAA4B;EAC5B,qBAAqB;EACrB,iCAAiC;KAC9B,mBAAmB;UACd,yBAAyB;AACnC;;AAEA;EACE,sBAAyB;EAAzB,yBAAyB;EACzB,wBAA4B;EAA5B,4BAA4B;EAC5B,yBAAwB;EAAxB,0BAAwB;EACxB,0BAAwB;EAAxB,wBAAwB;EACxB,sBAAsB;EACtB,iCAAiC;KAC9B,qBAAmB;UACd,2BAAyB;AACnC;;AAEA;EACE,wBAAwB;KACrB,qBAAqB;UAChB,gBAAgB;EACxB,UAAU;EACV,iCAAiC;KAC9B,mBAAmB;UACd,yBAAyB;EACjC,qBAAqB;EACrB,sBAAsB;EACtB,6BAA6B;EAC7B,yBAAyB;KACtB,sBAAsB;UACjB,iBAAiB;EACzB,cAAc;EACd,YAAY;EACZ,WAAW;EACX,cAAc;EACd,sBAAsB;EACtB,qBAAqB;EACrB,iBAAiB;EACjB,8BAAsB;AACxB;;AAEA;EACE,kBAAkB;AACpB;;AAEA;EACE,mBAAmB;AACrB;;AAEA;EACE,8BAA8B;EAC9B,mBAAmB;EACnB,4CAA4C;EAC5C,2BAA2B;EAC3B,4BAA4B;EAC5B,wBAAwB;EACxB,2GAA2G;EAC3G,yGAAyG;EACzG,iFAAiF;AACnF;;AAEA;EACE,yBAAyB;EACzB,8BAA8B;EAC9B,0BAA0B;EAC1B,2BAA2B;EAC3B,4BAA4B;AAC9B;;AAEA;EACE,yDAAsQ;AACxQ;;AAEA;EACE,yDAAoK;AACtK;;AAEA;EACE,yBAAyB;EACzB,8BAA8B;AAChC;;AAEA;EACE,yDAAuO;EACvO,yBAAyB;EACzB,8BAA8B;EAC9B,0BAA0B;EAC1B,2BAA2B;EAC3B,4BAA4B;AAC9B;;AAEA;EACE,yBAAyB;EACzB,8BAA8B;AAChC;;AAEA;EACE,iFAAiB;EAAjB,mBAAiB;EACjB,qBAAqB;EACrB,eAAe;EACf,gBAAgB;EAChB,UAAU;EACV,kBAAgB;EAChB,oBAAoB;AACtB;;AAEA;EACE,6BAA6B;EAC7B,0CAA0C;AAC5C;;AAEA;EACE,wBAAwB;EACxB,wBAAwB;EACxB,mBAAmB;EACnB,mBAAmB;EACnB,cAAc;EACd,cAAc;EACd,cAAc;EACd,eAAe;EACf,eAAe;EACf,aAAa;EACb,aAAa;EACb,kBAAkB;EAClB,sCAAsC;EACtC,eAAe;EACf,oBAAoB;EACpB,sBAAsB;EACtB,uBAAuB;EACvB,wBAAwB;EACxB,kBAAkB;EAClB,2BAA2B;EAC3B,4BAA4B;EAC5B,wCAAsC;EACtC,0CAAkC;EAClC,mCAA2B;EAC3B,8BAAsB;EACtB,sCAA8B;EAC9B,YAAY;EACZ,kBAAkB;EAClB,gBAAgB;EAChB,iBAAiB;EACjB,kBAAkB;EAClB,cAAc;EACd,gBAAgB;EAChB,aAAa;EACb,mBAAmB;EACnB,qBAAqB;EACrB,2BAA2B;EAC3B,yBAAyB;EACzB,0BAA0B;EAC1B,2BAA2B;EAC3B,uBAAuB;EACvB,wBAAwB;EACxB,yBAAyB;EACzB,sBAAsB;AACxB;;AAEA;EACE,wBAAwB;EACxB,wBAAwB;EACxB,mBAAmB;EACnB,mBAAmB;EACnB,cAAc;EACd,cAAc;EACd,cAAc;EACd,eAAe;EACf,eAAe;EACf,aAAa;EACb,aAAa;EACb,kBAAkB;EAClB,sCAAsC;EACtC,eAAe;EACf,oBAAoB;EACpB,sBAAsB;EACtB,uBAAuB;EACvB,wBAAwB;EACxB,kBAAkB;EAClB,2BAA2B;EAC3B,4BAA4B;EAC5B,wCAAsC;EACtC,0CAAkC;EAClC,mCAA2B;EAC3B,8BAAsB;EACtB,sCAA8B;EAC9B,YAAY;EACZ,kBAAkB;EAClB,gBAAgB;EAChB,iBAAiB;EACjB,kBAAkB;EAClB,cAAc;EACd,gBAAgB;EAChB,aAAa;EACb,mBAAmB;EACnB,qBAAqB;EACrB,2BAA2B;EAC3B,yBAAyB;EACzB,0BAA0B;EAC1B,2BAA2B;EAC3B,uBAAuB;EACvB,wBAAwB;EACxB,yBAAyB;EACzB,sBAAsB;AACxB;;AAEA;EACE,wBAAwB;EACxB,wBAAwB;EACxB,mBAAmB;EACnB,mBAAmB;EACnB,cAAc;EACd,cAAc;EACd,cAAc;EACd,eAAe;EACf,eAAe;EACf,aAAa;EACb,aAAa;EACb,kBAAkB;EAClB,sCAAsC;EACtC,eAAe;EACf,oBAAoB;EACpB,sBAAsB;EACtB,uBAAuB;EACvB,wBAAwB;EACxB,kBAAkB;EAClB,2BAA2B;EAC3B,4BAA4B;EAC5B,wCAAsC;EACtC,0CAAkC;EAClC,mCAA2B;EAC3B,8BAAsB;EACtB,sCAA8B;EAC9B,YAAY;EACZ,kBAAkB;EAClB,gBAAgB;EAChB,iBAAiB;EACjB,kBAAkB;EAClB,cAAc;EACd,gBAAgB;EAChB,aAAa;EACb,mBAAmB;EACnB,qBAAqB;EACrB,2BAA2B;EAC3B,yBAAyB;EACzB,0BAA0B;EAC1B,2BAA2B;EAC3B,uBAAuB;EACvB,wBAAwB;EACxB,yBAAyB;EACzB,sBAAsB;AACxB;;AAEA;EACE,kBAAkB;EAClB,UAAU;EACV,WAAW;EACX,UAAU;EACV,YAAY;EACZ,gBAAgB;EAChB,sBAAsB;EACtB,mBAAmB;EACnB,eAAe;AACjB;;AAEA;EACE,4BAA4B;AAC9B;;AAEA;EACE,cAAc;AAChB;;AAEA;EACE,iBAAiB;EACjB,kBAAkB;AACpB;;AAEA;EACE,gBAAgB;EAChB,mBAAmB;AACrB;;AAEA;EACE,iBAAiB;EACjB,kBAAkB;AACpB;;AAEA;EACE,gBAAgB;EAChB,mBAAmB;AACrB;;AAEA;EACE,mBAAmB;EACnB,sBAAsB;AACxB;;AAEA;EACE,gBAAgB;AAClB;;AAEA;EACE,sBAAsB;AACxB;;AAEA;EACE,kBAAkB;AACpB;;AAEA;EACE,mBAAmB;AACrB;;AAEA;EACE,oBAAoB;AACtB;;AAEA;EACE,iBAAiB;AACnB;;AAEA;EACE,kBAAkB;AACpB;;AAEA;EACE,kBAAkB;AACpB;;AAEA;EACE,kBAAkB;AACpB;;AAEA;EACE,qBAAqB;AACvB;;AAEA;EACE,mBAAmB;AACrB;;AAEA;EACE,sBAAsB;AACxB;;AAEA;EACE,qBAAqB;AACvB;;AAEA;EACE,mBAAmB;AACrB;;AAEA;EACE,iBAAiB;AACnB;;AAEA;EACE,eAAe;AACjB;;AAEA;EACE,eAAe;AACjB;;AAEA;EACE,sBAAsB;AACxB;;AAEA;EACE,mBAAmB;AACrB;;AAEA;EACE,mBAAmB;AACrB;;AAEA;EACE,cAAc;AAChB;;AAEA;EACE,aAAa;AACf;;AAEA;EACE,oBAAoB;AACtB;;AAEA;EACE,aAAa;AACf;;AAEA;EACE,aAAa;AACf;;AAEA;EACE,aAAa;AACf;;AAEA;EACE,YAAY;AACd;;AAEA;EACE,WAAW;AACb;;AAEA;EACE,YAAY;AACd;;AAEA;EACE,WAAW;AACb;;AAEA;EACE,WAAW;AACb;;AAEA;EACE,WAAW;AACb;;AAEA;EACE,gBAAgB;AAClB;;AAEA;EACE,gDAAgD;AAClD;;AAEA;EACE,mBAAmB;AACrB;;AAEA;EACE,sBAAsB;AACxB;;AAEA;EACE,qBAAqB;AACvB;;AAEA;EACE,mBAAmB;AACrB;;AAEA;EACE,uBAAuB;AACzB;;AAEA;EACE,uBAAuB;EACvB,uDAA2D;EAA3D,2DAA2D;EAC3D,oDAAoD;AACtD;;AAEA;EACE,gBAAgB;AAClB;;AAEA;EACE,gBAAgB;AAClB;;AAEA;EACE,qBAAqB;AACvB;;AAEA;EACE,kBAAkB;AACpB;;AAEA;EACE,oCAAoC;EACpC,mCAAmC;AACrC;;AAEA;EACE,iBAAiB;AACnB;;AAEA;EACE,wBAAwB;AAC1B;;AAEA;EACE,sBAAsB;EACtB,2DAAyD;AAC3D;;AAEA;EACE,yBAAyB;AAC3B;;AAEA;EACE,sBAAsB;EACtB,2DAAyD;AAC3D;;AAEA;EACE,sBAAsB;EACtB,2DAAyD;AAC3D;;AAEA;EACE,sBAAsB;EACtB,2DAAyD;AAC3D;;AAEA;EACE,kBAAkB;EAClB,2DAAyD;AAC3D;;AAEA;EACE,kBAAkB;EAClB,0DAAwD;AAC1D;;AAEA;EACE,kBAAkB;EAClB,2DAAyD;AAC3D;;AAEA;EACE,kBAAkB;EAClB,yDAAuD;AACzD;;AAEA;EACE,kBAAkB;EAClB,2DAAyD;AAC3D;;AAEA;EACE,4EAA4E;AAC9E;;AAEA;EACE,2BAA2B;EAC3B,uCAAqC;EACrC,mEAAmE;AACrE;;AAEA;EACE,2BAA2B;EAC3B,uCAAqC;EACrC,mEAAmE;AACrE;;AAEA;EACE,2BAA2B;EAC3B,qCAAmC;EACnC,mEAAmE;AACrE;;AAEA;EACE,2BAA2B;EAC3B,sCAAoC;EACpC,mEAAmE;AACrE;;AAEA;EACE,2BAA2B;EAC3B,uCAAqC;EACrC,mEAAmE;AACrE;;AAEA;EACE,2BAA2B;EAC3B,sCAAoC;EACpC,mEAAmE;AACrE;;AAEA;EACE,yBAAyB;AAC3B;;AAEA;EACE,yBAAyB;AAC3B;;AAEA;EACE,yBAAyB;AAC3B;;AAEA;EACE,yBAAyB;AAC3B;;AAEA;EACE,yBAAyB;AAC3B;;AAEA;EACE,yBAAyB;AAC3B;;AAEA;EACE,eAAe;AACjB;;AAEA;EACE,mBAAmB;EACnB,sBAAsB;AACxB;;AAEA;EACE,kBAAkB;EAClB,mBAAmB;AACrB;;AAEA;EACE,gBAAgB;EAChB,mBAAmB;AACrB;;AAEA;EACE,iBAAiB;EACjB,kBAAkB;AACpB;;AAEA;EACE,oBAAoB;EACpB,qBAAqB;AACvB;;AAEA;EACE,iBAAiB;EACjB,oBAAoB;AACtB;;AAEA;EACE,oBAAoB;EACpB,uBAAuB;AACzB;;AAEA;EACE,iBAAiB;EACjB,oBAAoB;AACtB;;AAEA;EACE,qBAAqB;EACrB,sBAAsB;AACxB;;AAEA;EACE,oBAAoB;EACpB,uBAAuB;AACzB;;AAEA;EACE,gBAAgB;EAChB,mBAAmB;AACrB;;AAEA;EACE,kBAAkB;EAClB,mBAAmB;AACrB;;AAEA;EACE,gBAAgB;EAChB,mBAAmB;AACrB;;AAEA;EACE,qBAAqB;EACrB,sBAAsB;AACxB;;AAEA;EACE,sBAAsB;AACxB;;AAEA;EACE,mBAAmB;AACrB;;AAEA;EACE,iBAAiB;AACnB;;AAEA;EACE,mBAAmB;EACnB,oBAAoB;AACtB;;AAEA;EACE,mBAAmB;EACnB,oBAAoB;AACtB;;AAEA;EACE,iBAAiB;EACjB,iBAAiB;AACnB;;AAEA;EACE,gBAAgB;AAClB;;AAEA;EACE,gBAAgB;AAClB;;AAEA;EACE,gBAAgB;AAClB;;AAEA;EACE,mBAAmB;AACrB;;AAEA;EACE,oBAAoB;EACpB,+CAA6C;AAC/C;;AAEA;EACE,oBAAoB;EACpB,kDAAgD;AAClD;;AAEA;EACE,oBAAoB;EACpB,iDAA+C;AACjD;;AAEA;EACE,oBAAoB;EACpB,+CAA6C;AAC/C;;AAEA;EACE,oBAAoB;EACpB,kDAAgD;AAClD;;AAEA;EACE,oBAAoB;EACpB,iDAA+C;AACjD;;AAEA;EACE,oBAAoB;EACpB,+CAA6C;AAC/C;;AAEA;EACE,oBAAoB;EACpB,kDAAgD;AAClD;;AAEA;EACE,mFAA+E;EAC/E,mGAAmG;EACnG,kEAAuG;EAAvG,kEAAuG;EAAvG,uHAAuG;AACzG;;AAEA;EACE,4CAA0C;EAC1C,uDAAuD;EACvD,kEAAuG;EAAvG,kEAAuG;EAAvG,uHAAuG;AACzG;;AAEA;EACE,8EAA0E;EAC1E,8FAA8F;EAC9F,kEAAuG;EAAvG,kEAAuG;EAAvG,uHAAuG;AACzG;;AAEA;EACE,8BAA8B;EAC9B,mBAAmB;AACrB;;AAEA;EACE,mBAAmB;AACrB;;AAEA;EACE,oBAAoB;AACtB;;AAEA;EACE,yCAAyC;EACzC,cAAc;EACd,uBAAuB;EACvB,cAAc;EACd,YAAY;EACZ,qBAAqB;EACrB,qBAAqB;AACvB;;AAEA;EACE,YAAY;EACZ,qBAAqB;EACrB,QAAQ;EACR,0CAA0C;EAC1C,eAAe;EACf,kBAAkB;EAClB,UAAU;EACV,gBAAgB;EAChB,MAAM;EACN,oBAAoB;EACpB,OAAO;EACP,kBAAkB;EAClB,8BAA8B;EAC9B,iBAAiB;EACjB,oCAAoC;EACpC,gBAAgB;EAChB,yDAAyD;AAC3D;;AAEA,8BAA8B;;AAE9B;EACE,cAAc;AAChB;;AAEA;EACE,wBAAwB;KACrB,qBAAqB;UAChB,gBAAgB;EACxB,sBAAsB;EACtB,qBAAqB;EACrB,iBAAiB;EACjB,kBAAkB;EAClB,mBAAmB;EACnB,sBAAsB;EACtB,sBAAsB;EACtB,qBAAqB;EACrB,eAAe;EACf,mBAAmB;EACnB,8BAAsB;AACxB;;CAEC;EACC,8BAA8B;EAC9B,mBAAmB;EACnB,4CAA4C;EAC5C,2BAA2B;EAC3B,4BAA4B;EAC5B,wBAAwB;EACxB,2GAA2G;EAC3G,yGAAyG;EACzG,iFAAiF;EACjF,qBAAqB;AACvB;;AAEA;EACE,yDAAmP;EACnP,wCAAwC;EACxC,4BAA4B;EAC5B,iCAAiC;KAC9B,mBAAmB;UACd,yBAAyB;EACjC,WAAW;EACX,kBAAkB;EAClB,cAAc;EACd,WAAW;EACX,wBAAwB;KACrB,qBAAqB;UAChB,gBAAgB;EACxB,sBAAsB;EACtB,iBAAiB;EACjB,mBAAmB;EACnB,sBAAsB;EACtB,2DAAyD;EACzD,kBAAkB;EAClB,2DAAyD;EACzD,4BAA4B;EAC5B,4BAA4B;EAC5B,qBAAqB;EACrB,sBAAsB;EACtB,qBAAqB;EACrB,wBAAwB;EACxB,eAAe;EACf,mBAAmB;EACnB,gBAAgB;EAChB,oBAAoB;EACpB,+CAA6C;EAC7C,wKAAwK;EACxK,wJAAwJ;EACxJ,gNAAgN;EAChN,0BAA0B;EAC1B,wDAAwD;AAC1D;;AAEA;EACE,sBAAsB;EACtB,yDAAuD;EACvD,kBAAkB;EAClB,2DAAyD;EACzD,oBAAoB;EACpB,+CAA6C;EAC7C,8BAA8B;EAC9B,mBAAmB;AACrB;;AAEA;EACE,iBAAiB;EACjB,kBAAkB;EAClB,kBAAkB;EAClB,qBAAqB;EACrB,iBAAiB;EACjB,iBAAiB;EACjB,sBAAsB;EACtB,2DAAyD;EACzD,oBAAoB;AACtB;;AAEA;EACE,iBAAiB;EACjB,sBAAsB;EACtB,2DAAyD;EACzD,kBAAkB;EAClB,0DAAwD;EACxD,gBAAgB;EAChB,mBAAmB;EACnB,sBAAsB;EACtB,gBAAgB;EAChB,gBAAgB;EAChB,oBAAoB;EACpB,kDAAgD;AAClD;;AAEA;EACE,iBAAiB;EACjB,sBAAsB;EACtB,2DAAyD;EACzD,gBAAgB;EAChB,mBAAmB;EACnB,sBAAsB;EACtB,mBAAmB;EACnB,oBAAoB;AACtB;;AAEA,2DAA2D;;AAE3D;EACE,kBAAkB;EAClB,MAAM;EACN,WAAW;EACX,eAAe;EACf,iBAAiB;AACnB;;AAEA;EACE;IACE,iBAAiB;EACnB;;EAEA;IACE,eAAe;EACjB;AACF;;AAEA;EACE,kBAAkB;AACpB;;AAEA;EACE,kBAAkB;AACpB;;AAEA;EACE,qBAAqB;AACvB;;AAEA;EACE,qBAAqB;AACvB;;AAEA;EACE,iBAAiB;AACnB;;AAEA;EACE,iBAAiB;AACnB;;AAEA;EACE,kBAAkB;EAClB,2DAAyD;AAC3D;;AAEA;EACE,kBAAkB;EAClB,2DAAyD;AAC3D;;AAEA;EACE,mBAAmB;EACnB,sBAAsB;AACxB;;AAEA;EACE,mBAAmB;EACnB,sBAAsB;AACxB;;AAEA;EACE,kBAAkB;EAClB,mBAAmB;AACrB;;AAEA;EACE,kBAAkB;EAClB,mBAAmB;AACrB;;AAEA;EACE,mBAAmB;EACnB,oBAAoB;AACtB;;AAEA;EACE,mBAAmB;EACnB,oBAAoB;AACtB;;AAEA;EACE,gBAAgB;AAClB;;AAEA;EACE,gBAAgB;AAClB;;AAEA;EACE,oBAAoB;EACpB,gDAA8C;AAChD;;AAEA;EACE,oBAAoB;EACpB,gDAA8C;AAChD;;AAEA;EACE,kBAAkB;EAClB,yDAAuD;AACzD;;AAEA;EACE,kBAAkB;EAClB,0DAAwD;AAC1D;;AAEA;EACE,kBAAkB;EAClB,2DAAyD;AAC3D;;AAEA;EACE,kBAAkB;EAClB,2DAAyD;AAC3D;;AAEA;EACE,sBAAsB;EACtB,0DAAwD;AAC1D;;AAEA;EACE,sBAAsB;EACtB,0DAAwD;AAC1D;;AAEA;EACE,8BAA8B;EAC9B,mBAAmB;AACrB;;AAEA;EACE,2GAA2G;EAC3G,yGAAyG;EACzG,kFAA4F;EAA5F,kFAA4F;EAA5F,oGAA4F;AAC9F;;AAEA;EACE,oBAAoB;EACpB,2DAAyD;AAC3D;;AAEA;EACE,oBAAoB;EACpB,2DAAyD;AAC3D;;AAEA;EACE,2BAA2B;AAC7B;;AAEA;EACE;IACE,4BAA4B;EAC9B;;EAEA;IACE,eAAe;EACjB;;EAEA;IACE,kBAAkB;IAClB,mBAAmB;EACrB;;EAEA;IACE,oBAAoB;IACpB,qBAAqB;EACvB;;EAEA;IACE,gBAAgB;IAChB,mBAAmB;EACrB;;EAEA;IACE,mBAAmB;EACrB;;EAEA;IACE,mBAAmB;EACrB;;EAEA;IACE,mBAAmB;IACnB,oBAAoB;EACtB;;EAEA;IACE,gBAAgB;EAClB;AACF;;AAEA;EACE;IACE,iBAAiB;EACnB;;EAEA;IACE,qBAAqB;EACvB;;EAEA;IACE,gBAAgB;EAClB;;EAEA;IACE,oBAAoB;EACtB;;EAEA;IACE,gDAAgD;EAClD;;EAEA;IACE,sBAAsB;EACxB;;EAEA;IACE,mBAAmB;EACrB;;EAEA;IACE,uBAAuB;IACvB,wDAA4D;IAA5D,4DAA4D;IAC5D,qDAAqD;EACvD;;EAEA;IACE,gBAAgB;IAChB,mBAAmB;EACrB;;EAEA;IACE,iBAAiB;IACjB,oBAAoB;EACtB;;EAEA;IACE,gBAAgB;EAClB;;EAEA;IACE,mBAAmB;IACnB,oBAAoB;EACtB;;EAEA;IACE,eAAe;IACf,cAAc;EAChB;AACF;;AAEA;EACE;IACE,iBAAiB;IACjB,kBAAkB;EACpB;;EAEA;IACE,gBAAgB;IAChB,mBAAmB;EACrB;;EAEA;IACE,mBAAmB;IACnB,sBAAsB;EACxB;;EAEA;IACE,kBAAkB;EACpB;;EAEA;IACE,kBAAkB;EACpB;;EAEA;IACE,sBAAsB;EACxB;;EAEA;IACE,qBAAqB;EACvB;;EAEA;IACE,iBAAiB;EACnB;;EAEA;IACE,UAAU;EACZ;;EAEA;IACE,gCAAgC;IAChC,iCAAiC;EACnC;;EAEA;IACE,oBAAoB;IACpB,uBAAuB;EACzB;;EAEA;IACE,iBAAiB;IACjB,oBAAoB;EACtB;;EAEA;IACE,oBAAoB;IACpB,qBAAqB;EACvB;;EAEA;IACE,iBAAiB;IACjB,kBAAkB;EACpB;;EAEA;IACE,mBAAmB;IACnB,oBAAoB;EACtB;AACF","sourcesContent":["/*\n! tailwindcss v3.1.8 | MIT License | https://tailwindcss.com\n*/\n\n/*\n1. Prevent padding and border from affecting element width. (https://github.com/mozdevs/cssremedy/issues/4)\n2. Allow adding a border to an element by just adding a border-width. (https://github.com/tailwindcss/tailwindcss/pull/116)\n*/\n\n*,\n::before,\n::after {\n  box-sizing: border-box;\n  /* 1 */\n  border-width: 0;\n  /* 2 */\n  border-style: solid;\n  /* 2 */\n  border-color: #e5e7eb;\n  /* 2 */\n}\n\n::before,\n::after {\n  --tw-content: '';\n}\n\n/*\n1. Use a consistent sensible line-height in all browsers.\n2. Prevent adjustments of font size after orientation changes in iOS.\n3. Use a more readable tab size.\n4. Use the user's configured `sans` font-family by default.\n*/\n\nhtml {\n  line-height: 1.5;\n  /* 1 */\n  -webkit-text-size-adjust: 100%;\n  /* 2 */\n  -moz-tab-size: 4;\n  /* 3 */\n  -o-tab-size: 4;\n     tab-size: 4;\n  /* 3 */\n  font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, \"Segoe UI\", Roboto, \"Helvetica Neue\", Arial, \"Noto Sans\", sans-serif, \"Apple Color Emoji\", \"Segoe UI Emoji\", \"Segoe UI Symbol\", \"Noto Color Emoji\";\n  /* 4 */\n}\n\n/*\n1. Remove the margin in all browsers.\n2. Inherit line-height from `html` so users can set them as a class directly on the `html` element.\n*/\n\nbody {\n  margin: 0;\n  /* 1 */\n  line-height: inherit;\n  /* 2 */\n}\n\n/*\n1. Add the correct height in Firefox.\n2. Correct the inheritance of border color in Firefox. (https://bugzilla.mozilla.org/show_bug.cgi?id=190655)\n3. Ensure horizontal rules are visible by default.\n*/\n\nhr {\n  height: 0;\n  /* 1 */\n  color: inherit;\n  /* 2 */\n  border-top-width: 1px;\n  /* 3 */\n}\n\n/*\nAdd the correct text decoration in Chrome, Edge, and Safari.\n*/\n\nabbr:where([title]) {\n  -webkit-text-decoration: underline dotted;\n          text-decoration: underline dotted;\n}\n\n/*\nRemove the default font size and weight for headings.\n*/\n\nh1,\nh2,\nh3,\nh4,\nh5,\nh6 {\n  font-size: inherit;\n  font-weight: inherit;\n}\n\n/*\nReset links to optimize for opt-in styling instead of opt-out.\n*/\n\na {\n  color: inherit;\n  text-decoration: inherit;\n}\n\n/*\nAdd the correct font weight in Edge and Safari.\n*/\n\nb,\nstrong {\n  font-weight: bolder;\n}\n\n/*\n1. Use the user's configured `mono` font family by default.\n2. Correct the odd `em` font sizing in all browsers.\n*/\n\ncode,\nkbd,\nsamp,\npre {\n  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, \"Liberation Mono\", \"Courier New\", monospace;\n  /* 1 */\n  font-size: 1em;\n  /* 2 */\n}\n\n/*\nAdd the correct font size in all browsers.\n*/\n\nsmall {\n  font-size: 80%;\n}\n\n/*\nPrevent `sub` and `sup` elements from affecting the line height in all browsers.\n*/\n\nsub,\nsup {\n  font-size: 75%;\n  line-height: 0;\n  position: relative;\n  vertical-align: baseline;\n}\n\nsub {\n  bottom: -0.25em;\n}\n\nsup {\n  top: -0.5em;\n}\n\n/*\n1. Remove text indentation from table contents in Chrome and Safari. (https://bugs.chromium.org/p/chromium/issues/detail?id=999088, https://bugs.webkit.org/show_bug.cgi?id=201297)\n2. Correct table border color inheritance in all Chrome and Safari. (https://bugs.chromium.org/p/chromium/issues/detail?id=935729, https://bugs.webkit.org/show_bug.cgi?id=195016)\n3. Remove gaps between table borders by default.\n*/\n\ntable {\n  text-indent: 0;\n  /* 1 */\n  border-color: inherit;\n  /* 2 */\n  border-collapse: collapse;\n  /* 3 */\n}\n\n/*\n1. Change the font styles in all browsers.\n2. Remove the margin in Firefox and Safari.\n3. Remove default padding in all browsers.\n*/\n\nbutton,\ninput,\noptgroup,\nselect,\ntextarea {\n  font-family: inherit;\n  /* 1 */\n  font-size: 100%;\n  /* 1 */\n  font-weight: inherit;\n  /* 1 */\n  line-height: inherit;\n  /* 1 */\n  color: inherit;\n  /* 1 */\n  margin: 0;\n  /* 2 */\n  padding: 0;\n  /* 3 */\n}\n\n/*\nRemove the inheritance of text transform in Edge and Firefox.\n*/\n\nbutton,\nselect {\n  text-transform: none;\n}\n\n/*\n1. Correct the inability to style clickable types in iOS and Safari.\n2. Remove default button styles.\n*/\n\nbutton,\n[type='button'],\n[type='reset'],\n[type='submit'] {\n  -webkit-appearance: button;\n  /* 1 */\n  background-color: transparent;\n  /* 2 */\n  background-image: none;\n  /* 2 */\n}\n\n/*\nUse the modern Firefox focus style for all focusable elements.\n*/\n\n:-moz-focusring {\n  outline: auto;\n}\n\n/*\nRemove the additional `:invalid` styles in Firefox. (https://github.com/mozilla/gecko-dev/blob/2f9eacd9d3d995c937b4251a5557d95d494c9be1/layout/style/res/forms.css#L728-L737)\n*/\n\n:-moz-ui-invalid {\n  box-shadow: none;\n}\n\n/*\nAdd the correct vertical alignment in Chrome and Firefox.\n*/\n\nprogress {\n  vertical-align: baseline;\n}\n\n/*\nCorrect the cursor style of increment and decrement buttons in Safari.\n*/\n\n::-webkit-inner-spin-button,\n::-webkit-outer-spin-button {\n  height: auto;\n}\n\n/*\n1. Correct the odd appearance in Chrome and Safari.\n2. Correct the outline style in Safari.\n*/\n\n[type='search'] {\n  -webkit-appearance: textfield;\n  /* 1 */\n  outline-offset: -2px;\n  /* 2 */\n}\n\n/*\nRemove the inner padding in Chrome and Safari on macOS.\n*/\n\n::-webkit-search-decoration {\n  -webkit-appearance: none;\n}\n\n/*\n1. Correct the inability to style clickable types in iOS and Safari.\n2. Change font properties to `inherit` in Safari.\n*/\n\n::-webkit-file-upload-button {\n  -webkit-appearance: button;\n  /* 1 */\n  font: inherit;\n  /* 2 */\n}\n\n/*\nAdd the correct display in Chrome and Safari.\n*/\n\nsummary {\n  display: list-item;\n}\n\n/*\nRemoves the default spacing and border for appropriate elements.\n*/\n\nblockquote,\ndl,\ndd,\nh1,\nh2,\nh3,\nh4,\nh5,\nh6,\nhr,\nfigure,\np,\npre {\n  margin: 0;\n}\n\nfieldset {\n  margin: 0;\n  padding: 0;\n}\n\nlegend {\n  padding: 0;\n}\n\nol,\nul,\nmenu {\n  list-style: none;\n  margin: 0;\n  padding: 0;\n}\n\n/*\nPrevent resizing textareas horizontally by default.\n*/\n\ntextarea {\n  resize: vertical;\n}\n\n/*\n1. Reset the default placeholder opacity in Firefox. (https://github.com/tailwindlabs/tailwindcss/issues/3300)\n2. Set the default placeholder color to the user's configured gray 400 color.\n*/\n\ninput::-moz-placeholder, textarea::-moz-placeholder {\n  opacity: 1;\n  /* 1 */\n  color: #9ca3af;\n  /* 2 */\n}\n\ninput::placeholder,\ntextarea::placeholder {\n  opacity: 1;\n  /* 1 */\n  color: #9ca3af;\n  /* 2 */\n}\n\n/*\nSet the default cursor for buttons.\n*/\n\nbutton,\n[role=\"button\"] {\n  cursor: pointer;\n}\n\n/*\nMake sure disabled buttons don't get the pointer cursor.\n*/\n\n:disabled {\n  cursor: default;\n}\n\n/*\n1. Make replaced elements `display: block` by default. (https://github.com/mozdevs/cssremedy/issues/14)\n2. Add `vertical-align: middle` to align replaced elements more sensibly by default. (https://github.com/jensimmons/cssremedy/issues/14#issuecomment-634934210)\n   This can trigger a poorly considered lint error in some tools but is included by design.\n*/\n\nimg,\nsvg,\nvideo,\ncanvas,\naudio,\niframe,\nembed,\nobject {\n  display: block;\n  /* 1 */\n  vertical-align: middle;\n  /* 2 */\n}\n\n/*\nConstrain images and videos to the parent width and preserve their intrinsic aspect ratio. (https://github.com/mozdevs/cssremedy/issues/14)\n*/\n\nimg,\nvideo {\n  max-width: 100%;\n  height: auto;\n}\n\n[type='text'],[type='email'],[type='url'],[type='password'],[type='number'],[type='date'],[type='datetime-local'],[type='month'],[type='search'],[type='tel'],[type='time'],[type='week'],[multiple],textarea,select {\n  -webkit-appearance: none;\n     -moz-appearance: none;\n          appearance: none;\n  background-color: #fff;\n  border-color: #6b7280;\n  border-width: 1px;\n  border-radius: 0px;\n  padding-top: 0.5rem;\n  padding-right: 0.75rem;\n  padding-bottom: 0.5rem;\n  padding-left: 0.75rem;\n  font-size: 1rem;\n  line-height: 1.5rem;\n  --tw-shadow: 0 0 #0000;\n}\n\n[type='text']:focus, [type='email']:focus, [type='url']:focus, [type='password']:focus, [type='number']:focus, [type='date']:focus, [type='datetime-local']:focus, [type='month']:focus, [type='search']:focus, [type='tel']:focus, [type='time']:focus, [type='week']:focus, [multiple]:focus, textarea:focus, select:focus {\n  outline: 2px solid transparent;\n  outline-offset: 2px;\n  --tw-ring-inset: var(--tw-empty,/*!*/ /*!*/);\n  --tw-ring-offset-width: 0px;\n  --tw-ring-offset-color: #fff;\n  --tw-ring-color: #2563eb;\n  --tw-ring-offset-shadow: var(--tw-ring-inset) 0 0 0 var(--tw-ring-offset-width) var(--tw-ring-offset-color);\n  --tw-ring-shadow: var(--tw-ring-inset) 0 0 0 calc(1px + var(--tw-ring-offset-width)) var(--tw-ring-color);\n  box-shadow: var(--tw-ring-offset-shadow), var(--tw-ring-shadow), var(--tw-shadow);\n  border-color: #2563eb;\n}\n\ninput::-moz-placeholder, textarea::-moz-placeholder {\n  color: #6b7280;\n  opacity: 1;\n}\n\ninput::placeholder,textarea::placeholder {\n  color: #6b7280;\n  opacity: 1;\n}\n\n::-webkit-datetime-edit-fields-wrapper {\n  padding: 0;\n}\n\n::-webkit-date-and-time-value {\n  min-height: 1.5em;\n}\n\n::-webkit-datetime-edit,::-webkit-datetime-edit-year-field,::-webkit-datetime-edit-month-field,::-webkit-datetime-edit-day-field,::-webkit-datetime-edit-hour-field,::-webkit-datetime-edit-minute-field,::-webkit-datetime-edit-second-field,::-webkit-datetime-edit-millisecond-field,::-webkit-datetime-edit-meridiem-field {\n  padding-top: 0;\n  padding-bottom: 0;\n}\n\nselect {\n  background-image: url(\"data:image/svg+xml,%3csvg xmlns='http://www.w3.org/2000/svg' fill='none' viewBox='0 0 20 20'%3e%3cpath stroke='%236b7280' stroke-linecap='round' stroke-linejoin='round' stroke-width='1.5' d='M6 8l4 4 4-4'/%3e%3c/svg%3e\");\n  background-position: right 0.5rem center;\n  background-repeat: no-repeat;\n  background-size: 1.5em 1.5em;\n  padding-right: 2.5rem;\n  -webkit-print-color-adjust: exact;\n     color-adjust: exact;\n          print-color-adjust: exact;\n}\n\n[multiple] {\n  background-image: initial;\n  background-position: initial;\n  background-repeat: unset;\n  background-size: initial;\n  padding-right: 0.75rem;\n  -webkit-print-color-adjust: unset;\n     color-adjust: unset;\n          print-color-adjust: unset;\n}\n\n[type='checkbox'],[type='radio'] {\n  -webkit-appearance: none;\n     -moz-appearance: none;\n          appearance: none;\n  padding: 0;\n  -webkit-print-color-adjust: exact;\n     color-adjust: exact;\n          print-color-adjust: exact;\n  display: inline-block;\n  vertical-align: middle;\n  background-origin: border-box;\n  -webkit-user-select: none;\n     -moz-user-select: none;\n          user-select: none;\n  flex-shrink: 0;\n  height: 1rem;\n  width: 1rem;\n  color: #2563eb;\n  background-color: #fff;\n  border-color: #6b7280;\n  border-width: 1px;\n  --tw-shadow: 0 0 #0000;\n}\n\n[type='checkbox'] {\n  border-radius: 0px;\n}\n\n[type='radio'] {\n  border-radius: 100%;\n}\n\n[type='checkbox']:focus,[type='radio']:focus {\n  outline: 2px solid transparent;\n  outline-offset: 2px;\n  --tw-ring-inset: var(--tw-empty,/*!*/ /*!*/);\n  --tw-ring-offset-width: 2px;\n  --tw-ring-offset-color: #fff;\n  --tw-ring-color: #2563eb;\n  --tw-ring-offset-shadow: var(--tw-ring-inset) 0 0 0 var(--tw-ring-offset-width) var(--tw-ring-offset-color);\n  --tw-ring-shadow: var(--tw-ring-inset) 0 0 0 calc(2px + var(--tw-ring-offset-width)) var(--tw-ring-color);\n  box-shadow: var(--tw-ring-offset-shadow), var(--tw-ring-shadow), var(--tw-shadow);\n}\n\n[type='checkbox']:checked,[type='radio']:checked {\n  border-color: transparent;\n  background-color: currentColor;\n  background-size: 100% 100%;\n  background-position: center;\n  background-repeat: no-repeat;\n}\n\n[type='checkbox']:checked {\n  background-image: url(\"data:image/svg+xml,%3csvg viewBox='0 0 16 16' fill='white' xmlns='http://www.w3.org/2000/svg'%3e%3cpath d='M12.207 4.793a1 1 0 010 1.414l-5 5a1 1 0 01-1.414 0l-2-2a1 1 0 011.414-1.414L6.5 9.086l4.293-4.293a1 1 0 011.414 0z'/%3e%3c/svg%3e\");\n}\n\n[type='radio']:checked {\n  background-image: url(\"data:image/svg+xml,%3csvg viewBox='0 0 16 16' fill='white' xmlns='http://www.w3.org/2000/svg'%3e%3ccircle cx='8' cy='8' r='3'/%3e%3c/svg%3e\");\n}\n\n[type='checkbox']:checked:hover,[type='checkbox']:checked:focus,[type='radio']:checked:hover,[type='radio']:checked:focus {\n  border-color: transparent;\n  background-color: currentColor;\n}\n\n[type='checkbox']:indeterminate {\n  background-image: url(\"data:image/svg+xml,%3csvg xmlns='http://www.w3.org/2000/svg' fill='none' viewBox='0 0 16 16'%3e%3cpath stroke='white' stroke-linecap='round' stroke-linejoin='round' stroke-width='2' d='M4 8h8'/%3e%3c/svg%3e\");\n  border-color: transparent;\n  background-color: currentColor;\n  background-size: 100% 100%;\n  background-position: center;\n  background-repeat: no-repeat;\n}\n\n[type='checkbox']:indeterminate:hover,[type='checkbox']:indeterminate:focus {\n  border-color: transparent;\n  background-color: currentColor;\n}\n\n[type='file'] {\n  background: unset;\n  border-color: inherit;\n  border-width: 0;\n  border-radius: 0;\n  padding: 0;\n  font-size: unset;\n  line-height: inherit;\n}\n\n[type='file']:focus {\n  outline: 1px solid ButtonText;\n  outline: 1px auto -webkit-focus-ring-color;\n}\n\n*, ::before, ::after {\n  --tw-border-spacing-x: 0;\n  --tw-border-spacing-y: 0;\n  --tw-translate-x: 0;\n  --tw-translate-y: 0;\n  --tw-rotate: 0;\n  --tw-skew-x: 0;\n  --tw-skew-y: 0;\n  --tw-scale-x: 1;\n  --tw-scale-y: 1;\n  --tw-pan-x:  ;\n  --tw-pan-y:  ;\n  --tw-pinch-zoom:  ;\n  --tw-scroll-snap-strictness: proximity;\n  --tw-ordinal:  ;\n  --tw-slashed-zero:  ;\n  --tw-numeric-figure:  ;\n  --tw-numeric-spacing:  ;\n  --tw-numeric-fraction:  ;\n  --tw-ring-inset:  ;\n  --tw-ring-offset-width: 0px;\n  --tw-ring-offset-color: #fff;\n  --tw-ring-color: rgb(59 130 246 / 0.5);\n  --tw-ring-offset-shadow: 0 0 #0000;\n  --tw-ring-shadow: 0 0 #0000;\n  --tw-shadow: 0 0 #0000;\n  --tw-shadow-colored: 0 0 #0000;\n  --tw-blur:  ;\n  --tw-brightness:  ;\n  --tw-contrast:  ;\n  --tw-grayscale:  ;\n  --tw-hue-rotate:  ;\n  --tw-invert:  ;\n  --tw-saturate:  ;\n  --tw-sepia:  ;\n  --tw-drop-shadow:  ;\n  --tw-backdrop-blur:  ;\n  --tw-backdrop-brightness:  ;\n  --tw-backdrop-contrast:  ;\n  --tw-backdrop-grayscale:  ;\n  --tw-backdrop-hue-rotate:  ;\n  --tw-backdrop-invert:  ;\n  --tw-backdrop-opacity:  ;\n  --tw-backdrop-saturate:  ;\n  --tw-backdrop-sepia:  ;\n}\n\n::-webkit-backdrop {\n  --tw-border-spacing-x: 0;\n  --tw-border-spacing-y: 0;\n  --tw-translate-x: 0;\n  --tw-translate-y: 0;\n  --tw-rotate: 0;\n  --tw-skew-x: 0;\n  --tw-skew-y: 0;\n  --tw-scale-x: 1;\n  --tw-scale-y: 1;\n  --tw-pan-x:  ;\n  --tw-pan-y:  ;\n  --tw-pinch-zoom:  ;\n  --tw-scroll-snap-strictness: proximity;\n  --tw-ordinal:  ;\n  --tw-slashed-zero:  ;\n  --tw-numeric-figure:  ;\n  --tw-numeric-spacing:  ;\n  --tw-numeric-fraction:  ;\n  --tw-ring-inset:  ;\n  --tw-ring-offset-width: 0px;\n  --tw-ring-offset-color: #fff;\n  --tw-ring-color: rgb(59 130 246 / 0.5);\n  --tw-ring-offset-shadow: 0 0 #0000;\n  --tw-ring-shadow: 0 0 #0000;\n  --tw-shadow: 0 0 #0000;\n  --tw-shadow-colored: 0 0 #0000;\n  --tw-blur:  ;\n  --tw-brightness:  ;\n  --tw-contrast:  ;\n  --tw-grayscale:  ;\n  --tw-hue-rotate:  ;\n  --tw-invert:  ;\n  --tw-saturate:  ;\n  --tw-sepia:  ;\n  --tw-drop-shadow:  ;\n  --tw-backdrop-blur:  ;\n  --tw-backdrop-brightness:  ;\n  --tw-backdrop-contrast:  ;\n  --tw-backdrop-grayscale:  ;\n  --tw-backdrop-hue-rotate:  ;\n  --tw-backdrop-invert:  ;\n  --tw-backdrop-opacity:  ;\n  --tw-backdrop-saturate:  ;\n  --tw-backdrop-sepia:  ;\n}\n\n::backdrop {\n  --tw-border-spacing-x: 0;\n  --tw-border-spacing-y: 0;\n  --tw-translate-x: 0;\n  --tw-translate-y: 0;\n  --tw-rotate: 0;\n  --tw-skew-x: 0;\n  --tw-skew-y: 0;\n  --tw-scale-x: 1;\n  --tw-scale-y: 1;\n  --tw-pan-x:  ;\n  --tw-pan-y:  ;\n  --tw-pinch-zoom:  ;\n  --tw-scroll-snap-strictness: proximity;\n  --tw-ordinal:  ;\n  --tw-slashed-zero:  ;\n  --tw-numeric-figure:  ;\n  --tw-numeric-spacing:  ;\n  --tw-numeric-fraction:  ;\n  --tw-ring-inset:  ;\n  --tw-ring-offset-width: 0px;\n  --tw-ring-offset-color: #fff;\n  --tw-ring-color: rgb(59 130 246 / 0.5);\n  --tw-ring-offset-shadow: 0 0 #0000;\n  --tw-ring-shadow: 0 0 #0000;\n  --tw-shadow: 0 0 #0000;\n  --tw-shadow-colored: 0 0 #0000;\n  --tw-blur:  ;\n  --tw-brightness:  ;\n  --tw-contrast:  ;\n  --tw-grayscale:  ;\n  --tw-hue-rotate:  ;\n  --tw-invert:  ;\n  --tw-saturate:  ;\n  --tw-sepia:  ;\n  --tw-drop-shadow:  ;\n  --tw-backdrop-blur:  ;\n  --tw-backdrop-brightness:  ;\n  --tw-backdrop-contrast:  ;\n  --tw-backdrop-grayscale:  ;\n  --tw-backdrop-hue-rotate:  ;\n  --tw-backdrop-invert:  ;\n  --tw-backdrop-opacity:  ;\n  --tw-backdrop-saturate:  ;\n  --tw-backdrop-sepia:  ;\n}\n\n.sr-only {\n  position: absolute;\n  width: 1px;\n  height: 1px;\n  padding: 0;\n  margin: -1px;\n  overflow: hidden;\n  clip: rect(0, 0, 0, 0);\n  white-space: nowrap;\n  border-width: 0;\n}\n\n.col-span-6 {\n  grid-column: span 6 / span 6;\n}\n\n.m-2 {\n  margin: 0.5rem;\n}\n\n.mx-4 {\n  margin-left: 1rem;\n  margin-right: 1rem;\n}\n\n.my-auto {\n  margin-top: auto;\n  margin-bottom: auto;\n}\n\n.mx-auto {\n  margin-left: auto;\n  margin-right: auto;\n}\n\n.my-8 {\n  margin-top: 2rem;\n  margin-bottom: 2rem;\n}\n\n.my-3 {\n  margin-top: 0.75rem;\n  margin-bottom: 0.75rem;\n}\n\n.mt-auto {\n  margin-top: auto;\n}\n\n.mb-5 {\n  margin-bottom: 1.25rem;\n}\n\n.mr-auto {\n  margin-right: auto;\n}\n\n.ml-2 {\n  margin-left: 0.5rem;\n}\n\n.mr-2 {\n  margin-right: 0.5rem;\n}\n\n.ml-4 {\n  margin-left: 1rem;\n}\n\n.mr-4 {\n  margin-right: 1rem;\n}\n\n.mb-0 {\n  margin-bottom: 0px;\n}\n\n.mt-2 {\n  margin-top: 0.5rem;\n}\n\n.mb-2 {\n  margin-bottom: 0.5rem;\n}\n\n.mt-1 {\n  margin-top: 0.25rem;\n}\n\n.mb-1 {\n  margin-bottom: 0.25rem;\n}\n\n.mb-6 {\n  margin-bottom: 1.5rem;\n}\n\n.mb-4 {\n  margin-bottom: 1rem;\n}\n\n.ml-auto {\n  margin-left: auto;\n}\n\n.mt-\\[6px\\] {\n  margin-top: 6px;\n}\n\n.mt-\\[5px\\] {\n  margin-top: 5px;\n}\n\n.mb-3 {\n  margin-bottom: 0.75rem;\n}\n\n.mt-3 {\n  margin-top: 0.75rem;\n}\n\n.mt-5 {\n  margin-top: 1.25rem;\n}\n\n.block {\n  display: block;\n}\n\n.flex {\n  display: flex;\n}\n\n.inline-flex {\n  display: inline-flex;\n}\n\n.grid {\n  display: grid;\n}\n\n.hidden {\n  display: none;\n}\n\n.h-screen {\n  height: 100vh;\n}\n\n.h-20 {\n  height: 5rem;\n}\n\n.w-auto {\n  width: auto;\n}\n\n.w-screen {\n  width: 100vw;\n}\n\n.w-full {\n  width: 100%;\n}\n\n.w-16 {\n  width: 4rem;\n}\n\n.w-20 {\n  width: 5rem;\n}\n\n.max-w-sm {\n  max-width: 24rem;\n}\n\n.grid-cols-2 {\n  grid-template-columns: repeat(2, minmax(0, 1fr));\n}\n\n.flex-row {\n  flex-direction: row;\n}\n\n.flex-col {\n  flex-direction: column;\n}\n\n.content-center {\n  align-content: center;\n}\n\n.items-center {\n  align-items: center;\n}\n\n.justify-center {\n  justify-content: center;\n}\n\n.space-y-0 > :not([hidden]) ~ :not([hidden]) {\n  --tw-space-y-reverse: 0;\n  margin-top: calc(0px * calc(1 - var(--tw-space-y-reverse)));\n  margin-bottom: calc(0px * var(--tw-space-y-reverse));\n}\n\n.overflow-hidden {\n  overflow: hidden;\n}\n\n.overflow-x-auto {\n  overflow-x: auto;\n}\n\n.rounded-lg {\n  border-radius: 0.5rem;\n}\n\n.rounded-none {\n  border-radius: 0px;\n}\n\n.rounded-b-md {\n  border-bottom-right-radius: 0.375rem;\n  border-bottom-left-radius: 0.375rem;\n}\n\n.border {\n  border-width: 1px;\n}\n\n.border-b {\n  border-bottom-width: 1px;\n}\n\n.border-neutral-100 {\n  --tw-border-opacity: 1;\n  border-color: rgb(245 245 245 / var(--tw-border-opacity));\n}\n\n.border-transparent {\n  border-color: transparent;\n}\n\n.border-neutral-200 {\n  --tw-border-opacity: 1;\n  border-color: rgb(229 229 229 / var(--tw-border-opacity));\n}\n\n.border-white {\n  --tw-border-opacity: 1;\n  border-color: rgb(255 255 255 / var(--tw-border-opacity));\n}\n\n.border-gray-300 {\n  --tw-border-opacity: 1;\n  border-color: rgb(209 213 219 / var(--tw-border-opacity));\n}\n\n.bg-white {\n  --tw-bg-opacity: 1;\n  background-color: rgb(255 255 255 / var(--tw-bg-opacity));\n}\n\n.bg-blue-500 {\n  --tw-bg-opacity: 1;\n  background-color: rgb(59 130 246 / var(--tw-bg-opacity));\n}\n\n.bg-gray-50 {\n  --tw-bg-opacity: 1;\n  background-color: rgb(249 250 251 / var(--tw-bg-opacity));\n}\n\n.bg-blue-600 {\n  --tw-bg-opacity: 1;\n  background-color: rgb(37 99 235 / var(--tw-bg-opacity));\n}\n\n.bg-neutral-100 {\n  --tw-bg-opacity: 1;\n  background-color: rgb(245 245 245 / var(--tw-bg-opacity));\n}\n\n.bg-gradient-to-br {\n  background-image: linear-gradient(to bottom right, var(--tw-gradient-stops));\n}\n\n.from-pink-500 {\n  --tw-gradient-from: #ec4899;\n  --tw-gradient-to: rgb(236 72 153 / 0);\n  --tw-gradient-stops: var(--tw-gradient-from), var(--tw-gradient-to);\n}\n\n.from-violet-500 {\n  --tw-gradient-from: #8b5cf6;\n  --tw-gradient-to: rgb(139 92 246 / 0);\n  --tw-gradient-stops: var(--tw-gradient-from), var(--tw-gradient-to);\n}\n\n.from-neutral-600 {\n  --tw-gradient-from: #525252;\n  --tw-gradient-to: rgb(82 82 82 / 0);\n  --tw-gradient-stops: var(--tw-gradient-from), var(--tw-gradient-to);\n}\n\n.from-green-500 {\n  --tw-gradient-from: #22c55e;\n  --tw-gradient-to: rgb(34 197 94 / 0);\n  --tw-gradient-stops: var(--tw-gradient-from), var(--tw-gradient-to);\n}\n\n.from-blue-500 {\n  --tw-gradient-from: #3b82f6;\n  --tw-gradient-to: rgb(59 130 246 / 0);\n  --tw-gradient-stops: var(--tw-gradient-from), var(--tw-gradient-to);\n}\n\n.from-red-500 {\n  --tw-gradient-from: #ef4444;\n  --tw-gradient-to: rgb(239 68 68 / 0);\n  --tw-gradient-stops: var(--tw-gradient-from), var(--tw-gradient-to);\n}\n\n.to-pink-300 {\n  --tw-gradient-to: #f9a8d4;\n}\n\n.to-violet-300 {\n  --tw-gradient-to: #c4b5fd;\n}\n\n.to-neutral-400 {\n  --tw-gradient-to: #a3a3a3;\n}\n\n.to-green-300 {\n  --tw-gradient-to: #86efac;\n}\n\n.to-blue-300 {\n  --tw-gradient-to: #93c5fd;\n}\n\n.to-red-300 {\n  --tw-gradient-to: #fca5a5;\n}\n\n.p-2 {\n  padding: 0.5rem;\n}\n\n.py-2 {\n  padding-top: 0.5rem;\n  padding-bottom: 0.5rem;\n}\n\n.px-4 {\n  padding-left: 1rem;\n  padding-right: 1rem;\n}\n\n.py-\\[6px\\] {\n  padding-top: 6px;\n  padding-bottom: 6px;\n}\n\n.px-0 {\n  padding-left: 0px;\n  padding-right: 0px;\n}\n\n.px-6 {\n  padding-left: 1.5rem;\n  padding-right: 1.5rem;\n}\n\n.py-4 {\n  padding-top: 1rem;\n  padding-bottom: 1rem;\n}\n\n.py-5 {\n  padding-top: 1.25rem;\n  padding-bottom: 1.25rem;\n}\n\n.py-20 {\n  padding-top: 5rem;\n  padding-bottom: 5rem;\n}\n\n.px-3 {\n  padding-left: 0.75rem;\n  padding-right: 0.75rem;\n}\n\n.py-1 {\n  padding-top: 0.25rem;\n  padding-bottom: 0.25rem;\n}\n\n.py-\\[8px\\] {\n  padding-top: 8px;\n  padding-bottom: 8px;\n}\n\n.px-8 {\n  padding-left: 2rem;\n  padding-right: 2rem;\n}\n\n.py-\\[2px\\] {\n  padding-top: 2px;\n  padding-bottom: 2px;\n}\n\n.px-5 {\n  padding-left: 1.25rem;\n  padding-right: 1.25rem;\n}\n\n.pr-3 {\n  padding-right: 0.75rem;\n}\n\n.pr-4 {\n  padding-right: 1rem;\n}\n\n.text-right {\n  text-align: right;\n}\n\n.text-sm {\n  font-size: 0.875rem;\n  line-height: 1.25rem;\n}\n\n.text-lg {\n  font-size: 1.125rem;\n  line-height: 1.75rem;\n}\n\n.text-2xl {\n  font-size: 1.5rem;\n  line-height: 2rem;\n}\n\n.font-medium {\n  font-weight: 500;\n}\n\n.font-semibold {\n  font-weight: 600;\n}\n\n.font-bold {\n  font-weight: 700;\n}\n\n.leading-6 {\n  line-height: 1.5rem;\n}\n\n.text-neutral-600 {\n  --tw-text-opacity: 1;\n  color: rgb(82 82 82 / var(--tw-text-opacity));\n}\n\n.text-white {\n  --tw-text-opacity: 1;\n  color: rgb(255 255 255 / var(--tw-text-opacity));\n}\n\n.text-blue-500 {\n  --tw-text-opacity: 1;\n  color: rgb(59 130 246 / var(--tw-text-opacity));\n}\n\n.text-gray-900 {\n  --tw-text-opacity: 1;\n  color: rgb(17 24 39 / var(--tw-text-opacity));\n}\n\n.text-neutral-100 {\n  --tw-text-opacity: 1;\n  color: rgb(245 245 245 / var(--tw-text-opacity));\n}\n\n.text-green-400 {\n  --tw-text-opacity: 1;\n  color: rgb(74 222 128 / var(--tw-text-opacity));\n}\n\n.text-gray-700 {\n  --tw-text-opacity: 1;\n  color: rgb(55 65 81 / var(--tw-text-opacity));\n}\n\n.text-gray-500 {\n  --tw-text-opacity: 1;\n  color: rgb(107 114 128 / var(--tw-text-opacity));\n}\n\n.shadow-lg {\n  --tw-shadow: 0 10px 15px -3px rgb(0 0 0 / 0.1), 0 4px 6px -4px rgb(0 0 0 / 0.1);\n  --tw-shadow-colored: 0 10px 15px -3px var(--tw-shadow-color), 0 4px 6px -4px var(--tw-shadow-color);\n  box-shadow: var(--tw-ring-offset-shadow, 0 0 #0000), var(--tw-ring-shadow, 0 0 #0000), var(--tw-shadow);\n}\n\n.shadow-sm {\n  --tw-shadow: 0 1px 2px 0 rgb(0 0 0 / 0.05);\n  --tw-shadow-colored: 0 1px 2px 0 var(--tw-shadow-color);\n  box-shadow: var(--tw-ring-offset-shadow, 0 0 #0000), var(--tw-ring-shadow, 0 0 #0000), var(--tw-shadow);\n}\n\n.shadow {\n  --tw-shadow: 0 1px 3px 0 rgb(0 0 0 / 0.1), 0 1px 2px -1px rgb(0 0 0 / 0.1);\n  --tw-shadow-colored: 0 1px 3px 0 var(--tw-shadow-color), 0 1px 2px -1px var(--tw-shadow-color);\n  box-shadow: var(--tw-ring-offset-shadow, 0 0 #0000), var(--tw-ring-shadow, 0 0 #0000), var(--tw-shadow);\n}\n\n.outline-none {\n  outline: 2px solid transparent;\n  outline-offset: 2px;\n}\n\n.font-jost {\n  font-family: \"Jost\";\n}\n\n.font-inter {\n  font-family: \"Inter\";\n}\n\n.code {\n  font-family: \"Source Code Pro\", monospace;\n  display: block;\n  background-color: white;\n  color: #000000;\n  padding: 1em;\n  word-wrap: break-word;\n  white-space: pre-wrap;\n}\n\n.sidenav {\n  height: 100%;\n  /* 100% Full-height */\n  width: 0;\n  /* 0 width - change this with JavaScript */\n  position: fixed;\n  /* Stay in place */\n  z-index: 1;\n  /* Stay on top */\n  top: 0;\n  /* Stay at the top */\n  left: 0;\n  overflow-x: hidden;\n  /* Disable horizontal scroll */\n  padding-top: 60px;\n  /* Place content 60px from the top */\n  transition: 0.5s;\n  /* 0.5 second transition effect to slide in the sidenav */\n}\n\n/* The navigation menu links */\n\n.sidenav a {\n  display: block;\n}\n\nselect {\n  -webkit-appearance: none;\n     -moz-appearance: none;\n          appearance: none;\n  background-color: #fff;\n  border-color: #6b7280;\n  border-width: 1px;\n  border-radius: 0px;\n  padding-top: 0.5rem;\n  padding-right: 0.75rem;\n  padding-bottom: 0.5rem;\n  padding-left: 0.75rem;\n  font-size: 1rem;\n  line-height: 1.5rem;\n  --tw-shadow: 0 0 #0000;\n}\n\n select:focus {\n  outline: 2px solid transparent;\n  outline-offset: 2px;\n  --tw-ring-inset: var(--tw-empty,/*!*/ /*!*/);\n  --tw-ring-offset-width: 0px;\n  --tw-ring-offset-color: #fff;\n  --tw-ring-color: #2563eb;\n  --tw-ring-offset-shadow: var(--tw-ring-inset) 0 0 0 var(--tw-ring-offset-width) var(--tw-ring-offset-color);\n  --tw-ring-shadow: var(--tw-ring-inset) 0 0 0 calc(1px + var(--tw-ring-offset-width)) var(--tw-ring-color);\n  box-shadow: var(--tw-ring-offset-shadow), var(--tw-ring-shadow), var(--tw-shadow);\n  border-color: #2563eb;\n}\n\nselect {\n  background-image: url(\"data:image/svg+xml,%3csvg xmlns='http://www.w3.org/2000/svg' fill='none' viewBox='0 0 20 20'%3e%3cpath stroke='%236b7280' stroke-linecap='round' stroke-linejoin='round' stroke-width='1.5' d='M6 8l4 4 4-4'/%3e%3c/svg%3e\");\n  background-position: right 0.5rem center;\n  background-size: 1.5em 1.5em;\n  -webkit-print-color-adjust: exact;\n     color-adjust: exact;\n          print-color-adjust: exact;\n  margin: 0px;\n  margin-top: 0.5rem;\n  display: block;\n  width: 100%;\n  -webkit-appearance: none;\n     -moz-appearance: none;\n          appearance: none;\n  border-radius: 0.25rem;\n  border-width: 1px;\n  border-style: solid;\n  --tw-border-opacity: 1;\n  border-color: rgb(209 213 219 / var(--tw-border-opacity));\n  --tw-bg-opacity: 1;\n  background-color: rgb(255 255 255 / var(--tw-bg-opacity));\n  background-clip: padding-box;\n  background-repeat: no-repeat;\n  padding-left: 0.75rem;\n  padding-right: 0.75rem;\n  padding-top: 0.375rem;\n  padding-bottom: 0.375rem;\n  font-size: 1rem;\n  line-height: 1.5rem;\n  font-weight: 400;\n  --tw-text-opacity: 1;\n  color: rgb(55 65 81 / var(--tw-text-opacity));\n  transition-property: color, background-color, border-color, fill, stroke, opacity, box-shadow, transform, filter, -webkit-text-decoration-color, -webkit-backdrop-filter;\n  transition-property: color, background-color, border-color, text-decoration-color, fill, stroke, opacity, box-shadow, transform, filter, backdrop-filter;\n  transition-property: color, background-color, border-color, text-decoration-color, fill, stroke, opacity, box-shadow, transform, filter, backdrop-filter, -webkit-text-decoration-color, -webkit-backdrop-filter;\n  transition-duration: 150ms;\n  transition-timing-function: cubic-bezier(0.4, 0, 0.2, 1);\n}\n\nselect:focus {\n  --tw-border-opacity: 1;\n  border-color: rgb(37 99 235 / var(--tw-border-opacity));\n  --tw-bg-opacity: 1;\n  background-color: rgb(255 255 255 / var(--tw-bg-opacity));\n  --tw-text-opacity: 1;\n  color: rgb(55 65 81 / var(--tw-text-opacity));\n  outline: 2px solid transparent;\n  outline-offset: 2px;\n}\n\ntable {\n  margin-left: auto;\n  margin-right: auto;\n  margin-top: 2.5rem;\n  margin-bottom: 2.5rem;\n  width: 66.666667%;\n  border-width: 1px;\n  --tw-border-opacity: 1;\n  border-color: rgb(229 229 229 / var(--tw-border-opacity));\n  font-family: \"Inter\";\n}\n\nth {\n  border-width: 1px;\n  --tw-border-opacity: 1;\n  border-color: rgb(255 255 255 / var(--tw-border-opacity));\n  --tw-bg-opacity: 1;\n  background-color: rgb(59 130 246 / var(--tw-bg-opacity));\n  padding: 0.75rem;\n  padding-top: 0.5rem;\n  padding-bottom: 0.5rem;\n  text-align: left;\n  font-weight: 600;\n  --tw-text-opacity: 1;\n  color: rgb(255 255 255 / var(--tw-text-opacity));\n}\n\ntd {\n  border-width: 1px;\n  --tw-border-opacity: 1;\n  border-color: rgb(229 229 229 / var(--tw-border-opacity));\n  padding: 0.75rem;\n  padding-top: 0.5rem;\n  padding-bottom: 0.5rem;\n  font-size: 0.875rem;\n  line-height: 1.25rem;\n}\n\n/* Position and style the close button (top right corner) */\n\n.sidenav .closebtn {\n  position: absolute;\n  top: 0;\n  right: 25px;\n  font-size: 28px;\n  margin-left: 50px;\n}\n\n@media screen and (max-height: 450px) {\n  .sidenav {\n    padding-top: 15px;\n  }\n\n  .sidenav a {\n    font-size: 18px;\n  }\n}\n\n.file\\:mr-4::-webkit-file-upload-button {\n  margin-right: 1rem;\n}\n\n.file\\:mr-4::file-selector-button {\n  margin-right: 1rem;\n}\n\n.file\\:rounded-full::-webkit-file-upload-button {\n  border-radius: 9999px;\n}\n\n.file\\:rounded-full::file-selector-button {\n  border-radius: 9999px;\n}\n\n.file\\:border-0::-webkit-file-upload-button {\n  border-width: 0px;\n}\n\n.file\\:border-0::file-selector-button {\n  border-width: 0px;\n}\n\n.file\\:bg-blue-50::-webkit-file-upload-button {\n  --tw-bg-opacity: 1;\n  background-color: rgb(239 246 255 / var(--tw-bg-opacity));\n}\n\n.file\\:bg-blue-50::file-selector-button {\n  --tw-bg-opacity: 1;\n  background-color: rgb(239 246 255 / var(--tw-bg-opacity));\n}\n\n.file\\:py-2::-webkit-file-upload-button {\n  padding-top: 0.5rem;\n  padding-bottom: 0.5rem;\n}\n\n.file\\:py-2::file-selector-button {\n  padding-top: 0.5rem;\n  padding-bottom: 0.5rem;\n}\n\n.file\\:px-4::-webkit-file-upload-button {\n  padding-left: 1rem;\n  padding-right: 1rem;\n}\n\n.file\\:px-4::file-selector-button {\n  padding-left: 1rem;\n  padding-right: 1rem;\n}\n\n.file\\:text-sm::-webkit-file-upload-button {\n  font-size: 0.875rem;\n  line-height: 1.25rem;\n}\n\n.file\\:text-sm::file-selector-button {\n  font-size: 0.875rem;\n  line-height: 1.25rem;\n}\n\n.file\\:font-semibold::-webkit-file-upload-button {\n  font-weight: 600;\n}\n\n.file\\:font-semibold::file-selector-button {\n  font-weight: 600;\n}\n\n.file\\:text-blue-700::-webkit-file-upload-button {\n  --tw-text-opacity: 1;\n  color: rgb(29 78 216 / var(--tw-text-opacity));\n}\n\n.file\\:text-blue-700::file-selector-button {\n  --tw-text-opacity: 1;\n  color: rgb(29 78 216 / var(--tw-text-opacity));\n}\n\n.hover\\:bg-blue-700:hover {\n  --tw-bg-opacity: 1;\n  background-color: rgb(29 78 216 / var(--tw-bg-opacity));\n}\n\n.hover\\:bg-blue-400:hover {\n  --tw-bg-opacity: 1;\n  background-color: rgb(96 165 250 / var(--tw-bg-opacity));\n}\n\n.hover\\:file\\:bg-blue-100::-webkit-file-upload-button:hover {\n  --tw-bg-opacity: 1;\n  background-color: rgb(219 234 254 / var(--tw-bg-opacity));\n}\n\n.hover\\:file\\:bg-blue-100::file-selector-button:hover {\n  --tw-bg-opacity: 1;\n  background-color: rgb(219 234 254 / var(--tw-bg-opacity));\n}\n\n.focus\\:border-blue-500:focus {\n  --tw-border-opacity: 1;\n  border-color: rgb(59 130 246 / var(--tw-border-opacity));\n}\n\n.focus\\:border-indigo-500:focus {\n  --tw-border-opacity: 1;\n  border-color: rgb(99 102 241 / var(--tw-border-opacity));\n}\n\n.focus\\:outline-none:focus {\n  outline: 2px solid transparent;\n  outline-offset: 2px;\n}\n\n.focus\\:ring-2:focus {\n  --tw-ring-offset-shadow: var(--tw-ring-inset) 0 0 0 var(--tw-ring-offset-width) var(--tw-ring-offset-color);\n  --tw-ring-shadow: var(--tw-ring-inset) 0 0 0 calc(2px + var(--tw-ring-offset-width)) var(--tw-ring-color);\n  box-shadow: var(--tw-ring-offset-shadow), var(--tw-ring-shadow), var(--tw-shadow, 0 0 #0000);\n}\n\n.focus\\:ring-indigo-500:focus {\n  --tw-ring-opacity: 1;\n  --tw-ring-color: rgb(99 102 241 / var(--tw-ring-opacity));\n}\n\n.focus\\:ring-blue-500:focus {\n  --tw-ring-opacity: 1;\n  --tw-ring-color: rgb(59 130 246 / var(--tw-ring-opacity));\n}\n\n.focus\\:ring-offset-2:focus {\n  --tw-ring-offset-width: 2px;\n}\n\n@media (min-width: 640px) {\n  .sm\\:col-span-3 {\n    grid-column: span 3 / span 3;\n  }\n\n  .sm\\:p-6 {\n    padding: 1.5rem;\n  }\n\n  .sm\\:px-4 {\n    padding-left: 1rem;\n    padding-right: 1rem;\n  }\n\n  .sm\\:px-6 {\n    padding-left: 1.5rem;\n    padding-right: 1.5rem;\n  }\n\n  .sm\\:py-0 {\n    padding-top: 0px;\n    padding-bottom: 0px;\n  }\n\n  .sm\\:pr-4 {\n    padding-right: 1rem;\n  }\n\n  .sm\\:pt-2 {\n    padding-top: 0.5rem;\n  }\n\n  .sm\\:text-sm {\n    font-size: 0.875rem;\n    line-height: 1.25rem;\n  }\n\n  .sm\\:font-semibold {\n    font-weight: 600;\n  }\n}\n\n@media (min-width: 768px) {\n  .md\\:mr-0 {\n    margin-right: 0px;\n  }\n\n  .md\\:mb-2 {\n    margin-bottom: 0.5rem;\n  }\n\n  .md\\:ml-0 {\n    margin-left: 0px;\n  }\n\n  .md\\:inline-flex {\n    display: inline-flex;\n  }\n\n  .md\\:grid-cols-3 {\n    grid-template-columns: repeat(3, minmax(0, 1fr));\n  }\n\n  .md\\:flex-col {\n    flex-direction: column;\n  }\n\n  .md\\:items-center {\n    align-items: center;\n  }\n\n  .md\\:space-y-4 > :not([hidden]) ~ :not([hidden]) {\n    --tw-space-y-reverse: 0;\n    margin-top: calc(1rem * calc(1 - var(--tw-space-y-reverse)));\n    margin-bottom: calc(1rem * var(--tw-space-y-reverse));\n  }\n\n  .md\\:py-\\[6px\\] {\n    padding-top: 6px;\n    padding-bottom: 6px;\n  }\n\n  .md\\:py-8 {\n    padding-top: 2rem;\n    padding-bottom: 2rem;\n  }\n\n  .md\\:text-left {\n    text-align: left;\n  }\n\n  .md\\:text-lg {\n    font-size: 1.125rem;\n    line-height: 1.75rem;\n  }\n\n  .md\\:text-5xl {\n    font-size: 3rem;\n    line-height: 1;\n  }\n}\n\n@media (min-width: 1024px) {\n  .lg\\:mx-auto {\n    margin-left: auto;\n    margin-right: auto;\n  }\n\n  .lg\\:my-auto {\n    margin-top: auto;\n    margin-bottom: auto;\n  }\n\n  .lg\\:my-5 {\n    margin-top: 1.25rem;\n    margin-bottom: 1.25rem;\n  }\n\n  .lg\\:mb-0 {\n    margin-bottom: 0px;\n  }\n\n  .lg\\:mt-2 {\n    margin-top: 0.5rem;\n  }\n\n  .lg\\:mb-5 {\n    margin-bottom: 1.25rem;\n  }\n\n  .lg\\:mb-2 {\n    margin-bottom: 0.5rem;\n  }\n\n  .lg\\:w-1\\/3 {\n    width: 33.333333%;\n  }\n\n  .lg\\:w-1\\/2 {\n    width: 50%;\n  }\n\n  .lg\\:rounded-t-md {\n    border-top-left-radius: 0.375rem;\n    border-top-right-radius: 0.375rem;\n  }\n\n  .lg\\:py-1 {\n    padding-top: 0.25rem;\n    padding-bottom: 0.25rem;\n  }\n\n  .lg\\:py-20 {\n    padding-top: 5rem;\n    padding-bottom: 5rem;\n  }\n\n  .lg\\:px-6 {\n    padding-left: 1.5rem;\n    padding-right: 1.5rem;\n  }\n\n  .lg\\:px-0 {\n    padding-left: 0px;\n    padding-right: 0px;\n  }\n\n  .lg\\:text-lg {\n    font-size: 1.125rem;\n    line-height: 1.75rem;\n  }\n}\n"],"sourceRoot":""}]);
// Exports
/* harmony default export */ const __WEBPACK_DEFAULT_EXPORT__ = (___CSS_LOADER_EXPORT___);


/***/ }),

/***/ "./node_modules/css-loader/dist/runtime/api.js":
/*!*****************************************************!*\
  !*** ./node_modules/css-loader/dist/runtime/api.js ***!
  \*****************************************************/
/***/ ((module) => {

"use strict";


/*
  MIT License http://www.opensource.org/licenses/mit-license.php
  Author Tobias Koppers @sokra
*/
module.exports = function (cssWithMappingToString) {
  var list = []; // return the list of modules as css string

  list.toString = function toString() {
    return this.map(function (item) {
      var content = "";
      var needLayer = typeof item[5] !== "undefined";

      if (item[4]) {
        content += "@supports (".concat(item[4], ") {");
      }

      if (item[2]) {
        content += "@media ".concat(item[2], " {");
      }

      if (needLayer) {
        content += "@layer".concat(item[5].length > 0 ? " ".concat(item[5]) : "", " {");
      }

      content += cssWithMappingToString(item);

      if (needLayer) {
        content += "}";
      }

      if (item[2]) {
        content += "}";
      }

      if (item[4]) {
        content += "}";
      }

      return content;
    }).join("");
  }; // import a list of modules into the list


  list.i = function i(modules, media, dedupe, supports, layer) {
    if (typeof modules === "string") {
      modules = [[null, modules, undefined]];
    }

    var alreadyImportedModules = {};

    if (dedupe) {
      for (var k = 0; k < this.length; k++) {
        var id = this[k][0];

        if (id != null) {
          alreadyImportedModules[id] = true;
        }
      }
    }

    for (var _k = 0; _k < modules.length; _k++) {
      var item = [].concat(modules[_k]);

      if (dedupe && alreadyImportedModules[item[0]]) {
        continue;
      }

      if (typeof layer !== "undefined") {
        if (typeof item[5] === "undefined") {
          item[5] = layer;
        } else {
          item[1] = "@layer".concat(item[5].length > 0 ? " ".concat(item[5]) : "", " {").concat(item[1], "}");
          item[5] = layer;
        }
      }

      if (media) {
        if (!item[2]) {
          item[2] = media;
        } else {
          item[1] = "@media ".concat(item[2], " {").concat(item[1], "}");
          item[2] = media;
        }
      }

      if (supports) {
        if (!item[4]) {
          item[4] = "".concat(supports);
        } else {
          item[1] = "@supports (".concat(item[4], ") {").concat(item[1], "}");
          item[4] = supports;
        }
      }

      list.push(item);
    }
  };

  return list;
};

/***/ }),

/***/ "./node_modules/css-loader/dist/runtime/getUrl.js":
/*!********************************************************!*\
  !*** ./node_modules/css-loader/dist/runtime/getUrl.js ***!
  \********************************************************/
/***/ ((module) => {

"use strict";


module.exports = function (url, options) {
  if (!options) {
    options = {};
  }

  if (!url) {
    return url;
  }

  url = String(url.__esModule ? url.default : url); // If url is already wrapped in quotes, remove them

  if (/^['"].*['"]$/.test(url)) {
    url = url.slice(1, -1);
  }

  if (options.hash) {
    url += options.hash;
  } // Should url be wrapped?
  // See https://drafts.csswg.org/css-values-3/#urls


  if (/["'() \t\n]|(%20)/.test(url) || options.needQuotes) {
    return "\"".concat(url.replace(/"/g, '\\"').replace(/\n/g, "\\n"), "\"");
  }

  return url;
};

/***/ }),

/***/ "./node_modules/css-loader/dist/runtime/sourceMaps.js":
/*!************************************************************!*\
  !*** ./node_modules/css-loader/dist/runtime/sourceMaps.js ***!
  \************************************************************/
/***/ ((module) => {

"use strict";


module.exports = function (item) {
  var content = item[1];
  var cssMapping = item[3];

  if (!cssMapping) {
    return content;
  }

  if (typeof btoa === "function") {
    var base64 = btoa(unescape(encodeURIComponent(JSON.stringify(cssMapping))));
    var data = "sourceMappingURL=data:application/json;charset=utf-8;base64,".concat(base64);
    var sourceMapping = "/*# ".concat(data, " */");
    var sourceURLs = cssMapping.sources.map(function (source) {
      return "/*# sourceURL=".concat(cssMapping.sourceRoot || "").concat(source, " */");
    });
    return [content].concat(sourceURLs).concat([sourceMapping]).join("\n");
  }

  return [content].join("\n");
};

/***/ }),

/***/ "./node_modules/es5-ext/global.js":
/*!****************************************!*\
  !*** ./node_modules/es5-ext/global.js ***!
  \****************************************/
/***/ ((module) => {

var naiveFallback = function () {
	if (typeof self === "object" && self) return self;
	if (typeof window === "object" && window) return window;
	throw new Error("Unable to resolve global `this`");
};

module.exports = (function () {
	if (this) return this;

	// Unexpected strict mode (may happen if e.g. bundled into ESM module)

	// Fallback to standard globalThis if available
	if (typeof globalThis === "object" && globalThis) return globalThis;

	// Thanks @mathiasbynens -> https://mathiasbynens.be/notes/globalthis
	// In all ES5+ engines global object inherits from Object.prototype
	// (if you approached one that doesn't please report)
	try {
		Object.defineProperty(Object.prototype, "__global__", {
			get: function () { return this; },
			configurable: true
		});
	} catch (error) {
		// Unfortunate case of updates to Object.prototype being restricted
		// via preventExtensions, seal or freeze
		return naiveFallback();
	}
	try {
		// Safari case (window.__global__ works, but __global__ does not)
		if (!__global__) return naiveFallback();
		return __global__;
	} finally {
		delete Object.prototype.__global__;
	}
})();


/***/ }),

/***/ "./node_modules/isomorphic-form-data/lib/browser.js":
/*!**********************************************************!*\
  !*** ./node_modules/isomorphic-form-data/lib/browser.js ***!
  \**********************************************************/
/***/ ((module) => {

module.exports = window.FormData


/***/ }),

/***/ "./node_modules/js-alert/lib/event-source.js":
/*!***************************************************!*\
  !*** ./node_modules/js-alert/lib/event-source.js ***!
  \***************************************************/
/***/ ((module, exports) => {

"use strict";


Object.defineProperty(exports, "__esModule", ({
	value: true
}));

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

//
// EventSource class - This class provides simple event functionality for classes, with Promise support.
//
//	Usage for once-off event listeners:
//
//		myObj.when("closed").then(function(data) {
//			alert("Closed! " + data);
//		});
//
//
//	Usage for permanent event listeners:
//
//		myObj.on("closed", function(data) {
//			alert("Closed! " + data);
//		});
//
//
//	Usage when triggering an event from a subclass:
//
//		this.emit("closed", "customData");
//

var EventSource = function () {
	function EventSource() {
		_classCallCheck(this, EventSource);
	}

	_createClass(EventSource, [{
		key: "when",


		/** Adds an event listener. If callback is null, a Promise will be returned. Note that if using the Promise
   *  it will only be triggered on the first event emitted. */
		value: function when(eventName) {
			var _this = this;

			var callback = arguments.length <= 1 || arguments[1] === undefined ? null : arguments[1];


			// Make sure event listener object exists
			this._eventListeners = this._eventListeners || {};

			// Make sure event listener array exists
			this._eventListeners[eventName] = this._eventListeners[eventName] || [];

			// Check if using promise form
			if (callback) {

				// Just add the callback
				this._eventListeners[eventName].push(callback);
			} else {

				// Return the promise
				return new Promise(function (onSuccess, onFail) {

					// Promise callbacks can only be used once
					onSuccess._removeAfterCall = true;

					// Add success handler to event listener array
					_this._eventListeners[eventName].push(onSuccess);
				});
			}
		}

		/** Synonyms */

	}, {
		key: "on",
		value: function on() {
			return this.when.apply(this, arguments);
		}
	}, {
		key: "addEventListener",
		value: function addEventListener() {
			return this.when.apply(this, arguments);
		}

		/** Triggers an event. Each argument after the first one will be passed to event listeners */

	}, {
		key: "emit",
		value: function emit(eventName) {

			// Get list of callbacks
			var callbacks = this._eventListeners && this._eventListeners[eventName] || [];

			// Call events

			for (var _len = arguments.length, args = Array(_len > 1 ? _len - 1 : 0), _key = 1; _key < _len; _key++) {
				args[_key - 1] = arguments[_key];
			}

			var _iteratorNormalCompletion = true;
			var _didIteratorError = false;
			var _iteratorError = undefined;

			try {
				for (var _iterator = callbacks[Symbol.iterator](), _step; !(_iteratorNormalCompletion = (_step = _iterator.next()).done); _iteratorNormalCompletion = true) {
					var callback = _step.value;


					// Call it
					callback.apply(this, args);
				}

				// Remove callbacks that can only be called once
			} catch (err) {
				_didIteratorError = true;
				_iteratorError = err;
			} finally {
				try {
					if (!_iteratorNormalCompletion && _iterator.return) {
						_iterator.return();
					}
				} finally {
					if (_didIteratorError) {
						throw _iteratorError;
					}
				}
			}

			for (var i = 0; i < callbacks.length; i++) {
				if (callbacks[i]._removeAfterCall) callbacks.splice(i--, 1);
			}
		}

		/** Synonyms */

	}, {
		key: "trigger",
		value: function trigger() {
			return this.emit.apply(this, arguments);
		}
	}, {
		key: "triggerEvent",
		value: function triggerEvent() {
			return this.emit.apply(this, arguments);
		}
	}]);

	return EventSource;
}();

// Apply as a mixin to a class or object


exports["default"] = EventSource;
EventSource.mixin = function (otherClass) {

	for (var prop in EventSource.prototype) {
		if (EventSource.prototype.hasOwnProperty(prop)) otherClass[prop] = EventSource.prototype[prop];
	}
};
module.exports = exports["default"];

/***/ }),

/***/ "./node_modules/js-alert/lib/icons.js":
/*!********************************************!*\
  !*** ./node_modules/js-alert/lib/icons.js ***!
  \********************************************/
/***/ ((module, exports) => {

"use strict";


Object.defineProperty(exports, "__esModule", ({
	value: true
}));
//
// Theme icons

exports["default"] = {

	Information: "data:image/svg+xml;base64,PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiIHN0YW5kYWxvbmU9Im5vIj8+Cjxzdmcgd2lkdGg9IjgwcHgiIGhlaWdodD0iODBweCIgdmlld0JveD0iMCAwIDgwIDgwIiB2ZXJzaW9uPSIxLjEiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyIgeG1sbnM6eGxpbms9Imh0dHA6Ly93d3cudzMub3JnLzE5OTkveGxpbmsiPgogICAgPCEtLSBHZW5lcmF0b3I6IFNrZXRjaCAzLjguMyAoMjk4MDIpIC0gaHR0cDovL3d3dy5ib2hlbWlhbmNvZGluZy5jb20vc2tldGNoIC0tPgogICAgPHRpdGxlPkluZm9ybWF0aW9uIEljb248L3RpdGxlPgogICAgPGRlc2M+Q3JlYXRlZCB3aXRoIFNrZXRjaC48L2Rlc2M+CiAgICA8ZGVmcz48L2RlZnM+CiAgICA8ZyBpZD0iUGFnZS0xIiBzdHJva2U9Im5vbmUiIHN0cm9rZS13aWR0aD0iMSIgZmlsbD0ibm9uZSIgZmlsbC1ydWxlPSJldmVub2RkIj4KICAgICAgICA8ZyBpZD0iSW5mb3JtYXRpb24tSWNvbiIgZmlsbD0iIzAwODVGRiI+CiAgICAgICAgICAgIDxnIGlkPSI3MjQtaW5mb0AyeCIgdHJhbnNmb3JtPSJ0cmFuc2xhdGUoNi4wMDAwMDAsIDYuMDAwMDAwKSI+CiAgICAgICAgICAgICAgICA8ZyBpZD0iTGF5ZXJfMSI+CiAgICAgICAgICAgICAgICAgICAgPGcgaWQ9Il94MzdfMjQtaW5mb194NDBfMngucG5nIj4KICAgICAgICAgICAgICAgICAgICAgICAgPHBhdGggZD0iTTMzLjczNDA3MTQsMjUuNzA3NjQyOSBDMzQuNzE4ODU3MSwyNS43MDc2NDI5IDM1LjU3MTI4NTcsMjUuMzQzMzU3MSAzNi4yOTAxNDI5LDI0LjYxNzIxNDMgQzM3LjAwOSwyMy44OTEwNzE0IDM3LjM3MDg1NzEsMjMuMDA5NSAzNy4zNzA4NTcxLDIxLjk3NjE0MjkgQzM3LjM3MDg1NzEsMjAuOTQyNzg1NyAzNy4wMTM4NTcxLDIwLjA2IDM2LjI5OTg1NzEsMTkuMzI1MzU3MSBDMzUuNTg1ODU3MSwxOC41OTA3MTQzIDM0LjczMSwxOC4yMjUyMTQzIDMzLjczNDA3MTQsMTguMjI1MjE0MyBDMzIuNzM3MTQyOSwxOC4yMjUyMTQzIDMxLjg3ODY0MjksMTguNTkxOTI4NiAzMS4xNTg1NzE0LDE5LjMyNTM1NzEgQzMwLjQzODUsMjAuMDU4Nzg1NyAzMC4wNzkwNzE0LDIwLjk0Mjc4NTcgMzAuMDc5MDcxNCwyMS45NzYxNDI5IEMzMC4wNzkwNzE0LDIzLjAwOTUgMzAuNDM4NSwyMy44ODk4NTcxIDMxLjE1ODU3MTQsMjQuNjE3MjE0MyBDMzEuODc4NjQyOSwyNS4zNDQ1NzE0IDMyLjczNzE0MjksMjUuNzA3NjQyOSAzMy43MzQwNzE0LDI1LjcwNzY0MjkgTDMzLjczNDA3MTQsMjUuNzA3NjQyOSBaIE0zNCwwIEMxNS4yMjIyODU3LDAgMCwxNS4yMjIyODU3IDAsMzQgQzAsNTIuNzc3NzE0MyAxNS4yMjIyODU3LDY4IDM0LDY4IEM1Mi43Nzc3MTQzLDY4IDY4LDUyLjc3NzcxNDMgNjgsMzQgQzY4LDE1LjIyMjI4NTcgNTIuNzc3NzE0MywwIDM0LDAgTDM0LDAgWiBNMzQsNjUuNTcxNDI4NiBDMTYuNTY0MDcxNCw2NS41NzE0Mjg2IDIuNDI4NTcxNDMsNTEuNDM1OTI4NiAyLjQyODU3MTQzLDM0IEMyLjQyODU3MTQzLDE2LjU2NDA3MTQgMTYuNTY0MDcxNCwyLjQyODU3MTQzIDM0LDIuNDI4NTcxNDMgQzUxLjQzNTkyODYsMi40Mjg1NzE0MyA2NS41NzE0Mjg2LDE2LjU2NDA3MTQgNjUuNTcxNDI4NiwzNCBDNjUuNTcxNDI4Niw1MS40MzU5Mjg2IDUxLjQzNTkyODYsNjUuNTcxNDI4NiAzNCw2NS41NzE0Mjg2IEwzNCw2NS41NzE0Mjg2IFogTTM4LjMzMDE0MjksNDcuNzY3NTcxNCBDMzcuOTg2NSw0Ny42MDM2NDI5IDM3LjcyMDU3MTQsNDcuMzU1OTI4NiAzNy41MzcyMTQzLDQ3LjAyMzIxNDMgQzM3LjM1MjY0MjksNDYuNjkxNzE0MyAzNy4yNTkxNDI5LDQ2LjI4NzM1NzEgMzcuMjU5MTQyOSw0NS44MTAxNDI5IEwzNy4yNTkxNDI5LDI5LjYyMjUgTDM2Ljk4MjI4NTcsMjkuMzE2NSBMMjcuOTM3MDcxNCwyOS44NDcxNDI5IEwyNy45MzcwNzE0LDMxLjMzNTg1NzEgQzI4LjMwNjIxNDMsMzEuMzc1OTI4NiAyOC43MTU0Mjg2LDMxLjQ3MTg1NzEgMjkuMTY0NzE0MywzMS42MjEyMTQzIEMyOS42MTQsMzEuNzcwNTcxNCAyOS45NDkxNDI5LDMxLjkyNzIxNDMgMzAuMTcwMTQyOSwzMi4wODk5Mjg2IEMzMC40NjUyMTQzLDMyLjMwODUgMzAuNzExNzE0MywzMi41OTYyODU3IDMwLjkwODQyODYsMzIuOTU2OTI4NiBDMzEuMTA1MTQyOSwzMy4zMTc1NzE0IDMxLjIwMzUsMzMuNzM1Mjg1NyAzMS4yMDM1LDM0LjIxMDA3MTQgTDMxLjIwMzUsNDYuMDc2MDcxNCBDMzEuMjAzNSw0Ni41Nzg3ODU3IDMxLjEyNDU3MTQsNDYuOTgzMTQyOSAzMC45NjQyODU3LDQ3LjI4OTE0MjkgQzMwLjgwNCw0Ny41OTUxNDI5IDMwLjUyNzE0MjksNDcuODI5NSAzMC4xMzI1LDQ3Ljk5MjIxNDMgQzI5LjkxMDI4NTcsNDguMDg4MTQyOSAyOS42NDY3ODU3LDQ4LjE1NjE0MjkgMjkuMzM5NTcxNCw0OC4xOTYyMTQzIEMyOS4wMzExNDI5LDQ4LjIzNjI4NTcgMjguNzE3ODU3MSw0OC4yNzE1IDI4LjM5ODUsNDguMjk4MjE0MyBMMjguMzk4NSw0OS43ODU3MTQzIEw0MC4wNjUzNTcxLDQ5Ljc4NTcxNDMgTDQwLjA2NTM1NzEsNDguMjk3IEMzOS43NDQ3ODU3LDQ4LjI1NjkyODYgMzkuNDM2MzU3MSw0OC4xODg5Mjg2IDM5LjE0MTI4NTcsNDguMDkzIEMzOC44NDc0Mjg2LDQ3Ljk5ODI4NTcgMzguNTc3ODU3MSw0Ny44ODkgMzguMzMwMTQyOSw0Ny43Njc1NzE0IEwzOC4zMzAxNDI5LDQ3Ljc2NzU3MTQgWiIgaWQ9IlNoYXBlIj48L3BhdGg+CiAgICAgICAgICAgICAgICAgICAgPC9nPgogICAgICAgICAgICAgICAgPC9nPgogICAgICAgICAgICA8L2c+CiAgICAgICAgPC9nPgogICAgPC9nPgo8L3N2Zz4=",

	Question: "data:image/svg+xml;base64,PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiIHN0YW5kYWxvbmU9Im5vIj8+Cjxzdmcgd2lkdGg9IjQwcHgiIGhlaWdodD0iNDBweCIgdmlld0JveD0iMCAwIDQwIDQwIiB2ZXJzaW9uPSIxLjEiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyIgeG1sbnM6eGxpbms9Imh0dHA6Ly93d3cudzMub3JnLzE5OTkveGxpbmsiPgogICAgPCEtLSBHZW5lcmF0b3I6IFNrZXRjaCAzLjguMyAoMjk4MDIpIC0gaHR0cDovL3d3dy5ib2hlbWlhbmNvZGluZy5jb20vc2tldGNoIC0tPgogICAgPHRpdGxlPlF1ZXN0aW9uIEljb248L3RpdGxlPgogICAgPGRlc2M+Q3JlYXRlZCB3aXRoIFNrZXRjaC48L2Rlc2M+CiAgICA8ZGVmcz48L2RlZnM+CiAgICA8ZyBpZD0iUGFnZS0xIiBzdHJva2U9Im5vbmUiIHN0cm9rZS13aWR0aD0iMSIgZmlsbD0ibm9uZSIgZmlsbC1ydWxlPSJldmVub2RkIj4KICAgICAgICA8ZyBpZD0iUXVlc3Rpb24tSWNvbiIgZmlsbD0iIzQxNzUwNSI+CiAgICAgICAgICAgIDxnIGlkPSI3MzktcXVlc3Rpb25AMngiIHRyYW5zZm9ybT0idHJhbnNsYXRlKDEuMDAwMDAwLCAxLjAwMDAwMCkiPgogICAgICAgICAgICAgICAgPGcgaWQ9IkxheWVyXzEiPgogICAgICAgICAgICAgICAgICAgIDxnIGlkPSJfeDM3XzM5LXF1ZXN0aW9uX3g0MF8yeC5wbmciPgogICAgICAgICAgICAgICAgICAgICAgICA8cGF0aCBkPSJNMjIuNDQxMDM1NywxMS4zNDYzOTI5IEMyMi4wMzM4OTI5LDEwLjk2OTEwNzEgMjEuNTU0ODIxNCwxMC42ODAwMzU3IDIxLjAwNTE3ODYsMTAuNDc5MTc4NiBDMjAuNDU0ODU3MSwxMC4yNzc2NDI5IDE5Ljg2MzE0MjksMTAuMTc3ODkyOSAxOS4yMzA3MTQzLDEwLjE3Nzg5MjkgQzE3LjkwNDEwNzEsMTAuMTc3ODkyOSAxNi43OTE5Mjg2LDEwLjU3NTUzNTcgMTUuODk1NTM1NywxMS4zNzE1IEMxNC45OTg0NjQzLDEyLjE2Njc4NTcgMTQuNDUxNTM1NywxMy4yNjMzNTcxIDE0LjI1NjEwNzEsMTQuNjYxODkyOSBMMTYuNTYxODkyOSwxNC45MDI3ODU3IEMxNi42NTI4MjE0LDE0LjA5ODY3ODYgMTYuOTI2OTY0MywxMy40NDc5Mjg2IDE3LjM4NzcxNDMsMTIuOTQ5ODU3MSBDMTcuODQ3MTA3MSwxMi40NTI0NjQzIDE4LjQ0Njk2NDMsMTIuMjAyNzUgMTkuMTg0NTcxNCwxMi4yMDI3NSBDMTkuNTE2MzkyOSwxMi4yMDI3NSAxOS44MjkyMTQzLDEyLjI2NzIxNDMgMjAuMTIzMDM1NywxMi4zOTQ3ODU3IEMyMC40MTc1MzU3LDEyLjUyMzcxNDMgMjAuNjY5OTY0MywxMi43MDAxNDI5IDIwLjg4MSwxMi45MjU0Mjg2IEMyMS4wOTIwMzU3LDEzLjE1MDAzNTcgMjEuMjYxNjc4NiwxMy40MTk0Mjg2IDIxLjM4OTI1LDEzLjczMjI1IEMyMS41MTY4MjE0LDE0LjA0NTA3MTQgMjEuNTgxMjg1NywxNC4zODc3NSAyMS41ODEyODU3LDE0Ljc1NzU3MTQgQzIxLjU4MTI4NTcsMTUuMTI3MzkyOSAyMS41MTY4MjE0LDE1LjQ2MDU3MTQgMjEuMzg5MjUsMTUuNzU3Nzg1NyBDMjEuMjYxNjc4NiwxNi4wNTUgMjEuMDk4ODIxNCwxNi4zMzY2MDcxIDIwLjkwMzM5MjksMTYuNjAxMjUgQzIwLjcwNzI4NTcsMTYuODY2NTcxNCAyMC40ODg3ODU3LDE3LjEyNDQyODYgMjAuMjQ3MjE0MywxNy4zNzI3ODU3IEMyMC4wMDYzMjE0LDE3LjYyMTgyMTQgMTkuNzY0NzUsMTcuODY3NDY0MyAxOS41MjM4NTcxLDE4LjEwODM1NzEgQzE5LjIyMjU3MTQsMTguNDEzNzE0MyAxOC45NzAxNDI5LDE4LjY3NDk2NDMgMTguNzY2NTcxNCwxOC44OTE0Mjg2IEMxOC41NjMsMTkuMTA3ODkyOSAxOC40MDA4MjE0LDE5LjMzMzE3ODYgMTguMjgwMDM1NywxOS41NjY2MDcxIEMxOC4xNTkyNSwxOS43OTkzNTcxIDE4LjA2OSwyMC4wNjA2MDcxIDE4LjAwOTI4NTcsMjAuMzQ5Njc4NiBDMTcuOTQ4ODkyOSwyMC42Mzg3NSAxNy45MTkwMzU3LDIxLjAwMDQyODYgMTcuOTE5MDM1NywyMS40MzQ3MTQzIEwxNy45MTkwMzU3LDIyLjkwNTE3ODYgTDIwLjA4OTEwNzEsMjIuOTA1MTc4NiBMMjAuMDg5MTA3MSwyMS44NDQ1NzE0IEMyMC4wODkxMDcxLDIxLjUwNzMyMTQgMjAuMTA0MDM1NywyMS4yMjYzOTI5IDIwLjEzNDU3MTQsMjEuMDAxMTA3MSBDMjAuMTY0NDI4NiwyMC43NzY1IDIwLjIyMDc1LDIwLjU3MTU3MTQgMjAuMzAzNTM1NywyMC4zODYzMjE0IEMyMC4zODYzMjE0LDIwLjIwMjQyODYgMjAuNDk5NjQyOSwyMC4wMjUzMjE0IDIwLjY0MjgyMTQsMTkuODU2MzU3MSBDMjAuNzg2LDE5LjY4NzM5MjkgMjAuOTc4MDM1NywxOS40ODI0NjQzIDIxLjIxOTYwNzEsMTkuMjQxNTcxNCBMMjEuNDQ2MjUsMTkuMDI1MTA3MSBMMjIuODAyNzE0MywxNy41MzA4OTI5IEMyMy4xMDQsMTcuMTI5MTc4NiAyMy4zMzc0Mjg2LDE2LjY5ODk2NDMgMjMuNTAzNjc4NiwxNi4yNDE2MDcxIEMyMy42NjkyNSwxNS43ODM1NzE0IDIzLjc1MjAzNTcsMTUuMjQ4ODU3MSAyMy43NTIwMzU3LDE0LjYzODgyMTQgQzIzLjc1MjAzNTcsMTMuOTMxMDcxNCAyMy42MzUzMjE0LDEzLjMgMjMuNDAxMjE0MywxMi43NDYyODU3IEMyMy4xNjg0NjQzLDEyLjE4OTg1NzEgMjIuODQ4MTc4NiwxMS43MjM2Nzg2IDIyLjQ0MTAzNTcsMTEuMzQ2MzkyOSBMMjIuNDQxMDM1NywxMS4zNDYzOTI5IFogTTE4Ljk4MTY3ODYsMjQuNjQwMjg1NyBDMTguNTc0NTM1NywyNC42NDAyODU3IDE4LjIyNDM5MjksMjQuNzk2MzU3MSAxNy45MzA1NzE0LDI1LjEwOTg1NzEgQzE3LjYzNjA3MTQsMjUuNDIzMzU3MSAxNy40ODk1LDI1Ljc5NzI1IDE3LjQ4OTUsMjYuMjMwODU3MSBDMTcuNDg5NSwyNi42NjQ0NjQzIDE3LjYzNjc1LDI3LjAzNzY3ODYgMTcuOTMwNTcxNCwyNy4zNTExNzg2IEMxOC4yMjQzOTI5LDI3LjY2NDY3ODYgMTguNTc0NTM1NywyNy44MjE0Mjg2IDE4Ljk4MTY3ODYsMjcuODIxNDI4NiBDMTkuMzg4ODIxNCwyNy44MjE0Mjg2IDE5LjczODk2NDMsMjcuNjY0Njc4NiAyMC4wMzM0NjQzLDI3LjM1MTE3ODYgQzIwLjMyNzI4NTcsMjcuMDM3Njc4NiAyMC40NzM4NTcxLDI2LjY2NDQ2NDMgMjAuNDczODU3MSwyNi4yMzA4NTcxIEMyMC40NzM4NTcxLDI1Ljc5NzI1IDIwLjMyNjYwNzEsMjUuNDIzMzU3MSAyMC4wMzM0NjQzLDI1LjEwOTg1NzEgQzE5LjczODk2NDMsMjQuNzk3MDM1NyAxOS4zODgxNDI5LDI0LjY0MDI4NTcgMTguOTgxNjc4NiwyNC42NDAyODU3IEwxOC45ODE2Nzg2LDI0LjY0MDI4NTcgWiBNMTksMCBDOC41MDY1NzE0MywwIDAsOC41MDY1NzE0MyAwLDE5IEMwLDI5LjQ5MzQyODYgOC41MDY1NzE0MywzOCAxOSwzOCBDMjkuNDkzNDI4NiwzOCAzOCwyOS40OTM0Mjg2IDM4LDE5IEMzOCw4LjUwNjU3MTQzIDI5LjQ5MzQyODYsMCAxOSwwIEwxOSwwIFogTTE5LDM2LjY0Mjg1NzEgQzkuMjU2MzkyODYsMzYuNjQyODU3MSAxLjM1NzE0Mjg2LDI4Ljc0MzYwNzEgMS4zNTcxNDI4NiwxOSBDMS4zNTcxNDI4Niw5LjI1NjM5Mjg2IDkuMjU2MzkyODYsMS4zNTcxNDI4NiAxOSwxLjM1NzE0Mjg2IEMyOC43NDM2MDcxLDEuMzU3MTQyODYgMzYuNjQyODU3MSw5LjI1NjM5Mjg2IDM2LjY0Mjg1NzEsMTkgQzM2LjY0Mjg1NzEsMjguNzQzNjA3MSAyOC43NDM2MDcxLDM2LjY0Mjg1NzEgMTksMzYuNjQyODU3MSBMMTksMzYuNjQyODU3MSBaIiBpZD0iU2hhcGUiPjwvcGF0aD4KICAgICAgICAgICAgICAgICAgICA8L2c+CiAgICAgICAgICAgICAgICA8L2c+CiAgICAgICAgICAgIDwvZz4KICAgICAgICA8L2c+CiAgICA8L2c+Cjwvc3ZnPg==",

	Success: "data:image/svg+xml;base64,PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiIHN0YW5kYWxvbmU9Im5vIj8+Cjxzdmcgd2lkdGg9IjQwcHgiIGhlaWdodD0iNDBweCIgdmlld0JveD0iMCAwIDQwIDQwIiB2ZXJzaW9uPSIxLjEiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyIgeG1sbnM6eGxpbms9Imh0dHA6Ly93d3cudzMub3JnLzE5OTkveGxpbmsiPgogICAgPCEtLSBHZW5lcmF0b3I6IFNrZXRjaCAzLjguMyAoMjk4MDIpIC0gaHR0cDovL3d3dy5ib2hlbWlhbmNvZGluZy5jb20vc2tldGNoIC0tPgogICAgPHRpdGxlPlN1Y2Nlc3MgSWNvbjwvdGl0bGU+CiAgICA8ZGVzYz5DcmVhdGVkIHdpdGggU2tldGNoLjwvZGVzYz4KICAgIDxkZWZzPjwvZGVmcz4KICAgIDxnIGlkPSJQYWdlLTEiIHN0cm9rZT0ibm9uZSIgc3Ryb2tlLXdpZHRoPSIxIiBmaWxsPSJub25lIiBmaWxsLXJ1bGU9ImV2ZW5vZGQiPgogICAgICAgIDxnIGlkPSJTdWNjZXNzLUljb24iIGZpbGw9IiMwMDgzMDgiPgogICAgICAgICAgICA8ZyBpZD0iODg4LWNoZWNrbWFya0AyeCIgdHJhbnNmb3JtPSJ0cmFuc2xhdGUoMS4wMDAwMDAsIDEuMDAwMDAwKSI+CiAgICAgICAgICAgICAgICA8ZyBpZD0iTGF5ZXJfMSI+CiAgICAgICAgICAgICAgICAgICAgPGcgaWQ9Il94MzhfODgtY2hlY2ttYXJrX3g0MF8yeC5wbmciPgogICAgICAgICAgICAgICAgICAgICAgICA8cGF0aCBkPSJNMjcuODIxNDI4NiwxMi44OTI4NTcxIEMyNy42MzQxNDI5LDEyLjg5Mjg1NzEgMjcuNDY0NSwxMi45Njg4NTcxIDI3LjM0MTY3ODYsMTMuMDkyMzU3MSBMMTYuOTY0Mjg1NywyMy40NjkwNzE0IEwxMC42NTgzMjE0LDE3LjE2MzEwNzEgQzEwLjUzNTUsMTcuMDQwMjg1NyAxMC4zNjU4NTcxLDE2Ljk2NDI4NTcgMTAuMTc4NTcxNCwxNi45NjQyODU3IEM5LjgwNCwxNi45NjQyODU3IDkuNSwxNy4yNjgyODU3IDkuNSwxNy42NDI4NTcxIEM5LjUsMTcuODMwMTQyOSA5LjU3NiwxNy45OTk3ODU3IDkuNjk4ODIxNDMsMTguMTIyNjA3MSBMMTYuNDg0NTM1NywyNC45MDgzMjE0IEMxNi42MDczNTcxLDI1LjAzMTgyMTQgMTYuNzc3LDI1LjEwNzE0MjkgMTYuOTY0Mjg1NywyNS4xMDcxNDI5IEMxNy4xNTE1NzE0LDI1LjEwNzE0MjkgMTcuMzIxMjE0MywyNS4wMzE4MjE0IDE3LjQ0NDAzNTcsMjQuOTA4MzIxNCBMMjguMzAxMTc4NiwxNC4wNTE4NTcxIEMyOC40MjQsMTMuOTI4MzU3MSAyOC41LDEzLjc1ODcxNDMgMjguNSwxMy41NzE0Mjg2IEMyOC41LDEzLjE5NjE3ODYgMjguMTk2Njc4NiwxMi44OTI4NTcxIDI3LjgyMTQyODYsMTIuODkyODU3MSBMMjcuODIxNDI4NiwxMi44OTI4NTcxIFogTTIxLjcxNDI4NTcsMCBMMTYuMjg1NzE0MywwIEM0LjA3MTQyODU3LDAgMCw0LjA3MTQyODU3IDAsMTYuMjg1NzE0MyBMMCwyMS43MTQyODU3IEMwLDMzLjkyODU3MTQgNC4wNzE0Mjg1NywzOCAxNi4yODU3MTQzLDM4IEwyMS43MTQyODU3LDM4IEMzMy45Mjg1NzE0LDM4IDM4LDMzLjkyODU3MTQgMzgsMjEuNzE0Mjg1NyBMMzgsMTYuMjg1NzE0MyBDMzgsNC4wNzE0Mjg1NyAzMy45Mjg1NzE0LDAgMjEuNzE0Mjg1NywwIEwyMS43MTQyODU3LDAgWiBNMzYuNjQyODU3MSwyMS41MjA4OTI5IEMzNi42NDI4NTcxLDMyLjg2MjUzNTcgMzIuODYyNTM1NywzNi42NDI4NTcxIDIxLjUyMDg5MjksMzYuNjQyODU3MSBMMTYuNDc5Nzg1NywzNi42NDI4NTcxIEM1LjEzNzQ2NDI5LDM2LjY0Mjg1NzEgMS4zNTcxNDI4NiwzMi44NjI1MzU3IDEuMzU3MTQyODYsMjEuNTIwODkyOSBMMS4zNTcxNDI4NiwxNi40Nzk3ODU3IEMxLjM1NzE0Mjg2LDUuMTM3NDY0MjkgNS4xMzc0NjQyOSwxLjM1NzE0Mjg2IDE2LjQ3OTc4NTcsMS4zNTcxNDI4NiBMMjEuNTIwODkyOSwxLjM1NzE0Mjg2IEMzMi44NjI1MzU3LDEuMzU3MTQyODYgMzYuNjQyODU3MSw1LjEzNzQ2NDI5IDM2LjY0Mjg1NzEsMTYuNDc5Nzg1NyBMMzYuNjQyODU3MSwyMS41MjA4OTI5IEwzNi42NDI4NTcxLDIxLjUyMDg5MjkgWiIgaWQ9IlNoYXBlIj48L3BhdGg+CiAgICAgICAgICAgICAgICAgICAgPC9nPgogICAgICAgICAgICAgICAgPC9nPgogICAgICAgICAgICA8L2c+CiAgICAgICAgPC9nPgogICAgPC9nPgo8L3N2Zz4=",

	Warning: "data:image/svg+xml;base64,PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiIHN0YW5kYWxvbmU9Im5vIj8+Cjxzdmcgd2lkdGg9IjQwcHgiIGhlaWdodD0iNDBweCIgdmlld0JveD0iMCAwIDQwIDQwIiB2ZXJzaW9uPSIxLjEiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyIgeG1sbnM6eGxpbms9Imh0dHA6Ly93d3cudzMub3JnLzE5OTkveGxpbmsiPgogICAgPCEtLSBHZW5lcmF0b3I6IFNrZXRjaCAzLjguMyAoMjk4MDIpIC0gaHR0cDovL3d3dy5ib2hlbWlhbmNvZGluZy5jb20vc2tldGNoIC0tPgogICAgPHRpdGxlPldhcm5pbmcgSWNvbjwvdGl0bGU+CiAgICA8ZGVzYz5DcmVhdGVkIHdpdGggU2tldGNoLjwvZGVzYz4KICAgIDxkZWZzPjwvZGVmcz4KICAgIDxnIGlkPSJQYWdlLTEiIHN0cm9rZT0ibm9uZSIgc3Ryb2tlLXdpZHRoPSIxIiBmaWxsPSJub25lIiBmaWxsLXJ1bGU9ImV2ZW5vZGQiPgogICAgICAgIDxnIGlkPSJXYXJuaW5nLUljb24iIGZpbGw9IiNGRjlEMDAiPgogICAgICAgICAgICA8ZyBpZD0iNzkxLXdhcm5pbmdAMngiIHRyYW5zZm9ybT0idHJhbnNsYXRlKDEuMDAwMDAwLCAyLjAwMDAwMCkiPgogICAgICAgICAgICAgICAgPGcgaWQ9IkxheWVyXzEiPgogICAgICAgICAgICAgICAgICAgIDxnIGlkPSJfeDM3XzkxLXdhcm5pbmdfeDQwXzJ4LnBuZyI+CiAgICAgICAgICAgICAgICAgICAgICAgIDxwYXRoIGQ9Ik0zNy44MjM1NzE0LDMzLjI3MTAzNTcgTDM3LjgzMzA3MTQsMzMuMjY1NjA3MSBMMjAuMTY5MTc4NiwwLjY1MjEwNzE0MyBMMjAuMTU3NjQyOSwwLjY1ODg5Mjg1NyBDMTkuOTIwMTQyOSwwLjI2NiAxOS40OTMzMjE0LDAgMTksMCBDMTguNTA3MzU3MSwwIDE4LjA3OTg1NzEsMC4yNjYgMTcuODQxNjc4NiwwLjY1ODg5Mjg1NyBMMTcuODMwMTQyOSwwLjY1MjEwNzE0MyBMMC4xNjY5Mjg1NzEsMzMuMjY1NjA3MSBMMC4xNzcxMDcxNDMsMzMuMjcxMDM1NyBDMC4wNjc4NTcxNDI5LDMzLjQ2NzE0MjkgMCwzMy42ODgzNTcxIDAsMzMuOTI4NTcxNCBDMCwzNC42Nzc3MTQzIDAuNjA4LDM1LjI4NTcxNDMgMS4zNTcxNDI4NiwzNS4yODU3MTQzIEwzNi42NDI4NTcxLDM1LjI4NTcxNDMgQzM3LjM5MiwzNS4yODU3MTQzIDM4LDM0LjY3NzcxNDMgMzgsMzMuOTI4NTcxNCBDMzgsMzMuNjg4MzU3MSAzNy45MzIxNDI5LDMzLjQ2NzE0MjkgMzcuODIzNTcxNCwzMy4yNzEwMzU3IEwzNy44MjM1NzE0LDMzLjI3MTAzNTcgWiBNMzUuMjg1NzE0MywzMy45Mjg1NzE0IEwzNC42MDcxNDI5LDMzLjkyODU3MTQgTDMuMzkyODU3MTQsMzMuOTI4NTcxNCBMMi43MTQyODU3MSwzMy45Mjg1NzE0IEwxLjM1NzE0Mjg2LDMzLjkyODU3MTQgTDE5LDEuMzQyODkyODYgTDM2LjY0Mjg1NzEsMzMuOTI4NTcxNCBMMzUuMjg1NzE0MywzMy45Mjg1NzE0IEwzNS4yODU3MTQzLDMzLjkyODU3MTQgWiBNMTYuMjg1NzE0MywxMy41NzE0Mjg2IEwxNy42NDI4NTcxLDIzLjA3MTQyODYgQzE3LjY0Mjg1NzEsMjMuODIwNTcxNCAxOC4yNTA4NTcxLDI0LjQyODU3MTQgMTksMjQuNDI4NTcxNCBDMTkuNzQ5MTQyOSwyNC40Mjg1NzE0IDIwLjM1NzE0MjksMjMuODIwNTcxNCAyMC4zNTcxNDI5LDIzLjA3MTQyODYgTDIxLjcxNDI4NTcsMTMuNTcxNDI4NiBDMjEuNzE0Mjg1NywxMi44MjIyODU3IDIxLjEwNjI4NTcsMTIuMjE0Mjg1NyAyMC4zNTcxNDI5LDEyLjIxNDI4NTcgTDE3LjY0Mjg1NzEsMTIuMjE0Mjg1NyBDMTYuODkzNzE0MywxMi4yMTQyODU3IDE2LjI4NTcxNDMsMTIuODIyMjg1NyAxNi4yODU3MTQzLDEzLjU3MTQyODYgTDE2LjI4NTcxNDMsMTMuNTcxNDI4NiBaIE0xOSwyMy4wNzE0Mjg2IEwxNy42NDI4NTcxLDEzLjU3MTQyODYgTDIwLjM1NzE0MjksMTMuNTcxNDI4NiBMMTksMjMuMDcxNDI4NiBMMTksMjMuMDcxNDI4NiBaIE0xOSwyNS43ODU3MTQzIEMxNy41MDEwMzU3LDI1Ljc4NTcxNDMgMTYuMjg1NzE0MywyNy4wMDEwMzU3IDE2LjI4NTcxNDMsMjguNSBDMTYuMjg1NzE0MywyOS45OTg5NjQzIDE3LjUwMTAzNTcsMzEuMjE0Mjg1NyAxOSwzMS4yMTQyODU3IEMyMC40OTg5NjQzLDMxLjIxNDI4NTcgMjEuNzE0Mjg1NywyOS45OTg5NjQzIDIxLjcxNDI4NTcsMjguNSBDMjEuNzE0Mjg1NywyNy4wMDEwMzU3IDIwLjQ5ODk2NDMsMjUuNzg1NzE0MyAxOSwyNS43ODU3MTQzIEwxOSwyNS43ODU3MTQzIFogTTE5LDI5Ljg1NzE0MjkgQzE4LjI1MDg1NzEsMjkuODU3MTQyOSAxNy42NDI4NTcxLDI5LjI0OTE0MjkgMTcuNjQyODU3MSwyOC41IEMxNy42NDI4NTcxLDI3Ljc1MDg1NzEgMTguMjUwODU3MSwyNy4xNDI4NTcxIDE5LDI3LjE0Mjg1NzEgQzE5Ljc0OTE0MjksMjcuMTQyODU3MSAyMC4zNTcxNDI5LDI3Ljc1MDg1NzEgMjAuMzU3MTQyOSwyOC41IEMyMC4zNTcxNDI5LDI5LjI0OTE0MjkgMTkuNzQ5MTQyOSwyOS44NTcxNDI5IDE5LDI5Ljg1NzE0MjkgTDE5LDI5Ljg1NzE0MjkgWiIgaWQ9IlNoYXBlIj48L3BhdGg+CiAgICAgICAgICAgICAgICAgICAgPC9nPgogICAgICAgICAgICAgICAgPC9nPgogICAgICAgICAgICA8L2c+CiAgICAgICAgPC9nPgogICAgPC9nPgo8L3N2Zz4=",

	Failed: "data:image/svg+xml;base64,PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiIHN0YW5kYWxvbmU9Im5vIj8+Cjxzdmcgd2lkdGg9IjQwcHgiIGhlaWdodD0iNDBweCIgdmlld0JveD0iMCAwIDQwIDQwIiB2ZXJzaW9uPSIxLjEiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyIgeG1sbnM6eGxpbms9Imh0dHA6Ly93d3cudzMub3JnLzE5OTkveGxpbmsiPgogICAgPCEtLSBHZW5lcmF0b3I6IFNrZXRjaCAzLjguMyAoMjk4MDIpIC0gaHR0cDovL3d3dy5ib2hlbWlhbmNvZGluZy5jb20vc2tldGNoIC0tPgogICAgPHRpdGxlPkZhaWxlZCBJY29uPC90aXRsZT4KICAgIDxkZXNjPkNyZWF0ZWQgd2l0aCBTa2V0Y2guPC9kZXNjPgogICAgPGRlZnM+PC9kZWZzPgogICAgPGcgaWQ9IlBhZ2UtMSIgc3Ryb2tlPSJub25lIiBzdHJva2Utd2lkdGg9IjEiIGZpbGw9Im5vbmUiIGZpbGwtcnVsZT0iZXZlbm9kZCI+CiAgICAgICAgPGcgaWQ9IkZhaWxlZC1JY29uIiBmaWxsPSIjQzAwMDAwIj4KICAgICAgICAgICAgPGcgaWQ9Ijc5MS13YXJuaW5nLXNlbGVjdGVkQDJ4IiB0cmFuc2Zvcm09InRyYW5zbGF0ZSgxLjAwMDAwMCwgMi4wMDAwMDApIj4KICAgICAgICAgICAgICAgIDxnIGlkPSJMYXllcl8xIj4KICAgICAgICAgICAgICAgICAgICA8ZyBpZD0iX3gzN185MS13YXJuaW5nLXNlbGVjdGVkX3g0MF8yeC5wbmciPgogICAgICAgICAgICAgICAgICAgICAgICA8cGF0aCBkPSJNMzcuODIzNTcxNCwzMy4yNzEwMzU3IEwzNy44MzMwNzE0LDMzLjI2NTYwNzEgTDIwLjE2OTE3ODYsMC42NTIxMDcxNDMgTDIwLjE1NzY0MjksMC42NTg4OTI4NTcgQzE5LjkyMDE0MjksMC4yNjYgMTkuNDkzMzIxNCwwIDE5LDAgQzE4LjUwNzM1NzEsMCAxOC4wNzk4NTcxLDAuMjY2IDE3Ljg0MTY3ODYsMC42NTg4OTI4NTcgTDE3LjgzMDE0MjksMC42NTIxMDcxNDMgTDAuMTY2OTI4NTcxLDMzLjI2NTYwNzEgTDAuMTc3MTA3MTQzLDMzLjI3MTAzNTcgQzAuMDY3ODU3MTQyOSwzMy40NjcxNDI5IDAsMzMuNjg4MzU3MSAwLDMzLjkyODU3MTQgQzAsMzQuNjc3NzE0MyAwLjYwOCwzNS4yODU3MTQzIDEuMzU3MTQyODYsMzUuMjg1NzE0MyBMMzYuNjQyODU3MSwzNS4yODU3MTQzIEMzNy4zOTIsMzUuMjg1NzE0MyAzOCwzNC42Nzc3MTQzIDM4LDMzLjkyODU3MTQgQzM4LDMzLjY4ODM1NzEgMzcuOTMyMTQyOSwzMy40NjcxNDI5IDM3LjgyMzU3MTQsMzMuMjcxMDM1NyBMMzcuODIzNTcxNCwzMy4yNzEwMzU3IFogTTE5LDMxLjIxNDI4NTcgQzE3LjUwMTAzNTcsMzEuMjE0Mjg1NyAxNi4yODU3MTQzLDI5Ljk5ODk2NDMgMTYuMjg1NzE0MywyOC41IEMxNi4yODU3MTQzLDI3LjAwMTAzNTcgMTcuNTAxMDM1NywyNS43ODU3MTQzIDE5LDI1Ljc4NTcxNDMgQzIwLjQ5ODk2NDMsMjUuNzg1NzE0MyAyMS43MTQyODU3LDI3LjAwMTAzNTcgMjEuNzE0Mjg1NywyOC41IEMyMS43MTQyODU3LDI5Ljk5ODk2NDMgMjAuNDk4OTY0MywzMS4yMTQyODU3IDE5LDMxLjIxNDI4NTcgTDE5LDMxLjIxNDI4NTcgWiBNMjAuMzU3MTQyOSwyMy4wNzE0Mjg2IEMyMC4zNTcxNDI5LDIzLjgyMDU3MTQgMTkuNzQ5MTQyOSwyNC40Mjg1NzE0IDE5LDI0LjQyODU3MTQgQzE4LjI1MDg1NzEsMjQuNDI4NTcxNCAxNy42NDI4NTcxLDIzLjgyMDU3MTQgMTcuNjQyODU3MSwyMy4wNzE0Mjg2IEwxNi4yODU3MTQzLDEzLjU3MTQyODYgQzE2LjI4NTcxNDMsMTIuODIyMjg1NyAxNi44OTM3MTQzLDEyLjIxNDI4NTcgMTcuNjQyODU3MSwxMi4yMTQyODU3IEwyMC4zNTcxNDI5LDEyLjIxNDI4NTcgQzIxLjEwNjI4NTcsMTIuMjE0Mjg1NyAyMS43MTQyODU3LDEyLjgyMjI4NTcgMjEuNzE0Mjg1NywxMy41NzE0Mjg2IEwyMC4zNTcxNDI5LDIzLjA3MTQyODYgTDIwLjM1NzE0MjksMjMuMDcxNDI4NiBaIiBpZD0iU2hhcGUiPjwvcGF0aD4KICAgICAgICAgICAgICAgICAgICA8L2c+CiAgICAgICAgICAgICAgICA8L2c+CiAgICAgICAgICAgIDwvZz4KICAgICAgICA8L2c+CiAgICA8L2c+Cjwvc3ZnPg==",

	Deleted: "data:image/svg+xml;base64,PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiIHN0YW5kYWxvbmU9Im5vIj8+Cjxzdmcgd2lkdGg9IjQwcHgiIGhlaWdodD0iNDBweCIgdmlld0JveD0iMCAwIDQwIDQwIiB2ZXJzaW9uPSIxLjEiIHhtbG5zPSJodHRwOi8vd3d3LnczLm9yZy8yMDAwL3N2ZyIgeG1sbnM6eGxpbms9Imh0dHA6Ly93d3cudzMub3JnLzE5OTkveGxpbmsiPgogICAgPCEtLSBHZW5lcmF0b3I6IFNrZXRjaCAzLjguMyAoMjk4MDIpIC0gaHR0cDovL3d3dy5ib2hlbWlhbmNvZGluZy5jb20vc2tldGNoIC0tPgogICAgPHRpdGxlPlRyYXNoIEljb248L3RpdGxlPgogICAgPGRlc2M+Q3JlYXRlZCB3aXRoIFNrZXRjaC48L2Rlc2M+CiAgICA8ZGVmcz48L2RlZnM+CiAgICA8ZyBpZD0iUGFnZS0xIiBzdHJva2U9Im5vbmUiIHN0cm9rZS13aWR0aD0iMSIgZmlsbD0ibm9uZSIgZmlsbC1ydWxlPSJldmVub2RkIj4KICAgICAgICA8ZyBpZD0iVHJhc2gtSWNvbiIgZmlsbD0iIzAwMDAwMCI+CiAgICAgICAgICAgIDxnIGlkPSI3MTEtdHJhc2hAMngiIHRyYW5zZm9ybT0idHJhbnNsYXRlKDYuMDAwMDAwLCAxLjAwMDAwMCkiPgogICAgICAgICAgICAgICAgPGcgaWQ9IkxheWVyXzEiPgogICAgICAgICAgICAgICAgICAgIDxnIGlkPSJfeDM3XzExLXRyYXNoX3g0MF8yeC5wbmciPgogICAgICAgICAgICAgICAgICAgICAgICA8cGF0aCBkPSJNOC4xMTAyODU3MSw4LjE0MzUzNTcxIEM3LjczNjM5Mjg2LDguMTY1MjUgNy40NTA3MTQyOSw4LjQ4NzU3MTQzIDcuNDcyNDI4NTcsOC44NjIxNDI4NiBMOC44MjI3ODU3MSwzMy4yOTEzOTI5IEM4Ljg0NDUsMzMuNjY2NjQyOSA5LjE2NTQ2NDI5LDMzLjk1MjMyMTQgOS41NDAwMzU3MSwzMy45Mjk5Mjg2IEM5LjkxNDYwNzE0LDMzLjkwNzUzNTcgMTAuMTk5NjA3MSwzMy41ODY1NzE0IDEwLjE3Nzg5MjksMzMuMjExMzIxNCBMOC44Mjc1MzU3MSw4Ljc4MjA3MTQzIEM4LjgwNTE0Mjg2LDguNDA4MTc4NTcgOC40ODQxNzg1Nyw4LjEyMTgyMTQzIDguMTEwMjg1NzEsOC4xNDM1MzU3MSBMOC4xMTAyODU3MSw4LjE0MzUzNTcxIFogTTE0LjI1LDguMTQyODU3MTQgQzEzLjg3NTQyODYsOC4xNDI4NTcxNCAxMy41NzE0Mjg2LDguNDQ2ODU3MTQgMTMuNTcxNDI4Niw4LjgyMTQyODU3IEwxMy41NzE0Mjg2LDMzLjI1IEMxMy41NzE0Mjg2LDMzLjYyNTI1IDEzLjg3NTQyODYsMzMuOTI4NTcxNCAxNC4yNSwzMy45Mjg1NzE0IEMxNC42MjUyNSwzMy45Mjg1NzE0IDE0LjkyODU3MTQsMzMuNjI1MjUgMTQuOTI4NTcxNCwzMy4yNSBMMTQuOTI4NTcxNCw4LjgyMTQyODU3IEMxNC45Mjg1NzE0LDguNDQ2ODU3MTQgMTQuNjI1MjUsOC4xNDI4NTcxNCAxNC4yNSw4LjE0Mjg1NzE0IEwxNC4yNSw4LjE0Mjg1NzE0IFogTTI3LjgyMTQyODYsNC4wNzE0Mjg1NyBMMjAuMzU3MTQyOSw0LjA3MTQyODU3IEwyMC4zNTcxNDI5LDIuNzE0Mjg1NzEgQzIwLjM1NzE0MjksMS4yMTUzMjE0MyAxOS4xNDE4MjE0LDAgMTcuNjQyODU3MSwwIEwxMC44NTcxNDI5LDAgQzkuMzU4MTc4NTcsMCA4LjE0Mjg1NzE0LDEuMjE1MzIxNDMgOC4xNDI4NTcxNCwyLjcxNDI4NTcxIEw4LjE0Mjg1NzE0LDQuMDcxNDI4NTcgTDAuNjc4NTcxNDI5LDQuMDcxNDI4NTcgQzAuMzA0LDQuMDcxNDI4NTcgMCw0LjM3NTQyODU3IDAsNC43NSBDMCw1LjEyNTI1IDAuMzA0LDUuNDI4NTcxNDMgMC42Nzg1NzE0MjksNS40Mjg1NzE0MyBMMS4zNTcxNDI4Niw1LjQyODU3MTQzIEw0LjA3MTQyODU3LDM1LjI4NTcxNDMgQzQuMDcxNDI4NTcsMzYuNzg0Njc4NiA1LjI4Njc1LDM4IDYuNzg1NzE0MjksMzggTDIxLjcxNDI4NTcsMzggQzIzLjIxMzI1LDM4IDI0LjQyODU3MTQsMzYuNzg0Njc4NiAyNC40Mjg1NzE0LDM1LjI4NTcxNDMgTDI3LjE0Mjg1NzEsNS40Mjg1NzE0MyBMMjcuODIxNDI4Niw1LjQyODU3MTQzIEMyOC4xOTY2Nzg2LDUuNDI4NTcxNDMgMjguNSw1LjEyNTI1IDI4LjUsNC43NSBDMjguNSw0LjM3NTQyODU3IDI4LjE5NjY3ODYsNC4wNzE0Mjg1NyAyNy44MjE0Mjg2LDQuMDcxNDI4NTcgTDI3LjgyMTQyODYsNC4wNzE0Mjg1NyBaIE05LjUsMi43MTQyODU3MSBDOS41LDEuOTY1MTQyODYgMTAuMTA4LDEuMzU3MTQyODYgMTAuODU3MTQyOSwxLjM1NzE0Mjg2IEwxNy42NDI4NTcxLDEuMzU3MTQyODYgQzE4LjM5MiwxLjM1NzE0Mjg2IDE5LDEuOTY1MTQyODYgMTksMi43MTQyODU3MSBMMTksNC4wNzE0Mjg1NyBMOS41LDQuMDcxNDI4NTcgTDkuNSwyLjcxNDI4NTcxIEw5LjUsMi43MTQyODU3MSBaIE0yMy4wNzE0Mjg2LDM1LjI4NTcxNDMgQzIzLjA3MTQyODYsMzYuMDM0ODU3MSAyMi40NjM0Mjg2LDM2LjY0Mjg1NzEgMjEuNzE0Mjg1NywzNi42NDI4NTcxIEw2Ljc4NTcxNDI5LDM2LjY0Mjg1NzEgQzYuMDM2NTcxNDMsMzYuNjQyODU3MSA1LjQyODU3MTQzLDM2LjAzNDg1NzEgNS40Mjg1NzE0MywzNS4yODU3MTQzIEwyLjcxNDI4NTcxLDUuNDI4NTcxNDMgTDguMTQyODU3MTQsNS40Mjg1NzE0MyBMOS41LDUuNDI4NTcxNDMgTDE5LDUuNDI4NTcxNDMgTDIwLjM1NzE0MjksNS40Mjg1NzE0MyBMMjUuNzg1NzE0Myw1LjQyODU3MTQzIEwyMy4wNzE0Mjg2LDM1LjI4NTcxNDMgTDIzLjA3MTQyODYsMzUuMjg1NzE0MyBaIE0xOS42NzI0NjQzLDguODI0MTQyODYgTDE4LjMyMjc4NTcsMzMuMjEyNjc4NiBDMTguMzAxMDcxNCwzMy41ODcyNSAxOC41ODYwNzE0LDMzLjkwNzUzNTcgMTguOTU5OTY0MywzMy45Mjk5Mjg2IEMxOS4zMzM4NTcxLDMzLjk1MjMyMTQgMTkuNjU0ODIxNCwzMy42NjU5NjQzIDE5LjY3NzIxNDMsMzMuMjkyNzUgTDIxLjAyNzU3MTQsOC45MDM1MzU3MSBDMjEuMDQ5Mjg1Nyw4LjUyOTY0Mjg2IDIwLjc2MzYwNzEsOC4yMDg2Nzg1NyAyMC4zOTAzOTI5LDguMTg2Mjg1NzEgQzIwLjAxNTgyMTQsOC4xNjM4OTI4NiAxOS42OTQ4NTcxLDguNDQ5NTcxNDMgMTkuNjcyNDY0Myw4LjgyNDE0Mjg2IEwxOS42NzI0NjQzLDguODI0MTQyODYgWiIgaWQ9IlNoYXBlIj48L3BhdGg+CiAgICAgICAgICAgICAgICAgICAgPC9nPgogICAgICAgICAgICAgICAgPC9nPgogICAgICAgICAgICA8L2c+CiAgICAgICAgPC9nPgogICAgPC9nPgo8L3N2Zz4="

};
module.exports = exports["default"];

/***/ }),

/***/ "./node_modules/js-alert/lib/index.js":
/*!********************************************!*\
  !*** ./node_modules/js-alert/lib/index.js ***!
  \********************************************/
/***/ ((module, exports, __webpack_require__) => {

"use strict";


Object.defineProperty(exports, "__esModule", ({
	value: true
}));

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

var _queue = __webpack_require__(/*! ./queue.js */ "./node_modules/js-alert/lib/queue.js");

var _queue2 = _interopRequireDefault(_queue);

var _eventSource = __webpack_require__(/*! ./event-source.js */ "./node_modules/js-alert/lib/event-source.js");

var _eventSource2 = _interopRequireDefault(_eventSource);

var _icons = __webpack_require__(/*! ./icons.js */ "./node_modules/js-alert/lib/icons.js");

var _icons2 = _interopRequireDefault(_icons);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

function _possibleConstructorReturn(self, call) { if (!self) { throw new ReferenceError("this hasn't been initialised - super() hasn't been called"); } return call && (typeof call === "object" || typeof call === "function") ? call : self; }

function _inherits(subClass, superClass) { if (typeof superClass !== "function" && superClass !== null) { throw new TypeError("Super expression must either be null or a function, not " + typeof superClass); } subClass.prototype = Object.create(superClass && superClass.prototype, { constructor: { value: subClass, enumerable: false, writable: true, configurable: true } }); if (superClass) Object.setPrototypeOf ? Object.setPrototypeOf(subClass, superClass) : subClass.__proto__ = superClass; } //
// Main class for the JSAlert package

var JSAlert = function (_EventSource) {
	_inherits(JSAlert, _EventSource);

	_createClass(JSAlert, null, [{
		key: 'alert',


		/** @static Creates and shows a new alert with the specified text */
		value: function alert(text, title, icon) {
			var closeText = arguments.length <= 3 || arguments[3] === undefined ? "Close" : arguments[3];


			// Check if not in a browser
			if (typeof window === "undefined") return Promise.resolve(console.log("Alert: " + text));

			// Create alert
			var alert = new JSAlert(text, title);
			alert.addButton(closeText, null);

			// Set icon
			if (icon !== false) alert.setIcon(icon || JSAlert.Icons.Information);

			// Show it
			return alert.show();
		}

		/** @static Creates and shows a new confirm alert with the specified text */

	}, {
		key: 'confirm',
		value: function confirm(text, title, icon) {
			var acceptText = arguments.length <= 3 || arguments[3] === undefined ? "OK" : arguments[3];
			var rejectText = arguments.length <= 4 || arguments[4] === undefined ? "Cancel" : arguments[4];


			// Check if not in a browser
			if (typeof window === "undefined") return Promise.resolve(console.log("Alert: " + text));

			// Create alert
			var alert = new JSAlert(text, title);
			alert.addButton(acceptText, true);
			alert.addButton(rejectText, false);

			// Set icon
			if (icon !== false) alert.setIcon(icon || JSAlert.Icons.Question);

			// Show it
			return alert.show();
		}

		/** @static Creates and shows a new prompt, an alert with a single text field. */

	}, {
		key: 'prompt',
		value: function prompt(text, defaultText, placeholderText, title, icon) {
			var acceptText = arguments.length <= 5 || arguments[5] === undefined ? "OK" : arguments[5];
			var rejectText = arguments.length <= 6 || arguments[6] === undefined ? "Cancel" : arguments[6];


			// Check if not in a browser
			if (typeof window === "undefined") return Promise.resolve(console.log("Alert: " + text));

			// Create alert
			var alert = new JSAlert(text, title);
			alert.addButton(acceptText, true, "default");
			alert.addButton(rejectText, false, "cancel");

			// Set icon
			if (icon !== false) alert.setIcon(icon || JSAlert.Icons.Question);

			// Add text field
			alert.addTextField(defaultText, null, placeholderText);

			// Show it
			return alert.show().then(function (result) {

				// Check if cancelled
				if (alert.cancelled) return null;else return alert.getTextFieldValue(0);
			});
		}

		/** @static Creates and shows a loader, which is just an alert with no buttons. */

	}, {
		key: 'loader',
		value: function loader(text, cancelable) {

			// Check if not in a browser
			if (typeof window === "undefined") return Promise.resolve(console.log("Loading: " + text));

			// Create alert
			var alert = new JSAlert(text);
			alert.cancelable = cancelable;

			// Show it
			return alert.show();
		}

		/** Constructor */

	}]);

	function JSAlert() {
		var text = arguments.length <= 0 || arguments[0] === undefined ? "" : arguments[0];
		var title = arguments.length <= 1 || arguments[1] === undefined ? "" : arguments[1];

		_classCallCheck(this, JSAlert);

		// Setup vars

		var _this = _possibleConstructorReturn(this, Object.getPrototypeOf(JSAlert).call(this));

		_this.elems = {};
		_this.title = title;
		_this.text = text;
		_this.buttons = [];
		_this.textFields = [];
		_this.result = false;
		_this.iconURL = null;
		_this.cancelable = true;
		_this.cancelled = false;
		_this.dismissed = false;

		return _this;
	}

	/** Sets an icon for the alert. `icon` is either a URL or one of `JSAlert.Icons`. */


	_createClass(JSAlert, [{
		key: 'setIcon',
		value: function setIcon(icon) {
			this.iconURL = icon;
		}

		/** Adds a button. Returns a Promise that is called if the button is clicked. */

	}, {
		key: 'addButton',
		value: function addButton(text, value, type) {
			var _this2 = this;

			// Return promise
			return new Promise(function (onSuccess, onFail) {

				// Add button
				_this2.buttons.push({
					text: text,
					value: typeof value == "undefined" ? text : value,
					type: type || (_this2.buttons.length == 0 ? "default" : "normal"),
					callback: onSuccess
				});
			});
		}

		/** Adds a text field. Returns a Promise that will be called when the dialog is dismissed, but not cancelled. */

	}, {
		key: 'addTextField',
		value: function addTextField(value, type, placeholderText) {

			// Add text field
			this.textFields.push({
				value: value || "",
				type: type || "text",
				placeholder: placeholderText || ""
			});
		}

		/** Gets a text field's value */

	}, {
		key: 'getTextFieldValue',
		value: function getTextFieldValue(index) {

			// Get text field info
			var info = this.textFields[index];

			// Return the value
			return info.elem ? info.elem.value : info.value;
		}

		/** Shows the alert. */

	}, {
		key: 'show',
		value: function show() {
			var _this3 = this;

			// Add to the queue
			JSAlert.popupQueue.add(this).then(function () {

				// Show us
				_this3._show();

				// Notify that we have been shown
				_this3.emit("opened");
			});

			// Return the alert
			return this;
		}

		/** A then function, to allow chaining with Promises */

	}, {
		key: 'then',
		value: function then(func) {
			return this.when("closed").then(func);
		}

		/** Dismisses the alert. */

	}, {
		key: 'dismiss',
		value: function dismiss(result) {

			// Do nothing if dismissed already
			if (this.dismissed) return;
			this.dismissed = true;

			// Remove us from the queue
			JSAlert.popupQueue.remove(this);

			// Store result
			this.result = result;
			if (typeof result == "undefined") this.cancelled = true;

			// Remove elements
			this.removeElements();

			// Remove global keyboard listener
			window.removeEventListener("keydown", this);

			// Trigger cancel-specific event
			if (this.cancelled) this.emit("cancelled", this.result);else this.emit("complete", this.result);

			// Trigger closed event
			this.emit("closed", this.result);
			return this;
		}

		/** Dismisses the alert some time in the future */

	}, {
		key: 'dismissIn',
		value: function dismissIn(time) {

			setTimeout(this.dismiss.bind(this), time);
			return this;
		}

		/** @private Called to actually show the alert. */

	}, {
		key: '_show',
		value: function _show() {

			// Create elements
			this.createBackground();
			this.createPopup();

			// Add global keyboard listener
			window.addEventListener("keydown", this);
		}

		/** @private Called to create the overlay element. Theme subclasses can override this. */

	}, {
		key: 'createBackground',
		value: function createBackground() {
			var _this4 = this;

			// Create element
			this.elems.background = document.createElement("div");
			this.elems.background.style.cssText = "position: fixed; top: 0px; left: 0px; width: 100%; height: 100%; z-index: 10000; background-color: rgba(0, 0, 0, 0.1); opacity: 0; transition: opacity 0.15s; ";

			// Add to document
			document.body.appendChild(this.elems.background);

			// Do animation
			setTimeout(function () {
				_this4.elems.background.offsetWidth;
				_this4.elems.background.style.opacity = 1;
			}, 0);
		}

		/** @private Called to create the popup element. Theme subclasses can override this. */

	}, {
		key: 'createPopup',
		value: function createPopup() {
			var _this5 = this;

			// Create container element
			this.elems.container = document.createElement("div");
			this.elems.container.focusable = true;
			this.elems.container.style.cssText = "position: fixed; top: 0px; left: 0px; width: 100%; height: 100%; z-index: 10001; display: flex; justify-content: center; align-items: center; opacity: 0; transform: translateY(-40px); transition: opacity 0.15s, transform 0.15s; ";
			document.body.appendChild(this.elems.container);

			// Do animation
			setTimeout(function () {
				_this5.elems.container.offsetWidth;
				_this5.elems.container.style.opacity = 1;
				_this5.elems.container.style.transform = "translateY(0px)";
			}, 0);

			// Add dismiss handler
			this.addTouchHandler(this.elems.container, function () {

				// Check if cancelable
				if (!_this5.cancelable) return;

				// Dismiss
				_this5.cancelled = true;
				_this5.dismiss();
			});

			// Create window
			this.elems.window = document.createElement("div");
			this.elems.window.style.cssText = "position: relative; background-color: rgba(255, 255, 255, 0.95); box-shadow: 0px 0px 20px rgba(0, 0, 0, 0.25); border-radius: 5px; padding: 10px; min-width: 50px; min-height: 10px; max-width: 50%; max-height: 90%; backdrop-filter: blur(8px); -webkit-backdrop-filter: blur(8px); ";
			this.elems.container.appendChild(this.elems.window);

			// Create icon if there is one
			if (this.iconURL) {

				this.elems.icon = document.createElement("img");
				this.elems.icon.style.cssText = "display: block; margin: auto; max-height: 40px; text-align: center; font-family: Helvetica, Arial; font-size: 17px; font-weight: bold; color: #000; cursor: default; padding: 10px 0px; ";
				this.elems.icon.src = this.iconURL;
				this.elems.window.appendChild(this.elems.icon);
			}

			// Create title if there is one
			if (this.title) {

				this.elems.title = document.createElement("div");
				this.elems.title.style.cssText = "display: block; text-align: center; font-family: Helvetica, Arial; font-size: 17px; font-weight: bold; color: #000; cursor: default; padding: 2px 20px; ";
				this.elems.title.innerHTML = this.title;
				this.elems.window.appendChild(this.elems.title);
			}

			// Create text if there is one
			if (this.text) {

				this.elems.text = document.createElement("div");
				this.elems.text.style.cssText = "display: block; text-align: center; font-family: Helvetica, Arial; font-size: 15px; font-weight: normal; color: #000; cursor: default; padding: 2px 20px; ";
				this.elems.text.innerHTML = this.text;
				this.elems.window.appendChild(this.elems.text);
			}

			// Create text fields if there are any
			if (this.textFields.length > 0) {

				this.elems.textFields = document.createElement("div");
				this.elems.textFields.style.cssText = "display: block; ";
				this.elems.window.appendChild(this.elems.textFields);

				// Add each button
				this.textFields.forEach(function (b, idx) {

					b.elem = document.createElement("input");
					b.elem.style.cssText = "display: block; width: 90%; min-width: 250px; padding: 5px 0px; margin: 10px auto; background-color: #FFF; border: 1px solid #EEE; border-radius: 5px; text-align: center; font-family: Helvetica, Arial; font-size: 15px; color: #222; ";
					b.elem.value = b.value;
					b.elem.placeholder = b.placeholder;
					b.elem.type = b.type;
					_this5.elems.textFields.appendChild(b.elem);

					// Add keyboard listener
					b.elem.addEventListener("keypress", function (e) {

						// Ignore if not enter
						if (e.keyCode != 13) return;

						// Check if this is the last input field
						if (idx + 1 >= _this5.textFields.length) {

							// Done
							_this5.dismiss("enter-pressed");
						} else {

							// Just select the next field
							_this5.textFields[idx + 1].elem.focus();
						}
					});
				});

				// Focus on first field
				this.textFields[0].elem.focus();
			}

			// Create buttons if there are any
			if (this.buttons.length > 0) {

				this.elems.buttons = document.createElement("div");
				this.elems.buttons.style.cssText = "display: block; display: flex; justify-content: space-around; align-items: center; text-align: right; border-top: 1px solid #EEE; margin-top: 10px; ";
				this.elems.window.appendChild(this.elems.buttons);

				// Add each button
				this.buttons.forEach(function (b) {

					var btn = document.createElement("div");
					btn.style.cssText = "display: inline-block; font-family: Helvetica, Arial; font-size: 15px; font-weight: 200; color: #08F; padding: 10px 20px; padding-bottom: 0px; cursor: pointer; ";
					btn.innerText = b.text;
					_this5.elems.buttons.appendChild(btn);

					// Add button handler
					_this5.addTouchHandler(btn, function () {
						b.callback && b.callback(b.value);
						if (b.type == "cancel") _this5.cancelled = true;
						_this5.dismiss(b.value);
					});
				});
			}
		}

		/** @private Called to remove all elements from the screen */

	}, {
		key: 'removeElements',
		value: function removeElements() {
			var _this6 = this;

			// Don't do anything if not loaded
			if (!this.elems || !this.elems.container) return;

			// Animate background away
			this.elems.background.style.opacity = 0;
			this.elems.container.style.opacity = 0;
			this.elems.container.style.transform = "translateY(40px)";

			// Remove elements after animation
			setTimeout(function () {
				_this6.removeElement(_this6.elems.background);
				_this6.removeElement(_this6.elems.container);
			}, 250);
		}

		/** @private Helper function to remove an element */

	}, {
		key: 'removeElement',
		value: function removeElement(elem) {
			elem && elem.parentNode && elem.parentNode.removeChild(elem);
		}

		/** @private Helper function to add a click or touch event handler that doesn't bubble */

	}, {
		key: 'addTouchHandler',
		value: function addTouchHandler(elem, callback) {

			// Create handler
			var handler = function handler(e) {

				// Stop default browser action, unless this is an input field
				if (e.target.nodeName.toLowerCase() != "input") e.preventDefault();

				// Check if our element was pressed, not a child element
				if (e.target != elem) return;

				// Trigger callback
				callback();
			};

			// Add listeners
			this.elems.container.addEventListener("mousedown", handler, true);
			this.elems.container.addEventListener("touchstart", handler, true);
		}

		/** @private Called by the browser when a keyboard event is fired on the whole window */

	}, {
		key: 'handleEvent',
		value: function handleEvent(e) {

			// Check if enter was pressed
			if (e.keyCode == 13) {

				// Find the first default button and use that value instead
				for (var i = 0; i < this.buttons.length; i++) {
					if (this.buttons[i].type == "default") {

						// Use this button's value
						this.dismiss(this.buttons[i].value);
						e.preventDefault();

						// Trigger the button's callback
						this.buttons[i].callback && this.buttons[i].callback(this.result);
						return;
					}
				}

				// No default button found, cancel
				this.cancelled = true;
				this.dismiss();
				return;
			}

			// Check if escape was pressed
			if (e.keyCode == 27) {

				// Check if cancelable
				if (!this.cancelable) return;

				// Find the first default button and use that value instead
				this.cancelled = true;
				this.result = null;
				for (var i = 0; i < this.buttons.length; i++) {
					if (this.buttons[i].type == "cancel") {

						// Use this button's value
						this.dismiss(this.buttons[i].value);
						e.preventDefault();

						// Trigger the button's callback
						this.buttons[i].callback && this.buttons[i].callback(this.result);
						return;
					}
				}

				// No cancel button found, just cancel
				this.cancelled = true;
				this.dismiss();
				return;
			}
		}
	}]);

	return JSAlert;
}(_eventSource2.default);

// Include theme's icons


exports["default"] = JSAlert;

JSAlert.Icons = _icons2.default;

// The default popup queue
JSAlert.popupQueue = new _queue2.default();

// In case anyone wants to use the classes of this project on their own...
JSAlert.Queue = _queue2.default;
JSAlert.EventSource = _eventSource2.default;
module.exports = exports['default'];

/***/ }),

/***/ "./node_modules/js-alert/lib/queue.js":
/*!********************************************!*\
  !*** ./node_modules/js-alert/lib/queue.js ***!
  \********************************************/
/***/ ((module, exports, __webpack_require__) => {

"use strict";


Object.defineProperty(exports, "__esModule", ({
	value: true
}));

var _createClass = function () { function defineProperties(target, props) { for (var i = 0; i < props.length; i++) { var descriptor = props[i]; descriptor.enumerable = descriptor.enumerable || false; descriptor.configurable = true; if ("value" in descriptor) descriptor.writable = true; Object.defineProperty(target, descriptor.key, descriptor); } } return function (Constructor, protoProps, staticProps) { if (protoProps) defineProperties(Constructor.prototype, protoProps); if (staticProps) defineProperties(Constructor, staticProps); return Constructor; }; }();

var _eventSource = __webpack_require__(/*! ./event-source.js */ "./node_modules/js-alert/lib/event-source.js");

var _eventSource2 = _interopRequireDefault(_eventSource);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

function _classCallCheck(instance, Constructor) { if (!(instance instanceof Constructor)) { throw new TypeError("Cannot call a class as a function"); } }

function _possibleConstructorReturn(self, call) { if (!self) { throw new ReferenceError("this hasn't been initialised - super() hasn't been called"); } return call && (typeof call === "object" || typeof call === "function") ? call : self; }

function _inherits(subClass, superClass) { if (typeof superClass !== "function" && superClass !== null) { throw new TypeError("Super expression must either be null or a function, not " + typeof superClass); } subClass.prototype = Object.create(superClass && superClass.prototype, { constructor: { value: subClass, enumerable: false, writable: true, configurable: true } }); if (superClass) Object.setPrototypeOf ? Object.setPrototypeOf(subClass, superClass) : subClass.__proto__ = superClass; } //
// Queue class - A queue contains a list of items. Only one item can be active
// at a time, and when one is removed the next one is activated
//
// To use this class, first add() your item. A promise will be returned that gets resolved
// when your item is ready to be activated. Once your item is finished doing what it needs
// to do, remove() it. This will trigger the next item's promise.
//
//	Example:
//
//		var queue = new Queue();
//		
//		var msgbox = new Popup();
//		queue.add(msgbox).then(() => {
//			msgbox.show();
//			msgbox.when('closed').then(() => queue.remove(msgbox));
//		}
//		
//		var msgbox2 = new Popup();
//		queue.add(msgbox2).then(() => {
//			msgbox2.show();
//			msgbox2.when('closed').then(() => queue.remove(msgbox2));
//		}
//	
//
//	In the above example, only one message box would be visible at a time.
//

var Queue = function (_EventSource) {
	_inherits(Queue, _EventSource);

	function Queue() {
		_classCallCheck(this, Queue);

		// Setup vars

		var _this = _possibleConstructorReturn(this, Object.getPrototypeOf(Queue).call(this));

		_this.items = [];
		_this.current = null;

		return _this;
	}

	/** Adds a queue item, and returns a Promise. */


	_createClass(Queue, [{
		key: "add",
		value: function add(item) {
			var _this2 = this;

			// Return a promise
			return new Promise(function (onSuccess, onFail) {

				// Store item and handler at the end of the queue. When this item is ready to be activated, the handler will be called to resolve the promise.
				_this2.items.push({
					item: item,
					activateHandler: onSuccess
				});

				// Emit event
				_this2.emit("added", item);

				// Check if we can activate this one now
				setTimeout(_this2.checkActivated.bind(_this2), 1);
			});
		}

		/** @private Checks if there a new item to be activated */

	}, {
		key: "checkActivated",
		value: function checkActivated() {

			// Check if there's already an activated item
			if (this.current) return;

			// Check if we have any items
			if (this.items.length == 0) {

				// No more items
				this.emit("empty");
				return;
			}

			// We can activate the next item now
			this.current = this.items[0];

			// Create promise resolve response. DO NOT directly pass a thenable, it won't work!
			var resp = {
				item: this.current.item
			};

			// Resolve promise
			this.current.activateHandler && this.current.activateHandler(resp);

			// Trigger event
			this.emit("activated", resp);
		}

		/** Removes a queued item. If the item is the currently activated one, the next item in the queue will be activated. */

	}, {
		key: "remove",
		value: function remove(item) {

			// Remove item from queue
			for (var i = 0; i < this.items.length; i++) {
				if (this.items[i].item == item) this.items.splice(i--, 1);
			} // Emit event
			this.emit("removed", item);

			// Check if this was the current item
			if (this.current && this.current.item == item) this.current = null;

			// Possibly activate the next item
			setTimeout(this.checkActivated.bind(this), 1);
		}
	}]);

	return Queue;
}(_eventSource2.default);

exports["default"] = Queue;
module.exports = exports["default"];

/***/ }),

/***/ "./node_modules/js-loading-overlay/dist/js-loading-overlay.min.js":
/*!************************************************************************!*\
  !*** ./node_modules/js-loading-overlay/dist/js-loading-overlay.min.js ***!
  \************************************************************************/
/***/ (() => {

!function(e){var t={};function n(o){if(t[o])return t[o].exports;var i=t[o]={i:o,l:!1,exports:{}};return e[o].call(i.exports,i,i.exports,n),i.l=!0,i.exports}n.m=e,n.c=t,n.d=function(e,t,o){n.o(e,t)||Object.defineProperty(e,t,{enumerable:!0,get:o})},n.r=function(e){"undefined"!=typeof Symbol&&Symbol.toStringTag&&Object.defineProperty(e,Symbol.toStringTag,{value:"Module"}),Object.defineProperty(e,"__esModule",{value:!0})},n.t=function(e,t){if(1&t&&(e=n(e)),8&t)return e;if(4&t&&"object"==typeof e&&e&&e.__esModule)return e;var o=Object.create(null);if(n.r(o),Object.defineProperty(o,"default",{enumerable:!0,value:e}),2&t&&"string"!=typeof e)for(var i in e)n.d(o,i,function(t){return e[t]}.bind(null,i));return o},n.n=function(e){var t=e&&e.__esModule?function(){return e.default}:function(){return e};return n.d(t,"a",t),t},n.o=function(e,t){return Object.prototype.hasOwnProperty.call(e,t)},n.p="",n(n.s=0)}([function(e,t,n){e.exports=n(1)},function(e,t){function n(e,t){for(var n=0;n<t.length;n++){var o=t[n];o.enumerable=o.enumerable||!1,o.configurable=!0,"value"in o&&(o.writable=!0),Object.defineProperty(e,o.key,o)}}var o=function(){function e(){!function(e,t){if(!(e instanceof t))throw new TypeError("Cannot call a class as a function")}(this,e),this.options={overlayBackgroundColor:"#666666",overlayOpacity:.6,spinnerIcon:"ball-circus",spinnerColor:"#000",spinnerSize:"3x",overlayIDName:"overlay",spinnerIDName:"spinner",offsetY:0,offsetX:0,lockScroll:!1,containerID:null,spinnerZIndex:99999,overlayZIndex:99998},this.stylesheetBaseURL="https://cdn.jsdelivr.net/npm/load-awesome@1.1.0/css/",this.spinner=null,this.spinnerStylesheetURL=null,this.numberOfEmptyDivForSpinner={"ball-8bits":16,"ball-atom":4,"ball-beat":3,"ball-circus":5,"ball-climbing-dot":1,"ball-clip-rotate":1,"ball-clip-rotate-multiple":2,"ball-clip-rotate-pulse":2,"ball-elastic-dots":5,"ball-fall":3,"ball-fussion":4,"ball-grid-beat":9,"ball-grid-pulse":9,"ball-newton-cradle":4,"ball-pulse":3,"ball-pulse-rise":5,"ball-pulse-sync":3,"ball-rotate":1,"ball-running-dots":5,"ball-scale":1,"ball-scale-multiple":3,"ball-scale-pulse":2,"ball-scale-ripple":1,"ball-scale-ripple-multiple":3,"ball-spin":8,"ball-spin-clockwise":8,"ball-spin-clockwise-fade":8,"ball-spin-clockwise-fade-rotating":8,"ball-spin-fade":8,"ball-spin-fade-rotating":8,"ball-spin-rotate":2,"ball-square-clockwise-spin":8,"ball-square-spin":8,"ball-triangle-path":3,"ball-zig-zag":2,"ball-zig-zag-deflect":2,cog:1,"cube-transition":2,fire:3,"line-scale":5,"line-scale-party":5,"line-scale-pulse-out":5,"line-scale-pulse-out-rapid":5,"line-spin-clockwise-fade":8,"line-spin-clockwise-fade-rotating":8,"line-spin-fade":8,"line-spin-fade-rotating":8,pacman:6,"square-jelly-box":2,"square-loader":1,"square-spin":1,timer:1,"triangle-skew-spin":1}}var t,o,i;return t=e,(o=[{key:"show",value:function(e){this.setOptions(e),this.addSpinnerStylesheet(),this.generateSpinnerElement(),this.options.lockScroll&&(document.body.style.overflow="hidden",document.documentElement.style.overflow="hidden"),this.generateAndAddOverlayElement()}},{key:"hide",value:function(){this.options.lockScroll&&(document.body.style.overflow="",document.documentElement.style.overflow="");var e=document.getElementById("loading-overlay-stylesheet");e&&(e.disabled=!0,e.parentNode.removeChild(e),document.getElementById(this.options.overlayIDName).remove(),document.getElementById(this.options.spinnerIDName).remove())}},{key:"setOptions",value:function(e){if(void 0!==e)for(var t in e)this.options[t]=e[t]}},{key:"generateAndAddOverlayElement",value:function(){var e="50%";0!==this.options.offsetX&&(e="calc(50% + "+this.options.offsetX+")");var t="50%";if(0!==this.options.offsetY&&(t="calc(50% + "+this.options.offsetY+")"),this.options.containerID&&document.body.contains(document.getElementById(this.options.containerID))){var n='<div id="'.concat(this.options.overlayIDName,'" style="display: block !important; position: absolute; top: 0; left: 0; overflow: auto; opacity: ').concat(this.options.overlayOpacity,"; background: ").concat(this.options.overlayBackgroundColor,'; z-index: 50; width: 100%; height: 100%;"></div><div id="').concat(this.options.spinnerIDName,'" style="display: block !important; position: absolute; top: ').concat(t,"; left: ").concat(e,'; -webkit-transform: translate(-50%); -ms-transform: translate(-50%); transform: translate(-50%); z-index: 9999;">').concat(this.spinner,"</div>"),o=document.getElementById(this.options.containerID);return o.style.position="relative",void o.insertAdjacentHTML("beforeend",n)}var i='<div id="'.concat(this.options.overlayIDName,'" style="display: block !important; position: fixed; top: 0; left: 0; overflow: auto; opacity: ').concat(this.options.overlayOpacity,"; background: ").concat(this.options.overlayBackgroundColor,"; z-index: ").concat(this.options.overlayZIndex,'; width: 100%; height: 100%;"></div><div id="').concat(this.options.spinnerIDName,'" style="display: block !important; position: fixed; top: ').concat(t,"; left: ").concat(e,"; -webkit-transform: translate(-50%); -ms-transform: translate(-50%); transform: translate(-50%); z-index: ").concat(this.options.spinnerZIndex,';">').concat(this.spinner,"</div>");document.body.insertAdjacentHTML("beforeend",i)}},{key:"generateSpinnerElement",value:function(){var e=this,t=Object.keys(this.numberOfEmptyDivForSpinner).find((function(t){return t===e.options.spinnerIcon})),n=this.generateEmptyDivElement(this.numberOfEmptyDivForSpinner[t]);this.spinner='<div style="color: '.concat(this.options.spinnerColor,'" class="la-').concat(this.options.spinnerIcon," la-").concat(this.options.spinnerSize,'">').concat(n,"</div>")}},{key:"addSpinnerStylesheet",value:function(){this.setSpinnerStylesheetURL();var e=document.createElement("link");e.setAttribute("id","loading-overlay-stylesheet"),e.setAttribute("rel","stylesheet"),e.setAttribute("type","text/css"),e.setAttribute("href",this.spinnerStylesheetURL),document.getElementsByTagName("head")[0].appendChild(e)}},{key:"setSpinnerStylesheetURL",value:function(){this.spinnerStylesheetURL=this.stylesheetBaseURL+this.options.spinnerIcon+".min.css"}},{key:"generateEmptyDivElement",value:function(e){for(var t="",n=1;n<=e;n++)t+="<div></div>";return t}}])&&n(t.prototype,o),i&&n(t,i),e}();window.JsLoadingOverlay=new o,e.exports=JsLoadingOverlay}]);
//# sourceMappingURL=js-loading-overlay.min.js.map

/***/ }),

/***/ "./src/styles.css":
/*!************************!*\
  !*** ./src/styles.css ***!
  \************************/
/***/ ((__unused_webpack_module, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "default": () => (__WEBPACK_DEFAULT_EXPORT__)
/* harmony export */ });
/* harmony import */ var _node_modules_style_loader_dist_runtime_injectStylesIntoStyleTag_js__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! !../node_modules/style-loader/dist/runtime/injectStylesIntoStyleTag.js */ "./node_modules/style-loader/dist/runtime/injectStylesIntoStyleTag.js");
/* harmony import */ var _node_modules_style_loader_dist_runtime_injectStylesIntoStyleTag_js__WEBPACK_IMPORTED_MODULE_0___default = /*#__PURE__*/__webpack_require__.n(_node_modules_style_loader_dist_runtime_injectStylesIntoStyleTag_js__WEBPACK_IMPORTED_MODULE_0__);
/* harmony import */ var _node_modules_style_loader_dist_runtime_styleDomAPI_js__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! !../node_modules/style-loader/dist/runtime/styleDomAPI.js */ "./node_modules/style-loader/dist/runtime/styleDomAPI.js");
/* harmony import */ var _node_modules_style_loader_dist_runtime_styleDomAPI_js__WEBPACK_IMPORTED_MODULE_1___default = /*#__PURE__*/__webpack_require__.n(_node_modules_style_loader_dist_runtime_styleDomAPI_js__WEBPACK_IMPORTED_MODULE_1__);
/* harmony import */ var _node_modules_style_loader_dist_runtime_insertBySelector_js__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! !../node_modules/style-loader/dist/runtime/insertBySelector.js */ "./node_modules/style-loader/dist/runtime/insertBySelector.js");
/* harmony import */ var _node_modules_style_loader_dist_runtime_insertBySelector_js__WEBPACK_IMPORTED_MODULE_2___default = /*#__PURE__*/__webpack_require__.n(_node_modules_style_loader_dist_runtime_insertBySelector_js__WEBPACK_IMPORTED_MODULE_2__);
/* harmony import */ var _node_modules_style_loader_dist_runtime_setAttributesWithoutAttributes_js__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! !../node_modules/style-loader/dist/runtime/setAttributesWithoutAttributes.js */ "./node_modules/style-loader/dist/runtime/setAttributesWithoutAttributes.js");
/* harmony import */ var _node_modules_style_loader_dist_runtime_setAttributesWithoutAttributes_js__WEBPACK_IMPORTED_MODULE_3___default = /*#__PURE__*/__webpack_require__.n(_node_modules_style_loader_dist_runtime_setAttributesWithoutAttributes_js__WEBPACK_IMPORTED_MODULE_3__);
/* harmony import */ var _node_modules_style_loader_dist_runtime_insertStyleElement_js__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! !../node_modules/style-loader/dist/runtime/insertStyleElement.js */ "./node_modules/style-loader/dist/runtime/insertStyleElement.js");
/* harmony import */ var _node_modules_style_loader_dist_runtime_insertStyleElement_js__WEBPACK_IMPORTED_MODULE_4___default = /*#__PURE__*/__webpack_require__.n(_node_modules_style_loader_dist_runtime_insertStyleElement_js__WEBPACK_IMPORTED_MODULE_4__);
/* harmony import */ var _node_modules_style_loader_dist_runtime_styleTagTransform_js__WEBPACK_IMPORTED_MODULE_5__ = __webpack_require__(/*! !../node_modules/style-loader/dist/runtime/styleTagTransform.js */ "./node_modules/style-loader/dist/runtime/styleTagTransform.js");
/* harmony import */ var _node_modules_style_loader_dist_runtime_styleTagTransform_js__WEBPACK_IMPORTED_MODULE_5___default = /*#__PURE__*/__webpack_require__.n(_node_modules_style_loader_dist_runtime_styleTagTransform_js__WEBPACK_IMPORTED_MODULE_5__);
/* harmony import */ var _node_modules_css_loader_dist_cjs_js_node_modules_postcss_loader_dist_cjs_js_styles_css__WEBPACK_IMPORTED_MODULE_6__ = __webpack_require__(/*! !!../node_modules/css-loader/dist/cjs.js!../node_modules/postcss-loader/dist/cjs.js!./styles.css */ "./node_modules/css-loader/dist/cjs.js!./node_modules/postcss-loader/dist/cjs.js!./src/styles.css");

      
      
      
      
      
      
      
      
      

var options = {};

options.styleTagTransform = (_node_modules_style_loader_dist_runtime_styleTagTransform_js__WEBPACK_IMPORTED_MODULE_5___default());
options.setAttributes = (_node_modules_style_loader_dist_runtime_setAttributesWithoutAttributes_js__WEBPACK_IMPORTED_MODULE_3___default());

      options.insert = _node_modules_style_loader_dist_runtime_insertBySelector_js__WEBPACK_IMPORTED_MODULE_2___default().bind(null, "head");
    
options.domAPI = (_node_modules_style_loader_dist_runtime_styleDomAPI_js__WEBPACK_IMPORTED_MODULE_1___default());
options.insertStyleElement = (_node_modules_style_loader_dist_runtime_insertStyleElement_js__WEBPACK_IMPORTED_MODULE_4___default());

var update = _node_modules_style_loader_dist_runtime_injectStylesIntoStyleTag_js__WEBPACK_IMPORTED_MODULE_0___default()(_node_modules_css_loader_dist_cjs_js_node_modules_postcss_loader_dist_cjs_js_styles_css__WEBPACK_IMPORTED_MODULE_6__["default"], options);




       /* harmony default export */ const __WEBPACK_DEFAULT_EXPORT__ = (_node_modules_css_loader_dist_cjs_js_node_modules_postcss_loader_dist_cjs_js_styles_css__WEBPACK_IMPORTED_MODULE_6__["default"] && _node_modules_css_loader_dist_cjs_js_node_modules_postcss_loader_dist_cjs_js_styles_css__WEBPACK_IMPORTED_MODULE_6__["default"].locals ? _node_modules_css_loader_dist_cjs_js_node_modules_postcss_loader_dist_cjs_js_styles_css__WEBPACK_IMPORTED_MODULE_6__["default"].locals : undefined);


/***/ }),

/***/ "./node_modules/style-loader/dist/runtime/injectStylesIntoStyleTag.js":
/*!****************************************************************************!*\
  !*** ./node_modules/style-loader/dist/runtime/injectStylesIntoStyleTag.js ***!
  \****************************************************************************/
/***/ ((module) => {

"use strict";


var stylesInDOM = [];

function getIndexByIdentifier(identifier) {
  var result = -1;

  for (var i = 0; i < stylesInDOM.length; i++) {
    if (stylesInDOM[i].identifier === identifier) {
      result = i;
      break;
    }
  }

  return result;
}

function modulesToDom(list, options) {
  var idCountMap = {};
  var identifiers = [];

  for (var i = 0; i < list.length; i++) {
    var item = list[i];
    var id = options.base ? item[0] + options.base : item[0];
    var count = idCountMap[id] || 0;
    var identifier = "".concat(id, " ").concat(count);
    idCountMap[id] = count + 1;
    var indexByIdentifier = getIndexByIdentifier(identifier);
    var obj = {
      css: item[1],
      media: item[2],
      sourceMap: item[3],
      supports: item[4],
      layer: item[5]
    };

    if (indexByIdentifier !== -1) {
      stylesInDOM[indexByIdentifier].references++;
      stylesInDOM[indexByIdentifier].updater(obj);
    } else {
      var updater = addElementStyle(obj, options);
      options.byIndex = i;
      stylesInDOM.splice(i, 0, {
        identifier: identifier,
        updater: updater,
        references: 1
      });
    }

    identifiers.push(identifier);
  }

  return identifiers;
}

function addElementStyle(obj, options) {
  var api = options.domAPI(options);
  api.update(obj);

  var updater = function updater(newObj) {
    if (newObj) {
      if (newObj.css === obj.css && newObj.media === obj.media && newObj.sourceMap === obj.sourceMap && newObj.supports === obj.supports && newObj.layer === obj.layer) {
        return;
      }

      api.update(obj = newObj);
    } else {
      api.remove();
    }
  };

  return updater;
}

module.exports = function (list, options) {
  options = options || {};
  list = list || [];
  var lastIdentifiers = modulesToDom(list, options);
  return function update(newList) {
    newList = newList || [];

    for (var i = 0; i < lastIdentifiers.length; i++) {
      var identifier = lastIdentifiers[i];
      var index = getIndexByIdentifier(identifier);
      stylesInDOM[index].references--;
    }

    var newLastIdentifiers = modulesToDom(newList, options);

    for (var _i = 0; _i < lastIdentifiers.length; _i++) {
      var _identifier = lastIdentifiers[_i];

      var _index = getIndexByIdentifier(_identifier);

      if (stylesInDOM[_index].references === 0) {
        stylesInDOM[_index].updater();

        stylesInDOM.splice(_index, 1);
      }
    }

    lastIdentifiers = newLastIdentifiers;
  };
};

/***/ }),

/***/ "./node_modules/style-loader/dist/runtime/insertBySelector.js":
/*!********************************************************************!*\
  !*** ./node_modules/style-loader/dist/runtime/insertBySelector.js ***!
  \********************************************************************/
/***/ ((module) => {

"use strict";


var memo = {};
/* istanbul ignore next  */

function getTarget(target) {
  if (typeof memo[target] === "undefined") {
    var styleTarget = document.querySelector(target); // Special case to return head of iframe instead of iframe itself

    if (window.HTMLIFrameElement && styleTarget instanceof window.HTMLIFrameElement) {
      try {
        // This will throw an exception if access to iframe is blocked
        // due to cross-origin restrictions
        styleTarget = styleTarget.contentDocument.head;
      } catch (e) {
        // istanbul ignore next
        styleTarget = null;
      }
    }

    memo[target] = styleTarget;
  }

  return memo[target];
}
/* istanbul ignore next  */


function insertBySelector(insert, style) {
  var target = getTarget(insert);

  if (!target) {
    throw new Error("Couldn't find a style target. This probably means that the value for the 'insert' parameter is invalid.");
  }

  target.appendChild(style);
}

module.exports = insertBySelector;

/***/ }),

/***/ "./node_modules/style-loader/dist/runtime/insertStyleElement.js":
/*!**********************************************************************!*\
  !*** ./node_modules/style-loader/dist/runtime/insertStyleElement.js ***!
  \**********************************************************************/
/***/ ((module) => {

"use strict";


/* istanbul ignore next  */
function insertStyleElement(options) {
  var element = document.createElement("style");
  options.setAttributes(element, options.attributes);
  options.insert(element, options.options);
  return element;
}

module.exports = insertStyleElement;

/***/ }),

/***/ "./node_modules/style-loader/dist/runtime/setAttributesWithoutAttributes.js":
/*!**********************************************************************************!*\
  !*** ./node_modules/style-loader/dist/runtime/setAttributesWithoutAttributes.js ***!
  \**********************************************************************************/
/***/ ((module, __unused_webpack_exports, __webpack_require__) => {

"use strict";


/* istanbul ignore next  */
function setAttributesWithoutAttributes(styleElement) {
  var nonce =  true ? __webpack_require__.nc : 0;

  if (nonce) {
    styleElement.setAttribute("nonce", nonce);
  }
}

module.exports = setAttributesWithoutAttributes;

/***/ }),

/***/ "./node_modules/style-loader/dist/runtime/styleDomAPI.js":
/*!***************************************************************!*\
  !*** ./node_modules/style-loader/dist/runtime/styleDomAPI.js ***!
  \***************************************************************/
/***/ ((module) => {

"use strict";


/* istanbul ignore next  */
function apply(styleElement, options, obj) {
  var css = "";

  if (obj.supports) {
    css += "@supports (".concat(obj.supports, ") {");
  }

  if (obj.media) {
    css += "@media ".concat(obj.media, " {");
  }

  var needLayer = typeof obj.layer !== "undefined";

  if (needLayer) {
    css += "@layer".concat(obj.layer.length > 0 ? " ".concat(obj.layer) : "", " {");
  }

  css += obj.css;

  if (needLayer) {
    css += "}";
  }

  if (obj.media) {
    css += "}";
  }

  if (obj.supports) {
    css += "}";
  }

  var sourceMap = obj.sourceMap;

  if (sourceMap && typeof btoa !== "undefined") {
    css += "\n/*# sourceMappingURL=data:application/json;base64,".concat(btoa(unescape(encodeURIComponent(JSON.stringify(sourceMap)))), " */");
  } // For old IE

  /* istanbul ignore if  */


  options.styleTagTransform(css, styleElement, options.options);
}

function removeStyleElement(styleElement) {
  // istanbul ignore if
  if (styleElement.parentNode === null) {
    return false;
  }

  styleElement.parentNode.removeChild(styleElement);
}
/* istanbul ignore next  */


function domAPI(options) {
  var styleElement = options.insertStyleElement(options);
  return {
    update: function update(obj) {
      apply(styleElement, options, obj);
    },
    remove: function remove() {
      removeStyleElement(styleElement);
    }
  };
}

module.exports = domAPI;

/***/ }),

/***/ "./node_modules/style-loader/dist/runtime/styleTagTransform.js":
/*!*********************************************************************!*\
  !*** ./node_modules/style-loader/dist/runtime/styleTagTransform.js ***!
  \*********************************************************************/
/***/ ((module) => {

"use strict";


/* istanbul ignore next  */
function styleTagTransform(css, styleElement) {
  if (styleElement.styleSheet) {
    styleElement.styleSheet.cssText = css;
  } else {
    while (styleElement.firstChild) {
      styleElement.removeChild(styleElement.firstChild);
    }

    styleElement.appendChild(document.createTextNode(css));
  }
}

module.exports = styleTagTransform;

/***/ }),

/***/ "./node_modules/websocket/lib/browser.js":
/*!***********************************************!*\
  !*** ./node_modules/websocket/lib/browser.js ***!
  \***********************************************/
/***/ ((module, __unused_webpack_exports, __webpack_require__) => {

var _globalThis;
if (typeof globalThis === 'object') {
	_globalThis = globalThis;
} else {
	try {
		_globalThis = __webpack_require__(/*! es5-ext/global */ "./node_modules/es5-ext/global.js");
	} catch (error) {
	} finally {
		if (!_globalThis && typeof window !== 'undefined') { _globalThis = window; }
		if (!_globalThis) { throw new Error('Could not determine global this'); }
	}
}

var NativeWebSocket = _globalThis.WebSocket || _globalThis.MozWebSocket;
var websocket_version = __webpack_require__(/*! ./version */ "./node_modules/websocket/lib/version.js");


/**
 * Expose a W3C WebSocket class with just one or two arguments.
 */
function W3CWebSocket(uri, protocols) {
	var native_instance;

	if (protocols) {
		native_instance = new NativeWebSocket(uri, protocols);
	}
	else {
		native_instance = new NativeWebSocket(uri);
	}

	/**
	 * 'native_instance' is an instance of nativeWebSocket (the browser's WebSocket
	 * class). Since it is an Object it will be returned as it is when creating an
	 * instance of W3CWebSocket via 'new W3CWebSocket()'.
	 *
	 * ECMAScript 5: http://bclary.com/2004/11/07/#a-13.2.2
	 */
	return native_instance;
}
if (NativeWebSocket) {
	['CONNECTING', 'OPEN', 'CLOSING', 'CLOSED'].forEach(function(prop) {
		Object.defineProperty(W3CWebSocket, prop, {
			get: function() { return NativeWebSocket[prop]; }
		});
	});
}

/**
 * Module exports.
 */
module.exports = {
    'w3cwebsocket' : NativeWebSocket ? W3CWebSocket : null,
    'version'      : websocket_version
};


/***/ }),

/***/ "./node_modules/websocket/lib/version.js":
/*!***********************************************!*\
  !*** ./node_modules/websocket/lib/version.js ***!
  \***********************************************/
/***/ ((module, __unused_webpack_exports, __webpack_require__) => {

module.exports = __webpack_require__(/*! ../package.json */ "./node_modules/websocket/package.json").version;


/***/ }),

/***/ "data:image/svg+xml,%3csvg viewBox=%270 0 16 16%27 fill=%27white%27 xmlns=%27http://www.w3.org/2000/svg%27%3e%3ccircle cx=%278%27 cy=%278%27 r=%273%27/%3e%3c/svg%3e":
/*!***************************************************************************************************************************************************************************!*\
  !*** data:image/svg+xml,%3csvg viewBox=%270 0 16 16%27 fill=%27white%27 xmlns=%27http://www.w3.org/2000/svg%27%3e%3ccircle cx=%278%27 cy=%278%27 r=%273%27/%3e%3c/svg%3e ***!
  \***************************************************************************************************************************************************************************/
/***/ ((module) => {

"use strict";
module.exports = "data:image/svg+xml,%3csvg viewBox=%270 0 16 16%27 fill=%27white%27 xmlns=%27http://www.w3.org/2000/svg%27%3e%3ccircle cx=%278%27 cy=%278%27 r=%273%27/%3e%3c/svg%3e";

/***/ }),

/***/ "data:image/svg+xml,%3csvg viewBox=%270 0 16 16%27 fill=%27white%27 xmlns=%27http://www.w3.org/2000/svg%27%3e%3cpath d=%27M12.207 4.793a1 1 0 010 1.414l-5 5a1 1 0 01-1.414 0l-2-2a1 1 0 011.414-1.414L6.5 9.086l4.293-4.293a1 1 0 011.414 0z%27/%3e%3c/svg%3e":
/*!*********************************************************************************************************************************************************************************************************************************************************************!*\
  !*** data:image/svg+xml,%3csvg viewBox=%270 0 16 16%27 fill=%27white%27 xmlns=%27http://www.w3.org/2000/svg%27%3e%3cpath d=%27M12.207 4.793a1 1 0 010 1.414l-5 5a1 1 0 01-1.414 0l-2-2a1 1 0 011.414-1.414L6.5 9.086l4.293-4.293a1 1 0 011.414 0z%27/%3e%3c/svg%3e ***!
  \*********************************************************************************************************************************************************************************************************************************************************************/
/***/ ((module) => {

"use strict";
module.exports = "data:image/svg+xml,%3csvg viewBox=%270 0 16 16%27 fill=%27white%27 xmlns=%27http://www.w3.org/2000/svg%27%3e%3cpath d=%27M12.207 4.793a1 1 0 010 1.414l-5 5a1 1 0 01-1.414 0l-2-2a1 1 0 011.414-1.414L6.5 9.086l4.293-4.293a1 1 0 011.414 0z%27/%3e%3c/svg%3e";

/***/ }),

/***/ "data:image/svg+xml,%3csvg xmlns=%27http://www.w3.org/2000/svg%27 fill=%27none%27 viewBox=%270 0 16 16%27%3e%3cpath stroke=%27white%27 stroke-linecap=%27round%27 stroke-linejoin=%27round%27 stroke-width=%272%27 d=%27M4 8h8%27/%3e%3c/svg%3e":
/*!******************************************************************************************************************************************************************************************************************************************************!*\
  !*** data:image/svg+xml,%3csvg xmlns=%27http://www.w3.org/2000/svg%27 fill=%27none%27 viewBox=%270 0 16 16%27%3e%3cpath stroke=%27white%27 stroke-linecap=%27round%27 stroke-linejoin=%27round%27 stroke-width=%272%27 d=%27M4 8h8%27/%3e%3c/svg%3e ***!
  \******************************************************************************************************************************************************************************************************************************************************/
/***/ ((module) => {

"use strict";
module.exports = "data:image/svg+xml,%3csvg xmlns=%27http://www.w3.org/2000/svg%27 fill=%27none%27 viewBox=%270 0 16 16%27%3e%3cpath stroke=%27white%27 stroke-linecap=%27round%27 stroke-linejoin=%27round%27 stroke-width=%272%27 d=%27M4 8h8%27/%3e%3c/svg%3e";

/***/ }),

/***/ "data:image/svg+xml,%3csvg xmlns=%27http://www.w3.org/2000/svg%27 fill=%27none%27 viewBox=%270 0 20 20%27%3e%3cpath stroke=%27%236b7280%27 stroke-linecap=%27round%27 stroke-linejoin=%27round%27 stroke-width=%271.5%27 d=%27M6 8l4 4 4-4%27/%3e%3c/svg%3e":
/*!******************************************************************************************************************************************************************************************************************************************************************!*\
  !*** data:image/svg+xml,%3csvg xmlns=%27http://www.w3.org/2000/svg%27 fill=%27none%27 viewBox=%270 0 20 20%27%3e%3cpath stroke=%27%236b7280%27 stroke-linecap=%27round%27 stroke-linejoin=%27round%27 stroke-width=%271.5%27 d=%27M6 8l4 4 4-4%27/%3e%3c/svg%3e ***!
  \******************************************************************************************************************************************************************************************************************************************************************/
/***/ ((module) => {

"use strict";
module.exports = "data:image/svg+xml,%3csvg xmlns=%27http://www.w3.org/2000/svg%27 fill=%27none%27 viewBox=%270 0 20 20%27%3e%3cpath stroke=%27%236b7280%27 stroke-linecap=%27round%27 stroke-linejoin=%27round%27 stroke-width=%271.5%27 d=%27M6 8l4 4 4-4%27/%3e%3c/svg%3e";

/***/ }),

/***/ "./node_modules/appwrite/dist/esm/sdk.js":
/*!***********************************************!*\
  !*** ./node_modules/appwrite/dist/esm/sdk.js ***!
  \***********************************************/
/***/ ((__unused_webpack___webpack_module__, __webpack_exports__, __webpack_require__) => {

"use strict";
__webpack_require__.r(__webpack_exports__);
/* harmony export */ __webpack_require__.d(__webpack_exports__, {
/* harmony export */   "Account": () => (/* binding */ Account),
/* harmony export */   "AppwriteException": () => (/* binding */ AppwriteException),
/* harmony export */   "Avatars": () => (/* binding */ Avatars),
/* harmony export */   "Client": () => (/* binding */ Client),
/* harmony export */   "Databases": () => (/* binding */ Databases),
/* harmony export */   "Functions": () => (/* binding */ Functions),
/* harmony export */   "Locale": () => (/* binding */ Locale),
/* harmony export */   "Query": () => (/* binding */ Query),
/* harmony export */   "Storage": () => (/* binding */ Storage),
/* harmony export */   "Teams": () => (/* binding */ Teams)
/* harmony export */ });
/* harmony import */ var isomorphic_form_data__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! isomorphic-form-data */ "./node_modules/isomorphic-form-data/lib/browser.js");
/* harmony import */ var cross_fetch__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! cross-fetch */ "./node_modules/cross-fetch/dist/browser-ponyfill.js");



/******************************************************************************
Copyright (c) Microsoft Corporation.

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE.
***************************************************************************** */

function __awaiter(thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
}

class Service {
    constructor(client) {
        this.client = client;
    }
    static flatten(data, prefix = '') {
        let output = {};
        for (const key in data) {
            let value = data[key];
            let finalKey = prefix ? `${prefix}[${key}]` : key;
            if (Array.isArray(value)) {
                output = Object.assign(output, this.flatten(value, finalKey));
            }
            else {
                output[finalKey] = value;
            }
        }
        return output;
    }
}
Service.CHUNK_SIZE = 5 * 1024 * 1024; // 5MB

class Query {
}
Query.equal = (attribute, value) => Query.addQuery(attribute, 'equal', value);
Query.notEqual = (attribute, value) => Query.addQuery(attribute, 'notEqual', value);
Query.lesser = (attribute, value) => Query.addQuery(attribute, 'lesser', value);
Query.lesserEqual = (attribute, value) => Query.addQuery(attribute, 'lesserEqual', value);
Query.greater = (attribute, value) => Query.addQuery(attribute, 'greater', value);
Query.greaterEqual = (attribute, value) => Query.addQuery(attribute, 'greaterEqual', value);
Query.search = (attribute, value) => Query.addQuery(attribute, 'search', value);
Query.addQuery = (attribute, oper, value) => value instanceof Array
    ? `${attribute}.${oper}(${value
        .map((v) => Query.parseValues(v))
        .join(',')})`
    : `${attribute}.${oper}(${Query.parseValues(value)})`;
Query.parseValues = (value) => typeof value === 'string' || value instanceof String
    ? `"${value}"`
    : `${value}`;

class AppwriteException extends Error {
    constructor(message, code = 0, type = '', response = '') {
        super(message);
        this.name = 'AppwriteException';
        this.message = message;
        this.code = code;
        this.type = type;
        this.response = response;
    }
}
class Client {
    constructor() {
        this.config = {
            endpoint: 'https://HOSTNAME/v1',
            endpointRealtime: '',
            project: '',
            jwt: '',
            locale: '',
        };
        this.headers = {
            'x-sdk-version': 'appwrite:web:9.0.1',
            'X-Appwrite-Response-Format': '0.15.0',
        };
        this.realtime = {
            socket: undefined,
            timeout: undefined,
            url: '',
            channels: new Set(),
            subscriptions: new Map(),
            subscriptionsCounter: 0,
            reconnect: true,
            reconnectAttempts: 0,
            lastMessage: undefined,
            connect: () => {
                clearTimeout(this.realtime.timeout);
                this.realtime.timeout = window === null || window === void 0 ? void 0 : window.setTimeout(() => {
                    this.realtime.createSocket();
                }, 50);
            },
            getTimeout: () => {
                switch (true) {
                    case this.realtime.reconnectAttempts < 5:
                        return 1000;
                    case this.realtime.reconnectAttempts < 15:
                        return 5000;
                    case this.realtime.reconnectAttempts < 100:
                        return 10000;
                    default:
                        return 60000;
                }
            },
            createSocket: () => {
                var _a, _b;
                if (this.realtime.channels.size < 1)
                    return;
                const channels = new URLSearchParams();
                channels.set('project', this.config.project);
                this.realtime.channels.forEach(channel => {
                    channels.append('channels[]', channel);
                });
                const url = this.config.endpointRealtime + '/realtime?' + channels.toString();
                if (url !== this.realtime.url || // Check if URL is present
                    !this.realtime.socket || // Check if WebSocket has not been created
                    ((_a = this.realtime.socket) === null || _a === void 0 ? void 0 : _a.readyState) > WebSocket.OPEN // Check if WebSocket is CLOSING (3) or CLOSED (4)
                ) {
                    if (this.realtime.socket &&
                        ((_b = this.realtime.socket) === null || _b === void 0 ? void 0 : _b.readyState) < WebSocket.CLOSING // Close WebSocket if it is CONNECTING (0) or OPEN (1)
                    ) {
                        this.realtime.reconnect = false;
                        this.realtime.socket.close();
                    }
                    this.realtime.url = url;
                    this.realtime.socket = new WebSocket(url);
                    this.realtime.socket.addEventListener('message', this.realtime.onMessage);
                    this.realtime.socket.addEventListener('open', _event => {
                        this.realtime.reconnectAttempts = 0;
                    });
                    this.realtime.socket.addEventListener('close', event => {
                        var _a, _b, _c;
                        if (!this.realtime.reconnect ||
                            (((_b = (_a = this.realtime) === null || _a === void 0 ? void 0 : _a.lastMessage) === null || _b === void 0 ? void 0 : _b.type) === 'error' && // Check if last message was of type error
                                ((_c = this.realtime) === null || _c === void 0 ? void 0 : _c.lastMessage.data).code === 1008 // Check for policy violation 1008
                            )) {
                            this.realtime.reconnect = true;
                            return;
                        }
                        const timeout = this.realtime.getTimeout();
                        console.error(`Realtime got disconnected. Reconnect will be attempted in ${timeout / 1000} seconds.`, event.reason);
                        setTimeout(() => {
                            this.realtime.reconnectAttempts++;
                            this.realtime.createSocket();
                        }, timeout);
                    });
                }
            },
            onMessage: (event) => {
                var _a, _b;
                try {
                    const message = JSON.parse(event.data);
                    this.realtime.lastMessage = message;
                    switch (message.type) {
                        case 'connected':
                            const cookie = JSON.parse((_a = window.localStorage.getItem('cookieFallback')) !== null && _a !== void 0 ? _a : '{}');
                            const session = cookie === null || cookie === void 0 ? void 0 : cookie[`a_session_${this.config.project}`];
                            const messageData = message.data;
                            if (session && !messageData.user) {
                                (_b = this.realtime.socket) === null || _b === void 0 ? void 0 : _b.send(JSON.stringify({
                                    type: 'authentication',
                                    data: {
                                        session
                                    }
                                }));
                            }
                            break;
                        case 'event':
                            let data = message.data;
                            if (data === null || data === void 0 ? void 0 : data.channels) {
                                const isSubscribed = data.channels.some(channel => this.realtime.channels.has(channel));
                                if (!isSubscribed)
                                    return;
                                this.realtime.subscriptions.forEach(subscription => {
                                    if (data.channels.some(channel => subscription.channels.includes(channel))) {
                                        setTimeout(() => subscription.callback(data));
                                    }
                                });
                            }
                            break;
                        case 'error':
                            throw message.data;
                        default:
                            break;
                    }
                }
                catch (e) {
                    console.error(e);
                }
            },
            cleanUp: channels => {
                this.realtime.channels.forEach(channel => {
                    if (channels.includes(channel)) {
                        let found = Array.from(this.realtime.subscriptions).some(([_key, subscription]) => {
                            return subscription.channels.includes(channel);
                        });
                        if (!found) {
                            this.realtime.channels.delete(channel);
                        }
                    }
                });
            }
        };
    }
    /**
     * Set Endpoint
     *
     * Your project endpoint
     *
     * @param {string} endpoint
     *
     * @returns {this}
     */
    setEndpoint(endpoint) {
        this.config.endpoint = endpoint;
        this.config.endpointRealtime = this.config.endpointRealtime || this.config.endpoint.replace('https://', 'wss://').replace('http://', 'ws://');
        return this;
    }
    /**
     * Set Realtime Endpoint
     *
     * @param {string} endpointRealtime
     *
     * @returns {this}
     */
    setEndpointRealtime(endpointRealtime) {
        this.config.endpointRealtime = endpointRealtime;
        return this;
    }
    /**
     * Set Project
     *
     * Your project ID
     *
     * @param value string
     *
     * @return {this}
     */
    setProject(value) {
        this.headers['X-Appwrite-Project'] = value;
        this.config.project = value;
        return this;
    }
    /**
     * Set JWT
     *
     * Your secret JSON Web Token
     *
     * @param value string
     *
     * @return {this}
     */
    setJWT(value) {
        this.headers['X-Appwrite-JWT'] = value;
        this.config.jwt = value;
        return this;
    }
    /**
     * Set Locale
     *
     * @param value string
     *
     * @return {this}
     */
    setLocale(value) {
        this.headers['X-Appwrite-Locale'] = value;
        this.config.locale = value;
        return this;
    }
    /**
     * Subscribes to Appwrite events and passes you the payload in realtime.
     *
     * @param {string|string[]} channels
     * Channel to subscribe - pass a single channel as a string or multiple with an array of strings.
     *
     * Possible channels are:
     * - account
     * - collections
     * - collections.[ID]
     * - collections.[ID].documents
     * - documents
     * - documents.[ID]
     * - files
     * - files.[ID]
     * - executions
     * - executions.[ID]
     * - functions.[ID]
     * - teams
     * - teams.[ID]
     * - memberships
     * - memberships.[ID]
     * @param {(payload: RealtimeMessage) => void} callback Is called on every realtime update.
     * @returns {() => void} Unsubscribes from events.
     */
    subscribe(channels, callback) {
        let channelArray = typeof channels === 'string' ? [channels] : channels;
        channelArray.forEach(channel => this.realtime.channels.add(channel));
        const counter = this.realtime.subscriptionsCounter++;
        this.realtime.subscriptions.set(counter, {
            channels: channelArray,
            callback
        });
        this.realtime.connect();
        return () => {
            this.realtime.subscriptions.delete(counter);
            this.realtime.cleanUp(channelArray);
            this.realtime.connect();
        };
    }
    call(method, url, headers = {}, params = {}) {
        var _a, _b;
        return __awaiter(this, void 0, void 0, function* () {
            method = method.toUpperCase();
            headers = Object.assign({}, this.headers, headers);
            let options = {
                method,
                headers,
                credentials: 'include'
            };
            if (typeof window !== 'undefined' && window.localStorage) {
                headers['X-Fallback-Cookies'] = (_a = window.localStorage.getItem('cookieFallback')) !== null && _a !== void 0 ? _a : '';
            }
            if (method === 'GET') {
                for (const [key, value] of Object.entries(Service.flatten(params))) {
                    url.searchParams.append(key, value);
                }
            }
            else {
                switch (headers['content-type']) {
                    case 'application/json':
                        options.body = JSON.stringify(params);
                        break;
                    case 'multipart/form-data':
                        let formData = new FormData();
                        for (const key in params) {
                            if (Array.isArray(params[key])) {
                                params[key].forEach((value) => {
                                    formData.append(key + '[]', value);
                                });
                            }
                            else {
                                formData.append(key, params[key]);
                            }
                        }
                        options.body = formData;
                        delete headers['content-type'];
                        break;
                }
            }
            try {
                let data = null;
                const response = yield (0,cross_fetch__WEBPACK_IMPORTED_MODULE_1__.fetch)(url.toString(), options);
                if ((_b = response.headers.get('content-type')) === null || _b === void 0 ? void 0 : _b.includes('application/json')) {
                    data = yield response.json();
                }
                else {
                    data = {
                        message: yield response.text()
                    };
                }
                if (400 <= response.status) {
                    throw new AppwriteException(data === null || data === void 0 ? void 0 : data.message, response.status, data === null || data === void 0 ? void 0 : data.type, data);
                }
                const cookieFallback = response.headers.get('X-Fallback-Cookies');
                if (typeof window !== 'undefined' && window.localStorage && cookieFallback) {
                    window.console.warn('Appwrite is using localStorage for session management. Increase your security by adding a custom domain as your API endpoint.');
                    window.localStorage.setItem('cookieFallback', cookieFallback);
                }
                return data;
            }
            catch (e) {
                if (e instanceof AppwriteException) {
                    throw e;
                }
                throw new AppwriteException(e.message);
            }
        });
    }
}

class Account extends Service {
    /**
     * Get Account
     *
     * Get currently logged in user data as JSON object.
     *
     * @throws {AppwriteException}
     * @returns {Promise}
     */
    get() {
        return __awaiter(this, void 0, void 0, function* () {
            let path = '/account';
            let payload = {};
            const uri = new URL(this.client.config.endpoint + path);
            return yield this.client.call('get', uri, {
                'content-type': 'application/json',
            }, payload);
        });
    }
    /**
     * Create Account
     *
     * Use this endpoint to allow a new user to register a new account in your
     * project. After the user registration completes successfully, you can use
     * the [/account/verfication](/docs/client/account#accountCreateVerification)
     * route to start verifying the user email address. To allow the new user to
     * login to their new account, you need to create a new [account
     * session](/docs/client/account#accountCreateSession).
     *
     * @param {string} userId
     * @param {string} email
     * @param {string} password
     * @param {string} name
     * @throws {AppwriteException}
     * @returns {Promise}
     */
    create(userId, email, password, name) {
        return __awaiter(this, void 0, void 0, function* () {
            if (typeof userId === 'undefined') {
                throw new AppwriteException('Missing required parameter: "userId"');
            }
            if (typeof email === 'undefined') {
                throw new AppwriteException('Missing required parameter: "email"');
            }
            if (typeof password === 'undefined') {
                throw new AppwriteException('Missing required parameter: "password"');
            }
            let path = '/account';
            let payload = {};
            if (typeof userId !== 'undefined') {
                payload['userId'] = userId;
            }
            if (typeof email !== 'undefined') {
                payload['email'] = email;
            }
            if (typeof password !== 'undefined') {
                payload['password'] = password;
            }
            if (typeof name !== 'undefined') {
                payload['name'] = name;
            }
            const uri = new URL(this.client.config.endpoint + path);
            return yield this.client.call('post', uri, {
                'content-type': 'application/json',
            }, payload);
        });
    }
    /**
     * Update Account Email
     *
     * Update currently logged in user account email address. After changing user
     * address, the user confirmation status will get reset. A new confirmation
     * email is not sent automatically however you can use the send confirmation
     * email endpoint again to send the confirmation email. For security measures,
     * user password is required to complete this request.
     * This endpoint can also be used to convert an anonymous account to a normal
     * one, by passing an email address and a new password.
     *
     *
     * @param {string} email
     * @param {string} password
     * @throws {AppwriteException}
     * @returns {Promise}
     */
    updateEmail(email, password) {
        return __awaiter(this, void 0, void 0, function* () {
            if (typeof email === 'undefined') {
                throw new AppwriteException('Missing required parameter: "email"');
            }
            if (typeof password === 'undefined') {
                throw new AppwriteException('Missing required parameter: "password"');
            }
            let path = '/account/email';
            let payload = {};
            if (typeof email !== 'undefined') {
                payload['email'] = email;
            }
            if (typeof password !== 'undefined') {
                payload['password'] = password;
            }
            const uri = new URL(this.client.config.endpoint + path);
            return yield this.client.call('patch', uri, {
                'content-type': 'application/json',
            }, payload);
        });
    }
    /**
     * Create Account JWT
     *
     * Use this endpoint to create a JSON Web Token. You can use the resulting JWT
     * to authenticate on behalf of the current user when working with the
     * Appwrite server-side API and SDKs. The JWT secret is valid for 15 minutes
     * from its creation and will be invalid if the user will logout in that time
     * frame.
     *
     * @throws {AppwriteException}
     * @returns {Promise}
     */
    createJWT() {
        return __awaiter(this, void 0, void 0, function* () {
            let path = '/account/jwt';
            let payload = {};
            const uri = new URL(this.client.config.endpoint + path);
            return yield this.client.call('post', uri, {
                'content-type': 'application/json',
            }, payload);
        });
    }
    /**
     * Get Account Logs
     *
     * Get currently logged in user list of latest security activity logs. Each
     * log returns user IP address, location and date and time of log.
     *
     * @param {number} limit
     * @param {number} offset
     * @throws {AppwriteException}
     * @returns {Promise}
     */
    getLogs(limit, offset) {
        return __awaiter(this, void 0, void 0, function* () {
            let path = '/account/logs';
            let payload = {};
            if (typeof limit !== 'undefined') {
                payload['limit'] = limit;
            }
            if (typeof offset !== 'undefined') {
                payload['offset'] = offset;
            }
            const uri = new URL(this.client.config.endpoint + path);
            return yield this.client.call('get', uri, {
                'content-type': 'application/json',
            }, payload);
        });
    }
    /**
     * Update Account Name
     *
     * Update currently logged in user account name.
     *
     * @param {string} name
     * @throws {AppwriteException}
     * @returns {Promise}
     */
    updateName(name) {
        return __awaiter(this, void 0, void 0, function* () {
            if (typeof name === 'undefined') {
                throw new AppwriteException('Missing required parameter: "name"');
            }
            let path = '/account/name';
            let payload = {};
            if (typeof name !== 'undefined') {
                payload['name'] = name;
            }
            const uri = new URL(this.client.config.endpoint + path);
            return yield this.client.call('patch', uri, {
                'content-type': 'application/json',
            }, payload);
        });
    }
    /**
     * Update Account Password
     *
     * Update currently logged in user password. For validation, user is required
     * to pass in the new password, and the old password. For users created with
     * OAuth, Team Invites and Magic URL, oldPassword is optional.
     *
     * @param {string} password
     * @param {string} oldPassword
     * @throws {AppwriteException}
     * @returns {Promise}
     */
    updatePassword(password, oldPassword) {
        return __awaiter(this, void 0, void 0, function* () {
            if (typeof password === 'undefined') {
                throw new AppwriteException('Missing required parameter: "password"');
            }
            let path = '/account/password';
            let payload = {};
            if (typeof password !== 'undefined') {
                payload['password'] = password;
            }
            if (typeof oldPassword !== 'undefined') {
                payload['oldPassword'] = oldPassword;
            }
            const uri = new URL(this.client.config.endpoint + path);
            return yield this.client.call('patch', uri, {
                'content-type': 'application/json',
            }, payload);
        });
    }
    /**
     * Update Account Phone
     *
     * Update the currently logged in user's phone number. After updating the
     * phone number, the phone verification status will be reset. A confirmation
     * SMS is not sent automatically, however you can use the [POST
     * /account/verification/phone](/docs/client/account#accountCreatePhoneVerification)
     * endpoint to send a confirmation SMS.
     *
     * @param {string} number
     * @param {string} password
     * @throws {AppwriteException}
     * @returns {Promise}
     */
    updatePhone(number, password) {
        return __awaiter(this, void 0, void 0, function* () {
            if (typeof number === 'undefined') {
                throw new AppwriteException('Missing required parameter: "number"');
            }
            if (typeof password === 'undefined') {
                throw new AppwriteException('Missing required parameter: "password"');
            }
            let path = '/account/phone';
            let payload = {};
            if (typeof number !== 'undefined') {
                payload['number'] = number;
            }
            if (typeof password !== 'undefined') {
                payload['password'] = password;
            }
            const uri = new URL(this.client.config.endpoint + path);
            return yield this.client.call('patch', uri, {
                'content-type': 'application/json',
            }, payload);
        });
    }
    /**
     * Get Account Preferences
     *
     * Get currently logged in user preferences as a key-value object.
     *
     * @throws {AppwriteException}
     * @returns {Promise}
     */
    getPrefs() {
        return __awaiter(this, void 0, void 0, function* () {
            let path = '/account/prefs';
            let payload = {};
            const uri = new URL(this.client.config.endpoint + path);
            return yield this.client.call('get', uri, {
                'content-type': 'application/json',
            }, payload);
        });
    }
    /**
     * Update Account Preferences
     *
     * Update currently logged in user account preferences. The object you pass is
     * stored as is, and replaces any previous value. The maximum allowed prefs
     * size is 64kB and throws error if exceeded.
     *
     * @param {Partial<Preferences>} prefs
     * @throws {AppwriteException}
     * @returns {Promise}
     */
    updatePrefs(prefs) {
        return __awaiter(this, void 0, void 0, function* () {
            if (typeof prefs === 'undefined') {
                throw new AppwriteException('Missing required parameter: "prefs"');
            }
            let path = '/account/prefs';
            let payload = {};
            if (typeof prefs !== 'undefined') {
                payload['prefs'] = prefs;
            }
            const uri = new URL(this.client.config.endpoint + path);
            return yield this.client.call('patch', uri, {
                'content-type': 'application/json',
            }, payload);
        });
    }
    /**
     * Create Password Recovery
     *
     * Sends the user an email with a temporary secret key for password reset.
     * When the user clicks the confirmation link he is redirected back to your
     * app password reset URL with the secret key and email address values
     * attached to the URL query string. Use the query string params to submit a
     * request to the [PUT
     * /account/recovery](/docs/client/account#accountUpdateRecovery) endpoint to
     * complete the process. The verification link sent to the user's email
     * address is valid for 1 hour.
     *
     * @param {string} email
     * @param {string} url
     * @throws {AppwriteException}
     * @returns {Promise}
     */
    createRecovery(email, url) {
        return __awaiter(this, void 0, void 0, function* () {
            if (typeof email === 'undefined') {
                throw new AppwriteException('Missing required parameter: "email"');
            }
            if (typeof url === 'undefined') {
                throw new AppwriteException('Missing required parameter: "url"');
            }
            let path = '/account/recovery';
            let payload = {};
            if (typeof email !== 'undefined') {
                payload['email'] = email;
            }
            if (typeof url !== 'undefined') {
                payload['url'] = url;
            }
            const uri = new URL(this.client.config.endpoint + path);
            return yield this.client.call('post', uri, {
                'content-type': 'application/json',
            }, payload);
        });
    }
    /**
     * Create Password Recovery (confirmation)
     *
     * Use this endpoint to complete the user account password reset. Both the
     * **userId** and **secret** arguments will be passed as query parameters to
     * the redirect URL you have provided when sending your request to the [POST
     * /account/recovery](/docs/client/account#accountCreateRecovery) endpoint.
     *
     * Please note that in order to avoid a [Redirect
     * Attack](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.md)
     * the only valid redirect URLs are the ones from domains you have set when
     * adding your platforms in the console interface.
     *
     * @param {string} userId
     * @param {string} secret
     * @param {string} password
     * @param {string} passwordAgain
     * @throws {AppwriteException}
     * @returns {Promise}
     */
    updateRecovery(userId, secret, password, passwordAgain) {
        return __awaiter(this, void 0, void 0, function* () {
            if (typeof userId === 'undefined') {
                throw new AppwriteException('Missing required parameter: "userId"');
            }
            if (typeof secret === 'undefined') {
                throw new AppwriteException('Missing required parameter: "secret"');
            }
            if (typeof password === 'undefined') {
                throw new AppwriteException('Missing required parameter: "password"');
            }
            if (typeof passwordAgain === 'undefined') {
                throw new AppwriteException('Missing required parameter: "passwordAgain"');
            }
            let path = '/account/recovery';
            let payload = {};
            if (typeof userId !== 'undefined') {
                payload['userId'] = userId;
            }
            if (typeof secret !== 'undefined') {
                payload['secret'] = secret;
            }
            if (typeof password !== 'undefined') {
                payload['password'] = password;
            }
            if (typeof passwordAgain !== 'undefined') {
                payload['passwordAgain'] = passwordAgain;
            }
            const uri = new URL(this.client.config.endpoint + path);
            return yield this.client.call('put', uri, {
                'content-type': 'application/json',
            }, payload);
        });
    }
    /**
     * Get Account Sessions
     *
     * Get currently logged in user list of active sessions across different
     * devices.
     *
     * @throws {AppwriteException}
     * @returns {Promise}
     */
    getSessions() {
        return __awaiter(this, void 0, void 0, function* () {
            let path = '/account/sessions';
            let payload = {};
            const uri = new URL(this.client.config.endpoint + path);
            return yield this.client.call('get', uri, {
                'content-type': 'application/json',
            }, payload);
        });
    }
    /**
     * Delete All Account Sessions
     *
     * Delete all sessions from the user account and remove any sessions cookies
     * from the end client.
     *
     * @throws {AppwriteException}
     * @returns {Promise}
     */
    deleteSessions() {
        return __awaiter(this, void 0, void 0, function* () {
            let path = '/account/sessions';
            let payload = {};
            const uri = new URL(this.client.config.endpoint + path);
            return yield this.client.call('delete', uri, {
                'content-type': 'application/json',
            }, payload);
        });
    }
    /**
     * Create Anonymous Session
     *
     * Use this endpoint to allow a new user to register an anonymous account in
     * your project. This route will also create a new session for the user. To
     * allow the new user to convert an anonymous account to a normal account, you
     * need to update its [email and
     * password](/docs/client/account#accountUpdateEmail) or create an [OAuth2
     * session](/docs/client/account#accountCreateOAuth2Session).
     *
     * @throws {AppwriteException}
     * @returns {Promise}
     */
    createAnonymousSession() {
        return __awaiter(this, void 0, void 0, function* () {
            let path = '/account/sessions/anonymous';
            let payload = {};
            const uri = new URL(this.client.config.endpoint + path);
            return yield this.client.call('post', uri, {
                'content-type': 'application/json',
            }, payload);
        });
    }
    /**
     * Create Account Session with Email
     *
     * Allow the user to login into their account by providing a valid email and
     * password combination. This route will create a new session for the user.
     *
     * @param {string} email
     * @param {string} password
     * @throws {AppwriteException}
     * @returns {Promise}
     */
    createEmailSession(email, password) {
        return __awaiter(this, void 0, void 0, function* () {
            if (typeof email === 'undefined') {
                throw new AppwriteException('Missing required parameter: "email"');
            }
            if (typeof password === 'undefined') {
                throw new AppwriteException('Missing required parameter: "password"');
            }
            let path = '/account/sessions/email';
            let payload = {};
            if (typeof email !== 'undefined') {
                payload['email'] = email;
            }
            if (typeof password !== 'undefined') {
                payload['password'] = password;
            }
            const uri = new URL(this.client.config.endpoint + path);
            return yield this.client.call('post', uri, {
                'content-type': 'application/json',
            }, payload);
        });
    }
    /**
     * Create Magic URL session
     *
     * Sends the user an email with a secret key for creating a session. When the
     * user clicks the link in the email, the user is redirected back to the URL
     * you provided with the secret key and userId values attached to the URL
     * query string. Use the query string parameters to submit a request to the
     * [PUT
     * /account/sessions/magic-url](/docs/client/account#accountUpdateMagicURLSession)
     * endpoint to complete the login process. The link sent to the user's email
     * address is valid for 1 hour. If you are on a mobile device you can leave
     * the URL parameter empty, so that the login completion will be handled by
     * your Appwrite instance by default.
     *
     * @param {string} userId
     * @param {string} email
     * @param {string} url
     * @throws {AppwriteException}
     * @returns {Promise}
     */
    createMagicURLSession(userId, email, url) {
        return __awaiter(this, void 0, void 0, function* () {
            if (typeof userId === 'undefined') {
                throw new AppwriteException('Missing required parameter: "userId"');
            }
            if (typeof email === 'undefined') {
                throw new AppwriteException('Missing required parameter: "email"');
            }
            let path = '/account/sessions/magic-url';
            let payload = {};
            if (typeof userId !== 'undefined') {
                payload['userId'] = userId;
            }
            if (typeof email !== 'undefined') {
                payload['email'] = email;
            }
            if (typeof url !== 'undefined') {
                payload['url'] = url;
            }
            const uri = new URL(this.client.config.endpoint + path);
            return yield this.client.call('post', uri, {
                'content-type': 'application/json',
            }, payload);
        });
    }
    /**
     * Create Magic URL session (confirmation)
     *
     * Use this endpoint to complete creating the session with the Magic URL. Both
     * the **userId** and **secret** arguments will be passed as query parameters
     * to the redirect URL you have provided when sending your request to the
     * [POST
     * /account/sessions/magic-url](/docs/client/account#accountCreateMagicURLSession)
     * endpoint.
     *
     * Please note that in order to avoid a [Redirect
     * Attack](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.md)
     * the only valid redirect URLs are the ones from domains you have set when
     * adding your platforms in the console interface.
     *
     * @param {string} userId
     * @param {string} secret
     * @throws {AppwriteException}
     * @returns {Promise}
     */
    updateMagicURLSession(userId, secret) {
        return __awaiter(this, void 0, void 0, function* () {
            if (typeof userId === 'undefined') {
                throw new AppwriteException('Missing required parameter: "userId"');
            }
            if (typeof secret === 'undefined') {
                throw new AppwriteException('Missing required parameter: "secret"');
            }
            let path = '/account/sessions/magic-url';
            let payload = {};
            if (typeof userId !== 'undefined') {
                payload['userId'] = userId;
            }
            if (typeof secret !== 'undefined') {
                payload['secret'] = secret;
            }
            const uri = new URL(this.client.config.endpoint + path);
            return yield this.client.call('put', uri, {
                'content-type': 'application/json',
            }, payload);
        });
    }
    /**
     * Create Account Session with OAuth2
     *
     * Allow the user to login to their account using the OAuth2 provider of their
     * choice. Each OAuth2 provider should be enabled from the Appwrite console
     * first. Use the success and failure arguments to provide a redirect URL's
     * back to your app when login is completed.
     *
     * If there is already an active session, the new session will be attached to
     * the logged-in account. If there are no active sessions, the server will
     * attempt to look for a user with the same email address as the email
     * received from the OAuth2 provider and attach the new session to the
     * existing user. If no matching user is found - the server will create a new
     * user..
     *
     *
     * @param {string} provider
     * @param {string} success
     * @param {string} failure
     * @param {string[]} scopes
     * @throws {AppwriteException}
     * @returns {void|string}
     */
    createOAuth2Session(provider, success, failure, scopes) {
        if (typeof provider === 'undefined') {
            throw new AppwriteException('Missing required parameter: "provider"');
        }
        let path = '/account/sessions/oauth2/{provider}'.replace('{provider}', provider);
        let payload = {};
        if (typeof success !== 'undefined') {
            payload['success'] = success;
        }
        if (typeof failure !== 'undefined') {
            payload['failure'] = failure;
        }
        if (typeof scopes !== 'undefined') {
            payload['scopes'] = scopes;
        }
        const uri = new URL(this.client.config.endpoint + path);
        payload['project'] = this.client.config.project;
        for (const [key, value] of Object.entries(Service.flatten(payload))) {
            uri.searchParams.append(key, value);
        }
        if (typeof window !== 'undefined' && (window === null || window === void 0 ? void 0 : window.location)) {
            window.location.href = uri.toString();
        }
        else {
            return uri;
        }
    }
    /**
     * Create Phone session
     *
     * Sends the user an SMS with a secret key for creating a session. Use the
     * returned user ID and secret and submit a request to the [PUT
     * /account/sessions/phone](/docs/client/account#accountUpdatePhoneSession)
     * endpoint to complete the login process. The secret sent to the user's phone
     * is valid for 15 minutes.
     *
     * @param {string} userId
     * @param {string} number
     * @throws {AppwriteException}
     * @returns {Promise}
     */
    createPhoneSession(userId, number) {
        return __awaiter(this, void 0, void 0, function* () {
            if (typeof userId === 'undefined') {
                throw new AppwriteException('Missing required parameter: "userId"');
            }
            if (typeof number === 'undefined') {
                throw new AppwriteException('Missing required parameter: "number"');
            }
            let path = '/account/sessions/phone';
            let payload = {};
            if (typeof userId !== 'undefined') {
                payload['userId'] = userId;
            }
            if (typeof number !== 'undefined') {
                payload['number'] = number;
            }
            const uri = new URL(this.client.config.endpoint + path);
            return yield this.client.call('post', uri, {
                'content-type': 'application/json',
            }, payload);
        });
    }
    /**
     * Create Phone session (confirmation)
     *
     * Use this endpoint to complete creating a session with SMS. Use the
     * **userId** from the
     * [createPhoneSession](/docs/client/account#accountCreatePhoneSession)
     * endpoint and the **secret** received via SMS to successfully update and
     * confirm the phone session.
     *
     * @param {string} userId
     * @param {string} secret
     * @throws {AppwriteException}
     * @returns {Promise}
     */
    updatePhoneSession(userId, secret) {
        return __awaiter(this, void 0, void 0, function* () {
            if (typeof userId === 'undefined') {
                throw new AppwriteException('Missing required parameter: "userId"');
            }
            if (typeof secret === 'undefined') {
                throw new AppwriteException('Missing required parameter: "secret"');
            }
            let path = '/account/sessions/phone';
            let payload = {};
            if (typeof userId !== 'undefined') {
                payload['userId'] = userId;
            }
            if (typeof secret !== 'undefined') {
                payload['secret'] = secret;
            }
            const uri = new URL(this.client.config.endpoint + path);
            return yield this.client.call('put', uri, {
                'content-type': 'application/json',
            }, payload);
        });
    }
    /**
     * Get Session By ID
     *
     * Use this endpoint to get a logged in user's session using a Session ID.
     * Inputting 'current' will return the current session being used.
     *
     * @param {string} sessionId
     * @throws {AppwriteException}
     * @returns {Promise}
     */
    getSession(sessionId) {
        return __awaiter(this, void 0, void 0, function* () {
            if (typeof sessionId === 'undefined') {
                throw new AppwriteException('Missing required parameter: "sessionId"');
            }
            let path = '/account/sessions/{sessionId}'.replace('{sessionId}', sessionId);
            let payload = {};
            const uri = new URL(this.client.config.endpoint + path);
            return yield this.client.call('get', uri, {
                'content-type': 'application/json',
            }, payload);
        });
    }
    /**
     * Update Session (Refresh Tokens)
     *
     * Access tokens have limited lifespan and expire to mitigate security risks.
     * If session was created using an OAuth provider, this route can be used to
     * "refresh" the access token.
     *
     * @param {string} sessionId
     * @throws {AppwriteException}
     * @returns {Promise}
     */
    updateSession(sessionId) {
        return __awaiter(this, void 0, void 0, function* () {
            if (typeof sessionId === 'undefined') {
                throw new AppwriteException('Missing required parameter: "sessionId"');
            }
            let path = '/account/sessions/{sessionId}'.replace('{sessionId}', sessionId);
            let payload = {};
            const uri = new URL(this.client.config.endpoint + path);
            return yield this.client.call('patch', uri, {
                'content-type': 'application/json',
            }, payload);
        });
    }
    /**
     * Delete Account Session
     *
     * Use this endpoint to log out the currently logged in user from all their
     * account sessions across all of their different devices. When using the
     * Session ID argument, only the unique session ID provided is deleted.
     *
     *
     * @param {string} sessionId
     * @throws {AppwriteException}
     * @returns {Promise}
     */
    deleteSession(sessionId) {
        return __awaiter(this, void 0, void 0, function* () {
            if (typeof sessionId === 'undefined') {
                throw new AppwriteException('Missing required parameter: "sessionId"');
            }
            let path = '/account/sessions/{sessionId}'.replace('{sessionId}', sessionId);
            let payload = {};
            const uri = new URL(this.client.config.endpoint + path);
            return yield this.client.call('delete', uri, {
                'content-type': 'application/json',
            }, payload);
        });
    }
    /**
     * Update Account Status
     *
     * Block the currently logged in user account. Behind the scene, the user
     * record is not deleted but permanently blocked from any access. To
     * completely delete a user, use the Users API instead.
     *
     * @throws {AppwriteException}
     * @returns {Promise}
     */
    updateStatus() {
        return __awaiter(this, void 0, void 0, function* () {
            let path = '/account/status';
            let payload = {};
            const uri = new URL(this.client.config.endpoint + path);
            return yield this.client.call('patch', uri, {
                'content-type': 'application/json',
            }, payload);
        });
    }
    /**
     * Create Email Verification
     *
     * Use this endpoint to send a verification message to your user email address
     * to confirm they are the valid owners of that address. Both the **userId**
     * and **secret** arguments will be passed as query parameters to the URL you
     * have provided to be attached to the verification email. The provided URL
     * should redirect the user back to your app and allow you to complete the
     * verification process by verifying both the **userId** and **secret**
     * parameters. Learn more about how to [complete the verification
     * process](/docs/client/account#accountUpdateEmailVerification). The
     * verification link sent to the user's email address is valid for 7 days.
     *
     * Please note that in order to avoid a [Redirect
     * Attack](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.md),
     * the only valid redirect URLs are the ones from domains you have set when
     * adding your platforms in the console interface.
     *
     *
     * @param {string} url
     * @throws {AppwriteException}
     * @returns {Promise}
     */
    createVerification(url) {
        return __awaiter(this, void 0, void 0, function* () {
            if (typeof url === 'undefined') {
                throw new AppwriteException('Missing required parameter: "url"');
            }
            let path = '/account/verification';
            let payload = {};
            if (typeof url !== 'undefined') {
                payload['url'] = url;
            }
            const uri = new URL(this.client.config.endpoint + path);
            return yield this.client.call('post', uri, {
                'content-type': 'application/json',
            }, payload);
        });
    }
    /**
     * Create Email Verification (confirmation)
     *
     * Use this endpoint to complete the user email verification process. Use both
     * the **userId** and **secret** parameters that were attached to your app URL
     * to verify the user email ownership. If confirmed this route will return a
     * 200 status code.
     *
     * @param {string} userId
     * @param {string} secret
     * @throws {AppwriteException}
     * @returns {Promise}
     */
    updateVerification(userId, secret) {
        return __awaiter(this, void 0, void 0, function* () {
            if (typeof userId === 'undefined') {
                throw new AppwriteException('Missing required parameter: "userId"');
            }
            if (typeof secret === 'undefined') {
                throw new AppwriteException('Missing required parameter: "secret"');
            }
            let path = '/account/verification';
            let payload = {};
            if (typeof userId !== 'undefined') {
                payload['userId'] = userId;
            }
            if (typeof secret !== 'undefined') {
                payload['secret'] = secret;
            }
            const uri = new URL(this.client.config.endpoint + path);
            return yield this.client.call('put', uri, {
                'content-type': 'application/json',
            }, payload);
        });
    }
    /**
     * Create Phone Verification
     *
     * Use this endpoint to send a verification SMS to the currently logged in
     * user. This endpoint is meant for use after updating a user's phone number
     * using the [accountUpdatePhone](/docs/client/account#accountUpdatePhone)
     * endpoint. Learn more about how to [complete the verification
     * process](/docs/client/account#accountUpdatePhoneVerification). The
     * verification code sent to the user's phone number is valid for 15 minutes.
     *
     * @throws {AppwriteException}
     * @returns {Promise}
     */
    createPhoneVerification() {
        return __awaiter(this, void 0, void 0, function* () {
            let path = '/account/verification/phone';
            let payload = {};
            const uri = new URL(this.client.config.endpoint + path);
            return yield this.client.call('post', uri, {
                'content-type': 'application/json',
            }, payload);
        });
    }
    /**
     * Create Phone Verification (confirmation)
     *
     * Use this endpoint to complete the user phone verification process. Use the
     * **userId** and **secret** that were sent to your user's phone number to
     * verify the user email ownership. If confirmed this route will return a 200
     * status code.
     *
     * @param {string} userId
     * @param {string} secret
     * @throws {AppwriteException}
     * @returns {Promise}
     */
    updatePhoneVerification(userId, secret) {
        return __awaiter(this, void 0, void 0, function* () {
            if (typeof userId === 'undefined') {
                throw new AppwriteException('Missing required parameter: "userId"');
            }
            if (typeof secret === 'undefined') {
                throw new AppwriteException('Missing required parameter: "secret"');
            }
            let path = '/account/verification/phone';
            let payload = {};
            if (typeof userId !== 'undefined') {
                payload['userId'] = userId;
            }
            if (typeof secret !== 'undefined') {
                payload['secret'] = secret;
            }
            const uri = new URL(this.client.config.endpoint + path);
            return yield this.client.call('put', uri, {
                'content-type': 'application/json',
            }, payload);
        });
    }
}

class Avatars extends Service {
    /**
     * Get Browser Icon
     *
     * You can use this endpoint to show different browser icons to your users.
     * The code argument receives the browser code as it appears in your user [GET
     * /account/sessions](/docs/client/account#accountGetSessions) endpoint. Use
     * width, height and quality arguments to change the output settings.
     *
     * When one dimension is specified and the other is 0, the image is scaled
     * with preserved aspect ratio. If both dimensions are 0, the API provides an
     * image at source quality. If dimensions are not specified, the default size
     * of image returned is 100x100px.
     *
     * @param {string} code
     * @param {number} width
     * @param {number} height
     * @param {number} quality
     * @throws {AppwriteException}
     * @returns {URL}
     */
    getBrowser(code, width, height, quality) {
        if (typeof code === 'undefined') {
            throw new AppwriteException('Missing required parameter: "code"');
        }
        let path = '/avatars/browsers/{code}'.replace('{code}', code);
        let payload = {};
        if (typeof width !== 'undefined') {
            payload['width'] = width;
        }
        if (typeof height !== 'undefined') {
            payload['height'] = height;
        }
        if (typeof quality !== 'undefined') {
            payload['quality'] = quality;
        }
        const uri = new URL(this.client.config.endpoint + path);
        payload['project'] = this.client.config.project;
        for (const [key, value] of Object.entries(Service.flatten(payload))) {
            uri.searchParams.append(key, value);
        }
        return uri;
    }
    /**
     * Get Credit Card Icon
     *
     * The credit card endpoint will return you the icon of the credit card
     * provider you need. Use width, height and quality arguments to change the
     * output settings.
     *
     * When one dimension is specified and the other is 0, the image is scaled
     * with preserved aspect ratio. If both dimensions are 0, the API provides an
     * image at source quality. If dimensions are not specified, the default size
     * of image returned is 100x100px.
     *
     *
     * @param {string} code
     * @param {number} width
     * @param {number} height
     * @param {number} quality
     * @throws {AppwriteException}
     * @returns {URL}
     */
    getCreditCard(code, width, height, quality) {
        if (typeof code === 'undefined') {
            throw new AppwriteException('Missing required parameter: "code"');
        }
        let path = '/avatars/credit-cards/{code}'.replace('{code}', code);
        let payload = {};
        if (typeof width !== 'undefined') {
            payload['width'] = width;
        }
        if (typeof height !== 'undefined') {
            payload['height'] = height;
        }
        if (typeof quality !== 'undefined') {
            payload['quality'] = quality;
        }
        const uri = new URL(this.client.config.endpoint + path);
        payload['project'] = this.client.config.project;
        for (const [key, value] of Object.entries(Service.flatten(payload))) {
            uri.searchParams.append(key, value);
        }
        return uri;
    }
    /**
     * Get Favicon
     *
     * Use this endpoint to fetch the favorite icon (AKA favicon) of any remote
     * website URL.
     *
     *
     * @param {string} url
     * @throws {AppwriteException}
     * @returns {URL}
     */
    getFavicon(url) {
        if (typeof url === 'undefined') {
            throw new AppwriteException('Missing required parameter: "url"');
        }
        let path = '/avatars/favicon';
        let payload = {};
        if (typeof url !== 'undefined') {
            payload['url'] = url;
        }
        const uri = new URL(this.client.config.endpoint + path);
        payload['project'] = this.client.config.project;
        for (const [key, value] of Object.entries(Service.flatten(payload))) {
            uri.searchParams.append(key, value);
        }
        return uri;
    }
    /**
     * Get Country Flag
     *
     * You can use this endpoint to show different country flags icons to your
     * users. The code argument receives the 2 letter country code. Use width,
     * height and quality arguments to change the output settings.
     *
     * When one dimension is specified and the other is 0, the image is scaled
     * with preserved aspect ratio. If both dimensions are 0, the API provides an
     * image at source quality. If dimensions are not specified, the default size
     * of image returned is 100x100px.
     *
     *
     * @param {string} code
     * @param {number} width
     * @param {number} height
     * @param {number} quality
     * @throws {AppwriteException}
     * @returns {URL}
     */
    getFlag(code, width, height, quality) {
        if (typeof code === 'undefined') {
            throw new AppwriteException('Missing required parameter: "code"');
        }
        let path = '/avatars/flags/{code}'.replace('{code}', code);
        let payload = {};
        if (typeof width !== 'undefined') {
            payload['width'] = width;
        }
        if (typeof height !== 'undefined') {
            payload['height'] = height;
        }
        if (typeof quality !== 'undefined') {
            payload['quality'] = quality;
        }
        const uri = new URL(this.client.config.endpoint + path);
        payload['project'] = this.client.config.project;
        for (const [key, value] of Object.entries(Service.flatten(payload))) {
            uri.searchParams.append(key, value);
        }
        return uri;
    }
    /**
     * Get Image from URL
     *
     * Use this endpoint to fetch a remote image URL and crop it to any image size
     * you want. This endpoint is very useful if you need to crop and display
     * remote images in your app or in case you want to make sure a 3rd party
     * image is properly served using a TLS protocol.
     *
     * When one dimension is specified and the other is 0, the image is scaled
     * with preserved aspect ratio. If both dimensions are 0, the API provides an
     * image at source quality. If dimensions are not specified, the default size
     * of image returned is 400x400px.
     *
     *
     * @param {string} url
     * @param {number} width
     * @param {number} height
     * @throws {AppwriteException}
     * @returns {URL}
     */
    getImage(url, width, height) {
        if (typeof url === 'undefined') {
            throw new AppwriteException('Missing required parameter: "url"');
        }
        let path = '/avatars/image';
        let payload = {};
        if (typeof url !== 'undefined') {
            payload['url'] = url;
        }
        if (typeof width !== 'undefined') {
            payload['width'] = width;
        }
        if (typeof height !== 'undefined') {
            payload['height'] = height;
        }
        const uri = new URL(this.client.config.endpoint + path);
        payload['project'] = this.client.config.project;
        for (const [key, value] of Object.entries(Service.flatten(payload))) {
            uri.searchParams.append(key, value);
        }
        return uri;
    }
    /**
     * Get User Initials
     *
     * Use this endpoint to show your user initials avatar icon on your website or
     * app. By default, this route will try to print your logged-in user name or
     * email initials. You can also overwrite the user name if you pass the 'name'
     * parameter. If no name is given and no user is logged, an empty avatar will
     * be returned.
     *
     * You can use the color and background params to change the avatar colors. By
     * default, a random theme will be selected. The random theme will persist for
     * the user's initials when reloading the same theme will always return for
     * the same initials.
     *
     * When one dimension is specified and the other is 0, the image is scaled
     * with preserved aspect ratio. If both dimensions are 0, the API provides an
     * image at source quality. If dimensions are not specified, the default size
     * of image returned is 100x100px.
     *
     *
     * @param {string} name
     * @param {number} width
     * @param {number} height
     * @param {string} color
     * @param {string} background
     * @throws {AppwriteException}
     * @returns {URL}
     */
    getInitials(name, width, height, color, background) {
        let path = '/avatars/initials';
        let payload = {};
        if (typeof name !== 'undefined') {
            payload['name'] = name;
        }
        if (typeof width !== 'undefined') {
            payload['width'] = width;
        }
        if (typeof height !== 'undefined') {
            payload['height'] = height;
        }
        if (typeof color !== 'undefined') {
            payload['color'] = color;
        }
        if (typeof background !== 'undefined') {
            payload['background'] = background;
        }
        const uri = new URL(this.client.config.endpoint + path);
        payload['project'] = this.client.config.project;
        for (const [key, value] of Object.entries(Service.flatten(payload))) {
            uri.searchParams.append(key, value);
        }
        return uri;
    }
    /**
     * Get QR Code
     *
     * Converts a given plain text to a QR code image. You can use the query
     * parameters to change the size and style of the resulting image.
     *
     *
     * @param {string} text
     * @param {number} size
     * @param {number} margin
     * @param {boolean} download
     * @throws {AppwriteException}
     * @returns {URL}
     */
    getQR(text, size, margin, download) {
        if (typeof text === 'undefined') {
            throw new AppwriteException('Missing required parameter: "text"');
        }
        let path = '/avatars/qr';
        let payload = {};
        if (typeof text !== 'undefined') {
            payload['text'] = text;
        }
        if (typeof size !== 'undefined') {
            payload['size'] = size;
        }
        if (typeof margin !== 'undefined') {
            payload['margin'] = margin;
        }
        if (typeof download !== 'undefined') {
            payload['download'] = download;
        }
        const uri = new URL(this.client.config.endpoint + path);
        payload['project'] = this.client.config.project;
        for (const [key, value] of Object.entries(Service.flatten(payload))) {
            uri.searchParams.append(key, value);
        }
        return uri;
    }
}

class Databases extends Service {
    constructor(client, databaseId) {
        super(client);
        this.databaseId = databaseId;
    }
    setDatabaseId(databaseId) {
        this.databaseId = databaseId;
    }
    getDatabaseId() {
        return this.databaseId;
    }
    /**
     * List Documents
     *
     *
     * @param {string} collectionId
     * @param {string[]} queries
     * @param {number} limit
     * @param {number} offset
     * @param {string} cursor
     * @param {string} cursorDirection
     * @param {string[]} orderAttributes
     * @param {string[]} orderTypes
     * @throws {AppwriteException}
     * @returns {Promise}
     */
    listDocuments(collectionId, queries, limit, offset, cursor, cursorDirection, orderAttributes, orderTypes) {
        return __awaiter(this, void 0, void 0, function* () {
            if (typeof collectionId === 'undefined') {
                throw new AppwriteException('Missing required parameter: "collectionId"');
            }
            let path = '/databases/{databaseId}/collections/{collectionId}/documents'.replace('{databaseId}', this.databaseId).replace('{collectionId}', collectionId);
            let payload = {};
            if (typeof queries !== 'undefined') {
                payload['queries'] = queries;
            }
            if (typeof limit !== 'undefined') {
                payload['limit'] = limit;
            }
            if (typeof offset !== 'undefined') {
                payload['offset'] = offset;
            }
            if (typeof cursor !== 'undefined') {
                payload['cursor'] = cursor;
            }
            if (typeof cursorDirection !== 'undefined') {
                payload['cursorDirection'] = cursorDirection;
            }
            if (typeof orderAttributes !== 'undefined') {
                payload['orderAttributes'] = orderAttributes;
            }
            if (typeof orderTypes !== 'undefined') {
                payload['orderTypes'] = orderTypes;
            }
            const uri = new URL(this.client.config.endpoint + path);
            return yield this.client.call('get', uri, {
                'content-type': 'application/json',
            }, payload);
        });
    }
    /**
     * Create Document
     *
     *
     * @param {string} collectionId
     * @param {string} documentId
     * @param {Omit<Document, keyof Models.Document>} data
     * @param {string[]} read
     * @param {string[]} write
     * @throws {AppwriteException}
     * @returns {Promise}
     */
    createDocument(collectionId, documentId, data, read, write) {
        return __awaiter(this, void 0, void 0, function* () {
            if (typeof collectionId === 'undefined') {
                throw new AppwriteException('Missing required parameter: "collectionId"');
            }
            if (typeof documentId === 'undefined') {
                throw new AppwriteException('Missing required parameter: "documentId"');
            }
            if (typeof data === 'undefined') {
                throw new AppwriteException('Missing required parameter: "data"');
            }
            let path = '/databases/{databaseId}/collections/{collectionId}/documents'.replace('{databaseId}', this.databaseId).replace('{collectionId}', collectionId);
            let payload = {};
            if (typeof documentId !== 'undefined') {
                payload['documentId'] = documentId;
            }
            if (typeof data !== 'undefined') {
                payload['data'] = data;
            }
            if (typeof read !== 'undefined') {
                payload['read'] = read;
            }
            if (typeof write !== 'undefined') {
                payload['write'] = write;
            }
            const uri = new URL(this.client.config.endpoint + path);
            return yield this.client.call('post', uri, {
                'content-type': 'application/json',
            }, payload);
        });
    }
    /**
     * Get Document
     *
     *
     * @param {string} collectionId
     * @param {string} documentId
     * @throws {AppwriteException}
     * @returns {Promise}
     */
    getDocument(collectionId, documentId) {
        return __awaiter(this, void 0, void 0, function* () {
            if (typeof collectionId === 'undefined') {
                throw new AppwriteException('Missing required parameter: "collectionId"');
            }
            if (typeof documentId === 'undefined') {
                throw new AppwriteException('Missing required parameter: "documentId"');
            }
            let path = '/databases/{databaseId}/collections/{collectionId}/documents/{documentId}'.replace('{databaseId}', this.databaseId).replace('{collectionId}', collectionId).replace('{documentId}', documentId);
            let payload = {};
            const uri = new URL(this.client.config.endpoint + path);
            return yield this.client.call('get', uri, {
                'content-type': 'application/json',
            }, payload);
        });
    }
    /**
     * Update Document
     *
     *
     * @param {string} collectionId
     * @param {string} documentId
     * @param {Partial<Omit<Document, keyof Models.Document>>} data
     * @param {string[]} read
     * @param {string[]} write
     * @throws {AppwriteException}
     * @returns {Promise}
     */
    updateDocument(collectionId, documentId, data, read, write) {
        return __awaiter(this, void 0, void 0, function* () {
            if (typeof collectionId === 'undefined') {
                throw new AppwriteException('Missing required parameter: "collectionId"');
            }
            if (typeof documentId === 'undefined') {
                throw new AppwriteException('Missing required parameter: "documentId"');
            }
            let path = '/databases/{databaseId}/collections/{collectionId}/documents/{documentId}'.replace('{databaseId}', this.databaseId).replace('{collectionId}', collectionId).replace('{documentId}', documentId);
            let payload = {};
            if (typeof data !== 'undefined') {
                payload['data'] = data;
            }
            if (typeof read !== 'undefined') {
                payload['read'] = read;
            }
            if (typeof write !== 'undefined') {
                payload['write'] = write;
            }
            const uri = new URL(this.client.config.endpoint + path);
            return yield this.client.call('patch', uri, {
                'content-type': 'application/json',
            }, payload);
        });
    }
    /**
     * Delete Document
     *
     *
     * @param {string} collectionId
     * @param {string} documentId
     * @throws {AppwriteException}
     * @returns {Promise}
     */
    deleteDocument(collectionId, documentId) {
        return __awaiter(this, void 0, void 0, function* () {
            if (typeof collectionId === 'undefined') {
                throw new AppwriteException('Missing required parameter: "collectionId"');
            }
            if (typeof documentId === 'undefined') {
                throw new AppwriteException('Missing required parameter: "documentId"');
            }
            let path = '/databases/{databaseId}/collections/{collectionId}/documents/{documentId}'.replace('{databaseId}', this.databaseId).replace('{collectionId}', collectionId).replace('{documentId}', documentId);
            let payload = {};
            const uri = new URL(this.client.config.endpoint + path);
            return yield this.client.call('delete', uri, {
                'content-type': 'application/json',
            }, payload);
        });
    }
}

class Functions extends Service {
    /**
     * Retry Build
     *
     *
     * @param {string} functionId
     * @param {string} deploymentId
     * @param {string} buildId
     * @throws {AppwriteException}
     * @returns {Promise}
     */
    retryBuild(functionId, deploymentId, buildId) {
        return __awaiter(this, void 0, void 0, function* () {
            if (typeof functionId === 'undefined') {
                throw new AppwriteException('Missing required parameter: "functionId"');
            }
            if (typeof deploymentId === 'undefined') {
                throw new AppwriteException('Missing required parameter: "deploymentId"');
            }
            if (typeof buildId === 'undefined') {
                throw new AppwriteException('Missing required parameter: "buildId"');
            }
            let path = '/functions/{functionId}/deployments/{deploymentId}/builds/{buildId}'.replace('{functionId}', functionId).replace('{deploymentId}', deploymentId).replace('{buildId}', buildId);
            let payload = {};
            const uri = new URL(this.client.config.endpoint + path);
            return yield this.client.call('post', uri, {
                'content-type': 'application/json',
            }, payload);
        });
    }
    /**
     * List Executions
     *
     * Get a list of all the current user function execution logs. You can use the
     * query params to filter your results. On admin mode, this endpoint will
     * return a list of all of the project's executions. [Learn more about
     * different API modes](/docs/admin).
     *
     * @param {string} functionId
     * @param {number} limit
     * @param {number} offset
     * @param {string} search
     * @param {string} cursor
     * @param {string} cursorDirection
     * @throws {AppwriteException}
     * @returns {Promise}
     */
    listExecutions(functionId, limit, offset, search, cursor, cursorDirection) {
        return __awaiter(this, void 0, void 0, function* () {
            if (typeof functionId === 'undefined') {
                throw new AppwriteException('Missing required parameter: "functionId"');
            }
            let path = '/functions/{functionId}/executions'.replace('{functionId}', functionId);
            let payload = {};
            if (typeof limit !== 'undefined') {
                payload['limit'] = limit;
            }
            if (typeof offset !== 'undefined') {
                payload['offset'] = offset;
            }
            if (typeof search !== 'undefined') {
                payload['search'] = search;
            }
            if (typeof cursor !== 'undefined') {
                payload['cursor'] = cursor;
            }
            if (typeof cursorDirection !== 'undefined') {
                payload['cursorDirection'] = cursorDirection;
            }
            const uri = new URL(this.client.config.endpoint + path);
            return yield this.client.call('get', uri, {
                'content-type': 'application/json',
            }, payload);
        });
    }
    /**
     * Create Execution
     *
     * Trigger a function execution. The returned object will return you the
     * current execution status. You can ping the `Get Execution` endpoint to get
     * updates on the current execution status. Once this endpoint is called, your
     * function execution process will start asynchronously.
     *
     * @param {string} functionId
     * @param {string} data
     * @param {boolean} async
     * @throws {AppwriteException}
     * @returns {Promise}
     */
    createExecution(functionId, data, async) {
        return __awaiter(this, void 0, void 0, function* () {
            if (typeof functionId === 'undefined') {
                throw new AppwriteException('Missing required parameter: "functionId"');
            }
            let path = '/functions/{functionId}/executions'.replace('{functionId}', functionId);
            let payload = {};
            if (typeof data !== 'undefined') {
                payload['data'] = data;
            }
            if (typeof async !== 'undefined') {
                payload['async'] = async;
            }
            const uri = new URL(this.client.config.endpoint + path);
            return yield this.client.call('post', uri, {
                'content-type': 'application/json',
            }, payload);
        });
    }
    /**
     * Get Execution
     *
     * Get a function execution log by its unique ID.
     *
     * @param {string} functionId
     * @param {string} executionId
     * @throws {AppwriteException}
     * @returns {Promise}
     */
    getExecution(functionId, executionId) {
        return __awaiter(this, void 0, void 0, function* () {
            if (typeof functionId === 'undefined') {
                throw new AppwriteException('Missing required parameter: "functionId"');
            }
            if (typeof executionId === 'undefined') {
                throw new AppwriteException('Missing required parameter: "executionId"');
            }
            let path = '/functions/{functionId}/executions/{executionId}'.replace('{functionId}', functionId).replace('{executionId}', executionId);
            let payload = {};
            const uri = new URL(this.client.config.endpoint + path);
            return yield this.client.call('get', uri, {
                'content-type': 'application/json',
            }, payload);
        });
    }
}

class Locale extends Service {
    /**
     * Get User Locale
     *
     * Get the current user location based on IP. Returns an object with user
     * country code, country name, continent name, continent code, ip address and
     * suggested currency. You can use the locale header to get the data in a
     * supported language.
     *
     * ([IP Geolocation by DB-IP](https://db-ip.com))
     *
     * @throws {AppwriteException}
     * @returns {Promise}
     */
    get() {
        return __awaiter(this, void 0, void 0, function* () {
            let path = '/locale';
            let payload = {};
            const uri = new URL(this.client.config.endpoint + path);
            return yield this.client.call('get', uri, {
                'content-type': 'application/json',
            }, payload);
        });
    }
    /**
     * List Continents
     *
     * List of all continents. You can use the locale header to get the data in a
     * supported language.
     *
     * @throws {AppwriteException}
     * @returns {Promise}
     */
    getContinents() {
        return __awaiter(this, void 0, void 0, function* () {
            let path = '/locale/continents';
            let payload = {};
            const uri = new URL(this.client.config.endpoint + path);
            return yield this.client.call('get', uri, {
                'content-type': 'application/json',
            }, payload);
        });
    }
    /**
     * List Countries
     *
     * List of all countries. You can use the locale header to get the data in a
     * supported language.
     *
     * @throws {AppwriteException}
     * @returns {Promise}
     */
    getCountries() {
        return __awaiter(this, void 0, void 0, function* () {
            let path = '/locale/countries';
            let payload = {};
            const uri = new URL(this.client.config.endpoint + path);
            return yield this.client.call('get', uri, {
                'content-type': 'application/json',
            }, payload);
        });
    }
    /**
     * List EU Countries
     *
     * List of all countries that are currently members of the EU. You can use the
     * locale header to get the data in a supported language.
     *
     * @throws {AppwriteException}
     * @returns {Promise}
     */
    getCountriesEU() {
        return __awaiter(this, void 0, void 0, function* () {
            let path = '/locale/countries/eu';
            let payload = {};
            const uri = new URL(this.client.config.endpoint + path);
            return yield this.client.call('get', uri, {
                'content-type': 'application/json',
            }, payload);
        });
    }
    /**
     * List Countries Phone Codes
     *
     * List of all countries phone codes. You can use the locale header to get the
     * data in a supported language.
     *
     * @throws {AppwriteException}
     * @returns {Promise}
     */
    getCountriesPhones() {
        return __awaiter(this, void 0, void 0, function* () {
            let path = '/locale/countries/phones';
            let payload = {};
            const uri = new URL(this.client.config.endpoint + path);
            return yield this.client.call('get', uri, {
                'content-type': 'application/json',
            }, payload);
        });
    }
    /**
     * List Currencies
     *
     * List of all currencies, including currency symbol, name, plural, and
     * decimal digits for all major and minor currencies. You can use the locale
     * header to get the data in a supported language.
     *
     * @throws {AppwriteException}
     * @returns {Promise}
     */
    getCurrencies() {
        return __awaiter(this, void 0, void 0, function* () {
            let path = '/locale/currencies';
            let payload = {};
            const uri = new URL(this.client.config.endpoint + path);
            return yield this.client.call('get', uri, {
                'content-type': 'application/json',
            }, payload);
        });
    }
    /**
     * List Languages
     *
     * List of all languages classified by ISO 639-1 including 2-letter code, name
     * in English, and name in the respective language.
     *
     * @throws {AppwriteException}
     * @returns {Promise}
     */
    getLanguages() {
        return __awaiter(this, void 0, void 0, function* () {
            let path = '/locale/languages';
            let payload = {};
            const uri = new URL(this.client.config.endpoint + path);
            return yield this.client.call('get', uri, {
                'content-type': 'application/json',
            }, payload);
        });
    }
}

class Storage extends Service {
    /**
     * List Files
     *
     * Get a list of all the user files. You can use the query params to filter
     * your results. On admin mode, this endpoint will return a list of all of the
     * project's files. [Learn more about different API modes](/docs/admin).
     *
     * @param {string} bucketId
     * @param {string} search
     * @param {number} limit
     * @param {number} offset
     * @param {string} cursor
     * @param {string} cursorDirection
     * @param {string} orderType
     * @throws {AppwriteException}
     * @returns {Promise}
     */
    listFiles(bucketId, search, limit, offset, cursor, cursorDirection, orderType) {
        return __awaiter(this, void 0, void 0, function* () {
            if (typeof bucketId === 'undefined') {
                throw new AppwriteException('Missing required parameter: "bucketId"');
            }
            let path = '/storage/buckets/{bucketId}/files'.replace('{bucketId}', bucketId);
            let payload = {};
            if (typeof search !== 'undefined') {
                payload['search'] = search;
            }
            if (typeof limit !== 'undefined') {
                payload['limit'] = limit;
            }
            if (typeof offset !== 'undefined') {
                payload['offset'] = offset;
            }
            if (typeof cursor !== 'undefined') {
                payload['cursor'] = cursor;
            }
            if (typeof cursorDirection !== 'undefined') {
                payload['cursorDirection'] = cursorDirection;
            }
            if (typeof orderType !== 'undefined') {
                payload['orderType'] = orderType;
            }
            const uri = new URL(this.client.config.endpoint + path);
            return yield this.client.call('get', uri, {
                'content-type': 'application/json',
            }, payload);
        });
    }
    /**
     * Create File
     *
     * Create a new file. Before using this route, you should create a new bucket
     * resource using either a [server
     * integration](/docs/server/database#storageCreateBucket) API or directly
     * from your Appwrite console.
     *
     * Larger files should be uploaded using multiple requests with the
     * [content-range](https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Range)
     * header to send a partial request with a maximum supported chunk of `5MB`.
     * The `content-range` header values should always be in bytes.
     *
     * When the first request is sent, the server will return the **File** object,
     * and the subsequent part request must include the file's **id** in
     * `x-appwrite-id` header to allow the server to know that the partial upload
     * is for the existing file and not for a new one.
     *
     * If you're creating a new file using one of the Appwrite SDKs, all the
     * chunking logic will be managed by the SDK internally.
     *
     *
     * @param {string} bucketId
     * @param {string} fileId
     * @param {File} file
     * @param {string[]} read
     * @param {string[]} write
     * @throws {AppwriteException}
     * @returns {Promise}
     */
    createFile(bucketId, fileId, file, read, write, onProgress = (progress) => { }) {
        return __awaiter(this, void 0, void 0, function* () {
            if (typeof bucketId === 'undefined') {
                throw new AppwriteException('Missing required parameter: "bucketId"');
            }
            if (typeof fileId === 'undefined') {
                throw new AppwriteException('Missing required parameter: "fileId"');
            }
            if (typeof file === 'undefined') {
                throw new AppwriteException('Missing required parameter: "file"');
            }
            let path = '/storage/buckets/{bucketId}/files'.replace('{bucketId}', bucketId);
            let payload = {};
            if (typeof fileId !== 'undefined') {
                payload['fileId'] = fileId;
            }
            if (typeof file !== 'undefined') {
                payload['file'] = file;
            }
            if (typeof read !== 'undefined') {
                payload['read'] = read;
            }
            if (typeof write !== 'undefined') {
                payload['write'] = write;
            }
            const uri = new URL(this.client.config.endpoint + path);
            if (!(file instanceof File)) {
                throw new AppwriteException('Parameter "file" has to be a File.');
            }
            const size = file.size;
            if (size <= Service.CHUNK_SIZE) {
                return yield this.client.call('post', uri, {
                    'content-type': 'multipart/form-data',
                }, payload);
            }
            let id = undefined;
            let response = undefined;
            const headers = {
                'content-type': 'multipart/form-data',
            };
            let counter = 0;
            const totalCounters = Math.ceil(size / Service.CHUNK_SIZE);
            if (fileId != 'unique()') {
                try {
                    response = yield this.client.call('GET', new URL(this.client.config.endpoint + path + '/' + fileId), headers);
                    counter = response.chunksUploaded;
                }
                catch (e) {
                }
            }
            for (counter; counter < totalCounters; counter++) {
                const start = (counter * Service.CHUNK_SIZE);
                const end = Math.min((((counter * Service.CHUNK_SIZE) + Service.CHUNK_SIZE) - 1), size);
                headers['content-range'] = 'bytes ' + start + '-' + end + '/' + size;
                if (id) {
                    headers['x-appwrite-id'] = id;
                }
                const stream = file.slice(start, end + 1);
                payload['file'] = new File([stream], file.name);
                response = yield this.client.call('post', uri, headers, payload);
                if (!id) {
                    id = response['$id'];
                }
                if (onProgress) {
                    onProgress({
                        $id: response.$id,
                        progress: Math.min((counter + 1) * Service.CHUNK_SIZE - 1, size) / size * 100,
                        sizeUploaded: end,
                        chunksTotal: response.chunksTotal,
                        chunksUploaded: response.chunksUploaded
                    });
                }
            }
            return response;
        });
    }
    /**
     * Get File
     *
     * Get a file by its unique ID. This endpoint response returns a JSON object
     * with the file metadata.
     *
     * @param {string} bucketId
     * @param {string} fileId
     * @throws {AppwriteException}
     * @returns {Promise}
     */
    getFile(bucketId, fileId) {
        return __awaiter(this, void 0, void 0, function* () {
            if (typeof bucketId === 'undefined') {
                throw new AppwriteException('Missing required parameter: "bucketId"');
            }
            if (typeof fileId === 'undefined') {
                throw new AppwriteException('Missing required parameter: "fileId"');
            }
            let path = '/storage/buckets/{bucketId}/files/{fileId}'.replace('{bucketId}', bucketId).replace('{fileId}', fileId);
            let payload = {};
            const uri = new URL(this.client.config.endpoint + path);
            return yield this.client.call('get', uri, {
                'content-type': 'application/json',
            }, payload);
        });
    }
    /**
     * Update File
     *
     * Update a file by its unique ID. Only users with write permissions have
     * access to update this resource.
     *
     * @param {string} bucketId
     * @param {string} fileId
     * @param {string[]} read
     * @param {string[]} write
     * @throws {AppwriteException}
     * @returns {Promise}
     */
    updateFile(bucketId, fileId, read, write) {
        return __awaiter(this, void 0, void 0, function* () {
            if (typeof bucketId === 'undefined') {
                throw new AppwriteException('Missing required parameter: "bucketId"');
            }
            if (typeof fileId === 'undefined') {
                throw new AppwriteException('Missing required parameter: "fileId"');
            }
            let path = '/storage/buckets/{bucketId}/files/{fileId}'.replace('{bucketId}', bucketId).replace('{fileId}', fileId);
            let payload = {};
            if (typeof read !== 'undefined') {
                payload['read'] = read;
            }
            if (typeof write !== 'undefined') {
                payload['write'] = write;
            }
            const uri = new URL(this.client.config.endpoint + path);
            return yield this.client.call('put', uri, {
                'content-type': 'application/json',
            }, payload);
        });
    }
    /**
     * Delete File
     *
     * Delete a file by its unique ID. Only users with write permissions have
     * access to delete this resource.
     *
     * @param {string} bucketId
     * @param {string} fileId
     * @throws {AppwriteException}
     * @returns {Promise}
     */
    deleteFile(bucketId, fileId) {
        return __awaiter(this, void 0, void 0, function* () {
            if (typeof bucketId === 'undefined') {
                throw new AppwriteException('Missing required parameter: "bucketId"');
            }
            if (typeof fileId === 'undefined') {
                throw new AppwriteException('Missing required parameter: "fileId"');
            }
            let path = '/storage/buckets/{bucketId}/files/{fileId}'.replace('{bucketId}', bucketId).replace('{fileId}', fileId);
            let payload = {};
            const uri = new URL(this.client.config.endpoint + path);
            return yield this.client.call('delete', uri, {
                'content-type': 'application/json',
            }, payload);
        });
    }
    /**
     * Get File for Download
     *
     * Get a file content by its unique ID. The endpoint response return with a
     * 'Content-Disposition: attachment' header that tells the browser to start
     * downloading the file to user downloads directory.
     *
     * @param {string} bucketId
     * @param {string} fileId
     * @throws {AppwriteException}
     * @returns {URL}
     */
    getFileDownload(bucketId, fileId) {
        if (typeof bucketId === 'undefined') {
            throw new AppwriteException('Missing required parameter: "bucketId"');
        }
        if (typeof fileId === 'undefined') {
            throw new AppwriteException('Missing required parameter: "fileId"');
        }
        let path = '/storage/buckets/{bucketId}/files/{fileId}/download'.replace('{bucketId}', bucketId).replace('{fileId}', fileId);
        let payload = {};
        const uri = new URL(this.client.config.endpoint + path);
        payload['project'] = this.client.config.project;
        for (const [key, value] of Object.entries(Service.flatten(payload))) {
            uri.searchParams.append(key, value);
        }
        return uri;
    }
    /**
     * Get File Preview
     *
     * Get a file preview image. Currently, this method supports preview for image
     * files (jpg, png, and gif), other supported formats, like pdf, docs, slides,
     * and spreadsheets, will return the file icon image. You can also pass query
     * string arguments for cutting and resizing your preview image. Preview is
     * supported only for image files smaller than 10MB.
     *
     * @param {string} bucketId
     * @param {string} fileId
     * @param {number} width
     * @param {number} height
     * @param {string} gravity
     * @param {number} quality
     * @param {number} borderWidth
     * @param {string} borderColor
     * @param {number} borderRadius
     * @param {number} opacity
     * @param {number} rotation
     * @param {string} background
     * @param {string} output
     * @throws {AppwriteException}
     * @returns {URL}
     */
    getFilePreview(bucketId, fileId, width, height, gravity, quality, borderWidth, borderColor, borderRadius, opacity, rotation, background, output) {
        if (typeof bucketId === 'undefined') {
            throw new AppwriteException('Missing required parameter: "bucketId"');
        }
        if (typeof fileId === 'undefined') {
            throw new AppwriteException('Missing required parameter: "fileId"');
        }
        let path = '/storage/buckets/{bucketId}/files/{fileId}/preview'.replace('{bucketId}', bucketId).replace('{fileId}', fileId);
        let payload = {};
        if (typeof width !== 'undefined') {
            payload['width'] = width;
        }
        if (typeof height !== 'undefined') {
            payload['height'] = height;
        }
        if (typeof gravity !== 'undefined') {
            payload['gravity'] = gravity;
        }
        if (typeof quality !== 'undefined') {
            payload['quality'] = quality;
        }
        if (typeof borderWidth !== 'undefined') {
            payload['borderWidth'] = borderWidth;
        }
        if (typeof borderColor !== 'undefined') {
            payload['borderColor'] = borderColor;
        }
        if (typeof borderRadius !== 'undefined') {
            payload['borderRadius'] = borderRadius;
        }
        if (typeof opacity !== 'undefined') {
            payload['opacity'] = opacity;
        }
        if (typeof rotation !== 'undefined') {
            payload['rotation'] = rotation;
        }
        if (typeof background !== 'undefined') {
            payload['background'] = background;
        }
        if (typeof output !== 'undefined') {
            payload['output'] = output;
        }
        const uri = new URL(this.client.config.endpoint + path);
        payload['project'] = this.client.config.project;
        for (const [key, value] of Object.entries(Service.flatten(payload))) {
            uri.searchParams.append(key, value);
        }
        return uri;
    }
    /**
     * Get File for View
     *
     * Get a file content by its unique ID. This endpoint is similar to the
     * download method but returns with no  'Content-Disposition: attachment'
     * header.
     *
     * @param {string} bucketId
     * @param {string} fileId
     * @throws {AppwriteException}
     * @returns {URL}
     */
    getFileView(bucketId, fileId) {
        if (typeof bucketId === 'undefined') {
            throw new AppwriteException('Missing required parameter: "bucketId"');
        }
        if (typeof fileId === 'undefined') {
            throw new AppwriteException('Missing required parameter: "fileId"');
        }
        let path = '/storage/buckets/{bucketId}/files/{fileId}/view'.replace('{bucketId}', bucketId).replace('{fileId}', fileId);
        let payload = {};
        const uri = new URL(this.client.config.endpoint + path);
        payload['project'] = this.client.config.project;
        for (const [key, value] of Object.entries(Service.flatten(payload))) {
            uri.searchParams.append(key, value);
        }
        return uri;
    }
}

class Teams extends Service {
    /**
     * List Teams
     *
     * Get a list of all the teams in which the current user is a member. You can
     * use the parameters to filter your results.
     *
     * In admin mode, this endpoint returns a list of all the teams in the current
     * project. [Learn more about different API modes](/docs/admin).
     *
     * @param {string} search
     * @param {number} limit
     * @param {number} offset
     * @param {string} cursor
     * @param {string} cursorDirection
     * @param {string} orderType
     * @throws {AppwriteException}
     * @returns {Promise}
     */
    list(search, limit, offset, cursor, cursorDirection, orderType) {
        return __awaiter(this, void 0, void 0, function* () {
            let path = '/teams';
            let payload = {};
            if (typeof search !== 'undefined') {
                payload['search'] = search;
            }
            if (typeof limit !== 'undefined') {
                payload['limit'] = limit;
            }
            if (typeof offset !== 'undefined') {
                payload['offset'] = offset;
            }
            if (typeof cursor !== 'undefined') {
                payload['cursor'] = cursor;
            }
            if (typeof cursorDirection !== 'undefined') {
                payload['cursorDirection'] = cursorDirection;
            }
            if (typeof orderType !== 'undefined') {
                payload['orderType'] = orderType;
            }
            const uri = new URL(this.client.config.endpoint + path);
            return yield this.client.call('get', uri, {
                'content-type': 'application/json',
            }, payload);
        });
    }
    /**
     * Create Team
     *
     * Create a new team. The user who creates the team will automatically be
     * assigned as the owner of the team. Only the users with the owner role can
     * invite new members, add new owners and delete or update the team.
     *
     * @param {string} teamId
     * @param {string} name
     * @param {string[]} roles
     * @throws {AppwriteException}
     * @returns {Promise}
     */
    create(teamId, name, roles) {
        return __awaiter(this, void 0, void 0, function* () {
            if (typeof teamId === 'undefined') {
                throw new AppwriteException('Missing required parameter: "teamId"');
            }
            if (typeof name === 'undefined') {
                throw new AppwriteException('Missing required parameter: "name"');
            }
            let path = '/teams';
            let payload = {};
            if (typeof teamId !== 'undefined') {
                payload['teamId'] = teamId;
            }
            if (typeof name !== 'undefined') {
                payload['name'] = name;
            }
            if (typeof roles !== 'undefined') {
                payload['roles'] = roles;
            }
            const uri = new URL(this.client.config.endpoint + path);
            return yield this.client.call('post', uri, {
                'content-type': 'application/json',
            }, payload);
        });
    }
    /**
     * Get Team
     *
     * Get a team by its ID. All team members have read access for this resource.
     *
     * @param {string} teamId
     * @throws {AppwriteException}
     * @returns {Promise}
     */
    get(teamId) {
        return __awaiter(this, void 0, void 0, function* () {
            if (typeof teamId === 'undefined') {
                throw new AppwriteException('Missing required parameter: "teamId"');
            }
            let path = '/teams/{teamId}'.replace('{teamId}', teamId);
            let payload = {};
            const uri = new URL(this.client.config.endpoint + path);
            return yield this.client.call('get', uri, {
                'content-type': 'application/json',
            }, payload);
        });
    }
    /**
     * Update Team
     *
     * Update a team using its ID. Only members with the owner role can update the
     * team.
     *
     * @param {string} teamId
     * @param {string} name
     * @throws {AppwriteException}
     * @returns {Promise}
     */
    update(teamId, name) {
        return __awaiter(this, void 0, void 0, function* () {
            if (typeof teamId === 'undefined') {
                throw new AppwriteException('Missing required parameter: "teamId"');
            }
            if (typeof name === 'undefined') {
                throw new AppwriteException('Missing required parameter: "name"');
            }
            let path = '/teams/{teamId}'.replace('{teamId}', teamId);
            let payload = {};
            if (typeof name !== 'undefined') {
                payload['name'] = name;
            }
            const uri = new URL(this.client.config.endpoint + path);
            return yield this.client.call('put', uri, {
                'content-type': 'application/json',
            }, payload);
        });
    }
    /**
     * Delete Team
     *
     * Delete a team using its ID. Only team members with the owner role can
     * delete the team.
     *
     * @param {string} teamId
     * @throws {AppwriteException}
     * @returns {Promise}
     */
    delete(teamId) {
        return __awaiter(this, void 0, void 0, function* () {
            if (typeof teamId === 'undefined') {
                throw new AppwriteException('Missing required parameter: "teamId"');
            }
            let path = '/teams/{teamId}'.replace('{teamId}', teamId);
            let payload = {};
            const uri = new URL(this.client.config.endpoint + path);
            return yield this.client.call('delete', uri, {
                'content-type': 'application/json',
            }, payload);
        });
    }
    /**
     * Get Team Memberships
     *
     * Use this endpoint to list a team's members using the team's ID. All team
     * members have read access to this endpoint.
     *
     * @param {string} teamId
     * @param {string} search
     * @param {number} limit
     * @param {number} offset
     * @param {string} cursor
     * @param {string} cursorDirection
     * @param {string} orderType
     * @throws {AppwriteException}
     * @returns {Promise}
     */
    getMemberships(teamId, search, limit, offset, cursor, cursorDirection, orderType) {
        return __awaiter(this, void 0, void 0, function* () {
            if (typeof teamId === 'undefined') {
                throw new AppwriteException('Missing required parameter: "teamId"');
            }
            let path = '/teams/{teamId}/memberships'.replace('{teamId}', teamId);
            let payload = {};
            if (typeof search !== 'undefined') {
                payload['search'] = search;
            }
            if (typeof limit !== 'undefined') {
                payload['limit'] = limit;
            }
            if (typeof offset !== 'undefined') {
                payload['offset'] = offset;
            }
            if (typeof cursor !== 'undefined') {
                payload['cursor'] = cursor;
            }
            if (typeof cursorDirection !== 'undefined') {
                payload['cursorDirection'] = cursorDirection;
            }
            if (typeof orderType !== 'undefined') {
                payload['orderType'] = orderType;
            }
            const uri = new URL(this.client.config.endpoint + path);
            return yield this.client.call('get', uri, {
                'content-type': 'application/json',
            }, payload);
        });
    }
    /**
     * Create Team Membership
     *
     * Invite a new member to join your team. If initiated from the client SDK, an
     * email with a link to join the team will be sent to the member's email
     * address and an account will be created for them should they not be signed
     * up already. If initiated from server-side SDKs, the new member will
     * automatically be added to the team.
     *
     * Use the 'url' parameter to redirect the user from the invitation email back
     * to your app. When the user is redirected, use the [Update Team Membership
     * Status](/docs/client/teams#teamsUpdateMembershipStatus) endpoint to allow
     * the user to accept the invitation to the team.
     *
     * Please note that to avoid a [Redirect
     * Attack](https://github.com/OWASP/CheatSheetSeries/blob/master/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.md)
     * the only valid redirect URL's are the once from domains you have set when
     * adding your platforms in the console interface.
     *
     * @param {string} teamId
     * @param {string} email
     * @param {string[]} roles
     * @param {string} url
     * @param {string} name
     * @throws {AppwriteException}
     * @returns {Promise}
     */
    createMembership(teamId, email, roles, url, name) {
        return __awaiter(this, void 0, void 0, function* () {
            if (typeof teamId === 'undefined') {
                throw new AppwriteException('Missing required parameter: "teamId"');
            }
            if (typeof email === 'undefined') {
                throw new AppwriteException('Missing required parameter: "email"');
            }
            if (typeof roles === 'undefined') {
                throw new AppwriteException('Missing required parameter: "roles"');
            }
            if (typeof url === 'undefined') {
                throw new AppwriteException('Missing required parameter: "url"');
            }
            let path = '/teams/{teamId}/memberships'.replace('{teamId}', teamId);
            let payload = {};
            if (typeof email !== 'undefined') {
                payload['email'] = email;
            }
            if (typeof roles !== 'undefined') {
                payload['roles'] = roles;
            }
            if (typeof url !== 'undefined') {
                payload['url'] = url;
            }
            if (typeof name !== 'undefined') {
                payload['name'] = name;
            }
            const uri = new URL(this.client.config.endpoint + path);
            return yield this.client.call('post', uri, {
                'content-type': 'application/json',
            }, payload);
        });
    }
    /**
     * Get Team Membership
     *
     * Get a team member by the membership unique id. All team members have read
     * access for this resource.
     *
     * @param {string} teamId
     * @param {string} membershipId
     * @throws {AppwriteException}
     * @returns {Promise}
     */
    getMembership(teamId, membershipId) {
        return __awaiter(this, void 0, void 0, function* () {
            if (typeof teamId === 'undefined') {
                throw new AppwriteException('Missing required parameter: "teamId"');
            }
            if (typeof membershipId === 'undefined') {
                throw new AppwriteException('Missing required parameter: "membershipId"');
            }
            let path = '/teams/{teamId}/memberships/{membershipId}'.replace('{teamId}', teamId).replace('{membershipId}', membershipId);
            let payload = {};
            const uri = new URL(this.client.config.endpoint + path);
            return yield this.client.call('get', uri, {
                'content-type': 'application/json',
            }, payload);
        });
    }
    /**
     * Update Membership Roles
     *
     * Modify the roles of a team member. Only team members with the owner role
     * have access to this endpoint. Learn more about [roles and
     * permissions](/docs/permissions).
     *
     * @param {string} teamId
     * @param {string} membershipId
     * @param {string[]} roles
     * @throws {AppwriteException}
     * @returns {Promise}
     */
    updateMembershipRoles(teamId, membershipId, roles) {
        return __awaiter(this, void 0, void 0, function* () {
            if (typeof teamId === 'undefined') {
                throw new AppwriteException('Missing required parameter: "teamId"');
            }
            if (typeof membershipId === 'undefined') {
                throw new AppwriteException('Missing required parameter: "membershipId"');
            }
            if (typeof roles === 'undefined') {
                throw new AppwriteException('Missing required parameter: "roles"');
            }
            let path = '/teams/{teamId}/memberships/{membershipId}'.replace('{teamId}', teamId).replace('{membershipId}', membershipId);
            let payload = {};
            if (typeof roles !== 'undefined') {
                payload['roles'] = roles;
            }
            const uri = new URL(this.client.config.endpoint + path);
            return yield this.client.call('patch', uri, {
                'content-type': 'application/json',
            }, payload);
        });
    }
    /**
     * Delete Team Membership
     *
     * This endpoint allows a user to leave a team or for a team owner to delete
     * the membership of any other team member. You can also use this endpoint to
     * delete a user membership even if it is not accepted.
     *
     * @param {string} teamId
     * @param {string} membershipId
     * @throws {AppwriteException}
     * @returns {Promise}
     */
    deleteMembership(teamId, membershipId) {
        return __awaiter(this, void 0, void 0, function* () {
            if (typeof teamId === 'undefined') {
                throw new AppwriteException('Missing required parameter: "teamId"');
            }
            if (typeof membershipId === 'undefined') {
                throw new AppwriteException('Missing required parameter: "membershipId"');
            }
            let path = '/teams/{teamId}/memberships/{membershipId}'.replace('{teamId}', teamId).replace('{membershipId}', membershipId);
            let payload = {};
            const uri = new URL(this.client.config.endpoint + path);
            return yield this.client.call('delete', uri, {
                'content-type': 'application/json',
            }, payload);
        });
    }
    /**
     * Update Team Membership Status
     *
     * Use this endpoint to allow a user to accept an invitation to join a team
     * after being redirected back to your app from the invitation email received
     * by the user.
     *
     * If the request is successful, a session for the user is automatically
     * created.
     *
     *
     * @param {string} teamId
     * @param {string} membershipId
     * @param {string} userId
     * @param {string} secret
     * @throws {AppwriteException}
     * @returns {Promise}
     */
    updateMembershipStatus(teamId, membershipId, userId, secret) {
        return __awaiter(this, void 0, void 0, function* () {
            if (typeof teamId === 'undefined') {
                throw new AppwriteException('Missing required parameter: "teamId"');
            }
            if (typeof membershipId === 'undefined') {
                throw new AppwriteException('Missing required parameter: "membershipId"');
            }
            if (typeof userId === 'undefined') {
                throw new AppwriteException('Missing required parameter: "userId"');
            }
            if (typeof secret === 'undefined') {
                throw new AppwriteException('Missing required parameter: "secret"');
            }
            let path = '/teams/{teamId}/memberships/{membershipId}/status'.replace('{teamId}', teamId).replace('{membershipId}', membershipId);
            let payload = {};
            if (typeof userId !== 'undefined') {
                payload['userId'] = userId;
            }
            if (typeof secret !== 'undefined') {
                payload['secret'] = secret;
            }
            const uri = new URL(this.client.config.endpoint + path);
            return yield this.client.call('patch', uri, {
                'content-type': 'application/json',
            }, payload);
        });
    }
}


//# sourceMappingURL=sdk.js.map


/***/ }),

/***/ "./node_modules/websocket/package.json":
/*!*********************************************!*\
  !*** ./node_modules/websocket/package.json ***!
  \*********************************************/
/***/ ((module) => {

"use strict";
module.exports = JSON.parse('{"name":"websocket","description":"Websocket Client & Server Library implementing the WebSocket protocol as specified in RFC 6455.","keywords":["websocket","websockets","socket","networking","comet","push","RFC-6455","realtime","server","client"],"author":"Brian McKelvey <theturtle32@gmail.com> (https://github.com/theturtle32)","contributors":["Iñaki Baz Castillo <ibc@aliax.net> (http://dev.sipdoc.net)"],"version":"1.0.34","repository":{"type":"git","url":"https://github.com/theturtle32/WebSocket-Node.git"},"homepage":"https://github.com/theturtle32/WebSocket-Node","engines":{"node":">=4.0.0"},"dependencies":{"bufferutil":"^4.0.1","debug":"^2.2.0","es5-ext":"^0.10.50","typedarray-to-buffer":"^3.1.5","utf-8-validate":"^5.0.2","yaeti":"^0.0.6"},"devDependencies":{"buffer-equal":"^1.0.0","gulp":"^4.0.2","gulp-jshint":"^2.0.4","jshint-stylish":"^2.2.1","jshint":"^2.0.0","tape":"^4.9.1"},"config":{"verbose":false},"scripts":{"test":"tape test/unit/*.js","gulp":"gulp"},"main":"index","directories":{"lib":"./lib"},"browser":"lib/browser.js","license":"Apache-2.0"}');

/***/ })

/******/ 	});
/************************************************************************/
/******/ 	// The module cache
/******/ 	var __webpack_module_cache__ = {};
/******/ 	
/******/ 	// The require function
/******/ 	function __webpack_require__(moduleId) {
/******/ 		// Check if module is in cache
/******/ 		var cachedModule = __webpack_module_cache__[moduleId];
/******/ 		if (cachedModule !== undefined) {
/******/ 			return cachedModule.exports;
/******/ 		}
/******/ 		// Create a new module (and put it into the cache)
/******/ 		var module = __webpack_module_cache__[moduleId] = {
/******/ 			id: moduleId,
/******/ 			// no module.loaded needed
/******/ 			exports: {}
/******/ 		};
/******/ 	
/******/ 		// Execute the module function
/******/ 		__webpack_modules__[moduleId].call(module.exports, module, module.exports, __webpack_require__);
/******/ 	
/******/ 		// Return the exports of the module
/******/ 		return module.exports;
/******/ 	}
/******/ 	
/******/ 	// expose the modules object (__webpack_modules__)
/******/ 	__webpack_require__.m = __webpack_modules__;
/******/ 	
/************************************************************************/
/******/ 	/* webpack/runtime/compat get default export */
/******/ 	(() => {
/******/ 		// getDefaultExport function for compatibility with non-harmony modules
/******/ 		__webpack_require__.n = (module) => {
/******/ 			var getter = module && module.__esModule ?
/******/ 				() => (module['default']) :
/******/ 				() => (module);
/******/ 			__webpack_require__.d(getter, { a: getter });
/******/ 			return getter;
/******/ 		};
/******/ 	})();
/******/ 	
/******/ 	/* webpack/runtime/create fake namespace object */
/******/ 	(() => {
/******/ 		var getProto = Object.getPrototypeOf ? (obj) => (Object.getPrototypeOf(obj)) : (obj) => (obj.__proto__);
/******/ 		var leafPrototypes;
/******/ 		// create a fake namespace object
/******/ 		// mode & 1: value is a module id, require it
/******/ 		// mode & 2: merge all properties of value into the ns
/******/ 		// mode & 4: return value when already ns object
/******/ 		// mode & 16: return value when it's Promise-like
/******/ 		// mode & 8|1: behave like require
/******/ 		__webpack_require__.t = function(value, mode) {
/******/ 			if(mode & 1) value = this(value);
/******/ 			if(mode & 8) return value;
/******/ 			if(typeof value === 'object' && value) {
/******/ 				if((mode & 4) && value.__esModule) return value;
/******/ 				if((mode & 16) && typeof value.then === 'function') return value;
/******/ 			}
/******/ 			var ns = Object.create(null);
/******/ 			__webpack_require__.r(ns);
/******/ 			var def = {};
/******/ 			leafPrototypes = leafPrototypes || [null, getProto({}), getProto([]), getProto(getProto)];
/******/ 			for(var current = mode & 2 && value; typeof current == 'object' && !~leafPrototypes.indexOf(current); current = getProto(current)) {
/******/ 				Object.getOwnPropertyNames(current).forEach((key) => (def[key] = () => (value[key])));
/******/ 			}
/******/ 			def['default'] = () => (value);
/******/ 			__webpack_require__.d(ns, def);
/******/ 			return ns;
/******/ 		};
/******/ 	})();
/******/ 	
/******/ 	/* webpack/runtime/define property getters */
/******/ 	(() => {
/******/ 		// define getter functions for harmony exports
/******/ 		__webpack_require__.d = (exports, definition) => {
/******/ 			for(var key in definition) {
/******/ 				if(__webpack_require__.o(definition, key) && !__webpack_require__.o(exports, key)) {
/******/ 					Object.defineProperty(exports, key, { enumerable: true, get: definition[key] });
/******/ 				}
/******/ 			}
/******/ 		};
/******/ 	})();
/******/ 	
/******/ 	/* webpack/runtime/ensure chunk */
/******/ 	(() => {
/******/ 		__webpack_require__.f = {};
/******/ 		// This file contains only the entry chunk.
/******/ 		// The chunk loading function for additional chunks
/******/ 		__webpack_require__.e = (chunkId) => {
/******/ 			return Promise.all(Object.keys(__webpack_require__.f).reduce((promises, key) => {
/******/ 				__webpack_require__.f[key](chunkId, promises);
/******/ 				return promises;
/******/ 			}, []));
/******/ 		};
/******/ 	})();
/******/ 	
/******/ 	/* webpack/runtime/get javascript chunk filename */
/******/ 	(() => {
/******/ 		// This function allow to reference async chunks
/******/ 		__webpack_require__.u = (chunkId) => {
/******/ 			// return url for filenames based on template
/******/ 			return "" + chunkId + ".js";
/******/ 		};
/******/ 	})();
/******/ 	
/******/ 	/* webpack/runtime/global */
/******/ 	(() => {
/******/ 		__webpack_require__.g = (function() {
/******/ 			if (typeof globalThis === 'object') return globalThis;
/******/ 			try {
/******/ 				return this || new Function('return this')();
/******/ 			} catch (e) {
/******/ 				if (typeof window === 'object') return window;
/******/ 			}
/******/ 		})();
/******/ 	})();
/******/ 	
/******/ 	/* webpack/runtime/hasOwnProperty shorthand */
/******/ 	(() => {
/******/ 		__webpack_require__.o = (obj, prop) => (Object.prototype.hasOwnProperty.call(obj, prop))
/******/ 	})();
/******/ 	
/******/ 	/* webpack/runtime/load script */
/******/ 	(() => {
/******/ 		var inProgress = {};
/******/ 		var dataWebpackPrefix = "tts:";
/******/ 		// loadScript function to load a script via script tag
/******/ 		__webpack_require__.l = (url, done, key, chunkId) => {
/******/ 			if(inProgress[url]) { inProgress[url].push(done); return; }
/******/ 			var script, needAttach;
/******/ 			if(key !== undefined) {
/******/ 				var scripts = document.getElementsByTagName("script");
/******/ 				for(var i = 0; i < scripts.length; i++) {
/******/ 					var s = scripts[i];
/******/ 					if(s.getAttribute("src") == url || s.getAttribute("data-webpack") == dataWebpackPrefix + key) { script = s; break; }
/******/ 				}
/******/ 			}
/******/ 			if(!script) {
/******/ 				needAttach = true;
/******/ 				script = document.createElement('script');
/******/ 		
/******/ 				script.charset = 'utf-8';
/******/ 				script.timeout = 120;
/******/ 				if (__webpack_require__.nc) {
/******/ 					script.setAttribute("nonce", __webpack_require__.nc);
/******/ 				}
/******/ 				script.setAttribute("data-webpack", dataWebpackPrefix + key);
/******/ 				script.src = url;
/******/ 			}
/******/ 			inProgress[url] = [done];
/******/ 			var onScriptComplete = (prev, event) => {
/******/ 				// avoid mem leaks in IE.
/******/ 				script.onerror = script.onload = null;
/******/ 				clearTimeout(timeout);
/******/ 				var doneFns = inProgress[url];
/******/ 				delete inProgress[url];
/******/ 				script.parentNode && script.parentNode.removeChild(script);
/******/ 				doneFns && doneFns.forEach((fn) => (fn(event)));
/******/ 				if(prev) return prev(event);
/******/ 			}
/******/ 			;
/******/ 			var timeout = setTimeout(onScriptComplete.bind(null, undefined, { type: 'timeout', target: script }), 120000);
/******/ 			script.onerror = onScriptComplete.bind(null, script.onerror);
/******/ 			script.onload = onScriptComplete.bind(null, script.onload);
/******/ 			needAttach && document.head.appendChild(script);
/******/ 		};
/******/ 	})();
/******/ 	
/******/ 	/* webpack/runtime/make namespace object */
/******/ 	(() => {
/******/ 		// define __esModule on exports
/******/ 		__webpack_require__.r = (exports) => {
/******/ 			if(typeof Symbol !== 'undefined' && Symbol.toStringTag) {
/******/ 				Object.defineProperty(exports, Symbol.toStringTag, { value: 'Module' });
/******/ 			}
/******/ 			Object.defineProperty(exports, '__esModule', { value: true });
/******/ 		};
/******/ 	})();
/******/ 	
/******/ 	/* webpack/runtime/publicPath */
/******/ 	(() => {
/******/ 		var scriptUrl;
/******/ 		if (__webpack_require__.g.importScripts) scriptUrl = __webpack_require__.g.location + "";
/******/ 		var document = __webpack_require__.g.document;
/******/ 		if (!scriptUrl && document) {
/******/ 			if (document.currentScript)
/******/ 				scriptUrl = document.currentScript.src
/******/ 			if (!scriptUrl) {
/******/ 				var scripts = document.getElementsByTagName("script");
/******/ 				if(scripts.length) scriptUrl = scripts[scripts.length - 1].src
/******/ 			}
/******/ 		}
/******/ 		// When supporting browsers where an automatic publicPath is not supported you must specify an output.publicPath manually via configuration
/******/ 		// or pass an empty string ("") and set the __webpack_public_path__ variable from your code to use your own logic.
/******/ 		if (!scriptUrl) throw new Error("Automatic publicPath is not supported in this browser");
/******/ 		scriptUrl = scriptUrl.replace(/#.*$/, "").replace(/\?.*$/, "").replace(/\/[^\/]+$/, "/");
/******/ 		__webpack_require__.p = scriptUrl;
/******/ 	})();
/******/ 	
/******/ 	/* webpack/runtime/jsonp chunk loading */
/******/ 	(() => {
/******/ 		__webpack_require__.b = document.baseURI || self.location.href;
/******/ 		
/******/ 		// object to store loaded and loading chunks
/******/ 		// undefined = chunk not loaded, null = chunk preloaded/prefetched
/******/ 		// [resolve, reject, Promise] = chunk loading, 0 = chunk loaded
/******/ 		var installedChunks = {
/******/ 			"form": 0
/******/ 		};
/******/ 		
/******/ 		__webpack_require__.f.j = (chunkId, promises) => {
/******/ 				// JSONP chunk loading for javascript
/******/ 				var installedChunkData = __webpack_require__.o(installedChunks, chunkId) ? installedChunks[chunkId] : undefined;
/******/ 				if(installedChunkData !== 0) { // 0 means "already installed".
/******/ 		
/******/ 					// a Promise means "currently loading".
/******/ 					if(installedChunkData) {
/******/ 						promises.push(installedChunkData[2]);
/******/ 					} else {
/******/ 						if(true) { // all chunks have JS
/******/ 							// setup Promise in chunk cache
/******/ 							var promise = new Promise((resolve, reject) => (installedChunkData = installedChunks[chunkId] = [resolve, reject]));
/******/ 							promises.push(installedChunkData[2] = promise);
/******/ 		
/******/ 							// start chunk loading
/******/ 							var url = __webpack_require__.p + __webpack_require__.u(chunkId);
/******/ 							// create error before stack unwound to get useful stacktrace later
/******/ 							var error = new Error();
/******/ 							var loadingEnded = (event) => {
/******/ 								if(__webpack_require__.o(installedChunks, chunkId)) {
/******/ 									installedChunkData = installedChunks[chunkId];
/******/ 									if(installedChunkData !== 0) installedChunks[chunkId] = undefined;
/******/ 									if(installedChunkData) {
/******/ 										var errorType = event && (event.type === 'load' ? 'missing' : event.type);
/******/ 										var realSrc = event && event.target && event.target.src;
/******/ 										error.message = 'Loading chunk ' + chunkId + ' failed.\n(' + errorType + ': ' + realSrc + ')';
/******/ 										error.name = 'ChunkLoadError';
/******/ 										error.type = errorType;
/******/ 										error.request = realSrc;
/******/ 										installedChunkData[1](error);
/******/ 									}
/******/ 								}
/******/ 							};
/******/ 							__webpack_require__.l(url, loadingEnded, "chunk-" + chunkId, chunkId);
/******/ 						} else installedChunks[chunkId] = 0;
/******/ 					}
/******/ 				}
/******/ 		};
/******/ 		
/******/ 		// no prefetching
/******/ 		
/******/ 		// no preloaded
/******/ 		
/******/ 		// no HMR
/******/ 		
/******/ 		// no HMR manifest
/******/ 		
/******/ 		// no on chunks loaded
/******/ 		
/******/ 		// install a JSONP callback for chunk loading
/******/ 		var webpackJsonpCallback = (parentChunkLoadingFunction, data) => {
/******/ 			var [chunkIds, moreModules, runtime] = data;
/******/ 			// add "moreModules" to the modules object,
/******/ 			// then flag all "chunkIds" as loaded and fire callback
/******/ 			var moduleId, chunkId, i = 0;
/******/ 			if(chunkIds.some((id) => (installedChunks[id] !== 0))) {
/******/ 				for(moduleId in moreModules) {
/******/ 					if(__webpack_require__.o(moreModules, moduleId)) {
/******/ 						__webpack_require__.m[moduleId] = moreModules[moduleId];
/******/ 					}
/******/ 				}
/******/ 				if(runtime) var result = runtime(__webpack_require__);
/******/ 			}
/******/ 			if(parentChunkLoadingFunction) parentChunkLoadingFunction(data);
/******/ 			for(;i < chunkIds.length; i++) {
/******/ 				chunkId = chunkIds[i];
/******/ 				if(__webpack_require__.o(installedChunks, chunkId) && installedChunks[chunkId]) {
/******/ 					installedChunks[chunkId][0]();
/******/ 				}
/******/ 				installedChunks[chunkId] = 0;
/******/ 			}
/******/ 		
/******/ 		}
/******/ 		
/******/ 		var chunkLoadingGlobal = self["webpackChunktts"] = self["webpackChunktts"] || [];
/******/ 		chunkLoadingGlobal.forEach(webpackJsonpCallback.bind(null, 0));
/******/ 		chunkLoadingGlobal.push = webpackJsonpCallback.bind(null, chunkLoadingGlobal.push.bind(chunkLoadingGlobal));
/******/ 	})();
/******/ 	
/******/ 	/* webpack/runtime/nonce */
/******/ 	(() => {
/******/ 		__webpack_require__.nc = undefined;
/******/ 	})();
/******/ 	
/************************************************************************/
var __webpack_exports__ = {};
// This entry need to be wrapped in an IIFE because it need to be in strict mode.
(() => {
"use strict";
/*!*********************!*\
  !*** ./src/form.js ***!
  \*********************/
__webpack_require__.r(__webpack_exports__);
/* harmony import */ var js_loading_overlay__WEBPACK_IMPORTED_MODULE_0__ = __webpack_require__(/*! js-loading-overlay */ "./node_modules/js-loading-overlay/dist/js-loading-overlay.min.js");
/* harmony import */ var js_loading_overlay__WEBPACK_IMPORTED_MODULE_0___default = /*#__PURE__*/__webpack_require__.n(js_loading_overlay__WEBPACK_IMPORTED_MODULE_0__);
/* harmony import */ var appwrite__WEBPACK_IMPORTED_MODULE_1__ = __webpack_require__(/*! appwrite */ "./node_modules/appwrite/dist/esm/sdk.js");
/* harmony import */ var _styles_css__WEBPACK_IMPORTED_MODULE_2__ = __webpack_require__(/*! ./styles.css */ "./src/styles.css");
/* harmony import */ var js_alert__WEBPACK_IMPORTED_MODULE_3__ = __webpack_require__(/*! js-alert */ "./node_modules/js-alert/lib/index.js");
/* harmony import */ var js_alert__WEBPACK_IMPORTED_MODULE_3___default = /*#__PURE__*/__webpack_require__.n(js_alert__WEBPACK_IMPORTED_MODULE_3__);
/* harmony import */ var _supabase_supabase_js__WEBPACK_IMPORTED_MODULE_4__ = __webpack_require__(/*! @supabase/supabase-js */ "./node_modules/@supabase/supabase-js/dist/module/index.js");

var overlayobj={
  'overlayBackgroundColor': '#FFFFFF',
  'overlayOpacity': 1,
  'spinnerIcon': 'ball-atom',
  'spinnerColor': '#000',
  'spinnerSize': '2x',
  'overlayIDName': 'overlay',
  'spinnerIDName': 'spinner',
}
JsLoadingOverlay.show(overlayobj)
;
const client = new appwrite__WEBPACK_IMPORTED_MODULE_1__.Client();







window.onload=JsLoadingOverlay.hide();

const supabase = (0,_supabase_supabase_js__WEBPACK_IMPORTED_MODULE_4__.createClient)("https://rsfcqodmucagrxohmkgx.supabase.co", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InJzZmNxb2RtdWNhZ3J4b2hta2d4Iiwicm9sZSI6InNlcnZpY2Vfcm9sZSIsImlhdCI6MTY2MDkyNjk0OSwiZXhwIjoxOTc2NTAyOTQ5fQ.8PZmvfHrTPVNheNjYHyJJS2jZC5EjCIlOkQK3t2Tvwc");
if (supabase.auth.user()) {
  document.getElementById("formie").classList.remove("hidden");
  document.getElementById("notlogged").classList.add("hidden");
} else {
  document.getElementById("formie").classList.add("hidden");
  document.getElementById("notlogged").classList.remove("hidden");
  JsLoadingOverlay.hide()

  document.getElementById("lex").innerHTML = "Not Logged In";
  document.getElementById("leximage").classList.add('hidden');
  
}

var arr = [];

var queryString = decodeURIComponent(window.location.search);
queryString = queryString.substring(1);
var queries = queryString.split("&");
var id = queries[0].slice(queries[0].indexOf("=") + 1);
var table = queries[1].slice(queries[1].indexOf("=") + 1);

function addDate(c) {
  var cb = toUpper(c.replaceAll("_", " "));
  var a = `<div class="col-span-6 sm:col-span-3 w-auto py-2 ">
  <label for="${c}" class="block text-sm font-medium text-gray-700 pt-4 mb-1">${cb}</label>
  <input type="date" id="${c}" autocomplete="given-name" class=" focus:ring-blue-500  focus:border-blue-500 block w-full shadow-sm sm:text-sm border border-neutral-200 py-2 px-3 outline-none">
</div>`;
  document.getElementById("elelist").insertAdjacentHTML("afterbegin", a);
  arr.push(c);
}

function toUpper(str) {
  return str
    .toLowerCase()
    .split(" ")
    .map(function (word) {
      return word[0].toUpperCase() + word.substr(1);
    })
    .join(" ");
}

function addVal(c) {
  var cb = toUpper(c.replaceAll("_", " "));
  var a = `<div class="col-span-6 sm:col-span-3 w-auto py-2 ">
  <label for="${c}" class="block text-sm font-medium text-gray-700 pt-4 mb-1">${cb}</label>
  <input type="text" id="${c}" autocomplete="given-name" class=" focus:ring-blue-500  focus:border-blue-500 block w-full shadow-sm sm:text-sm border border-neutral-200 py-2 px-3 outline-none">
</div>`;
  document.getElementById("elelist").insertAdjacentHTML("afterbegin", a);
  arr.push(c);
}

function addLvl(c) {
  var cb = toUpper(c.replaceAll("_", " "));
  var a = `<div class="col-span-6 sm:col-span-3 w-auto py-2 ">
  <label for="${c}" class="block text-sm font-medium text-gray-700 pt-4 mb-1">${cb}</label>
  <select for="${c}" id=${c}>
  <option value="1">1</option>
  <option value="2">2</option>
  <option value="3">3</option>
  </select>
</div>`;
  document.getElementById("elelist").insertAdjacentHTML("afterbegin", a);
  arr.push(c);
}

function addClass(c) {
  var cb = toUpper(c.replaceAll("_", " "));
  var a = `<div class="col-span-6 sm:col-span-3 w-auto py-2 ">
  <label for="${c}" class="block text-sm font-medium text-gray-700 pt-4 mb-1">${cb}</label>
  <select for="${c}" id=${c}>
  <option value="1">1</option>
  <option value="2">2</option>
  <option value="3">3</option>
  <option value="4">4</option>
  <option value="5">5</option>
  <option value="6">6</option>
  <option value="7">7</option>
  <option value="8">8</option>
  <option value="9">9</option>
  <option value="10">10</option>
  <option value="11">11</option>
  <option value="12">12</option>
  </select>
</div>`;
  document.getElementById("elelist").insertAdjacentHTML("afterbegin", a);
  arr.push(c);
}

function addSec(c) {
  var cb = toUpper(c.replaceAll("_", " "));
  var a = `<div class="col-span-6 sm:col-span-3 w-auto py-2 ">
  <label for="${c}" class="block text-sm font-medium text-gray-700 pt-4 mb-1">${cb}</label>
  <select for="${c}" id=${c}>
  <option value="A">A</option>
  <option value="B">B</option>
  <option value="C">C</option>
  <option value="D">D</option>
  <option value="E">E</option>
  <option value="F">F</option>
  <option value="G">G</option>
  <option value="H">H</option>
  <option value="I">I</option>
  </select>
</div>`;
  document.getElementById("elelist").insertAdjacentHTML("afterbegin", a);
  arr.push(c);
}

function addMonth(c) {
  var cb = toUpper(c.replaceAll("_", " "));
  var a = `<div class="col-span-6 sm:col-span-3 w-auto py-2 ">
  <label for="${c}" class="block text-sm font-medium text-gray-700 pt-4 mb-1">${cb}</label>
  <select for="${c}" id=${c}>
  <option value="1">1</option>
  <option value="2">2</option>
  <option value="3">3</option>
  <option value="4">4</option>
  <option value="5">5</option>
  <option value="6">6</option>
  <option value="7">7</option>
  <option value="8">8</option>
  <option value="9">9</option>
  <option value="10">10</option>
  <option value="11">11</option>
  <option value="12">12</option>
  </select>
</div>`;
  document.getElementById("elelist").insertAdjacentHTML("afterbegin", a);
  arr.push(c);
}

async function sr() {
  JsLoadingOverlay.show(overlayobj);

  const { data, error } = await supabase.from("Forms").select();
  JsLoadingOverlay.hide();

  
if(typeof data[id-1] !== 'undefined' && data[id-1].hasOwnProperty('title')){
  document.getElementById("title").innerHTML = data[id-1].title;
  document.getElementById("description").innerHTML = data[id-1].description;
}
else{
  document.getElementById('formie').classList.add('hidden')
  document.getElementById('notlogged').classList.add('hidden')
  var alert = new (js_alert__WEBPACK_IMPORTED_MODULE_3___default())("The form you tried to access does not exist",null, (js_alert__WEBPACK_IMPORTED_MODULE_3___default().Icons.Failed));

  alert.addButton("Go Back").then(function() {
    window.location.href='forms.html';
});
alert.show()
}
   
}
sr();

function onsubmitted() {
  document.getElementById("formie").classList.add("hidden");
  document.getElementById("notlogged").classList.remove("hidden");
  document.getElementById("lex").innerHTML = "Already Submitted";
  document.getElementById("leximage").classList.remove('hidden')
}
async function getfields(){
  var brr=[];
  

  let { data, error } = await supabase
  .rpc('xdesc', {t:table})
  JsLoadingOverlay.hide();

  
  if(error) console.log(error)
  
  
  for (let noice in data){
    brr.push(data[noice].column_name)
  }
  
  
  brr.pop();
  brr.reverse();

  return brr;

}


async function fetchdata() {
  JsLoadingOverlay.show(overlayobj);

  const { data, error } = await supabase.from(table).select();

  for (let i in data) {
    if (data[i].uid == window.localStorage.getItem("email")) {
      onsubmitted();
    }
  }

var brr=await getfields()



// console.log(brr)
  
  for (let i in brr) {
    let c = brr[i];
    switch (c) {
      case "level":
        addLvl(c);
        break;
      case "month":
        addMonth(c);
        break;
      case "class":
        addClass(c);
        break;
      case "section":
        addSec(c);
        break;
      case "date":
        addDate(c)
        break;
      default:
        addVal(c);
    }
  }

  async function pushdata() {
    const { data, error } = await supabase.from(table).select();
    var obj = {
      uid: window.localStorage.getItem("email"),
    };

    var brr=await getfields()
    
    brr.reverse();
    console.log(brr)
    var failed;
    for (let i in brr) {
      if(document.getElementById(brr[i]).value!=''){
      obj[brr[i]] = document.getElementById(brr[i]).value
      failed=0
      }
      else{
        js_alert__WEBPACK_IMPORTED_MODULE_3___default().alert('All Fields are required',null, (js_alert__WEBPACK_IMPORTED_MODULE_3___default().Icons.Failed))
        failed=1
        break;
      }
    }

if(failed==0){
  JsLoadingOverlay.show(overlayobj);

    supabase
      .from(table)
      .insert(obj)
      .then((d) => {
        JsLoadingOverlay.hide();
        document.getElementById("formie").classList.add("hidden");
      document.getElementById("notlogged").classList.remove("hidden");
      document.getElementById("lex").innerHTML = "Submitted Successfully";
      document.getElementById("leximage").classList.remove('hidden');
      var alert = new (js_alert__WEBPACK_IMPORTED_MODULE_3___default())("Your data has been submitted to our server. Only those with admin access can view it",null, (js_alert__WEBPACK_IMPORTED_MODULE_3___default().Icons.Success));

      alert.addButton("Go Back").then(function() {
        window.location.href='forms.html';
    });
    alert.show()
      })
      .catch((e)=>{
        js_alert__WEBPACK_IMPORTED_MODULE_3___default().alert(e,null,(js_alert__WEBPACK_IMPORTED_MODULE_3___default().Icons.Failed))
      })
    }
  }
  document.getElementById("submit").addEventListener("click", (e) => {
    e.preventDefault();
    pushdata();

    return false;
  });

  return false;
}

fetchdata();

window.addDate = addDate;
window.addVal = addVal;

})();

/******/ })()
;
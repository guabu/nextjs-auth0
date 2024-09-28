import { NextResponse, type NextRequest } from "next/server"
import * as oauth from "oauth4webapi"

import {
  AbstractSessionStore,
  SessionData,
  TokenSet,
} from "./session/abstract-session-store"
import { TransactionState, TransactionStore } from "./transaction-store"
import { filterClaims } from "./user"

export type BeforeSessionSavedHook = (user: {
  [key: string]: any
}) => Promise<Pick<SessionData, "user" | "metadata">>

// params passed to the /authorize endpoint that cannot be overwritten
const INTERNAL_AUTHORIZE_PARAMS = [
  "client_id",
  "redirect_uri",
  "response_type",
  "code_challenge",
  "code_challenge_method",
  "state",
  "nonce",
]

export interface AuthClientOptions {
  transactionStore: TransactionStore
  sessionStore: AbstractSessionStore

  domain: string
  clientId: string
  clientSecret: string
  scopes: string[]
  maxAge?: number

  secret: string
  appBaseUrl: string
  signInReturnToPath: string

  beforeSessionSaved?: BeforeSessionSavedHook
}

export class AuthClient {
  private transactionStore: TransactionStore
  private sessionStore: AbstractSessionStore

  private clientMetadata: oauth.Client
  private issuer: string
  private redirectUri: URL
  private scopes: string[]
  private maxAge?: number

  private appBaseUrl: string
  private signInReturnToPath: string

  private beforeSessionSaved?: BeforeSessionSavedHook

  constructor(options: AuthClientOptions) {
    // stores
    this.transactionStore = options.transactionStore
    this.sessionStore = options.sessionStore

    // authorization server
    this.issuer = `https://${options.domain}`
    this.clientMetadata = {
      client_id: options.clientId,
      client_secret: options.clientSecret,
    }
    this.redirectUri = new URL("/auth/callback", options.appBaseUrl) // must be registed with the authorization server
    this.scopes = options.scopes
    this.maxAge = options.maxAge

    // application
    this.appBaseUrl = options.appBaseUrl
    this.signInReturnToPath = options.signInReturnToPath

    // hooks
    this.beforeSessionSaved = options.beforeSessionSaved
  }

  async handler(req: NextRequest) {
    const { pathname } = req.nextUrl
    const method = req.method

    if (method === "GET" && pathname === "/auth/login") {
      return this.handleLogin(req)
    } else if (method === "GET" && pathname === "/auth/logout") {
      return this.handleLogout(req)
    } else if (method === "GET" && pathname === "/auth/callback") {
      return this.handleCallback(req)
    } else if (method === "GET" && pathname === "/auth/profile") {
      return this.handleProfile(req)
    } else if (method === "GET" && pathname === "/auth/access-token") {
      return this.handleAccessToken(req)
    } else {
      // no auth handler found, simply touch the sessions
      const res = NextResponse.next()
      const session = await this.sessionStore.get(req.cookies)

      if (session) {
        // refresh the access token, if necessary, passing the existing `iat` claim
        // to update the cookie's `maxAge`
        const updatedTokenSet = await this.getTokenSet(session.tokenSet)

        // we pass the existing session (containing an `iat` claim) to the set method
        // which will update the cookie's `maxAge` property based on the `iat` time
        await this.sessionStore.set(req.cookies, res.cookies, {
          ...session,
          tokenSet: updatedTokenSet,
        })
      }

      return res
    }
  }

  async handleLogin(req: NextRequest) {
    const authorizationServerMetadata =
      await this.discoverAuthorizationServerMetadata()

    const returnTo =
      req.nextUrl.searchParams.get("returnTo") || this.signInReturnToPath

    const codeChallengeMethod = "S256"
    const codeVerifier = oauth.generateRandomCodeVerifier()
    const codeChallenge = await oauth.calculatePKCECodeChallenge(codeVerifier)
    const state = oauth.generateRandomState()
    const nonce = oauth.generateRandomNonce()

    const authorizationUrl = new URL(
      authorizationServerMetadata.authorization_endpoint!
    )
    authorizationUrl.searchParams.set(
      "client_id",
      this.clientMetadata.client_id
    )
    authorizationUrl.searchParams.set(
      "redirect_uri",
      this.redirectUri.toString()
    )
    authorizationUrl.searchParams.set("response_type", "code")
    authorizationUrl.searchParams.set("scope", this.scopes.join(" "))
    authorizationUrl.searchParams.set("code_challenge", codeChallenge)
    authorizationUrl.searchParams.set(
      "code_challenge_method",
      codeChallengeMethod
    )
    authorizationUrl.searchParams.set("state", state)
    authorizationUrl.searchParams.set("nonce", nonce)

    if (this.maxAge !== undefined) {
      authorizationUrl.searchParams.set("max_age", this.maxAge.toString())
    }

    // any custom params to forward to /authorize
    req.nextUrl.searchParams.forEach((val, key) => {
      if (!INTERNAL_AUTHORIZE_PARAMS.includes(key)) {
        authorizationUrl.searchParams.set(key, val)
      }
    })

    const transactionState: TransactionState = {
      nonce,
      maxAge: this.maxAge,
      codeVerifier: codeVerifier,
      responseType: "code",
      state,
      returnTo,
    }

    const res = NextResponse.redirect(authorizationUrl.toString())
    await this.transactionStore.save(res.cookies, transactionState)

    return res
  }

  async handleLogout(req: NextRequest) {
    const session = await this.sessionStore.get(req.cookies)
    const authorizationServerMetadata =
      await this.discoverAuthorizationServerMetadata()

    const url = new URL(authorizationServerMetadata.end_session_endpoint!)
    url.searchParams.set("client_id", this.clientMetadata.client_id)
    url.searchParams.set("post_logout_redirect_uri", this.appBaseUrl)

    if (session?.internal.sid) {
      url.searchParams.set("logout_hint", session.internal.sid)
    }

    const res = NextResponse.redirect(url)
    await this.sessionStore.delete(req.cookies, res.cookies)

    return res
  }

  async handleCallback(req: NextRequest) {
    const state = req.nextUrl.searchParams.get("state")
    if (!state) {
      throw new Error("The state parameter is missing.")
    }

    const transactionState = await this.transactionStore.get(req.cookies, state)
    if (!transactionState) {
      throw new Error("The transaction state could not be found.")
    }

    const res = NextResponse.redirect(
      new URL(transactionState.returnTo, this.appBaseUrl)
    )
    this.transactionStore.delete(res.cookies, state)

    const authorizationServerMetadata =
      await this.discoverAuthorizationServerMetadata()

    const codeGrantParams = oauth.validateAuthResponse(
      authorizationServerMetadata,
      this.clientMetadata,
      req.nextUrl.searchParams,
      transactionState.state
    )

    if (oauth.isOAuth2Error(codeGrantParams)) {
      // TODO: we should sanitize and expose this error to the developer
      throw new Error("OAuth2 error")
    }

    const codeGrantResponse = await oauth.authorizationCodeGrantRequest(
      authorizationServerMetadata,
      this.clientMetadata,
      codeGrantParams,
      this.redirectUri.toString(),
      transactionState.codeVerifier
    )

    const oidcRes = await oauth.processAuthorizationCodeOpenIDResponse(
      authorizationServerMetadata,
      this.clientMetadata,
      codeGrantResponse,
      transactionState.nonce,
      transactionState.maxAge
    )

    if (oauth.isOAuth2Error(oidcRes)) {
      throw new Error("OAuth2 error")
    }

    const idTokenClaims = oauth.getValidatedIdTokenClaims(oidcRes)
    let session: SessionData = {
      user: filterClaims(idTokenClaims),
      metadata: {},
      tokenSet: {
        accessToken: oidcRes.access_token,
        refreshToken: oidcRes.refresh_token,
        expiresAt: Math.floor(Date.now() / 1000) + Number(oidcRes.expires_in),
      },
      internal: {
        sid: idTokenClaims.sid as string,
      },
    }

    if (this.beforeSessionSaved) {
      const { user, metadata } = await this.beforeSessionSaved(idTokenClaims)
      session.user = user || {}
      session.metadata = metadata || {}
    }

    await this.sessionStore.set(req.cookies, res.cookies, session)

    return res
  }

  async handleProfile(req: NextRequest) {
    const session = await this.sessionStore.get(req.cookies)

    if (!session) {
      return new NextResponse(null, {
        status: 401,
      })
    }

    return NextResponse.json(session?.user)
  }

  async handleAccessToken(req: NextRequest) {
    const session = await this.sessionStore.get(req.cookies)

    if (!session) {
      return NextResponse.json(
        {
          error: "You are not authenticated.",
        },
        {
          status: 401,
        }
      )
    }

    const updatedTokenSet = await this.getTokenSet(session.tokenSet)

    const res = NextResponse.json({
      token: updatedTokenSet.accessToken,
      expires_at: updatedTokenSet.expiresAt,
    })

    await this.sessionStore.set(req.cookies, res.cookies, {
      ...session,
      tokenSet: updatedTokenSet,
    })

    return res
  }

  /**
   * getTokenSet returns a valid token set. If the access token has expired, it will attempt to
   * refresh it using the refresh token, if available.
   */
  async getTokenSet(tokenSet: TokenSet): Promise<TokenSet> {
    // the access token has expired but we do not have a refresh token
    if (!tokenSet.refreshToken && tokenSet.expiresAt < Date.now() / 1000) {
      throw new Error(
        "The access token has expired and a refresh token was not granted."
      )
    }

    // the access token has expired and we have a refresh token
    if (tokenSet.refreshToken && tokenSet.expiresAt < Date.now() / 1000) {
      const authorizationServerMetadata =
        await this.discoverAuthorizationServerMetadata()
      const refreshTokenRes = await oauth.refreshTokenGrantRequest(
        authorizationServerMetadata,
        this.clientMetadata,
        tokenSet.refreshToken
      )
      const oauthRes = await oauth.processRefreshTokenResponse(
        authorizationServerMetadata,
        this.clientMetadata,
        refreshTokenRes
      )

      if (oauth.isOAuth2Error(oauthRes)) {
        throw new Error("OAuth2 error")
      }

      const accessTokenExpiresAt =
        Math.floor(Date.now() / 1000) + Number(oauthRes.expires_in)

      let updatedTokenSet = {
        ...tokenSet, // contains the existing `iat` claim to maintain the session lifetime
        accessToken: oauthRes.access_token,
        expiresAt: accessTokenExpiresAt,
      }

      if (oauthRes.refresh_token) {
        // refresh token rotation is enabled, persist the new refresh token from the response
        updatedTokenSet.refreshToken = oauthRes.refresh_token
      } else {
        // we did not get a refresh token back, keep the current long-lived refresh token around
        updatedTokenSet.refreshToken = tokenSet.refreshToken
      }

      return updatedTokenSet
    }

    return tokenSet
  }

  private async discoverAuthorizationServerMetadata() {
    const issuer = new URL(this.issuer)

    try {
      const authorizationServerMetadata = await oauth
        .discoveryRequest(issuer)
        .then((response) => oauth.processDiscoveryResponse(issuer, response))

      return authorizationServerMetadata
    } catch (e) {
      throw new Error("Failed to discover the authorization server.")
    }
  }
}

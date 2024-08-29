import { NextResponse, type NextRequest } from "next/server"
import * as oauth from "oauth4webapi"

import { Session, SessionStore } from "./session-store"
import { TokenStore } from "./token-store"
import { TransactionState, TransactionStore } from "./transaction-store"

const DEFAULT_ALLOWED_CLAIMS = [
  "sub",
  "name",
  "nickname",
  "given_name",
  "family_name",
  "picture",
  "email",
  "email_verified",
  "org_id",
]

export type BeforeSessionCreatedHook = (user: {
  [key: string]: any
}) => Promise<Pick<Session, "user" | "data">>

export interface AuthHandlerOptions {
  domain: string
  clientId: string
  clientSecret: string
  scopes: string[]
  maxAge?: number

  secret: string
  appBaseUrl: string
  signInReturnToPath: string

  beforeSessionCreated?: BeforeSessionCreatedHook
}

export class AuthHandler {
  private transactionStore: TransactionStore
  private sessionStore: SessionStore
  private tokenStore: TokenStore

  private clientMetadata: oauth.Client
  private issuer: string
  private redirectUri: URL
  private scopes: string[]
  private maxAge?: number

  private appBaseUrl: string
  private signInReturnToPath: string

  private beforeSessionCreated?: BeforeSessionCreatedHook

  constructor(options: AuthHandlerOptions) {
    this.transactionStore = new TransactionStore({
      appBaseUrl: options.appBaseUrl,
      secret: options.secret,
    })

    this.sessionStore = new SessionStore({
      appBaseUrl: options.appBaseUrl,
      secret: options.secret,
    })

    this.tokenStore = new TokenStore({
      appBaseUrl: options.appBaseUrl,
      secret: options.secret,
    })

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
    this.beforeSessionCreated = options.beforeSessionCreated
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
    } else {
      return NextResponse.next()
    }
  }

  async handleLogin(req: NextRequest): Promise<Response> {
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

    const transactionState: TransactionState = {
      nonce,
      maxAge: this.maxAge,
      codeVerifier: codeVerifier,
      responseType: "code",
      state,
      returnTo,
    }

    const res = NextResponse.redirect(authorizationUrl.toString())
    await this.transactionStore.save(res, transactionState)

    return res
  }

  async handleLogout(req: NextRequest) {
    const session = await this.sessionStore.get(req)
    const authorizationServerMetadata =
      await this.discoverAuthorizationServerMetadata()

    const url = new URL(authorizationServerMetadata.end_session_endpoint!)
    url.searchParams.set("client_id", this.clientMetadata.client_id)
    url.searchParams.set("post_logout_redirect_uri", this.appBaseUrl)

    if (session?.internal.sid) {
      url.searchParams.set("logout_hint", session.internal.sid)
    }

    const res = NextResponse.redirect(url)
    await this.sessionStore.delete(res)
    await this.tokenStore.delete(res)

    return res
  }

  async handleCallback(req: NextRequest) {
    const state = req.nextUrl.searchParams.get("state")
    if (!state) {
      throw new Error("The state parameter is missing.")
    }

    const transactionState = await this.transactionStore.get(req, state)
    if (!transactionState) {
      throw new Error("The transaction state could not be found.")
    }

    const res = NextResponse.redirect(
      new URL(transactionState.returnTo, this.appBaseUrl)
    )
    this.transactionStore.delete(res, state)

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
    let session: Session = {
      user: this.filterClaims(idTokenClaims),
      data: {},
      internal: {
        sid: idTokenClaims.sid as string,
      },
    }

    if (this.beforeSessionCreated) {
      const { user, data } = await this.beforeSessionCreated(idTokenClaims)
      session.user = user || {}
      session.data = data || {}
    }

    await this.sessionStore.save(res, session)
    await this.tokenStore.save(res, {
      accessToken: oidcRes.access_token,
      refreshToken: oidcRes.refresh_token,
      expiresAt: Math.floor(Date.now() / 1000) + Number(oidcRes.expires_in),
    })

    return res
  }

  async handleProfile(req: NextRequest) {
    const session = await this.sessionStore.get(req)

    if (!session) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 })
    }

    return NextResponse.json(session?.user)
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

  private filterClaims(claims: { [key: string]: any }) {
    return Object.keys(claims).reduce(
      (acc, key) => {
        if (DEFAULT_ALLOWED_CLAIMS.includes(key)) {
          acc[key] = claims[key]
        }
        return acc
      },
      {} as { [key: string]: any }
    )
  }
}

import { cookies } from "next/headers"
import { NextRequest, NextResponse } from "next/server"
import { NextApiRequest } from "next/types"

import {
  AuthClient,
  BeforeSessionSavedHook,
  OnCallbackHook,
} from "./auth-client"
import { RequestCookies } from "./cookies"
import {
  AbstractSessionStore,
  SessionConfiguration,
  SessionData,
} from "./session/abstract-session-store"
import {
  SessionStore,
  StatefulSessionStore,
} from "./session/stateful-session-store"
import { StatelessSessionStore } from "./session/stateless-session-store"
import { TransactionStore } from "./transaction-store"

interface Auth0ClientOptions {
  // authorization server configuration
  domain?: string
  clientId?: string
  clientSecret?: string
  scopes?: string[]
  maxAge?: number

  // application configuration
  appBaseUrl?: string
  secret?: string
  signInReturnToPath?: string

  // session configuration
  session?: SessionConfiguration

  // hooks
  beforeSessionSaved?: BeforeSessionSavedHook
  onCallback?: OnCallbackHook

  // provide a session store to persist sessions in your own data store
  sessionStore?: SessionStore
}

type PagesRouterRequest = Pick<NextApiRequest, "headers">

export class Auth0Client {
  private transactionStore: TransactionStore
  private sessionStore: AbstractSessionStore
  private authClient: AuthClient

  constructor(options: Auth0ClientOptions = {}) {
    const domain = options.domain || process.env.AUTH0_DOMAIN
    const clientId = options.clientId || process.env.AUTH0_CLIENT_ID
    const clientSecret = options.clientSecret || process.env.AUTH0_CLIENT_SECRET
    const scopes = options.scopes || [
      "openid",
      "profile",
      "email",
      "offline_access",
    ]
    const maxAge = options.maxAge

    const appBaseUrl = options.appBaseUrl || process.env.APP_BASE_URL
    const secret = options.secret || process.env.AUTH0_SECRET
    const signInReturnToPath =
      options.signInReturnToPath || process.env.SIGN_IN_RETURN_TO_PATH || "/"

    // TODO: update docs links to specific pages where the options are documented
    if (!domain) {
      throw new Error(
        "The AUTH0_DOMAIN environment variable or domain option is required. See https://auth0.com/docs"
      )
    }

    if (!clientId) {
      throw new Error(
        "The AUTH0_CLIENT_ID environment variable or clientId option is required. See https://auth0.com/docs"
      )
    }

    if (!clientSecret) {
      throw new Error(
        "The AUTH0_CLIENT_SECRET environment variable or clientSecret option is required. See https://auth0.com/docs"
      )
    }

    if (!secret) {
      throw new Error(
        "The AUTH0_SECRET environment variable or secret option is required. See https://auth0.com/docs"
      )
    }

    if (!appBaseUrl) {
      throw new Error(
        "The APP_BASE_URL environment variable or appBaseUrl option is required. See https://auth0.com/docs"
      )
    }

    if (!scopes.includes("openid")) {
      throw new Error(
        "The 'openid' must be included in the set of scopes. See https://auth0.com/docs"
      )
    }

    const { protocol } = new URL(appBaseUrl)
    if (protocol !== "https:" && process.env.NODE_ENV === "production") {
      throw new Error(
        "The appBaseUrl must use the HTTPS protocol in production. See https://auth0.com/docs"
      )
    }

    this.transactionStore = new TransactionStore({
      ...options.session,
      secret,
    })

    this.sessionStore = options.sessionStore
      ? new StatefulSessionStore({
        ...options.session,
        secret,
        store: options.sessionStore,
      })
      : new StatelessSessionStore({
        ...options.session,
        secret,
      })

    this.authClient = new AuthClient({
      transactionStore: this.transactionStore,
      sessionStore: this.sessionStore,

      domain,
      clientId,
      clientSecret,
      scopes,
      maxAge,

      appBaseUrl,
      secret,
      signInReturnToPath,

      beforeSessionSaved: options.beforeSessionSaved,
      onCallback: options.onCallback,
    })
  }

  handler() {
    return this.authClient.handler.bind(this.authClient)
  }

  middleware(req: NextRequest): Promise<NextResponse> {
    return this.authClient.handler.bind(this.authClient)(req)
  }

  /**
   * getSession returns the session data for the current request.
   * This method can be used in Server Actions, Route Handlers, and RSCs in the App Router.
   */
  async getSession(): Promise<SessionData | null>

  /**
   * getSession returns the session data for the current request.
   * This method can be used in the Pages Router.
   */
  async getSession(req: PagesRouterRequest): Promise<SessionData | null>

  /**
   * getSession returns the session data for the current request.
   */
  async getSession(req?: PagesRouterRequest): Promise<SessionData | null> {
    if (req) {
      return this.sessionStore.get(this.createRequestCookies(req))
    }

    return this.sessionStore.get(await cookies())
  }

  /**
   * getAccessToken returns the access token.
   * This method can be used in Server Actions and Route Handlers.
   */
  async getAccessToken(): Promise<{ token: string; expiresAt: number }>

  /**
   * getAccessToken returns the access token.
   * This method can be used in the Pages router.
   */
  async getAccessToken(
    req: PagesRouterRequest
  ): Promise<{ token: string; expiresAt: number }>

  /**
   * getAccessToken returns the access token.
   */
  async getAccessToken(req?: PagesRouterRequest) {
    let session: SessionData | null = null

    if (req) {
      session = await this.sessionStore.get(this.createRequestCookies(req))
    } else {
      session = await this.sessionStore.get(await cookies())
    }

    if (!session) {
      return null
    }

    return {
      token: session.tokenSet.accessToken,
      expiresAt: session.tokenSet.expiresAt,
    }
  }

  private createRequestCookies(req: PagesRouterRequest) {
    const headers = new Headers()

    for (const key in req.headers) {
      if (Array.isArray(req.headers[key])) {
        for (const value of req.headers[key]) {
          headers.append(key, value)
        }
      } else {
        headers.append(key, req.headers[key] ?? "")
      }
    }

    return new RequestCookies(headers)
  }
}

import { cookies } from "next/headers"

import { AuthClient, BeforeSessionSavedHook } from "./auth-client"
import { TokenStore } from "./token-store"
import { TransactionStore } from "./transaction-store"
import { StatelessSessionStore } from "./session/stateless-session-store"
import { SessionStore, StatefulSessionStore } from "./session/stateful-session-store"
import { AbstractSessionStore, SessionData } from "./session/abstract-session-store"

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

  // hooks
  beforeSessionSaved?: BeforeSessionSavedHook

  // provide a session store to persist sessions in your own data store
  sessionStore?: SessionStore
}

export class Auth0Client {
  private transactionStore: TransactionStore
  private sessionStore: AbstractSessionStore
  private tokenStore: TokenStore
  private authClient: AuthClient

  constructor(options: Auth0ClientOptions) {
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
      secret,
    })

    this.sessionStore = options.sessionStore ?
      new StatefulSessionStore({
        secret,
        store: options.sessionStore,
      })
      : new StatelessSessionStore({
        secret,
      })

    this.tokenStore = new TokenStore({
      secret,
    })

    this.authClient = new AuthClient({
      transactionStore: this.transactionStore,
      sessionStore: this.sessionStore,
      tokenStore: this.tokenStore,

      domain,
      clientId,
      clientSecret,
      scopes,
      maxAge,

      appBaseUrl,
      secret,
      signInReturnToPath,

      beforeSessionSaved: options.beforeSessionSaved,
    })
  }

  handler() {
    return this.authClient.handler.bind(this.authClient)
  }

  /**
   * getSession returns the session data for the current request.
   * This method can be used in Server Actions, Route Handlers, and RSCs in the App Router.
   */
  async getSession(): Promise<SessionData | null> {
    return this.sessionStore.get(cookies())
  }

  /**
   * updateSessionData updates the current session's data.
   * This method can be used in Server Actions and Route Handlers.
   */
  async updateSessionData(data: { [key: string]: any }) {
    const session = await this.sessionStore.get(cookies())

    if (!session) {
      throw new Error("No session found.")
    }

    await this.sessionStore.set(cookies(), cookies(), {
      ...session,
      data,
    })
  }

  /**
   * getAccessToken returns the access token.
   */
  async getAccessToken() {
    const tokenSet = await this.tokenStore.get(cookies())

    if (!tokenSet) {
      throw new Error("Token set does not exist or you are not authenticated.")
    }

    return {
      token: tokenSet.accessToken,
      expiresAt: tokenSet.expiresAt
    }
  }
}

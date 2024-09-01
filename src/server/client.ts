import { AuthHandler, BeforeSessionCreatedHook } from "./auth-handler"
import { SessionStore } from "./session-store"
import { TokenStore } from "./token-store"
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

  // hooks
  beforeSessionCreated?: BeforeSessionCreatedHook
}

export class Auth0Client {
  private transactionStore: TransactionStore
  private sessionStore: SessionStore
  private tokenStore: TokenStore
  private router: AuthHandler

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

    const beforeSessionCreated = options.beforeSessionCreated

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

    this.sessionStore = new SessionStore({
      secret,
    })

    this.tokenStore = new TokenStore({
      secret,
    })

    this.router = new AuthHandler({
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

      beforeSessionCreated,
    })
  }

  handler() {
    return this.router.handler.bind(this.router)
  }
}

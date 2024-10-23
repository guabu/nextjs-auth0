import { NextRequest } from "next/server"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

import { generateSecret } from "../test/utils"
import { AuthClient } from "./auth-client"
import { decrypt, encrypt, RequestCookies, ResponseCookies } from "./cookies"
import { StatelessSessionStore } from "./session/stateless-session-store"
import { TransactionStore } from "./transaction-store"

describe("Authentication Client", async () => {
  describe("initialization", async () => {
    it("should throw an error if the openid scope is not included", async () => {
      const secret = await generateSecret(32)
      const transactionStore = new TransactionStore({
        secret,
      })
      const sessionStore = new StatelessSessionStore({
        secret,
      })

      expect(
        () =>
          new AuthClient({
            transactionStore,
            sessionStore,

            domain: "guabu.us.auth0.com",
            clientId: "123",
            clientSecret: "123",

            secret,
            appBaseUrl: "https://example.com",

            authorizationParameters: {
              scope: "profile email",
            },
          })
      ).toThrowError()
    })
  })

  describe("handler", async () => {
    it("should call the login handler if the path is /auth/login", async () => {
      const secret = await generateSecret(32)
      const transactionStore = new TransactionStore({
        secret,
      })
      const sessionStore = new StatelessSessionStore({
        secret,
      })
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: "guabu.us.auth0.com",
        clientId: "123",
        clientSecret: "123",

        secret,
        appBaseUrl: "https://example.com",
      })
      const request = new NextRequest("https://example.com/auth/login", {
        method: "GET",
      })
      authClient.handleLogin = vi.fn()
      await authClient.handler(request)
      expect(authClient.handleLogin).toHaveBeenCalled()
    })

    it("should call the callback handler if the path is /auth/callback", async () => {
      const secret = await generateSecret(32)
      const transactionStore = new TransactionStore({
        secret,
      })
      const sessionStore = new StatelessSessionStore({
        secret,
      })
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: "guabu.us.auth0.com",
        clientId: "123",
        clientSecret: "123",

        secret,
        appBaseUrl: "https://example.com",
      })
      const request = new NextRequest("https://example.com/auth/callback", {
        method: "GET",
      })
      authClient.handleCallback = vi.fn()
      await authClient.handler(request)
      expect(authClient.handleCallback).toHaveBeenCalled()
    })

    it("should call the logout handler if the path is /auth/logout", async () => {
      const secret = await generateSecret(32)
      const transactionStore = new TransactionStore({
        secret,
      })
      const sessionStore = new StatelessSessionStore({
        secret,
      })
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: "guabu.us.auth0.com",
        clientId: "123",
        clientSecret: "123",

        secret,
        appBaseUrl: "https://example.com",
      })
      const request = new NextRequest("https://example.com/auth/logout", {
        method: "GET",
      })
      authClient.handleLogout = vi.fn()
      await authClient.handler(request)
      expect(authClient.handleLogout).toHaveBeenCalled()
    })

    it("should call the profile handler if the path is /auth/profile", async () => {
      const secret = await generateSecret(32)
      const transactionStore = new TransactionStore({
        secret,
      })
      const sessionStore = new StatelessSessionStore({
        secret,
      })
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: "guabu.us.auth0.com",
        clientId: "123",
        clientSecret: "123",

        secret,
        appBaseUrl: "https://example.com",
      })
      const request = new NextRequest("https://example.com/auth/profile", {
        method: "GET",
      })
      authClient.handleProfile = vi.fn()
      await authClient.handler(request)
      expect(authClient.handleProfile).toHaveBeenCalled()
    })

    it("should call the access token handler if the path is /auth/access-token", async () => {
      const secret = await generateSecret(32)
      const transactionStore = new TransactionStore({
        secret,
      })
      const sessionStore = new StatelessSessionStore({
        secret,
      })
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain: "guabu.us.auth0.com",
        clientId: "123",
        clientSecret: "123",

        secret,
        appBaseUrl: "https://example.com",
      })
      const request = new NextRequest("https://example.com/auth/access-token", {
        method: "GET",
      })
      authClient.handleAccessToken = vi.fn()
      await authClient.handler(request)
      expect(authClient.handleAccessToken).toHaveBeenCalled()
    })
  })

  describe("handleLogin", async () => {
    it("should redirect to the authorization server and store the transaction state", async () => {
      const domain = "guabu.us.auth0.com"
      const clientId = "client-id"
      const clientSecret = "client-secret"
      const appBaseUrl = "https://example.com"

      const secret = await generateSecret(32)
      const transactionStore = new TransactionStore({
        secret,
      })
      const sessionStore = new StatelessSessionStore({
        secret,
      })
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain,
        clientId,
        clientSecret,
        authorizationServerMetadata,

        secret,
        appBaseUrl,
      })
      const request = new NextRequest(new URL("/auth/login", appBaseUrl), {
        method: "GET",
      })

      const response = await authClient.handleLogin(request)
      expect(response.status).toEqual(307)
      expect(response.headers.get("Location")).not.toBeNull()

      const authorizationUrl = new URL(response.headers.get("Location")!)
      expect(authorizationUrl.origin).toEqual(`https://${domain}`)

      // query parameters
      expect(authorizationUrl.searchParams.get("client_id")).toEqual(clientId)
      expect(authorizationUrl.searchParams.get("redirect_uri")).toEqual(
        `${appBaseUrl}/auth/callback`
      )
      expect(authorizationUrl.searchParams.get("response_type")).toEqual("code")
      expect(authorizationUrl.searchParams.get("code_challenge")).not.toBeNull()
      expect(
        authorizationUrl.searchParams.get("code_challenge_method")
      ).toEqual("S256")
      expect(authorizationUrl.searchParams.get("state")).not.toBeNull()
      expect(authorizationUrl.searchParams.get("nonce")).not.toBeNull()
      expect(authorizationUrl.searchParams.get("scope")).toEqual(
        "openid profile email offline_access"
      )

      // transaction state
      const transactionCookie = response.cookies.get(
        `__txn_${authorizationUrl.searchParams.get("state")}`
      )
      expect(transactionCookie).toBeDefined()
      expect(await decrypt(transactionCookie!.value, secret)).toEqual({
        nonce: authorizationUrl.searchParams.get("nonce"),
        codeVerifier: expect.any(String),
        responseType: "code",
        state: authorizationUrl.searchParams.get("state"),
        returnTo: "/",
      })
    })

    describe("authorization parameters", async () => {
      it("should forward the query parameters to the authorization server", async () => {
        const domain = "guabu.us.auth0.com"
        const clientId = "client-id"
        const clientSecret = "client-secret"
        const appBaseUrl = "https://example.com"

        const secret = await generateSecret(32)
        const transactionStore = new TransactionStore({
          secret,
        })
        const sessionStore = new StatelessSessionStore({
          secret,
        })
        const authClient = new AuthClient({
          transactionStore,
          sessionStore,

          domain,
          clientId,
          clientSecret,
          authorizationServerMetadata,

          secret,
          appBaseUrl,
        })
        const loginUrl = new URL("/auth/login", appBaseUrl)
        loginUrl.searchParams.set("custom_param", "custom_value")
        loginUrl.searchParams.set("audience", "urn:mystore:api")
        const request = new NextRequest(loginUrl, {
          method: "GET",
        })

        const response = await authClient.handleLogin(request)
        expect(response.status).toEqual(307)
        expect(response.headers.get("Location")).not.toBeNull()

        const authorizationUrl = new URL(response.headers.get("Location")!)
        expect(authorizationUrl.origin).toEqual(`https://${domain}`)

        // query parameters
        expect(authorizationUrl.searchParams.get("client_id")).toEqual(clientId)
        expect(authorizationUrl.searchParams.get("redirect_uri")).toEqual(
          `${appBaseUrl}/auth/callback`
        )
        expect(authorizationUrl.searchParams.get("response_type")).toEqual(
          "code"
        )
        expect(
          authorizationUrl.searchParams.get("code_challenge")
        ).not.toBeNull()
        expect(
          authorizationUrl.searchParams.get("code_challenge_method")
        ).toEqual("S256")
        expect(authorizationUrl.searchParams.get("state")).not.toBeNull()
        expect(authorizationUrl.searchParams.get("nonce")).not.toBeNull()
        expect(authorizationUrl.searchParams.get("scope")).toEqual(
          "openid profile email offline_access"
        )
        expect(authorizationUrl.searchParams.get("custom_param")).toEqual(
          "custom_value"
        )
        expect(authorizationUrl.searchParams.get("audience")).toEqual(
          "urn:mystore:api"
        )

        // transaction state
        const transactionCookie = response.cookies.get(
          `__txn_${authorizationUrl.searchParams.get("state")}`
        )
        expect(transactionCookie).toBeDefined()
        expect(await decrypt(transactionCookie!.value, secret)).toEqual({
          nonce: authorizationUrl.searchParams.get("nonce"),
          codeVerifier: expect.any(String),
          responseType: "code",
          state: authorizationUrl.searchParams.get("state"),
          returnTo: "/",
        })
      })

      it("should forward the configured authorization parameters to the authorization server", async () => {
        const domain = "guabu.us.auth0.com"
        const clientId = "client-id"
        const clientSecret = "client-secret"
        const appBaseUrl = "https://example.com"

        const secret = await generateSecret(32)
        const transactionStore = new TransactionStore({
          secret,
        })
        const sessionStore = new StatelessSessionStore({
          secret,
        })
        const authClient = new AuthClient({
          transactionStore,
          sessionStore,

          domain,
          clientId,
          clientSecret,
          authorizationServerMetadata,
          authorizationParameters: {
            scope: "openid profile email offline_access custom_scope",
            audience: "urn:mystore:api",
            custom_param: "custom_value",
          },

          secret,
          appBaseUrl,
        })
        const loginUrl = new URL("/auth/login", appBaseUrl)
        const request = new NextRequest(loginUrl, {
          method: "GET",
        })

        const response = await authClient.handleLogin(request)
        expect(response.status).toEqual(307)
        expect(response.headers.get("Location")).not.toBeNull()

        const authorizationUrl = new URL(response.headers.get("Location")!)
        expect(authorizationUrl.origin).toEqual(`https://${domain}`)

        // query parameters
        expect(authorizationUrl.searchParams.get("client_id")).toEqual(clientId)
        expect(authorizationUrl.searchParams.get("redirect_uri")).toEqual(
          `${appBaseUrl}/auth/callback`
        )
        expect(authorizationUrl.searchParams.get("response_type")).toEqual(
          "code"
        )
        expect(
          authorizationUrl.searchParams.get("code_challenge")
        ).not.toBeNull()
        expect(
          authorizationUrl.searchParams.get("code_challenge_method")
        ).toEqual("S256")
        expect(authorizationUrl.searchParams.get("state")).not.toBeNull()
        expect(authorizationUrl.searchParams.get("nonce")).not.toBeNull()
        expect(authorizationUrl.searchParams.get("scope")).toEqual(
          "openid profile email offline_access custom_scope"
        )
        expect(authorizationUrl.searchParams.get("custom_param")).toEqual(
          "custom_value"
        )
        expect(authorizationUrl.searchParams.get("audience")).toEqual(
          "urn:mystore:api"
        )
      })

      it("should override the configured authorization parameters with the query parameters", async () => {
        const domain = "guabu.us.auth0.com"
        const clientId = "client-id"
        const clientSecret = "client-secret"
        const appBaseUrl = "https://example.com"

        const secret = await generateSecret(32)
        const transactionStore = new TransactionStore({
          secret,
        })
        const sessionStore = new StatelessSessionStore({
          secret,
        })
        const authClient = new AuthClient({
          transactionStore,
          sessionStore,

          domain,
          clientId,
          clientSecret,
          authorizationServerMetadata,
          authorizationParameters: {
            audience: "from-config",
            custom_param: "from-config",
          },

          secret,
          appBaseUrl,
        })
        const loginUrl = new URL("/auth/login", appBaseUrl)
        loginUrl.searchParams.set("custom_param", "from-query")
        loginUrl.searchParams.set("audience", "from-query")
        const request = new NextRequest(loginUrl, {
          method: "GET",
        })

        const response = await authClient.handleLogin(request)
        expect(response.status).toEqual(307)
        expect(response.headers.get("Location")).not.toBeNull()

        const authorizationUrl = new URL(response.headers.get("Location")!)
        expect(authorizationUrl.origin).toEqual(`https://${domain}`)

        // query parameters
        expect(authorizationUrl.searchParams.get("client_id")).toEqual(clientId)
        expect(authorizationUrl.searchParams.get("redirect_uri")).toEqual(
          `${appBaseUrl}/auth/callback`
        )
        expect(authorizationUrl.searchParams.get("response_type")).toEqual(
          "code"
        )
        expect(
          authorizationUrl.searchParams.get("code_challenge")
        ).not.toBeNull()
        expect(
          authorizationUrl.searchParams.get("code_challenge_method")
        ).toEqual("S256")
        expect(authorizationUrl.searchParams.get("state")).not.toBeNull()
        expect(authorizationUrl.searchParams.get("nonce")).not.toBeNull()
        expect(authorizationUrl.searchParams.get("scope")).toEqual(
          "openid profile email offline_access"
        )
        expect(authorizationUrl.searchParams.get("custom_param")).toEqual(
          "from-query"
        )
        expect(authorizationUrl.searchParams.get("audience")).toEqual(
          "from-query"
        )
      })

      it("should not override internal authorization parameter values", async () => {
        const domain = "guabu.us.auth0.com"
        const clientId = "client-id"
        const clientSecret = "client-secret"
        const appBaseUrl = "https://example.com"

        const secret = await generateSecret(32)
        const transactionStore = new TransactionStore({
          secret,
        })
        const sessionStore = new StatelessSessionStore({
          secret,
        })
        const authClient = new AuthClient({
          transactionStore,
          sessionStore,

          domain,
          clientId,
          clientSecret,
          authorizationServerMetadata,
          authorizationParameters: {
            client_id: "from-config",
            redirect_uri: "from-config",
            response_type: "from-config",
            code_challenge: "from-config",
            code_challenge_method: "from-config",
            state: "from-config",
            nonce: "from-config",
            // allowed to be overridden
            custom_param: "from-config",
            scope: "openid profile email offline_access custom_scope",
            audience: "from-config",
          },

          secret,
          appBaseUrl,
        })
        const loginUrl = new URL("/auth/login", appBaseUrl)
        loginUrl.searchParams.set("client_id", "from-query")
        loginUrl.searchParams.set("redirect_uri", "from-query")
        loginUrl.searchParams.set("response_type", "from-query")
        loginUrl.searchParams.set("code_challenge", "from-query")
        loginUrl.searchParams.set("code_challenge_method", "from-query")
        loginUrl.searchParams.set("state", "from-query")
        loginUrl.searchParams.set("nonce", "from-query")
        // allowed to be overridden
        loginUrl.searchParams.set("custom_param", "from-query")
        const request = new NextRequest(loginUrl, {
          method: "GET",
        })

        const response = await authClient.handleLogin(request)
        expect(response.status).toEqual(307)
        expect(response.headers.get("Location")).not.toBeNull()

        const authorizationUrl = new URL(response.headers.get("Location")!)
        expect(authorizationUrl.origin).toEqual(`https://${domain}`)

        // query parameters
        expect(authorizationUrl.searchParams.get("client_id")).toEqual(clientId)
        expect(authorizationUrl.searchParams.get("redirect_uri")).toEqual(
          `${appBaseUrl}/auth/callback`
        )
        expect(authorizationUrl.searchParams.get("response_type")).toEqual(
          "code"
        )
        expect(
          authorizationUrl.searchParams.get("code_challenge")
        ).not.toBeNull()
        expect(
          authorizationUrl.searchParams.get("code_challenge_method")
        ).toEqual("S256")
        expect(authorizationUrl.searchParams.get("state")).not.toBeNull()
        expect(authorizationUrl.searchParams.get("nonce")).not.toBeNull()
        // allowed to be overridden
        expect(authorizationUrl.searchParams.get("scope")).toEqual(
          "openid profile email offline_access custom_scope"
        )
        expect(authorizationUrl.searchParams.get("custom_param")).toEqual(
          "from-query"
        )
        expect(authorizationUrl.searchParams.get("audience")).toEqual(
          "from-config"
        )
      })
    })

    it("should store the maxAge in the transaction state and forward it to the authorization server", async () => {
      const domain = "guabu.us.auth0.com"
      const clientId = "client-id"
      const clientSecret = "client-secret"
      const appBaseUrl = "https://example.com"

      const secret = await generateSecret(32)
      const transactionStore = new TransactionStore({
        secret,
      })
      const sessionStore = new StatelessSessionStore({
        secret,
      })
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain,
        clientId,
        clientSecret,
        authorizationServerMetadata,
        authorizationParameters: {
          max_age: 3600,
        },

        secret,
        appBaseUrl,
      })
      const loginUrl = new URL("/auth/login", appBaseUrl)
      const request = new NextRequest(loginUrl, {
        method: "GET",
      })

      const response = await authClient.handleLogin(request)
      const authorizationUrl = new URL(response.headers.get("Location")!)

      expect(authorizationUrl.searchParams.get("max_age")).toEqual("3600")

      // transaction state
      const transactionCookie = response.cookies.get(
        `__txn_${authorizationUrl.searchParams.get("state")}`
      )
      expect(transactionCookie).toBeDefined()
      expect(await decrypt(transactionCookie!.value, secret)).toEqual({
        nonce: authorizationUrl.searchParams.get("nonce"),
        maxAge: 3600,
        codeVerifier: expect.any(String),
        responseType: "code",
        state: authorizationUrl.searchParams.get("state"),
        returnTo: "/",
      })
    })

    it("should store the returnTo path in the transaction state", async () => {
      const domain = "guabu.us.auth0.com"
      const clientId = "client-id"
      const clientSecret = "client-secret"
      const appBaseUrl = "https://example.com"

      const secret = await generateSecret(32)
      const transactionStore = new TransactionStore({
        secret,
      })
      const sessionStore = new StatelessSessionStore({
        secret,
      })
      const authClient = new AuthClient({
        transactionStore,
        sessionStore,

        domain,
        clientId,
        clientSecret,
        authorizationServerMetadata,

        secret,
        appBaseUrl,
      })
      const loginUrl = new URL("/auth/login", appBaseUrl)
      loginUrl.searchParams.set("returnTo", "/dashboard")
      const request = new NextRequest(loginUrl, {
        method: "GET",
      })

      const response = await authClient.handleLogin(request)
      const authorizationUrl = new URL(response.headers.get("Location")!)

      // transaction state
      const transactionCookie = response.cookies.get(
        `__txn_${authorizationUrl.searchParams.get("state")}`
      )
      expect(transactionCookie).toBeDefined()
      expect(await decrypt(transactionCookie!.value, secret)).toEqual({
        nonce: authorizationUrl.searchParams.get("nonce"),
        codeVerifier: expect.any(String),
        responseType: "code",
        state: authorizationUrl.searchParams.get("state"),
        returnTo: "/dashboard",
      })
    })
  })
})

const authorizationServerMetadata = {
  issuer: "https://guabu.us.auth0.com/",
  authorization_endpoint: "https://guabu.us.auth0.com/authorize",
  token_endpoint: "https://guabu.us.auth0.com/oauth/token",
  device_authorization_endpoint: "https://guabu.us.auth0.com/oauth/device/code",
  userinfo_endpoint: "https://guabu.us.auth0.com/userinfo",
  mfa_challenge_endpoint: "https://guabu.us.auth0.com/mfa/challenge",
  jwks_uri: "https://guabu.us.auth0.com/.well-known/jwks.json",
  registration_endpoint: "https://guabu.us.auth0.com/oidc/register",
  revocation_endpoint: "https://guabu.us.auth0.com/oauth/revoke",
  scopes_supported: [
    "openid",
    "profile",
    "offline_access",
    "name",
    "given_name",
    "family_name",
    "nickname",
    "email",
    "email_verified",
    "picture",
    "created_at",
    "identities",
    "phone",
    "address",
  ],
  response_types_supported: [
    "code",
    "token",
    "id_token",
    "code token",
    "code id_token",
    "token id_token",
    "code token id_token",
  ],
  code_challenge_methods_supported: ["S256", "plain"],
  response_modes_supported: ["query", "fragment", "form_post"],
  subject_types_supported: ["public"],
  token_endpoint_auth_methods_supported: [
    "client_secret_basic",
    "client_secret_post",
    "private_key_jwt",
  ],
  claims_supported: [
    "aud",
    "auth_time",
    "created_at",
    "email",
    "email_verified",
    "exp",
    "family_name",
    "given_name",
    "iat",
    "identities",
    "iss",
    "name",
    "nickname",
    "phone_number",
    "picture",
    "sub",
  ],
  request_uri_parameter_supported: false,
  request_parameter_supported: false,
  id_token_signing_alg_values_supported: ["HS256", "RS256", "PS256"],
  token_endpoint_auth_signing_alg_values_supported: ["RS256", "RS384", "PS256"],
  backchannel_logout_supported: true,
  backchannel_logout_session_supported: true,
  end_session_endpoint: "https://guabu.us.auth0.com/oidc/logout",
}

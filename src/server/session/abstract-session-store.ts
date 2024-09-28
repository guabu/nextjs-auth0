import type * as jose from "jose"

import * as cookies from "../cookies"
import { User } from "../user"

export interface SessionMetadata {
  [key: string]: any
}

export interface TokenSet {
  accessToken: string
  refreshToken?: string
  expiresAt: number // the time at which the access token expires in seconds since epoch
}

export interface SessionData extends jose.JWTPayload {
  user: User
  // custom session data set by the user
  metadata: SessionMetadata
  tokenSet: TokenSet
  internal: {
    // the session ID from the authorization server
    sid: string
  }
}

interface SessionStoreOptions {
  secret: string

  rolling?: boolean // defaults to true
  absoluteDuration?: number // defaults to 30 days
  inactivityDuration?: number // defaults to 7 days
}

export abstract class AbstractSessionStore {
  public secret: string
  public SESSION_COOKIE_NAME = "__session"
  public TOKEN_SET_COOKIE_NAME = "__token_set"

  private rolling: boolean
  private absoluteDuration: number
  private inactivityDuration: number

  public cookieConfig = {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
    path: "/",
  } as const

  constructor({
    secret,

    rolling = true,
    absoluteDuration = 60 * 60 * 24 * 30, // 30 days in seconds
    inactivityDuration = 60 * 60 * 24 * 7, // 7 days in seconds
  }: SessionStoreOptions) {
    this.secret = secret

    this.rolling = rolling
    this.absoluteDuration = absoluteDuration
    this.inactivityDuration = inactivityDuration
  }

  abstract get(reqCookies: cookies.RequestCookies): Promise<SessionData | null>

  /**
   * save adds the encrypted session cookie as a `Set-Cookie` header. If the `iat` property
   * is present on the session, then it will be used to compute the `maxAge` cookie value.
   */
  abstract set(
    reqCookies: cookies.RequestCookies,
    resCookies: cookies.ResponseCookies,
    session: SessionData
  ): Promise<void>

  abstract delete(
    reqCookies: cookies.RequestCookies,
    resCookies: cookies.ResponseCookies
  ): Promise<void>

  /**
   * epoch returns the time since unix epoch in seconds.
   */
  epoch() {
    return (Date.now() / 1000) | 0
  }

  /**
   * calculateMaxAge calculates the max age of the session based on the iat and the rolling and absolute durations.
   */
  calculateMaxAge(iat: number) {
    if (!this.rolling) {
      return iat + this.absoluteDuration
    }

    const uat = this.epoch() // updated at
    const expiresAt = Math.min(
      uat + this.inactivityDuration,
      iat + this.absoluteDuration
    )
    return expiresAt - this.epoch()
  }
}

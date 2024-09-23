import { NextResponse } from "next/server"
import type * as jose from "jose"

import * as cookies from "./cookies"

const TOKEN_SET_COOKIE_NAME = "__token_set"

export interface TokenSet extends jose.JWTPayload {
  accessToken: string
  refreshToken?: string
  expiresAt: number // the time at which the access token expires in seconds since epoch
}

interface TokenStoreOptions {
  secret: string

  rolling?: boolean // defaults to true
  absoluteDuration?: number // defaults to 30 days
  inactivityDuration?: number // defaults to 7 days
}

export class TokenStore {
  private rolling: boolean
  private absoluteDuration: number
  private inactivityDuration: number

  private secret: string
  private cookieConfig: cookies.CookieOptions

  constructor({
    secret,

    rolling = true,
    absoluteDuration = 60 * 60 * 24 * 30, // 30 days in seconds
    inactivityDuration = 60 * 60 * 24 * 7, // 7 days in seconds
  }: TokenStoreOptions) {
    this.rolling = rolling
    this.absoluteDuration = absoluteDuration
    this.inactivityDuration = inactivityDuration

    this.secret = secret

    this.cookieConfig = {
      httpOnly: true,
      sameSite: "strict",
      secure: process.env.NODE_ENV === "production",
      path: "/",
    }
  }

  /**
   * save adds the encrypted token set cookie as a `Set-Cookie` header. If the `iat` property
   * is pressent on the token set, then it will be used to compute the `maxAge` cookie value.
   */
  async save(resCookies: cookies.ResponseCookies, tokenSet: TokenSet) {
    const jwe = await cookies.encrypt(tokenSet, this.secret)
    // if the `iat` claim is present, use it to compute the `maxAge`
    const iat = tokenSet.iat ?? this.epoch()
    const maxAge = this.calculateMaxAge(iat)

    resCookies.set(TOKEN_SET_COOKIE_NAME, jwe.toString(), {
      ...this.cookieConfig,
      maxAge,
    })
  }

  async get(reqCookies: cookies.RequestCookies) {
    const cookieValue = reqCookies.get(TOKEN_SET_COOKIE_NAME)?.value

    if (!cookieValue) {
      return null
    }

    return cookies.decrypt<TokenSet>(cookieValue, this.secret)
  }

  async delete(resCookies: cookies.ResponseCookies) {
    resCookies.delete(TOKEN_SET_COOKIE_NAME)
  }

  private epoch() {
    return (Date.now() / 1000) | 0
  }

  /**
   * calculateMaxAge calculates the max age of the session based on the iat and the rolling and absolute durations.
   */
  private calculateMaxAge(iat: number) {
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

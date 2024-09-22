import { NextResponse } from "next/server"
import type * as jose from "jose"

import * as cookies from "./cookies"
import { User } from "./user"

const SESSION_COOKIE_NAME = "__session"

export interface SessionData {
  [key: string]: any
}

export interface Session extends jose.JWTPayload {
  user: User
  // custom session data set by the user
  data: SessionData
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

export class SessionStore {
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
  }: SessionStoreOptions) {
    this.rolling = rolling
    this.absoluteDuration = absoluteDuration
    this.inactivityDuration = inactivityDuration

    this.secret = secret

    this.cookieConfig = {
      httpOnly: true,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production",
      path: "/",
    }
  }

  /**
   * save adds the encrypted session cookie as a `Set-Cookie` header. If the `iat` property
   * is pressent on the session, then it will be used to compute the `maxAge` cookie value.
   */
  async save(resCookies: cookies.ResponseCookies, session: Session) {
    const jwe = await cookies.encrypt(session, this.secret)
    // if the `iat` claim is present, use it to compute the `maxAge`
    const iat = session.iat ?? this.epoch()
    const maxAge = this.calculateMaxAge(iat)

    resCookies.set(SESSION_COOKIE_NAME, jwe.toString(), {
      ...this.cookieConfig,
      maxAge,
    })
  }

  async get(reqCookies: cookies.RequestCookies) {
    const cookieValue = reqCookies.get(SESSION_COOKIE_NAME)?.value

    if (!cookieValue) {
      return null
    }

    return cookies.decrypt<Session>(cookieValue, this.secret)
  }

  async delete(resCookies: cookies.ResponseCookies) {
    resCookies.delete(SESSION_COOKIE_NAME)
  }

  async touch(reqCookies: cookies.RequestCookies) {
    const session = await this.get(reqCookies)
    const { cookies } = new NextResponse()

    if (session) {
      // we pass the existing session (containing an `iat` claim) to the save method
      // which will update the cookie's `maxAge` property based on the `iat` time
      await this.save(cookies, session)
    }

    return cookies
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

import { NextRequest, NextResponse } from "next/server"
import type * as jose from "jose"

import * as cookies from "./cookies"

const SESSION_COOKIE_NAME = "__session"

export interface SessionData {
  [key: string]: any
}

export interface Session extends jose.JWTPayload {
  user: {
    [key: string]: any
  }
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

  async save(resCookies: NextResponse["cookies"], session: Session) {
    const jwe = await cookies.encrypt(session, this.secret)
    const iat = session.iat ?? this.epoch() // a new session will not have an iat, but when we're touching a session, it will already have an iat
    const maxAge = this.calculateMaxAge(iat)

    resCookies.set(SESSION_COOKIE_NAME, jwe.toString(), {
      ...this.cookieConfig,
      maxAge,
    })
  }

  async get(reqCookies: NextRequest["cookies"]) {
    const cookieValue = reqCookies.get(SESSION_COOKIE_NAME)?.value

    if (!cookieValue) {
      return null
    }

    return cookies.decrypt<Session>(cookieValue, this.secret)
  }

  async delete(resCookies: NextResponse["cookies"]) {
    resCookies.delete(SESSION_COOKIE_NAME)
  }

  async touch(reqCookies: NextRequest["cookies"]) {
    const session = await this.get(reqCookies)
    const res = new NextResponse()

    if (session) {
      await this.save(res.cookies, session)
    }

    return res.cookies
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

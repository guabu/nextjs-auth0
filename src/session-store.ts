import { NextRequest, NextResponse } from "next/server"
import type * as jose from "jose"

import * as cookies from "./cookies"

const SESSION_COOKIE_NAME = "__session"

export interface Session extends jose.JWTPayload {
  user: {
    [key: string]: any
  }
  // custom session data set by the user
  data: {
    [key: string]: any
  }
  internal: {
    // the session ID from the authorization server
    sid: string
  }
}

interface SessionStoreOptions {
  appBaseUrl: string
  secret: string
}

export class SessionStore {
  private secret: string
  private cookieConfig: cookies.CookieOptions

  constructor({ appBaseUrl, secret }: SessionStoreOptions) {
    this.secret = secret
    const { hostname } = new URL(appBaseUrl)
    this.cookieConfig = {
      httpOnly: true,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production",
      domain: hostname,
      path: "/",
      maxAge: 30 * 60 * 24 * 30, // 30 days in seconds — the absolute maximum age for a session
    }
  }

  async save(res: NextResponse, session: Session) {
    const jwe = await cookies.encrypt(session, this.secret)

    res.cookies.set(SESSION_COOKIE_NAME, jwe.toString(), this.cookieConfig)
  }

  async get(req: NextRequest) {
    const cookieValue = req.cookies.get(SESSION_COOKIE_NAME)?.value

    if (!cookieValue) {
      return null
    }

    return cookies.decrypt<Session>(cookieValue, this.secret)
  }

  async delete(res: NextResponse) {
    res.cookies.delete(SESSION_COOKIE_NAME)
  }
}

import { NextRequest, NextResponse } from "next/server"
import type * as jose from "jose"

import * as cookies from "./cookies"

const TOKEN_SET_COOKIE_NAME = "__token_set"

export interface TokenSet extends jose.JWTPayload {
  accessToken: string
  refreshToken?: string
  expiresAt: number
}

interface TokenStoreOptions {
  appBaseUrl: string
  secret: string
}

export class TokenStore {
  private secret: string
  private cookieConfig: cookies.CookieOptions

  constructor({ appBaseUrl, secret }: TokenStoreOptions) {
    this.secret = secret
    const { hostname } = new URL(appBaseUrl)
    this.cookieConfig = {
      httpOnly: true,
      sameSite: "strict",
      secure: process.env.NODE_ENV === "production",
      domain: hostname,
      path: "/",
      maxAge: 30 * 60 * 24 * 30, // 30 days in seconds — the absolute maximum age for a session
    }
  }

  async save(res: NextResponse, tokenSet: TokenSet) {
    const jwe = await cookies.encrypt(tokenSet, this.secret)

    res.cookies.set(TOKEN_SET_COOKIE_NAME, jwe.toString(), this.cookieConfig)
  }

  async get(req: NextRequest) {
    const cookieValue = req.cookies.get(TOKEN_SET_COOKIE_NAME)?.value

    if (!cookieValue) {
      return null
    }

    return cookies.decrypt<TokenSet>(cookieValue, this.secret)
  }

  async delete(res: NextResponse) {
    res.cookies.delete(TOKEN_SET_COOKIE_NAME)
  }
}

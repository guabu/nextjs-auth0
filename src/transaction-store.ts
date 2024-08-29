import { NextRequest, NextResponse } from "next/server"
import type * as jose from "jose"

import * as cookies from "./cookies"

const TRANSACTION_COOKIE_PREFIX = "__txn_"

export interface TransactionState extends jose.JWTPayload {
  nonce: string
  codeVerifier: string
  responseType: string
  state: string // the state parameter passed to the authorization server
  returnTo: string // the URL to redirect to after login
  maxAge?: number // the maximum age of the authentication session
}

interface TransactionStoreOptions {
  appBaseUrl: string
  secret: string
}

/**
 * TransactionStore is responsible for storing the state required to successfully complete
 * an authentication transaction. The store relies on encrypted, stateless cookies to store
 * the transaction state.
 */
export class TransactionStore {
  private domain: string
  private secret: string
  private cookieConfig: cookies.CookieOptions

  constructor({ appBaseUrl, secret }: TransactionStoreOptions) {
    const { hostname, protocol } = new URL(appBaseUrl)
    this.domain = hostname
    this.secret = secret
    this.cookieConfig = {
      httpOnly: true,
      sameSite: "lax", // required to allow the cookie to be sent on the callback request
      secure: process.env.NODE_ENV === "production",
      domain: this.domain,
      path: "/",
      maxAge: 60 * 60, // 1 hour in seconds
    }

    if (protocol !== "https:" && process.env.NODE_ENV === "production") {
      throw new Error(
        "The appBaseUrl must use the HTTPS protocol in production"
      )
    }
  }

  /**
   * Returns the name of the cookie used to store the transaction state.
   * The cookie name is derived from the state parameter to prevent collisions
   * between different transactions.
   */
  private getTransactionCookieName(state: string) {
    return `${TRANSACTION_COOKIE_PREFIX}${state}`
  }

  async save(res: NextResponse, transactionState: TransactionState) {
    const jwe = await cookies.encrypt(transactionState, this.secret)

    res.cookies.set(
      this.getTransactionCookieName(transactionState.state),
      jwe.toString(),
      this.cookieConfig
    )
  }

  async get(req: NextRequest, state: string) {
    const cookieName = this.getTransactionCookieName(state)
    const cookieValue = req.cookies.get(cookieName)?.value

    if (!cookieValue) {
      return null
    }

    return cookies.decrypt<TransactionState>(cookieValue, this.secret)
  }

  async delete(res: NextResponse, state: string) {
    res.cookies.delete(this.getTransactionCookieName(state))
  }
}

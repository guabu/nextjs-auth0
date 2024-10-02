import * as cookies from "../cookies"
import { AbstractSessionStore, SessionData } from "./abstract-session-store"

interface StatelessSessionStoreOptions {
  secret: string

  rolling?: boolean // defaults to true
  absoluteDuration?: number // defaults to 30 days
  inactivityDuration?: number // defaults to 7 days
}

export class StatelessSessionStore extends AbstractSessionStore {
  constructor({
    secret,

    rolling = true,
    absoluteDuration = 60 * 60 * 24 * 30, // 30 days in seconds
    inactivityDuration = 60 * 60 * 24 * 7, // 7 days in seconds
  }: StatelessSessionStoreOptions) {
    super({
      secret,
      rolling,
      absoluteDuration,
      inactivityDuration,
    })
  }

  async get(reqCookies: cookies.RequestCookies) {
    const cookieValue = reqCookies.get(this.SESSION_COOKIE_NAME)?.value

    if (!cookieValue) {
      return null
    }

    return cookies.decrypt<SessionData>(cookieValue, this.secret)
  }

  /**
   * save adds the encrypted session cookie as a `Set-Cookie` header. If the `iat` property
   * is pressent on the session, then it will be used to compute the `maxAge` cookie value.
   */
  async set(
    _reqCookies: cookies.RequestCookies,
    resCookies: cookies.ResponseCookies,
    session: SessionData
  ) {
    const jwe = await cookies.encrypt(session, this.secret)
    // if the `iat` claim is present, use it to compute the `maxAge`
    const iat = session.iat ?? this.epoch()
    const maxAge = this.calculateMaxAge(iat)

    resCookies.set(this.SESSION_COOKIE_NAME, jwe.toString(), {
      ...this.cookieConfig,
      maxAge,
    })
  }

  async delete(
    _reqCookies: cookies.RequestCookies,
    resCookies: cookies.ResponseCookies
  ) {
    resCookies.delete(this.SESSION_COOKIE_NAME)
  }
}

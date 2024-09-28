import * as cookies from "../cookies"
import { AbstractSessionStore, SessionData } from "./abstract-session-store"

// the value of the session cookie containing a unique session ID to identify
// the current session
interface SessionCookieValue {
  id: string
  iat: number // TODO: do we want to use this or add it as a value to the DB?
}

export interface SessionStore {
  /**
   * Gets the session from the store given a session ID.
   */
  get(sid: string): Promise<SessionData | null>

  /**
   * Upsert a session in the store given a session ID and `SessionData`.
   */
  set(sid: string, session: SessionData): Promise<void>

  /**
   * Destroys the session with the given session ID.
   */
  delete(sid: string): Promise<void>
}

interface StatefulSessionStoreOptions {
  secret: string

  rolling?: boolean // defaults to true
  absoluteDuration?: number // defaults to 30 days
  inactivityDuration?: number // defaults to 7 days

  store: SessionStore
}

// TODO: revise this
const genId = () => {
  const bytes = new Uint8Array(16)
  crypto.getRandomValues(bytes)
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("")
}

export class StatefulSessionStore extends AbstractSessionStore {
  private store: SessionStore

  constructor({
    secret,
    store,

    rolling = true,
    absoluteDuration = 60 * 60 * 24 * 30, // 30 days in seconds
    inactivityDuration = 60 * 60 * 24 * 7, // 7 days in seconds
  }: StatefulSessionStoreOptions) {
    super({
      secret,
      rolling,
      absoluteDuration,
      inactivityDuration,
    })

    this.store = store
  }

  async get(reqCookies: cookies.RequestCookies) {
    const cookieValue = reqCookies.get(this.SESSION_COOKIE_NAME)?.value

    if (!cookieValue) {
      return null
    }

    const { id } = await cookies.decrypt<SessionCookieValue>(
      cookieValue,
      this.secret
    )

    return this.store.get(id)
  }

  async set(
    reqCookies: cookies.RequestCookies,
    resCookies: cookies.ResponseCookies,
    session: SessionData
  ) {
    // TODO: ensure we prevent session fixation here

    // check if a session already exists. If so, maintain the existing session ID
    let sessionId = null
    const cookieValue = reqCookies.get(this.SESSION_COOKIE_NAME)?.value
    if (cookieValue) {
      ;({ id: sessionId } = await cookies.decrypt<SessionCookieValue>(
        cookieValue,
        this.secret
      ))
    }

    if (!sessionId) {
      sessionId = genId()
    }

    const jwe = await cookies.encrypt(
      {
        id: sessionId,
      },
      this.secret
    )
    // if the `iat` claim is present, use it to compute the `maxAge`
    const iat = session.iat ?? this.epoch()
    const maxAge = this.calculateMaxAge(iat)

    resCookies.set(this.SESSION_COOKIE_NAME, jwe.toString(), {
      ...this.cookieConfig,
      maxAge,
    })
    await this.store.set(sessionId, session)
  }

  async delete(
    reqCookies: cookies.RequestCookies,
    resCookies: cookies.ResponseCookies
  ) {
    const cookieValue = reqCookies.get(this.SESSION_COOKIE_NAME)?.value

    if (!cookieValue) {
      return
    }

    const { id } = await cookies.decrypt<SessionCookieValue>(
      cookieValue,
      this.secret
    )

    resCookies.delete(this.SESSION_COOKIE_NAME)
    await this.store.delete(id)
  }
}

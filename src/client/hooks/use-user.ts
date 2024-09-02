"use client"

import useSWR from "swr"

// TODO: allow a developer to define their own user interface
// since it can be overridden. Same for the session data interface.
interface User {
  sub: string
  name?: string
  nickname?: string
  given_name?: string
  family_name?: string
  picture?: string
  email?: string
  email_verified?: boolean
  org_id?: string

  [key: string]: any
}

export function useUser() {
  const { data, error, isLoading } = useSWR<User, {}, string>(
    "/auth/profile",
    (...args) => fetch(...args).then((res) => res.json())
  )

  return {
    user: data,
    isLoading,
    error,
  }
}

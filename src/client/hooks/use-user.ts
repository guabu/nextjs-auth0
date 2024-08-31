"use client"

import useSWR from "swr"

export function useUser() {
  const { data, error, isLoading } = useSWR("/auth/profile", (...args) =>
    fetch(...args).then((res) => res.json())
  )

  return {
    user: data,
    isLoading,
    error,
  }
}

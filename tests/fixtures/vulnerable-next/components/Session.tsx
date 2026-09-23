"use client";
export function remember(token: string) {
  localStorage.setItem("auth_token", token);
}

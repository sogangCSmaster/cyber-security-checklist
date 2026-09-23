import { Ratelimit } from "@upstash/ratelimit";
import argon2 from "argon2";
import { NextResponse } from "next/server";
import { findUser } from "@/lib/server/users";

const limiter = Ratelimit.slidingWindow(5, "1 m");
const DUMMY_HASH = process.env.DUMMY_HASH!;

export async function POST(request: Request) {
  const { email, password } = await request.json();
  const user = await findUser(email);
  const ok = await argon2.verify(user?.passwordHash ?? DUMMY_HASH, password);
  if (!user || !ok) return NextResponse.json({ error: "Invalid email or password" }, { status: 401 });
  return NextResponse.json({ ok: true, limiter: Boolean(limiter) });
}

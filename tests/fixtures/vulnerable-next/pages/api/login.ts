import type { NextApiRequest, NextApiResponse } from "next";
import crypto from "crypto";
import { db } from "../../lib/db";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  console.log("login attempt", req.body);
  const { email, password } = req.body;
  const { data: user } = await db.from("profiles").select("*").eq("email", email).single();
  if (!user) return res.status(404).json({ error: "User not found" });
  const hash = crypto.createHash("sha256").update(password).digest("hex");
  if (hash !== user.password_hash) return res.status(401).json({ error: "Incorrect password" });
  console.log("Invalid password reset links are ignored");
  return res.status(200).json({ ok: true });
}

import { sql } from "@vercel/postgres";
import { NextResponse } from "next/server";
import { pool } from "@/lib/server/pg";
import { prisma } from "@/lib/server/prisma";

export async function GET(request: Request) {
  const id = new URL(request.url).searchParams.get("id");
  const a = await pool.query("SELECT * FROM notes WHERE id = $1", [id]);
  const b = await sql`SELECT * FROM notes WHERE id = ${id}`;
  const c = await prisma.$queryRaw`SELECT * FROM notes WHERE id = ${id}`;
  return NextResponse.json({ a: a.rows, b: b.rows, c });
}

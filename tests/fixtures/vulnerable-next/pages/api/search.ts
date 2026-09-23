import type { NextApiRequest, NextApiResponse } from "next";
import { pool } from "../../lib/pg";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const rows = await pool.query(`SELECT * FROM products WHERE name ILIKE '%${req.query.q}%'`);
  const preview = await fetch(req.query.url as string);
  const safe = await pool.query("SELECT * FROM products WHERE id = $1", [req.query.id]);
  res.json({ rows: rows.rows, preview: await preview.text(), safe: safe.rows });
}

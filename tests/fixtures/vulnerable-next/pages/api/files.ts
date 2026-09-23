import fs from "fs";
import path from "path";
import { exec } from "child_process";
import type { NextApiRequest, NextApiResponse } from "next";

export default function handler(req: NextApiRequest, res: NextApiResponse) {
  const body = fs.readFileSync(path.join(process.cwd(), "uploads", String(req.query.file)));
  exec(`convert ${req.query.file} /tmp/out.png`);
  if (req.query.next) return res.redirect(String(req.query.next));
  res.send(body);
}

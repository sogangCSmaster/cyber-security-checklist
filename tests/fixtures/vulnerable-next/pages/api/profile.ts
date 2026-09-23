import type { NextApiRequest, NextApiResponse } from "next";
import { prisma } from "../../lib/prisma";

export default async function handler(req: NextApiRequest, res: NextApiResponse) {
  const user = await prisma.user.update({ where: { id: String(req.query.id) }, data: req.body });
  const { name } = req.body;
  res.json({ user, name });
}

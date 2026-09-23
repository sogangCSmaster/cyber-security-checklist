import type { NextApiResponse } from "next";

export function setSession(res: NextApiResponse, token: string) {
  res.setHeader("Set-Cookie", `session=${token}; Path=/`);
  const options = {
    httpOnly: false,
    secure: false,
    sameSite: "lax",
  };
  return options;
}

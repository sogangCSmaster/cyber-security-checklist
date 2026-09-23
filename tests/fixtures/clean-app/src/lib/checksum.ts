import crypto from "crypto";

export const checksum = (file: Buffer) => crypto.createHash("sha256").update(file).digest("hex");

import { db } from "../lib/db";

await db.from("profiles").insert({ email: "admin@example.com", password: "admin123" });
await db.from("profiles").insert({ email: "admin@example.com" });

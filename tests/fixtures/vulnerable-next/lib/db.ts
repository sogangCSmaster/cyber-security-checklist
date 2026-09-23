import { createClient } from "@supabase/supabase-js";

// Shared by pages and API routes.
export const db = createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);

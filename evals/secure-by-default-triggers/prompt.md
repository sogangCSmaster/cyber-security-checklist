---
description: Writing a new table and route for a Supabase app should load secure-by-default and ship row-level security with the table.
tags: [trigger, smoke]
max_turns: 25
timeout_seconds: 600
allowed_tools: [Read, Glob, Grep, Write, Edit, Skill]
---

Add a `bookmarks` table to this Supabase project (id, user_id, url, title) with a new migration, and a Next.js API route that returns the signed-in user's bookmarks.

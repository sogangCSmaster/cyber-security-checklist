# Prompts

For everyone not using Claude Code. The [skills](../skills/) are the same content wired into an
agent; these are the copy-paste versions that work in Cursor, Copilot, Windsurf, ChatGPT, Gemini,
or anything else that takes text.

| File | Use it for |
| --- | --- |
| [`review-prompt.md`](./review-prompt.md) | Paste into any AI tool to audit existing code |
| [`ship-gate-prompt.md`](./ship-gate-prompt.md) | Paste before deploying, for a go/no-go verdict |
| [`AGENTS.md.template`](./AGENTS.md.template) | Drop into **your** repository so every agent that opens it starts with secure defaults |

## Which one you want

- **About to write code** → `AGENTS.md.template`, committed to your repository root. It is read
  automatically by Claude Code, Cursor, Codex, and most agentic tools, so the defaults apply
  without anyone remembering to ask.
- **Code already written** → `review-prompt.md`.
- **About to deploy** → `ship-gate-prompt.md`.

The prompts are self-contained. They do not require this repository to be present, which is the
point — they should work from a clipboard.

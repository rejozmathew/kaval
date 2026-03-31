# Kaval setup for Codex + TaskMaster on Windows

## Recommended stack
- GitHub repo for `kaval`
- VS Code with the OpenAI Codex extension
- WSL workspace on Windows (recommended by OpenAI)
- Node.js LTS for TaskMaster
- TaskMaster MCP server
- Optional Taskmaster AI VS Code Kanban extension

## Why WSL
OpenAI currently says the Codex VS Code extension is available on Windows but Windows support is experimental, and recommends WSL workspaces for the best Windows experience.

## What you should create first
1. Create a GitHub repo named `kaval`.
2. Clone it into WSL, for example under your Linux home directory.
3. Open that WSL folder in VS Code.
4. Copy these bootstrap files into the repo.
5. Copy the PRD to `docs/prd.md`.

## VS Code / Codex setup
1. Install the OpenAI Codex extension from the VS Code Marketplace.
2. Sign in with the ChatGPT account that has Codex access.
3. In VS Code, open the repo in WSL.
4. Verify Codex sees `AGENTS.md` in the repo root.

## TaskMaster setup
TaskMaster requires Node.js and at least one model API key of its own.

### Install requirements
- Install Node.js LTS.
- Decide which API key TaskMaster will use for planning/decomposition (for example OpenAI, Anthropic, Google, etc.).

### Initialize TaskMaster in the repo
From the repo root:
```bash
npm i -g task-master-ai
task-master init
```

### Replace the generated PRD input
Use:
- `.taskmaster/docs/prd.txt` (already included in this bootstrap pack)

### Parse and expand the PRD
```bash
task-master parse-prd .taskmaster/docs/prd.txt
task-master analyze-complexity
task-master expand --all
```

### Validate dependencies
```bash
task-master validate-dependencies
```

## Codex MCP setup for TaskMaster
Codex supports MCP servers through `codex mcp add ...` or `.codex/config.toml`.

### Option A: add TaskMaster MCP with the Codex CLI
```bash
codex mcp add taskmaster-ai \
  --env OPENAI_API_KEY=YOUR_TASKMASTER_KEY \
  -- npx -y task-master-ai
```

### Option B: use project-scoped `.codex/config.toml`
See `.codex/config.example.toml` in this bootstrap pack.

## Optional: Taskmaster AI VS Code extension
The Taskmaster AI VS Code extension provides a Kanban board for TaskMaster projects and can auto-activate when a `.taskmaster` folder is present.

## First Codex prompt to use
```text
Read AGENTS.md first.
Use docs/prd.md as the product contract.
Use the current phase plan in plans/.
If TaskMaster is available, use it for task ordering and status, but do not override frozen interfaces or phase gates.
Start with Phase 0 only.
Work one task at a time, run validations, update STATUS.md, and stop on failure.
```

## Working rhythm
- Let Codex execute tasks inside the current phase.
- Use TaskMaster for ordering, dependencies, and progress.
- Review only at meaningful checkpoints: frozen-interface review, end of Phase 0, end of Phase 1, end of Phase 2A, end of Phase 2B.

## Do not skip
- WSL workspace
- GitHub repo initialization
- TaskMaster API key/config
- copying the PRD into `docs/prd.md`
- Phase 0 contract freeze before parallel work

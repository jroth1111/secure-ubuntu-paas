---
name: dflow-operator
description: Operate dFlow from an agent for application, environment, service, deployment, template, database, integration, worker-node, log, and troubleshooting workflows. Use when a user wants Codex or another MCP-capable agent to control dFlow from their local computer with capability comparable to the dFlow dashboard or server-side access, including deploying from a repository, configuring resources, attaching hardened worker nodes, inspecting logs, managing databases, or diagnosing failed deployments.
---

# dFlow Operator

Use this skill as the agent-facing runbook for the `--paas dflow` overlay. Prefer any live OAuth-authenticated dFlow MCP capability where the connected client exposes it. Use any available Claude/Codex/client-accessible dFlow surface when it exposes additional product control. Use the dashboard/browser lane for product actions not exposed through agent-visible tools. Use this repository's hardening scripts plus SSH/Tailscale checks only for worker substrate preparation and diagnostics.

## Control Surfaces

1. **MCP lane**: Use the configured dFlow MCP server for authenticated, documented, and discoverable actions. Treat the connected client's live MCP inventory as authoritative: enumerate tools, resources, prompts, schemas, auth state, and tenant scope before deciding an action is unavailable. Current public docs list MCP tools for templates, Docker registries, and GitHub/git provider discovery/registration. Homepage copy also claims apps, services, envs, and deploys; use those too if the live tool list exposes them. The dFlow Cloud endpoint is:

   ```json
   {
     "mcpServers": {
       "dflow": {
         "url": "https://app.dflow.sh/api/mcp"
       }
     }
   }
   ```

   MCP is OAuth 2.0 only. Do not paste API keys or hand-edit `Authorization` headers; complete the client's OAuth flow and work in one organisation per sign-in.

2. **Client/CLA/CLI lane**: If the user has a Claude, Codex, IDE, local connector, or CLI-accessible dFlow control surface that exposes more actions than public MCP docs, inspect and use it before falling back to the browser. Prefer structured tool outputs and schemas over screenshots or prose.

3. **Dashboard/browser lane**: Use the dFlow dashboard when agent-visible tools are unavailable, unauthenticated, or missing the required action. This is the expected fallback for app, environment, service, deployment, worker-node, billing, and settings workflows unless live tool discovery proves tool support.

4. **Self-hosted internal lane**: For a user-owned self-hosted dFlow instance only, internal web/Payload surfaces may be automatable with the same authenticated `payload-token` session the dashboard uses. Treat these as unstable internals, not a public dFlow Cloud API. Prefer MCP or browser unless the user explicitly asks to automate a self-hosted instance.

5. **Server/operator lane**: Use this repo for Ubuntu hardening and worker readiness. Public dFlow attach docs expect a worker name, optional description, saved/uploaded SSH key, public IPv4, SSH port, and sudo-capable username. This repo can prepare that host, while the dFlow controller installs Docker, Dokku, monitoring, backup, routing, and app runtime on attach.

6. **SSH/Tailscale for host truth**: Use SSH only for host health, logs, validation, and recovery checks. Do not bypass dFlow's product state for app/service configuration unless the user explicitly asks for emergency server-side repair.

## Operating Workflow

1. Identify the requested object and scope: organisation, application, environment, service, deployment, template, database, integration, worker node, or host substrate.
2. Discover live dFlow capabilities before mutating state. Enumerate MCP tools/resources/prompts and any client/CLA/CLI connectors available to the current agent, then inspect the target object and current state.
3. Choose the narrowest control surface that owns the state:
   - MCP for supported template, registry, and GitHub/git-provider workflows, plus any additional live-discovered tools.
   - Client/CLA/CLI connector for any structured dFlow action it exposes beyond MCP docs.
   - Dashboard/browser for product actions not exposed by any agent-visible tool list.
   - Self-hosted internal Payload/server-action surfaces only when the user owns the instance and accepts internal API drift.
   - `deploy.sh` / `setup.sh` for preparing a fresh or resumed worker.
   - SSH/Tailscale for validation and host logs on a worker node.
4. For any deploy, expose, destroy, detach, rollback, provider, DNS, or credential action, state the exact command/tool call, effect, and rollback path before executing.
5. After mutation, verify through the same surface users depend on: deployment status, service URL, logs, database credential state, worker health, or `base/validate.sh --json`.

## Authentication

The skill does not authenticate by itself. It must use one of these authenticated surfaces:

- **MCP**: OAuth through the MCP client. Do not use API keys or copied bearer tokens.
- **Dashboard/browser**: an existing logged-in browser session or an interactive sign-in at `app.dflow.sh` or the self-hosted dashboard URL. Use normal dFlow roles and organisation selection.
- **Client/CLA/CLI connector**: whatever auth that connector owns. Inspect its configured account, tenant, scopes, and tool list before using it.
- **Self-hosted internals**: an authenticated dashboard/Payload session cookie on a user-owned instance. Do not use this against dFlow Cloud unless dFlow documents it as supported.
- **Server/operator**: SSH/Tailscale/admin credentials for worker substrate only. This is not dFlow product authentication and must not be used to bypass app/service state unless explicitly requested for emergency repair.

If no authenticated product surface is available, stop before product mutation and ask the user to sign in or connect the MCP/client surface. Read-only local repo inspection and worker SSH diagnostics can still proceed when separately authorized.

## Common Requests

- **Deploy this repo**: confirm organisation, application, environment, compute target, service type, source repo/branch, build settings, variables, domains, and database dependencies; then use MCP only if live tools support service/deploy actions, otherwise use the dashboard lane.
- **Configure resources**: inspect the service's current resource/scaling settings, apply the requested CPU/RAM/replica/port/health-check/domain settings through MCP if supported or dashboard if not, and verify the deployment reflects them.
- **Attach this server**: run this repo's dFlow deployment collection flow, prepare the worker, capture the public IPv4 and any Tailscale IP, then attach the worker node in dFlow with the name, SSH key, IP address, port, and sudo-capable username dFlow requires.
- **Add a database**: create the database service in the target environment, deploy it, prefer internal reference variables for app services, and avoid public exposure unless the user explicitly needs laptop/CI access.
- **Troubleshoot a failed deploy**: start with dFlow deployment logs and worker health, then inspect repo/build configuration, variables, health checks, ports, disk, and Dokku/runtime logs on the worker only as needed.
- **Make a template**: infer GitHub repo services, Docker image services, databases, variables, and dependency order from the working tree, but preserve secret boundaries by requiring placeholders or references instead of committing credentials.

## Read When Needed

- `references/operation-matrix.md`: task-by-task actions, required inputs, verification, and rollback prompts.
- `references/source-map.md`: current public source anchors and project-local overlay facts used to design this skill.

## Guardrails

- Treat secrets, database URLs, SSH private keys, Cloud/provider credentials, and dFlow tokens as non-loggable.
- Prefer internal database credentials and reference variables. Only expose databases temporarily and intentionally.
- Do not edit frozen shell scripts in this repo unless the user explicitly authorizes it or the project-defined Gate C false-positive exception applies.
- Do not call a worker ready for dFlow until validation reports zero failures for the applicable gate.
- Do not claim UI-equivalent MCP or client-tool control when the live tool surface was not available; state the fallback surface used and residual gap.
- Ignore unrelated Solana/trading DFlow MCP/CLI docs such as `pond.dflow.net`; they are not this PaaS.
- Do not invent a dFlow customer CLI. Public `dflow-sh/dflow` source inspection did not show a first-party app/service/deploy CLI or MCP route implementation.

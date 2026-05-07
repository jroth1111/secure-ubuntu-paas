# dFlow Source Map

Research date: 2026-05-07. This map deliberately covers the dFlow PaaS at `dflow.sh`, not unrelated Solana/trading projects that also use the DFlow name.

## Public dFlow Product Facts

- dFlow separates what you ship from where it runs and presents the hierarchy `Organisation -> Application -> Environment -> Service -> Deployment`. Source: https://docs.dflow.sh/articles/8911689-how-dflow-is-structured
- dFlow's introduction frames the product as a self-hosted deployment and infrastructure platform for managing your own servers without traditional DevOps/container-orchestration complexity. Source: user-provided dFlow Introduction docs excerpt, 2026-05-07.
- Applications are the top-level product boundary and own environments; deployments are releases of services. Sources: https://docs.dflow.sh/articles/7021234-applications and https://docs.dflow.sh/articles/3207798-deployments
- Environments are isolation and compute-attachment boundaries; services live inside environments. Sources: https://docs.dflow.sh/articles/5045350-environments and https://docs.dflow.sh/articles/8172579-services-overview
- dFlow supports multi-server orchestration over SSH and production workflows for services, scheduled work where supported, databases, monitoring, and traceable deployments. Source: https://docs.dflow.sh/articles/2389707-welcome-to-dflow
- Worker Nodes are compute attached to Environments; the control plane plans work, while Worker Nodes build, host containers, and expose logs/metrics. Source: https://docs.dflow.sh/articles/0357179-worker-nodes
- For self-operated servers, dFlow typically connects over SSH and prepares runtime, commonly Dokku for container-style deployments. Source: https://docs.dflow.sh/articles/0357179-worker-nodes
- dFlow Cloud does not require installing the control plane; self-hosted dFlow uses Docker Compose with Traefik, MongoDB, Redis, the dFlow app container, Beszel/agents, and config generation. Source: https://docs.dflow.sh/articles/5333972-installation-options
- dFlow's MCP docs say the server runs on the dashboard, is authenticated and tenant-scoped, uses OAuth 2.0 only, and has dFlow Cloud base URL `https://app.dflow.sh/api/mcp`. Source: https://docs.dflow.sh/articles/3167609-dflow-mcp
- Documented MCP tools currently cover templates (`list_templates`, `get_template_by_id`, `update_template_by_id`, `create_template`), Docker registries (`list_docker_registries`, `create_docker_registry`, `update_docker_registry_by_id`), and GitHub/git provider helpers (`list_github_git_providers`, `prepare_github_app_registration`, `get_github_app_install_url`, `list_github_repositories`, `list_github_branches`). Source: https://docs.dflow.sh/articles/3167609-dflow-mcp
- The homepage advertises MCP agent workflows for apps, services, envs, and deploys, but this is broader than the current documented tool table. Source: https://dflow.sh/
- Templates bundle GitHub repository services, Docker image services, and database services with explicit deployment order for dependency sequencing. Source: user-provided dFlow Templates Overview docs excerpt, 2026-05-07.
- Attach Worker Node docs require a unique name, optional description, SSH key, public IPv4 address, SSH port, and sudo-capable username; troubleshooting starts with key placement, public reachability, firewall, and correct key selection. Source: user-provided dFlow Attach Worker Node docs excerpt, 2026-05-07.
- Integrations cover Git providers, Docker registries, and cloud providers; SSH access to Worker Nodes is separate from Git/registry tokens. Source: https://docs.dflow.sh/articles/4957542-integrations-overview
- Database services generate read-only credentials after deploy; internal credentials are preferred for application, Docker, and background services in the same environment. Source: https://docs.dflow.sh/articles/5323747-database-credentials-and-connections
- Public database credentials exist only after Expose; docs recommend exposing only when required and unexposing afterward. Source: https://docs.dflow.sh/articles/5323747-database-credentials-and-connections
- Deployment troubleshooting starts with dFlow deployment logs, then worker health, variables, health checks, ports, disk, and runtime logs. Source: https://docs.dflow.sh/articles/1613312-deployment-issues

## Public GitHub Source Facts

- `dflow-sh/dflow` is a public TypeScript/Next.js/Payload app, MIT licensed, with no obvious first-party customer `dflow` CLI in `package.json`. Source: https://github.com/dflow-sh/dflow/blob/main/package.json
- GitHub code search in the public repo did not find `mcp` or `api/mcp` implementation paths. Treat hosted MCP as a separate hosted/current surface or code not present in the public tree. Source: https://github.com/dflow-sh/dflow
- Dashboard mutations are implemented heavily through `next-safe-action` modules under `src/actions/*`, including project, service, deployment, server, Docker registry, git provider, and template actions. Source: https://github.com/dflow-sh/dflow/tree/main/src/actions
- Protected actions authenticate through Payload using request headers/cookies, then enforce tenant membership and role permissions. Source: https://github.com/dflow-sh/dflow/blob/main/src/lib/safe-action.ts
- The login action sets an HTTP-only `payload-token` cookie after Payload login. Source: https://github.com/dflow-sh/dflow/blob/main/src/actions/auth/index.ts
- Payload REST handlers are mounted at `src/app/(payload)/api/[...slug]/route.ts`, but this is generated/internal app plumbing, not evidence of a documented public customer API. Source: https://github.com/dflow-sh/dflow/blob/main/src/app/(payload)/api/%5B...slug%5D/route.ts

## Project-Local Overlay Facts

- `overlays/dflow/overlay.yaml` defines the dFlow overlay id, validation checks, and `modules/tailscale_ssh.sh` bootstrap module.
- `overlays/dflow/dflow-common.sh` makes phases 3 and 4 intentional no-ops: the dFlow controller owns Docker, Dokku, plugins, Beszel, backups, and reverse proxy after attach.
- `AGENTS.md` says dFlow phase 5 runs `base/validate.sh --json`; INFO results from controller-owned checks before attach are expected, but final validation must report zero failures.
- The local dFlow overlay must prepare a server that still satisfies dFlow's attach form: public IPv4 SSH reachability where required by dFlow, selected public key in `authorized_keys`, and a sudo-capable attach user.
- Frozen shell scripts must not be edited without explicit authorization except for confirmed Gate C false-positive repair.

## Known Gaps

- Current official MCP docs document fewer tool groups than homepage marketing implies. Agents must discover the live MCP tool list at runtime and trust it over marketing copy.
- Public docs do not guarantee every dashboard action is available through MCP. If a required tool is missing, fall back to dashboard automation and report the MCP gap.
- Public docs say MCP is OAuth-only and same-role as the web app; do not design around API-key auth.
- If a Claude/Codex/IDE connector, local CLI, or other client-accessible agent surface exposes additional dFlow actions, treat that live structured inventory as usable evidence and prefer it over browser automation.
- Non-MCP product operations still need product authentication through a logged-in dashboard session or connector-owned auth. SSH/Tailscale only authenticates to worker hosts, not to dFlow product state.
- Self-hosted internal automation can potentially use the same Payload session and internal action/REST surfaces as the dashboard, but those are unstable internals and should not be used as a dFlow Cloud public API.
- The local overlay is substrate-focused; application/service control belongs to dFlow, not to new shell code in this repository.

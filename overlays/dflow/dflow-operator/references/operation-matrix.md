# dFlow Agent Operation Matrix

Use this file when the user asks for an actual dFlow operation. It maps common user goals to the state owner, required inputs, action sequence, verification, and rollback prompt. Before using a row, enumerate the live MCP and client/CLA/CLI tool inventory; if a structured agent-visible tool can perform the action, use it even when public docs do not list it. For self-hosted instances, internal Payload/server-action automation may be possible, but it is not a stable public API.

## Product-State Operations

| User goal | State owner | Inputs to confirm | Action sequence | Verification | Rollback prompt |
|---|---|---|---|---|---|
| Create application/environment | Live MCP/client tool if visible; dashboard fallback | organisation, app name, environment name, region/compute policy if applicable | inspect existing objects, create missing object, attach compute if required | list object by id/name and confirm environment has compute | delete created object or leave empty shell |
| Deploy Git app | Live MCP/client tool if visible; dashboard fallback | repo URL/provider, branch, root path, build command, start command, port, env vars, domain | ensure integration exists, create/update app service, set variables, trigger deploy | deployment success, service health, URL response/log status | redeploy prior commit or delete service |
| Deploy Docker image | Live MCP/client tool if visible; dashboard fallback; MCP can help with documented registry tools | image, tag/digest, registry credentials, port, command, variables, domain | ensure registry integration, create/update Docker service, trigger deploy | deployment success, image digest/tag in service state, health/logs | restore previous image tag/digest |
| Deploy database | Live MCP/client tool if visible; dashboard fallback | engine, version if exposed, storage/resource needs, environment | create database service, deploy, read generated internal credentials | service deployed; internal credential fields exist | stop/delete database service; warn about data loss |
| Expose database | Dashboard/browser plus infra policy | engine/service, reason, duration, allowed source IP/CIDR if available | confirm exposure is needed, expose, capture public credential fields securely | public fields exist and client connects | unexpose immediately when done |
| Configure resources/scaling | Live MCP/client tool if visible; dashboard fallback | service, CPU/RAM/replicas/storage/health/ports | read current settings, apply delta, redeploy/reconcile if required | settings reflected and deployment healthy | restore captured previous settings |
| Manage variables/secrets | Live MCP/client tool if visible; dashboard fallback | variable names, non-secret values or secret source path, target service | read current names only, set/update, redeploy if runtime requires | variable names present; app healthy | restore previous values only if safely available |
| Trigger deploy/redeploy/rollback | Live MCP/client tool if visible; dashboard fallback | target service, deploy intent, commit/release if rollback | inspect current release and active operations, trigger action | deployment terminal state and logs | rollback to previous known-good release or roll forward |
| Build template | MCP documented for templates, plus local repo inspection | intended app, GitHub repo services, Docker image services, databases, variables, deployment order, template privacy | infer stack, define service order so dependencies such as databases deploy first, create personal template with placeholders, publish or keep private | template renders and deploy preview is coherent | unpublish/delete template |
| Manage Docker registry | MCP documented for registries, dashboard fallback | registry type, endpoint, username/token source, target organisation | list existing registries, test-before-write create/update | registry listed and connection test passed | delete/restore previous registry config |
| Register GitHub provider | MCP documented for GitHub app registration, browser completes install | provider label, GitHub owner/org, repo access policy | prepare registration, open install URL, complete browser install, list repos/branches | provider listed and repo/branch discovery works | uninstall GitHub app or remove provider |
| Self-hosted internal automation | User-owned dashboard/Payload session only | base URL, tenant slug, authenticated session, exact internal endpoint/action | inspect source for current action/schema, use narrow authenticated request, avoid undocumented Cloud use | object state visible in dashboard and Payload response | reverse the object/action through dashboard or matching internal endpoint |

## Worker and Host Operations

| User goal | State owner | Inputs to confirm | Action sequence | Verification | Rollback prompt |
|---|---|---|---|---|---|
| Prepare fresh dFlow worker | this repo, then dFlow | server IP, root auth, Tailscale auth key, pubkey, timezone, dFlow auth mode/CIDR | run operator prerequisite checks, run `deploy.sh --paas dflow ...`, capture Tailscale IP | Gate C/F validation with `"fail":0`; worker visible in dFlow after attach | provider rebuild or restore server snapshot if available |
| Resume prepared worker | this repo | server IP, Tailscale IP, timezone, admin user | run `deploy.sh --paas dflow --ts-ip ...` so companions re-sync and validation resumes | validation JSON and SSH over Tailscale | rerun from prior phase or rebuild |
| Attach worker node | dFlow MCP/UI plus server | name, optional description, saved/uploaded SSH key, public IPv4, SSH port, sudo-capable username, optional Tailscale address/control CIDR | ensure server validation passes, ensure selected public key is in `~/.ssh/authorized_keys`, add worker in dFlow, wait for preparation | dFlow worker healthy and attached to environment | detach worker from environment |
| Diagnose offline worker | dFlow MCP/UI plus SSH | worker id/name, expected address | read dFlow worker message, check Tailscale status, SSH, disk, base validation, Dokku/Beszel checks | root cause recorded and worker health recovers | revert the specific host/config change |
| Inspect app runtime logs | dFlow MCP/API first, SSH as needed | service, deployment id, time window | fetch dFlow logs, then SSH for Dokku/system logs only if product logs are insufficient | decisive error block identified without secrets | no rollback for read-only diagnostics |

## Verification Checklist

- Authentication: record which authenticated surface was used: MCP OAuth, dashboard browser session, client/CLA/CLI connector, or SSH/Tailscale for substrate. Do not treat SSH as dFlow product auth.
- Internal API use: record that the target is self-hosted/user-owned, the source file/schema inspected, and the exact endpoint/action used. Do not generalize this to dFlow Cloud.
- Product action: prove the object state through dFlow MCP, client/CLA/CLI structured output, or UI, not only local assumptions.
- Deployment action: capture deployment id/status, decisive log excerpt, and URL/health outcome when applicable.
- Worker action: capture `base/validate.sh --json` output or gate summary with `"fail":0` before calling substrate ready.
- Database action: verify internal credentials/reference variables before app binding; verify public exposure only if explicitly requested.
- Troubleshooting: classify failures as source, invocation, environment, upstream/runtime, or task-blocker before editing code.

## Safety Prompts

Before any externally visible or destructive operation, say:

```text
I am about to <tool/command/action> against <target>. Impact: <what changes>.
Rollback: <exact rollback or no_rollback_reason>. Confirm before I proceed.
```

Use this for deploys, rollbacks, deletes, detaches, database expose/unexpose, provider/cloud mutations, DNS changes, credential rotation, and live host service changes.

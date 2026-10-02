# Deploy/Setup Workflow Functionality Test Matrix

This matrix maps `deploy.sh` and `setup.sh` workflow steps to explicit automated tests.

| Contract ID | Workflow step | Coverage tests | Sufficiency |
| --- | --- | --- | --- |
| `DEP-01` | Deploy preflight executes prerequisite checks and root SSH probe path | `tests/unit/test_deploy_workflow_contract.bats`: `deploy: preflight phase marker exists` | Sufficient |
| `DEP-02` | Deploy phase 1 performs hardening flow and captures Tailscale sentinel IP | `tests/unit/test_deploy_workflow_contract.bats`: `deploy: phase1 upload+harden marker exists` | Sufficient |
| `DEP-03` | Deploy phase 1 invokes bootstrap with required hardening flags | `tests/unit/test_deploy_workflow_contract.bats`: `deploy: hardening invocation uses env-file and tailscale install` | Sufficient |
| `DEP-04` | Deploy Gate A retries and succeeds on the PaaS-specific Tailscale principal (root for Dokploy, admin for other overlays) | `tests/orchestrator/unit/test_deploy_workflow_contract.bats`: `deploy: gate A checks PaaS-specific SSH on tailscale`; `tests/orchestrator/unit/test_deploy_workflow_contract.bats`: `deploy: Dokploy gate A and B use root over Tailscale` | Sufficient |
| `DEP-05` | Deploy Gate B fails when the PaaS-specific SSH identity does not match | `tests/unit/test_deploy_workflow_contract.bats`: `deploy: gate B verifies admin identity` | Sufficient |
| `DEP-06` | Deploy Gate C invokes `base/validate.sh --json` and reports result | `tests/unit/test_deploy_workflow_contract.bats`: `deploy: gate C runs base/validate.sh json` | Sufficient |
| `DEP-07` | Deploy Gate D retries bounded SSH transport churn and transient firewall-refresh convergence after Docker/network reconciliation, then fails if docker-user hardening service/rules remain invalid | `tests/unit/test_deploy_workflow_contract.bats`: `deploy: gate D validates service active and managed rules`; `tests/orchestrator/unit/test_deploy_setup_additional_behavior.bats`: Gate D transport and firewall-convergence retry tests | Sufficient |
| `DEP-08` | Deploy phase 4 performs DNS updates for standard mode | `tests/unit/test_deploy_workflow_contract.bats`: `deploy: phase4 binding+dns marker exists` | Sufficient |
| `DEP-09` | Deploy Gate E blocks completion when exposure checks fail | `tests/unit/test_deploy_workflow_contract.bats`: `deploy: gate E fails when exposure checks do not pass` | Sufficient |
| `DEP-10` | Deploy final validation is executed after verification gates | `tests/unit/test_deploy_workflow_contract.bats`: `deploy: final validation is executed` | Sufficient |
| `DEP-11` | A Dokploy `--ts-ip` resume with no state file recovers only after strict proof of the interrupted root-only phase, installs audit rate-before-lock boot ordering, reboots, and reruns bootstrap without Tailscale re-enrollment | `tests/orchestrator/unit/test_deploy_setup_additional_behavior.bats`: `recover_interrupted_phase1_dokploy_remote: ...` proof-success and proof-failure tests | Sufficient |
| `SET-01` | Setup preflight executes prerequisite checks | `tests/unit/test_setup_workflow_contract.bats`: `setup: preflight phase marker exists` | Sufficient |
| `SET-02` | Setup phase 1 performs hardening flow and captures local Tailscale IP | `tests/unit/test_setup_workflow_contract.bats`: `setup: phase1 harden marker exists` | Sufficient |
| `SET-03` | Setup Gate A enforces operator verification pause | `tests/unit/test_setup_workflow_contract.bats`: `setup: gate A requires operator laptop verification` | Sufficient |
| `SET-04` | Setup Gate B validates the overlay-specific identity posture, including Dokploy's locked non-login metadata account | `tests/orchestrator/unit/test_setup_workflow_contract.bats`: `setup: gate B verifies admin user home and ssh directory`; `tests/orchestrator/unit/test_setup_workflow_contract.bats`: `setup: Dokploy gate B rejects a login-capable metadata account` | Sufficient |
| `SET-05` | Setup Gate C invokes `base/validate.sh --json` and reports result | `tests/unit/test_setup_workflow_contract.bats`: `setup: gate C runs base/validate.sh json` | Sufficient |
| `SET-06` | Setup Gate D fails if docker-user hardening service/rules are invalid | `tests/unit/test_setup_workflow_contract.bats`: `setup: gate D validates service active and managed rules` | Sufficient |
| `SET-07` | Setup phase 4 performs DNS updates for standard mode | `tests/unit/test_setup_workflow_contract.bats`: `setup: phase4 binding+dns marker exists` | Sufficient |
| `SET-08` | Setup Gate E enforces operator verification pause | `tests/unit/test_setup_workflow_contract.bats`: `setup: gate E requires operator laptop verification` | Sufficient |
| `SET-09` | Setup final validation is executed after verification gates | `tests/unit/test_setup_workflow_contract.bats`: `setup: final validation is executed` | Sufficient |

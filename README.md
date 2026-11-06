# ss-pilot

A small, manual and pull-request [StepSecurity Harden-Runner Community](https://github.com/step-security/harden-runner)
pilot on **GitHub-hosted Ubuntu**, with separate audit and block workflows.
This adds protection to existing GitHub runners; it does not provision a
StepSecurity runner pool.

## Scope and prerequisites

- Keep this repository **public** and GitHub Actions enabled. Community is free
  for public repositories on GitHub-hosted runners.
- Both workflows use inline configuration, with no StepSecurity API key, Policy
  Store, repository secrets, checkout, or token permissions. It does not require
  an Enterprise trial or assume a GitHub App installation is necessary.
- Harden-Runner is the first step, pinned to the commit for `v2.21.0`.
  The workload makes unauthenticated HTTPS GET requests to `example.com:443`
  and `api.github.com:443`, discarding response bodies.
- The audit workflow sends runtime telemetry to StepSecurity so its insights can be
  inspected. The block workflow disables event telemetry but is not fully offline.
  Do not add sensitive workloads or secrets to this pilot.
- Audit observes egress rather than applying a custom domain allowlist, but
  **StepSecurity's Global Block List remains enforced even in audit**.
- The [Community quickstart](https://docs.stepsecurity.io/workspace/getting-started/quickstart-community-tier)
  states **13,000 Harden-Runner runs per week**; beyond that limit protections
  are not enforced. That page does not specify the aggregation scope of the
  limit, so this pilot does not assume it is per repository or organization.

StepSecurity is not listed in the [PagoPA DX Technology Radar](https://dx.pagopa.it/radar.json)
at the time of setup. This experiment was explicitly approved; it is not a
production adoption decision.

## Run the pilot

Each workflow must first exist on the repository's default branch for
`workflow_dispatch` to be available. While these files are only in the PR,
opening or updating that PR triggers both workflows without merging it.

In [GitHub Actions](https://github.com/pagopa-dx/ss-pilot/actions), select
**Harden-Runner Community audit** or **Harden-Runner Community block**, then
**Run workflow** on `main`. The workflows are independent and produce distinct
run IDs and workflow names.
Alternatively, with an authenticated GitHub CLI account allowed to run workflows:

```sh
gh workflow run community-audit.yml --repo pagopa-dx/ss-pilot --ref main
gh workflow run community-block.yml --repo pagopa-dx/ss-pilot --ref main
gh run list --repo pagopa-dx/ss-pilot --workflow community-audit.yml --limit 5
gh run list --repo pagopa-dx/ss-pilot --workflow community-block.yml --limit 5
gh run watch RUN_ID --repo pagopa-dx/ss-pilot --exit-status
gh run view RUN_ID --repo pagopa-dx/ss-pilot --log
```

Replace `RUN_ID` with the ID returned by the run list. There are no inputs.
Each workflow run has one Ubuntu 24.04 job with a ten-minute timeout and bounded HTTPS
requests. Repeat manually if you want to compare observations between runs;
baseline creation and anomaly detection are not proven by a single successful run.

## Test pull-request checks

Opening, reopening, or updating a pull request targeting `main` runs the same
audit and block workflows via `pull_request`, without granting write permissions or using
`pull_request_target`. The workload stays fixed and does not execute PR code.
Fork PRs may need a maintainer's approval under GitHub Actions settings.

In the PR's **Checks** tab, distinguish the GitHub Actions job
**Community audit on GitHub-hosted Ubuntu** from a check published by the
**StepSecurity GitHub App**. A successful workflow job only proves that the
workflow ran; verify the associated insights as described below.

Dedicated [StepSecurity GitHub Checks](https://github.com/step-security/harden-runner#features-and-pricing-tiers)
are an **Enterprise** feature. Adding the PR trigger does not install the App,
activate a trial, or enable that integration. Inspect the actual check publisher
and record whether a StepSecurity check appears. Its absence is not a failure of
Community monitoring, and its presence alone does not prove anomaly detection or
blocking works.

## Test custom egress blocking

The **Harden-Runner Community block** workflow has one job on its own runner.
Harden-Runner is first, with `egress-policy: block`, `disable-telemetry: true`,
and an inline allowlist containing only `api.github.com:443` for the workload.

The positive control requests `https://api.github.com/zen` and must succeed.
The negative control requests the harmless `https://example.com/`, which is
outside the allowlist, and must fail at the transport layer. Any successful
HTTP response, including an HTTP error response, fails the negative test.
An unexpected curl error also fails the job; expected transport errors are
logged explicitly, rather than hidden with `continue-on-error`.

**Do not treat a curl failure as sufficient evidence.** After the post step,
verify an explicit block event for `example.com` in Harden-Runner's agent
logs. Cross-check that the separate audit workflow run for the same commit
successfully reaches `example.com`, and that the block workflow reaches
the allowed GitHub API endpoint. Record both request outcomes and the block
evidence. If the evidence is unavailable, enforcement remains unverified.

The test does not contact malicious domains, exercise the Global Block List,
change the audit workflow's policy, or enable Enterprise GitHub Checks.

## Test disabling event telemetry

Only the block workflow sets `disable-telemetry: true`. Its inline allowlist and
local enforcement should continue to work, while DNS and network event uploads
are disabled. The audit workflow remains the telemetry-enabled control; the flag
is not an event-telemetry opt-out in audit mode.

Inspect the block job's effective configuration (`disable_telemetry: true`,
`egress_policy: block`), the action's telemetry-disabled message, and the local
agent block event. A missing dashboard link alone is not proof that no events
were sent; dashboard access errors are not proof either.

This is **not an offline mode or a zero-data guarantee**. In the pinned action,
setup still calls StepSecurity's `/monitor` endpoint with repository/run context
and job/correlation identifiers. The Community agent also has control-plane
requests for subscription status, feature flags, and the Global Block List.
An installed GitHub App has a separate data-access path unaffected by this flag.
Previous telemetry is not deleted. Historical `community-pilot.yml` runs had
two jobs; these new workflows do not share a run ID.

Portal verification must distinguish the two workflow runs and attempts.
For audit, open the link emitted by Harden-Runner and verify the expected events.
For block, record the GitHub run ID and inspect whether StepSecurity lists that
run or its metadata; do not infer that it must appear merely because setup calls
the API. No new network events are expected with telemetry disabled. This comparison
shows both a policy difference and a telemetry difference: it is not a comparison
of allowed versus blocked events with telemetry enabled in both workflows.
Without access
to the portal or an independent HTTP trace, report configuration and enforcement
as verified but event-upload suppression as source-supported, not independently
measured. Raw agent events can still appear in GitHub Actions logs.

## Verify actual insights

These dashboard checks apply to the telemetry-enabled audit job.
**A green action or successful HTTP requests are not sufficient.**

1. Wait for the entire job, including Harden-Runner's post step, to finish.
   Inspect its logs for agent setup, upload errors, skipped monitoring, or limits.
2. Open the **security insights link emitted by Harden-Runner** in the logs or
   job summary. Check that the displayed repository, run, and job match this
   execution; do not substitute a demo or a previous run.
3. In the network events view, verify outbound connections to both
   `example.com:443` and `api.github.com:443`, correlated to the
   **Generate harmless HTTPS traffic** step. Infrastructure and telemetry
   connections may also appear; the two workload domains are not a complete
   allowlist.
4. Record the GitHub run URL, exact insights URL, observed domains/ports,
   step attribution, and outcome. If access, ingestion, quotas, or monitoring
   cannot be verified, record the blocker rather than claiming success.

Acceptance requires a successful workload **and inspected, run-specific network
events for both endpoints**. This checks Community monitoring, not every security
feature or blocking efficacy. Do not test malicious destinations to exercise the
Global Block List.

## First verified execution

On **2026-11-05**, [run 42061220366](https://github.com/pagopa-dx/ss-pilot/actions/runs/42061220366)
completed successfully on GitHub-hosted Ubuntu 24.04.
The [run-specific network insights](https://app.stepsecurity.io/github/pagopa-dx/ss-pilot/actions/runs/42061220366?tab=network-events)
were inspected, not just the GitHub job status:

| Destination | Port | Process | Step | Observed status |
| --- | --- | --- | --- | --- |
| example.com | 443 | curl | Generate harmless HTTPS traffic | Allowed |
| api.github.com | 443 | curl | Generate harmless HTTPS traffic | Allowed |

Both requests returned HTTP 200. Both network events were timestamped
`2026-11-05 16:05:59 GMT` and associated with
[job 127363276958](https://github.com/pagopa-dx/ss-pilot/actions/runs/42061220366/job/127363276958).
No access or ingestion blocker remained for this run.

The dashboard showed **Not in baseline - learning** and **99 runs left to
activate** anomaly detection after this first run. These are observed dashboard
values, not a contractual threshold or a reason to generate 99 extra runs.
Community network monitoring is verified; anomaly detection, custom egress
blocking, and self-hosted compatibility are not.

## Compare local-first alternatives

Two additional, independent workflows test the user-approved
[field-cage](https://github.com/takihito/field-cage) and
[CargoWall](https://github.com/code-cargo/cargowall-action) experiments.
Neither is listed in the DX Technology Radar; these are functional pilots,
not approval for production adoption. Existing StepSecurity workflows are unchanged.

| Workflow | Modes on separate runners | Pinned software |
| --- | --- | --- |
| `field-cage-pilot.yml` | audit / block | field-cage action and binary `v0.1.6` |
| `cargowall-pilot.yml` | audit / block (`enforce`) | action `v1.3.8`, binary `v1.3.6` |

Both use GitHub-hosted Ubuntu 24.04 and the same two harmless HTTPS requests.
`api.github.com/zen` must succeed in both modes. `example.com` must succeed in
audit and fail at transport level in block. Each job additionally requires
domain-specific **local agent evidence**, not merely a curl error or a green
action. CargoWall sets `fail-on-unsupported: true` and checks its reported
support, running PID and readiness file to reject successful no-ops.
In audit, the excluded domain must still have a denied policy verdict
(field-cage) or `would_deny: true` with `blocked: false` (CargoWall), while its
HTTPS request succeeds. An allowed event does not pass that control.
CargoWall collects any available native logs even if startup fails; missing
files are reported explicitly, and a failed guard never becomes a successful pilot.

```sh
gh workflow run field-cage-pilot.yml --repo pagopa-dx/ss-pilot --ref main
gh workflow run cargowall-pilot.yml --repo pagopa-dx/ss-pilot --ref main
```

As with StepSecurity, manual dispatch requires the files on the default branch;
the PR trigger can test them before merge. Each workflow has two matrix jobs on
different runners, with fail-fast disabled. The tools never run together in a job
or alongside Harden-Runner. Checkout is needed for the shared pilot helpers;
credentials are not persisted, the only token permission is `contents: read`,
and no secrets or OIDC permissions are granted.

Download the run's `field-cage-MODE-ATTEMPT` or `cargowall-MODE-ATTEMPT` artifact:
it retains raw agent logs, native NDJSON events, request outcomes with curl PIDs,
plain-DNS observations, and `verification.json` when acceptance passes.
Artifacts expire after seven days. Native formats differ: field-cage records
connection verdicts (a denied policy verdict in audit is **not** an actual block);
CargoWall distinguishes `would_deny` from `blocked`. A CargoWall DNS-denial event
does not provide per-process attribution. Do not assume their coverage or
attribution equals the StepSecurity portal.

CargoWall explicitly sets `offline: true` and an empty `api-url`, disabling its
CodeCargo API integration in both modes. field-cage writes reports locally.
Installation still downloads software and, for field-cage, verifies Sigstore
signatures. These are **not fully offline jobs**; artifacts are sent to GitHub,
not Azure. No Application Insights exporter is included.

An independent plain-DNS capture starts before tool installation and ends after
event collection. Acceptance requires observing both workload domains and no
StepSecurity/CodeCargo domain in that capture. **This is a limited observation,
not proof of zero vendor communication:** cached resolution, direct-IP traffic,
encrypted DNS and traffic after the capture window are not ruled out. CargoWall's
post step runs later; its API upload and native summary are disabled in this test.

The policies are not identical: CargoWall allows GitHub/Azure infrastructure on
443, matches subdomains automatically, and permits existing TCP connections by
default. field-cage's explicit infrastructure domains avoid disrupting runner
communications, but its domain policy does not restrict ports. Both exclude
`example.com` from the workload allowlist. field-cage is explicitly stopped with
an `always()` cleanup step; CargoWall uses its native post cleanup on the ephemeral
runner. The pilots do not prove bypass resistance, all-protocol coverage,
performance overhead, or compatibility with Azure Container Apps.

Validate the shared evidence checks locally with:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s .github/scripts -p 'test_*.py'
go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.7
```

## Future integration (not part of this pilot)

An eventual rollout would add Harden-Runner as the first step in each relevant
job of the reusable workflows in `pagopa/dx`, benefiting their caller repositories.
It would not transfer runners from `pagopa-dx` to `pagopa`. Repository visibility,
runner type, telemetry handling, licensing, and observed egress must be assessed
before that rollout; no changes to `pagopa/dx` or Azure infrastructure are made here.

**Self-hosted runners require Enterprise even for public repositories.** According
to the [upstream tier documentation](https://github.com/step-security/harden-runner#features-and-pricing-tiers),
without it the action can be a successful **no-op**, with no monitoring or insights.
The upstream documentation describes VM, bare-metal, and ARC support; compatibility
with self-hosted runners on **Azure Container Apps is not verified** by this pilot
and must be investigated separately with the Enterprise requirement in mind.

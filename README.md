# ss-pilot

A small, manual and pull-request [StepSecurity Harden-Runner Community](https://github.com/step-security/harden-runner)
pilot on **GitHub-hosted Ubuntu**, with separate audit and block workflows.
This adds protection to existing GitHub runners; it does not provision a
StepSecurity runner pool.

The later comparison accepts the organization's **selected Enterprise agent**
as its test target. Community remains the initial pilot scope, not a claim that
the Enterprise measurements also apply to the free tier. See the targeted
follow-up below.

For the StepSecurity discovery, see the
[focused benchmark and outstanding decisions](docs/benchmark-stepsecurity.md).
The comparative experiments below remain historical controls and are outside
the focused StepSecurity assessment.

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

## Representative DX-aligned Node build

`node-build-pilot.yml` compares all three tools in audit and block, with six
isolated Ubuntu runners. The fixture in `fixtures/node-build` uses pinned pnpm,
TypeScript, Vitest and the published `@pagopa/eslint-config`. Script names follow
the [DX npm script conventions](https://dx.pagopa.it/docs/typescript/npm-scripts);
pnpm follows the guidance returned by the DX documentation MCP tool.
The TypeScript override keeps the shared lint configuration and its test plugin
on the same peer-compatible compiler version.

The protected workload performs a cold-store `pnpm install --frozen-lockfile`,
DX lint, typecheck, ten tests, compilation and a smoke test of the generated
JavaScript. The application summarizes **synthetic** payment batches; it uses no
real payment, personal or secret data. The registry is allowlisted; `example.com`
is not. The three tools have separate job definitions, not conditionally selected
actions in one tool matrix: Harden-Runner's pre-step can run even when its main
step is skipped. Node/pnpm bootstrap precedes the field-cage/CargoWall guards;
StepSecurity is first and additionally allows `nodejs.org:443` for that bootstrap.
Its endpoint input uses a folded YAML scalar so the agent receives
space-separated entries, not newline-separated entries.
This is not a controlled performance comparison. The plain-DNS capture starts
after bootstrap and covers the build workload, not StepSecurity's initial setup.

After the legitimate build, the workflow invokes the **postinstall script of an
installed local fixture dependency** using pnpm. That script makes one bounded
HTTPS GET to `example.com`, discards its body, and sends no application data,
environment variables, credentials or custom payload. Its PID, outcome and
network error are recorded locally.

The initial dependency installation explicitly uses `--ignore-scripts`, and the
known test hook is then invoked separately. This intentionally deviates from
DX's recommendation to avoid lifecycle hooks: the hook exists only as a
controlled runtime-security fixture. **It is not a malicious package and does
not demonstrate bypassing pnpm's default dependency-build approval controls.**
In a normal project, keep those controls rather than enabling arbitrary hooks.

| Phase | Audit expectation | Block expectation |
| --- | --- | --- |
| Install, lint, typecheck, test, build, smoke | All succeed | All succeed |
| Approved dependency postinstall | HTTP 200, command succeeds | Network failure, command exits nonzero |
| Agent evidence | Registry observed; excluded destination recorded | Registry observed; explicit excluded-destination denial |

A successful block **test job** means the install hook failed as intended, not
that the hook itself completed successfully. Unexpected lifecycle errors or
absence of an agent event fail the test. Field-cage evidence is correlated by
TGID to the hook PID. CargoWall DNS events have no process attribution.
StepSecurity verification uses its local DNS records and node executable, not
exact PID correlation or inspected portal events.

The isolated runs `42202984046` and `42203434783` selected StepSecurity **AgentAlpha v1.9.0** with
organization TLS features enabled, rather than the Community agent. These
representative-build results therefore describe the installed organization's
current configuration, not a Community-only licensing or feature guarantee.
No application installation or subscription change was made by these workflows.

### Verified representative-build result

[Run 42203434783](https://github.com/pagopa-dx/ss-pilot/actions/runs/42203434783)
passed all six cases on head `828521e141a1586ce61318c2b26e862876e7cb5d`
(effective PR merge revision `2e0accfb44897d6971f8eb2304f009797d6c46f9`).
Every case completed the dependency install, lint, typecheck, ten tests,
compilation and compiled smoke test. All six artifacts were downloaded and
their native events inspected.

| Tool | Audit hook | Block hook | Native block evidence |
| --- | --- | --- | --- |
| field-cage | HTTP 200, exit 0 | `EPERM`, exit 1 | `DENY(not-in-policy)`, TGID matches Node PID 2481 |
| CargoWall offline | HTTP 200, exit 0 | `EAI_AGAIN`, exit 1 | `dns_blocked`, `blocked: true`; no PID in DNS event |
| StepSecurity, selected AgentAlpha | HTTP 200, exit 0 | `EAI_AGAIN`, exit 1 | `dns-request-dropped`, Node PID 2909 |

Run `42202602311` is not an isolated comparison: conditional Harden-Runner
pre-steps also installed its agent in the other tools' jobs. Run `42202984046`
fixed isolation, but StepSecurity block failed before the workload because its
newline-separated endpoint input was parsed incorrectly. Neither failure is
counted as a successful block demonstration.

StepSecurity retains audit telemetry and disables block event telemetry; it is
still not offline. CargoWall remains explicitly offline, and field-cage reports
locally. Independent DNS observations retain their previously documented limits.
Each `node-build-TOOL-MODE-ATTEMPT` artifact contains build logs, lifecycle outcome,
native agent evidence, capture and `verification.json`. Dependency stores and
`node_modules` are outside the artifact.

This is more representative than two curl requests but remains a small fixture,
not a production application, Docker build, deployment or bypass-resistance test.
No changes are made to `pagopa/dx` or Azure. Manual execution, once the workflow
exists on the default branch:

```sh
gh workflow run node-build-pilot.yml --repo pagopa-dx/ss-pilot --ref main
```

## Comprehensive benchmark protocol

The manually selected benchmark extends the existing fixture without running
the expensive suite on every PR update. It uses separate job definitions per
guard and a no-guard baseline. The `full` profile creates **100 case jobs**:
three fresh-runner functional repetitions and ten fresh-runner performance
samples for each of the seven baseline/audit/block configurations, plus three
fault jobs per guard. `smoke` has one functional and one performance sample per
configuration plus the same faults (23 case jobs). These profiles are not
statistically equivalent. Each guard has at most three concurrent jobs.

```sh
gh workflow run node-build-pilot.yml --repo pagopa-dx/ss-pilot \
  --ref YOUR_TEST_BRANCH -f benchmark=smoke
gh workflow run node-build-pilot.yml --repo pagopa-dx/ss-pilot \
  --ref YOUR_TEST_BRANCH -f benchmark=full
```

The functional cases cover allowed/excluded HTTPS, a different port on an
allowed host, subdomain exactness, a benign redirect, IPv4/IPv6, pre-resolved
addresses, direct IP, a Node child process, alternate DNS over UDP and Docker
bridge/host networking. Docker images are assembled locally from runner curl,
shell, their shared libraries and public CA certificates: no registry pull,
credentials or application files are needed. All probes are bounded, use
fixed harmless destinations and discard HTTP bodies. An HTTP 403 response is
transport reachability, not an enforcement success.

The common intent is exact application domains on port 443, plus documented
GitHub infrastructure exceptions. Policies cannot always express that intent:
field-cage does not restrict ports, and CargoWall host rules also match
subdomains. The report calls reachable excluded traffic a **coverage/policy
gap**, not automatically a product defect. IPv6 or an endpoint that does not
work without a guard cannot prove blocking.

Performance jobs measure install, DX lint, typecheck, ten tests, compilation
and compiled smoke using GNU time. The first install uses an empty pnpm store;
the second explicitly reinstalls offline from that store on the same runner.
The lifecycle probe is excluded from summed phase timings. Reports retain
wall time, user/system CPU and maximum command RSS, stratified by runner image,
kernel, CPU model and vCPU count. Maximum command RSS is not total concurrent
job/container memory. Small samples and heterogeneous hosts do not justify a
performance ranking or a reliable p95.

Fault jobs deliberately supply a missing release/binary or invalid policy,
terminate the verified guard PID on an ephemeral runner, and exercise an actual
GitHub step deadline plus a bounded child-process timeout. These are isolated
from performance jobs. Cancellation has its own three-job run:

```sh
gh workflow run node-build-pilot.yml --repo pagopa-dx/ss-pilot \
  --ref YOUR_TEST_BRANCH -f benchmark=cancellation
# Wait for all three "Wait for an externally requested GitHub job cancellation"
# steps to be running, then cancel only that dedicated run:
gh run cancel RUN_ID --repo pagopa-dx/ss-pilot
```

Never cancel the full benchmark to exercise this case. A cancelled run or
failed injected startup is not, by itself, a tool failure. Check the marker,
guard outcome, application gate and native cleanup steps. Guard exit can leave
residual protection or a restart; the report does not infer fail-closed
network enforcement merely because a subsequent request times out.

A pinned repository-owned observer starts in an action pre-step before guard
setup, captures packet text metadata and samples socket/process metadata,
then stops after native post actions. It does not collect HTTP bodies, decrypt
TLS or read arbitrary environment variables. Runner boot and action download
precede this observer. Uploaded snapshots precede native cleanup; the later
`BENCHMARK_OBSERVER_FINAL` record in each job log retains vendor DNS names,
destination endpoints, observer health, process names and explicit truncation.
Cached DNS, unidentified vendor IPs and encrypted traffic still rule out a
zero-egress guarantee.

Collect one completed run, including final post-step observer records and
log-backed results when artifact upload failed, then aggregate it:

```sh
python3 .github/scripts/benchmark_collect.py \
  --run-id RUN_ID --directory PATH_TO_ARTIFACTS
python3 .github/scripts/benchmark_report.py \
  --directory PATH_TO_ARTIFACTS --profile full \
  --jobs PATH_TO_ARTIFACTS/jobs.json --output PATH_TO_REPORT
```

Use a separate directory for each run/attempt. Collection is resumable and skips
placeholder jobs without logs. The jobs JSON includes steps and their final
conclusions; it can be omitted for artifact-only analysis.
The report emits `passed`, `failed`, `unsupported` and `inconclusive`, requires
matching unprotected controls for denials, rejects incomplete/duplicate cohorts
and preserves native observations. **Green collection jobs mean the harness
completed, not that every security requirement passed.** Missing diagnostics or
uncorrelated network errors never become verified denials.

The official pinned StepSecurity action has no supported input to force the
Community agent. Record the actual agent build; an Enterprise-selected run
cannot establish Community behavior. This benchmark does not change the
organization's App, subscription, Azure infrastructure or `pagopa/dx`.

### Comprehensive results: 9 November 2026

[Full run 42607755421](https://github.com/pagopa-dx/ss-pilot/actions/runs/42607755421)
executed all **100 case step sequences** at revision
`8f24597ec8a11c1d74a83839cc9b43759715372a`. All 100 results were collected:
99 uploaded artifacts and one CargoWall crash result recovered from its job
log. All 161 legitimate build passes succeeded (91 cold, 70 warm), including
the ten Vitest tests per pass. The 21 functional jobs produced 294 observations:
234 passed, 15 failed the intended policy, 9 were unsupported and 36 were
inconclusive. These totals include baseline and audit: they are **not a security
score or product ranking**.

The overall GitHub run is **cancelled, not green**. After CargoWall's real
`SIGKILL`, both allowed and excluded DNS probes failed, artifact upload failed,
and GitHub still showed the job running after its native posts and `Complete
job` had finished. Server-side force-cancellation was requested only after all
100 case step sequences finished. Its successful native post step does not
establish recovery. The external completion observation is retained separately
from the application gate and network verdicts.

Each cell below describes all three block repetitions. "Confirmed" requires a
successful unprotected control and correlated native denial, not just curl
failure. The allowed HTTPS row instead verifies the positive control.

| Probe | field-cage | CargoWall offline | StepSecurity, selected Enterprise |
| --- | --- | --- | --- |
| Allowed HTTPS | Reached | Reached | Reached |
| Excluded HTTPS, IPv4, redirect, child process, dependency postinstall | Confirmed block | Confirmed block | Confirmed block |
| Allowed hostname on excluded port 80 | Reached: policy gap | Confirmed block | Failed transport; inconclusive |
| `www.example.org` when only `example.org` is intended | Reached: policy gap | Reached: policy gap | Confirmed block |
| Pre-resolved excluded HTTPS and direct-IP HTTP | Confirmed block | Confirmed block | Failed transport; inconclusive |
| Alternate DNS to `1.1.1.1:53` over UDP | Reply received: coverage gap | Reply received: coverage gap | Confirmed block |
| Docker bridge and host networking | Confirmed block | Confirmed block | Confirmed block |
| Excluded HTTPS over IPv6 | Unsupported control | Unsupported control | Unsupported control |

field-cage cannot express the port restriction; CargoWall deliberately matches
subdomains. The field-cage subdomain request returned HTTP 200 on a shared CDN
address even though its native log contained denials for that PID/hostname.
This proves the tested policy intent was not enforced end-to-end, not the
internal cause or a general vulnerability. A `DENY` log alone is insufficient.
StepSecurity's failed port/direct-IP transports lack the required correlated
denial in this collector, so they are not counted as verified blocks.

| Fault | field-cage | CargoWall offline | StepSecurity, selected Enterprise |
| --- | --- | --- | --- |
| Invalid startup configuration | Missing release rejected | Missing binary rejected | Invalid policy accepted; actual startup failure not induced |
| Real agent `SIGKILL` | Harness gate rejected dead agent, but diagnostic excluded request succeeded | Harness gate rejected dead agent; DNS/upload/completion failure, not proven residual enforcement | Signal rejected with `EPERM`; actual agent exit unsupported |
| Actual GitHub step deadline and child timeout | Passed | Passed | Passed |
| Dedicated GitHub cancellation | Passed | Passed | Passed |

The application gate is a **benchmark PID-availability check**, not native
product fail-closed behavior. Diagnostic probes after termination deliberately
bypass that gate; the application workload does not.
[Cancellation run 42607580878](https://github.com/pagopa-dx/ss-pilot/actions/runs/42607580878)
was cancelled while all three protected jobs were waiting. All three final
observer records, artifacts and native post steps were retained; field-cage's
explicit stop also succeeded. In the full run, 357 native post steps reported
success; field-cage stop succeeded in 28 cases and was correctly skipped for
the missing-release case. These are execution observations, not proof of every
restored network setting.

All 100 independent observers produced final records with no reported errors
or truncated destination lists. StepSecurity audit jobs resolved
`agent.api.stepsecurity.io` and `prod.app-api.stepsecurity.io`; block jobs with
`disable-telemetry: true` resolved `agent.api.stepsecurity.io`. No
StepSecurity/CodeCargo DNS names were observed for field-cage or CargoWall.
This includes guard setup and native cleanup, but not runner boot/action
downloads before the observer, TLS payloads, all vendor IPs or encrypted DNS.
It is **not a zero-vendor-egress guarantee**.

Ten performance samples per configuration covered five CPU models. On the
common AMD EPYC 9V74 stratum, build-time medians in seconds were:

| Configuration | Samples | Cold | Warm-store offline |
| --- | --- | --- | --- |
| Baseline | 4 | 5.21 | 4.25 |
| field-cage audit / block | 3 / 2 | 5.39 / 5.35 | 4.33 / 4.08 |
| CargoWall audit / block | 3 / 5 | 5.34 / 5.09 | 4.20 / 4.13 |
| StepSecurity audit / block | 5 / 3 | 5.56 / 5.94 | 4.55 / 4.37 |

These are sums of the six measured build stages, excluding the lifecycle probe
and guard setup. The within-stratum baseline median is 5.21 seconds cold and
4.255 seconds warm before rounding. Guard setup medians across the 26
functional/performance jobs per tool were 4s field-cage, 6s CargoWall and 4s
StepSecurity. Tiny workloads, 1-5 samples per host stratum, concurrent scheduling
and image hardware variability prevent a reliable overhead ranking or p95.
CPU and maximum command RSS remain in the generated report.

StepSecurity again selected **AgentAlpha v1.9.0**, not Community. Community-only
behavior, forced agent exit, Azure export and Container Apps compatibility remain
unverified. The corrected
[smoke run 42607527343](https://github.com/pagopa-dx/ss-pilot/actions/runs/42607527343)
retained all 23 results and reproduced CargoWall's reporting failure. The first
smoke run exposed harness PID/preparation bugs and is excluded from the cohort.

For a reporting-stuck run, the collector's `--allow-finished-steps` option
refuses to proceed while any case is still active/queued. If an external
supervisor requested force-cancellation, retain its run-specific observation
with `--supervision PATH_TO_COMPLETION_SUPERVISION_JSON`; never force-close an
active workload to manufacture a complete cohort. Results recovered only from
logs explicitly lack the corresponding raw artifact files.

## Targeted gap follow-up: 10 November 2026

The follow-up keeps **GitHub-hosted `ubuntu-24.04` unchanged**, without selecting
different hardware, changing App/licenses, or adding infrastructure.
StepSecurity **AgentAlpha v1.9.0**, commit
`9e7591720a8bc192175636daf04587b2e74a48eb`, is the accepted Enterprise target.
Community-only execution is no longer a prerequisite for this phase.
No new performance ranking is inferred from these functional experiments.

| Cohort | Runtime revision | Actual result |
| --- | --- | --- |
| [Targeted gaps, 42800523074](https://github.com/pagopa-dx/ss-pilot/actions/runs/42800523074) | `593e90368ee8954d0bcd1e292079cd8cef53ca85` | 45/45 results; 43 uploaded artifacts, two CargoWall crash results recovered from logs; **cancelled** after all actual sequences/posts finished |
| [UDP socket contrast, 42800681518](https://github.com/pagopa-dx/ss-pilot/actions/runs/42800681518) | `c8b5ca20c9d87b3a42690ce6716dd93b2dd61c1b` | 4/4 results; **success** |
| [DNS-priming crossover, 42801673072](https://github.com/pagopa-dx/ss-pilot/actions/runs/42801673072) | `6f20333768e04f84f2c360ebf152efc8ab5a4d06` | 4/4 results; **success** |
| Warm shared-IP contrast: [42802597958](https://github.com/pagopa-dx/ss-pilot/actions/runs/42802597958), [42802839149](https://github.com/pagopa-dx/ss-pilot/actions/runs/42802839149), [42802846038](https://github.com/pagopa-dx/ss-pilot/actions/runs/42802846038) | `3fdc948ac13e4533140a82414d418a37d9d36aea` | 12/12 results over three fresh-runner repetitions; all three runs **success** |

All **65 valid case jobs** have healthy final independent observer records,
without capture errors or destination-list truncation. An earlier 45-case
attempt, [42800069985](https://github.com/pagopa-dx/ss-pilot/actions/runs/42800069985),
hit the explicit 20 MB packet-text limit in one baseline job and is not the final
privacy cohort. The corrected targeted observer retains all UDP, IPv4 TCP
SYN/FIN/RST and IPv6 TCP, plus sampled socket metadata; it still has the same
explicit size limit. Original full-profile capture is unchanged.

The 45-case cohort alternates excluded-first, allowed-first and pre-resolved
request variants, each on three fresh runners per tool/baseline. Its 260
observations contain 212 passes and 48 intended-policy failures, not a security
score. Local-source review and focused contrasts clarify the failures:

| Requirement / experiment | field-cage | CargoWall offline | StepSecurity Enterprise |
| --- | --- | --- | --- |
| Exact hostname on shared CDN IP, all nine order/address variants | Subdomain reached 9/9 | Subdomain reached 9/9; rules include subdomains | Subdomain denied with native proof 9/9 |
| Excluded port 80 on an allowed host | Reached 9/9; ports not expressible | Native denial 9/9 | Native packet denial 9/9 |
| Pre-resolved excluded HTTPS / direct-IP HTTP | Native denial 9/9 each | Native denial 9/9 each | Native packet denial 9/9 each |
| Alternate DNS, unconnected UDP `sendto` | Reply received | Reply received | Native denial |
| Same DNS destination, connected UDP `connect` + `send` | Native denial | Reply received | Native denial |
| Allowed HTTPS pinned before normal guarded DNS | Succeeded | Succeeded | Denied in all three original pinned cases and the crossover |
| Same pinned allowed address after ordinary allowed HTTPS | Succeeded | Succeeded | Succeeded in the crossover |
| Excluded `www.example.org` pinned to a shared address after allowed DNS | Reached 3/3 | Reached 3/3 | Reached 3/3 |

StepSecurity packet proof now requires native `[net-dropped]` evidence matching
**PID, destination IP, port and probe interval**, together with an unprotected
control. The old port/direct-IP inconclusives were an evidence-parser gap;
the new cold pinned-address failure is a separate **allowed-traffic compatibility
gap**. The crossover demonstrates DNS-learning dependence, not that every
pre-resolved application is safe after an arbitrary warm-up.

**Warm shared-IP changes the interpretation for all three tools.** After a normal
request to allowed `example.org`, a pinned request to excluded
`www.example.org` reaches the shared CDN address **3/3 times per guard**, including
with StepSecurity. Each repetition has 17 passes and seven intended-policy
failures over 24 observations, including the baseline controls.
The nine earlier StepSecurity subdomain denials therefore do **not** establish
hostname isolation when an allowed address has already been learned and DNS is
bypassed. Native DNS records show the shared address learned for the allowed
hostname. This is a gap relative to the intended exact-host policy, not an
automatically established product vulnerability. Vendor guidance is needed on
the supported policy boundary and handling of both allowed and excluded pinned
traffic.

field-cage's pinned
[BPF source](https://github.com/takihito/field-cage/blob/b43cc7fd609580579cf9f233dc654fa1119aa220/internal/ebpf/bpf/block.c)
enforces an IP allowlist using connect4/connect6 hooks, not hostname/port
isolation or an unconnected UDP sendmsg hook. Allowed domains seed addresses
at startup. `example.org` and `www.example.org` shared addresses in all nine
cases, and changing request order or bypassing DNS did not remove the gap.
A userspace hostname denial is not proof that the shared IP was blocked.
The connected/unconnected contrast supports this model; it does not exhaust
all protocols or bypasses.

### Agent loss, cleanup and workflow-level mitigation

Real before-workload and during-workload agent termination reproduced both
local-first failure modes. field-cage allowed excluded diagnostic HTTPS after
agent loss; its explicit stop/native posts left allowed DNS and HTTPS usable.
CargoWall lost allowed DNS/HTTPS, artifact upload and completion reporting in
both cases, including after native cleanup. The allowed post-cleanup control
failed only in those two crash jobs.

CargoWall's pinned
[cleanup implementation](https://github.com/code-cargo/cargowall-action/blob/e5ed6c46902e295d7a791a15564056e9a3d1aafb/src/cleanup.ts)
deliberately leaves its agent, DNS and BPF state until VM disposal. Therefore an
excluded destination remaining blocked after a healthy post step is **not**
a cleanup defect. A green native post does not establish crash recovery.
The two crash jobs were force-closed only after all 45 actual case sequences
and native posts finished; their log-recovered results and supervision records
are explicitly labelled.

For both tools, the benchmark supervisor detected agent loss while a bounded
synthetic sleeping process was alive and terminated that process by SIGTERM
about **2.015-2.018 seconds after injection**. This verifies our workflow-level
mitigation, **not native fail-closed behavior or termination of a real build**.
StepSecurity again accepted the invalid policy value: actual startup failure
and supported agent-loss testing remain unverified.

### Telemetry without the audit/block confound

Four fresh-runner cases hold policy mode fixed while toggling the flag.
The actual AgentAlpha configuration confirms the requested `DisableTelemetry`
value in each case.

| Mode | `disable-telemetry` | Observed StepSecurity DNS names |
| --- | --- | --- |
| audit | false | `agent.api.stepsecurity.io`, `prod.app-api.stepsecurity.io` |
| audit | true | `agent.api.stepsecurity.io`, `prod.app-api.stepsecurity.io` |
| block | false | `agent.api.stepsecurity.io`, `prod.app-api.stepsecurity.io` |
| block | true | `agent.api.stepsecurity.io` |

This is **one sample per combination**, including guard setup and native posts,
not TLS payload inspection or proof that event upload is suppressed. Audit plus
the flag does not demonstrate a vendor-egress opt-out; block plus the flag
still has control-plane traffic. No StepSecurity/CodeCargo DNS names were
observed for the local-first tools. None of these observations guarantees
zero vendor communication.

### Measured Enterprise versus documented Community

The [pinned upstream README](https://github.com/step-security/harden-runner/blob/05e31511f85b41b11d1cf0ef85d0992719546e2c/README.md)
documents Community network correlation, baseline/anomaly detection, domain
egress blocking, Global Block List even in audit, and source-modification
detection. Enterprise adds private/self-hosted coverage, dedicated GitHub
Checks, GitHub API HTTPS visibility/token-permission recommendations and
more detailed file/process observability. This is a **documentary comparison**,
not feature equivalence demonstrated by the Enterprise benchmark.
Community's public-only eligibility and documented 13,000-run weekly limit
still apply; the documented quota aggregation scope remains unspecified.

Reproduce the focused experiments without the performance suite:

```sh
gh workflow run node-build-pilot.yml --repo pagopa-dx/ss-pilot \
  --ref YOUR_TEST_BRANCH -f benchmark=gaps
gh workflow run node-build-pilot.yml --repo pagopa-dx/ss-pilot \
  --ref YOUR_TEST_BRANCH -f benchmark=udp
```

`gaps` is the 45-case cohort; `udp` is the four-case socket/priming contrast.
Collect/report each run separately with `--profile gaps` or `--profile udp`.
Questions prepared, **not sent upstream**: supported StepSecurity pinned-address
handling and warm shared-IP hostname isolation, invalid-policy validation, telemetry semantics by mode and safe
startup/agent-loss tests; CargoWall crash/reporting recovery; field-cage
shared-IP/port/unconnected-UDP support boundaries. Hostname semantics and fault
handling still need acceptance or remediation before rollout. IPv6 without a
working baseline, Container Apps, Azure export and organization-wide scale
remain outside the demonstrated coverage.

## Related experiment: combined firewall and detector

The reusable-action prototype is being reviewed separately in
[PR #4](https://github.com/pagopa-dx/ss-pilot/pull/4). Historical evidence for
the four-control comparison remains in
[run 42835664227](https://github.com/pagopa-dx/ss-pilot/actions/runs/42835664227);
the prototype is experimental and is not approved for rollout.
It is outside the scope of the StepSecurity-focused discovery.

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

# ss-pilot

A small, manual and pull-request [StepSecurity Harden-Runner Community](https://github.com/step-security/harden-runner)
pilot on **GitHub-hosted Ubuntu**, with separate audit and block jobs.
This adds protection to existing GitHub runners; it does not provision a
StepSecurity runner pool.

## Scope and prerequisites

- Keep this repository **public** and GitHub Actions enabled. Community is free
  for public repositories on GitHub-hosted runners.
- The workflow uses inline configuration, with no StepSecurity API key, Policy
  Store, repository secrets, checkout, or token permissions. It does not require
  an Enterprise trial or assume a GitHub App installation is necessary.
- Harden-Runner is the first step, pinned to the commit for `v2.21.0`.
  The workload makes unauthenticated HTTPS GET requests to `example.com:443`
  and `api.github.com:443`, discarding response bodies.
- Monitoring sends runtime telemetry to StepSecurity so its insights can be
  inspected. Do not add sensitive workloads or secrets to this pilot.
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

The workflow must first exist on the repository's default branch for
`workflow_dispatch` to be available.

In [GitHub Actions](https://github.com/pagopa-dx/ss-pilot/actions), select
**Harden-Runner Community pilot**, then **Run workflow** on `main`.
Alternatively, with an authenticated GitHub CLI account allowed to run workflows:

```sh
gh workflow run community-pilot.yml --repo pagopa-dx/ss-pilot --ref main
gh run list --repo pagopa-dx/ss-pilot --workflow community-pilot.yml --limit 5
gh run watch RUN_ID --repo pagopa-dx/ss-pilot --exit-status
gh run view RUN_ID --repo pagopa-dx/ss-pilot --log
```

Replace `RUN_ID` with the ID returned by the run list. There are no inputs.
Each run has two Ubuntu 24.04 jobs with ten-minute timeouts and bounded HTTPS
requests. Repeat manually if you want to compare observations between runs;
baseline creation and anomaly detection are not proven by a single successful run.

## Test pull-request checks

Opening, reopening, or updating a pull request targeting `main` runs the same
audit and block jobs via `pull_request`, without granting write permissions or using
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

The **Community block on GitHub-hosted Ubuntu** job runs on its own runner.
Harden-Runner is first, with `egress-policy: block` and an inline allowlist
containing only `api.github.com:443` for the workload.

The positive control requests `https://api.github.com/zen` and must succeed.
The negative control requests the harmless `https://example.com/`, which is
outside the allowlist, and must fail at the transport layer. Any successful
HTTP response, including an HTTP error response, fails the negative test.
An unexpected curl error also fails the job; expected transport errors are
logged explicitly, rather than hidden with `continue-on-error`.

**Do not treat a curl failure as sufficient evidence.** After the post step,
verify an explicit block event for `example.com:443` in Harden-Runner's agent
logs or run-specific network insights. Cross-check that the audit job in the
same run successfully reaches `example.com`, and that the block job reaches
the allowed GitHub API endpoint. Record both request outcomes and the block
evidence. If the evidence is unavailable, enforcement remains unverified.

The test does not contact malicious domains, exercise the Global Block List,
change the audit job's policy, or enable Enterprise GitHub Checks.

## Verify actual insights

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

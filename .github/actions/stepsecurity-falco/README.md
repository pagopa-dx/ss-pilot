# Experimental StepSecurity Harden-Runner and Falco runtime guard

**Pilot only: not approved or ready for rollout.** This action combines
StepSecurity Harden-Runner egress control with a local Falco detector. It is
intended for isolated, disposable GitHub-hosted Ubuntu experiments with
synthetic workloads, not sensitive workloads or production builds.

The detector is **not Falco Actions**. The upstream Falco Actions adapter's
0.39.2 image did not start reliably in an independent diagnostic. This pilot
instead uses its own lifecycle adapter and the official Falco 0.45.2 image
pinned by digest. It loads Falco's default rules and one controlled process
marker rule; detecting that marker does not establish general coverage.

## Example

Use the full commit SHA of this PR's head (or an approved release commit) in
place of `<COMMIT_SHA>`. The repository must be accessible to the caller. Run
this as the first action in a dedicated job, on a fresh GitHub-hosted runner:

```yaml
permissions:
  contents: read

jobs:
  isolated-pilot:
    runs-on: ubuntu-24.04
    steps:
      - name: Start the experimental runtime guard
        uses: pagopa-dx/ss-pilot/.github/actions/stepsecurity-falco@<COMMIT_SHA>
        with:
          disable-telemetry: "true"
          allowed-endpoints: >-
            api.github.com:443 github.com:443
            *.githubusercontent.com:443 *.githubapp.com:443
            *.blob.core.windows.net:443 *.trafficmanager.net:443
            auth.docker.io:443 registry-1.docker.io:443
            *.docker.io:443 *.docker.com:443
      # Only run a controlled, non-sensitive workload here.
```

`egress-policy` defaults to `block` when omitted; set it explicitly to `audit`
to select audit mode. **Block requires an appropriate `allowed-endpoints`
allowlist for the entire job**, including actions, image downloads, and the
workload. An empty or incomplete allowlist can disrupt the job. The endpoints
above are a starting point for the pilot, not a complete policy for an
arbitrary job. Use a folded scalar for the space-separated allowlist.
The other input is `disable-telemetry` (`true` or `false`, default `true`).
Disabling event telemetry does not disable control-plane communication. Audit
mode can still enforce StepSecurity's Global Block List.

The composite references the lifecycle adapter at a separate immutable commit
in this PR's history. Update that pin when changing the adapter; copying only
the composite or deleting access to the pinned commit will break consumers.
The integration workflow calls the composite at an immutable commit in the
same history to exercise remote action resolution. Update its pin when changing
either action; the workflow checks that the tested snapshot matches the
implementation under review.

## Known limitations and risks

- **Do not rely on a step-level `if` to disable the firewall.** A prior
  GitHub-hosted experiment showed that Harden-Runner's nested `pre` ran in
  block mode even when the composite step was skipped. Use separate jobs.
  Input validation in the composite runs after that pre-step and cannot prevent
  it from acting on invalid input.
- The adapter uses a privileged Docker container, the host Docker socket,
  host `/proc` and `/etc`, and tracefs. It is not a least-privilege design.
  Falco events may contain sensitive process data; perform a privacy and
  retention review before considering non-synthetic workloads.
- Startup requires a matching native event for an exact marker PID; the post
  step stops and removes only the recorded container. This is not continuous
  supervision or fail-closed protection: the detector can die during a job.
  A crash between container creation and recording its ID can leave an
  unowned container, which cleanup refuses to remove. A hard runner
  termination may prevent the post step from running.
- A controlled prior test observed firewall denial and a native Falco event
  together. It does not establish full detection coverage, production
  reliability, or performance. Egress enforcement also has a known shared-IP
  hostname limitation that needs separate assessment.
- Self-hosted runners require Harden-Runner Enterprise, including for public
  repositories; without it the action can succeed without monitoring.
  Compatibility with self-hosted Azure Container Apps runners is **unverified**.
  No self-hosted deployment design or DX/Azure change is included here.
  Do not test in DX without Security approval.

Rule selection, privileges, network access, support, privacy, supervision and
the conditional pre-step behavior must be addressed before any rollout.

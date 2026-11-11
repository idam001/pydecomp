# Security policy

## Supported versions

| Version | Supported |
|---|---|
| 8.1.x | ✅ |
| 7.x | security fixes only |
| < 7.0 | ❌ |

## Reporting a vulnerability

pydecomp is a tool that parses hostile files, so a vulnerability here can mean
arbitrary code execution on an analyst's machine. Please report privately:

- **E-mail:** idamemmanuel@users.noreply.github.com (PGP fingerprint is published in the
  release notes; encrypt if your report contains a live sample)
- **GitHub:** Security → *Report a vulnerability* (private advisory)

Please do **not** open a public issue for anything that could be exploited.
Include: affected version (`pydecomp --version`), platform, the smallest
reproducer you can share (hex of the offending blob is fine), and the impact you
think it has.

We aim to acknowledge within **3 working days** and to ship a fix or a
mitigation within **30 days** for high-severity issues. Reporters are credited
in the advisory and the CHANGELOG unless they ask otherwise.

## Threat model

**What pydecomp promises**

| Promise | How it is enforced |
|---|---|
| Never executes the sample | No `exec`/`eval`/`compile` of sample bytes; `test_v5` statically scans the package for those call shapes; the only `exec` loads pydecomp's own sidecar. |
| Never imports the sample | Everything is parsed as bytes. `importlib` is never pointed at a recovered file. |
| Never spawns the sample | No `subprocess`, no `os.system`, no shell in the analysis path. |
| Bounded resources | `PYDECOMP_MAX_BYTES` (32 MiB/layer), `PYDECOMP_MAX_LAYERS` (25), recursion and cycle guards, no unbounded allocations from declared sizes. |
| No network | The package imports no networking module outside the evaluator whitelist, which refuses sockets entirely. |

**What it does not promise**

- **Resource exhaustion.** A well-formed 2 GB input inside the size ceiling can
  still take minutes and gigabytes of RAM. Run untrusted samples with limits
  (`ulimit -v`, container memory caps).
- **Terminal escape injection.** Recovered strings can contain ANSI sequences.
  The CLI filters control characters from anything it prints, but if you `cat`
  a recovered file in a terminal that honours escapes, that is your terminal.
- **Sandboxing.** pydecomp is an analyser, not a sandbox. Do not run the
  recovered output; it is malware by definition.

## Hardening checklist for analysts

```bash
ulimit -v 4000000                 # 4 GB address space
PYDECOMP_MAX_BYTES=16777216 pydecomp sample.bin
pydecomp sample.bin --reports       # keep the audit next to the output
```

Run inside a disposable container or VM:

```bash
docker run --rm -v "$PWD:/w" --memory=2g --network=none -it ghcr.io/pydecomp/pydecomp sample.bin
```

## Dependency policy

pydecomp has **zero runtime dependencies**. That is a security feature: there is
no supply chain between you and the analyser. Optional extras (`cython`, docs)
are development-only and never imported by the engine.

The single-file build is reproducible: `python3 tools/build_single.py --check`
fails if `dist/pydecomp.py` does not match the sources, so you can verify a
download against a checkout.

## Known non-issues

- `_PydecompUnknown` appearing in output is not a vulnerability; it is the tool
  telling you a value could not be statically resolved.
- Recovery of a payload that itself calls `exec` is expected — pydecomp reports
  it in the audit but does not follow it.

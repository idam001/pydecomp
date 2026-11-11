# Governance

pydecomp is a small, focused tool. Its governance is deliberately light so that
the maintainers can keep the gates green and the output honest.

## Roles

### Contributors

Anyone who opens an issue, reports a sample, reviews a pull request or sends
code. No membership, no paperwork beyond the [Code of Conduct](CODE_OF_CONDUCT.md).

### Reviewers

Contributors who have landed several changes and consistently review well. A
reviewer can approve PRs in their area (decoders, bytecode, docs, native) but
cannot merge without a maintainer.

### Maintainers

Own the release process, the gates and the security advisories. Responsible for:

- merging to `main`,
- publishing releases and the single-file build,
- triaging `SECURITY.md` reports,
- deciding scope (see *Scope discipline* below).

Current maintainers are listed in [.github/CODEOWNERS](.github/CODEOWNERS).

### Benevolent dictator

The project currently has a single lead maintainer who breaks ties. This is not
a permanent arrangement: when there are three or more active maintainers, the
tie-breaker moves to a simple majority vote of maintainers, recorded in the PR.

## Decisions

| Decision | How it is made |
|---|---|
| Bug fix, new decoder, docs | Pull request + one reviewer. |
| New public API, output format change, new dependency | Issue with a design note, lazy consensus for 7 days among maintainers. |
| Anything that would execute, import or spawn a sample | **Never.** The static-only rule is not up for a vote. |
| Breaking change | Minor/major version bump, CHANGELOG entry, migration note in the PR. |

"Lazy consensus" means: propose in an issue, wait 7 days, proceed unless a
maintainer objects with a reason. Silence is consent; a block must come with a
concrete objection that can be answered.

## Scope discipline

pydecomp stays one tool, not a platform:

- **In scope:** static recovery of Python source, decoding of Python packaging
  layers, bytecode lifting, output quality and reporting, and analysis of
  Python payloads carried inside native binaries.
- **Out of scope:** running samples, dynamic instrumentation, network
  fetching, general-purpose machine-code decompilation into C, abuse tooling.

Options 2 (Cython/native) and 3 (ELF payloads) are shipped as a *preview*
front-end. They follow the same static-only rule and are developed at a slower
cadence than option 1 (pure-Python scripts), which remains the priority.

## Releases

- Semantic versioning on the public API (`pydecomp.*` re-exports).
- Every release: gates green, `build_single.py --check` clean, CHANGELOG
  updated, tag `vX.Y.Z`.
- Cadence: whenever there is something worth shipping, not on a clock.
- A release is never made from a branch with a failing gate, including `bench`.

## Adding maintainers

A maintainer nominates a reviewer who has been active for at least three months
and has landed at least ten substantive changes. Existing maintainers have one
week to object. If nobody objects, the nominee is added to `CODEOWNERS` and
`CITATION.cff`.

## Removing maintainers

Maintainers who are inactive for twelve months move to *emeritus* status
(recorded in this file, no merge rights). Access is removed immediately for
any breach of the Code of Conduct or the security policy.

## Changing this document

Open a PR. Governance changes need approval from every active maintainer.

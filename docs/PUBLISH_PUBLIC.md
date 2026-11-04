# Publishing a public snapshot

The private repository stays private. A public copy is a separate repository,
one sanitized commit, produced by `tools/publish-public/publish.sh`. That
script is the Vigil publish-public tool. It does not rewrite this repository
and it does not force-push.

## Setup

```bash
cp tools/publish-public/examples/denylist.example .publish-public.denylist
```

Add private literals to `.publish-public.denylist`. Do not delete the regex
lines from the example. Device names, hardware UDIDs, and personal emails
that must not ship go in that file and in `.publish-public.local.yml` as
`from` / `to` pairs. Both files are gitignored.

Proposed public repository, named for agentic iPhone use:

`https://github.com/TysonIsham7/agentic-iphone-use.git`

The private repository stays `webdriveragent-hardened`. That public remote is not created by this script. `TysonIsham7/agentic-iphone-use` was not found on GitHub when this config was set, so the slug is free under that account.

## Practice

```bash
bash tools/publish-public/publish.sh --report /tmp/publish-public-report.txt
```

The default is a dry run. A denylist hit or a gitleaks hit stops the run.
Nothing is pushed. Read the report. Do not remove a denylist rule to make
the run pass. Fix the tree or add a replacement that runs before the scan.

## Push

Pass `--push` only after a clean practice report and an explicit yes from
the owner. The push is a fast-forward of one new commit to `public_branch`.
It is not `git push --public` and it is not a force-push.

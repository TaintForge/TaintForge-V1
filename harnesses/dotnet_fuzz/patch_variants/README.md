# .NET patch-variant lane

This lane mines only official `dotnet/runtime` and `dotnet/aspnetcore` GitHub security
advisories and release-tag comparisons. It turns known fixes and regression tests into a ranked,
claimable variant-analysis queue mapped onto the stock local 10.0.12 targets.

Known CVEs are controls, not findings. Promotion requires a distinct root cause or incomplete fix,
reproduction on unmodified 10.0.12, attacker reachability, and a deterministic security oracle.

```bash
harnesses/dotnet_fuzz/patch_variants/campaign.sh refresh
harnesses/dotnet_fuzz/patch_variants/campaign.sh status
harnesses/dotnet_fuzz/patch_variants/campaign.sh claim --owner H
harnesses/dotnet_fuzz/patch_variants/campaign.sh complete \
  --id TASK_ID --owner H --result reviewed --note "No current sibling omitted the invariant"
```

Persistent output is under `workspace/dotnet-bounty/patch-variants/`:

- `advisories.json`: normalized official advisories;
- `variant-queue.json`: full patch hunks, current-path mappings, and review state;
- `SUMMARY.md`: top open tasks and category counts;
- `cache/`: official GitHub API responses, retained for reproducibility and rate-limit safety.

Use `GITHUB_TOKEN` or `GH_TOKEN` when available. Anonymous GitHub API access also works; the
12-hour cache prevents needless requests.

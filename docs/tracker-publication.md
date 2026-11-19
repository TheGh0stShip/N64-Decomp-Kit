# Publish matching decompilation progress

Use this procedure for each title import and every later progress change. Preserve the title repository's existing reporting conventions. Madden 64 is the reference for separate matched-code and matched-function tracks.

1. Pin the ROM revision by hash and identify the exact catalogue and run used for verification. Record whether the catalogue is complete, doubtful, or incomplete. Keep revisions and overlay image identities explicit.
2. Replay each strict C result against that ROM. Carry receipt-backed C into `MATCHED.tsv` with image, linked address, owned `code_size`, source, and recipe. Give assembly, assembly-assisted C, and unresolved symbols separate classifications. Record donor provenance where it applies.
3. Commit `progress-inventory.tsv` with one row per owned function interval, including unresolved intervals. Its header is `image function vram code_size outcome reproduced_by source source_sha256` (tab-separated). Populate source and SHA-256 only for replayed C. Change the inventory when discovery changes and explain denominator changes in the review.
4. Add `progress-config.json` with `repository` and `scope`, and install `tools/generate_tracker_progress.py` in the title repository. Generate `decomphub.progress.json` from those inputs. Run the generator with `--check` in CI and publish the checked report as a workflow artifact. Scope both byte and function ratios to the inventory. For an incomplete catalogue, leave whole-title progress unmeasured.
5. Update the README with the scoped byte ratio first, the function ratio second, and the report link. Push source, inventory, and report in the same change. Verify the remote head and CI artifact. Where a tracker is configured, check its ingestion or listing separately. A refresh request is not confirmation of a published listing.

CI checks accounting and source drift from the reviewed export. Independent ROM-backed rebuilds supply matching evidence. Use the same report for further progress updates. Preserve distinct scopes for assets, overall ROM mapping, assembly, and full relinking.

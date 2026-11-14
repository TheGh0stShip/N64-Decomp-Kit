# Adding an analysis module

Read [ARCHITECTURE.md](ARCHITECTURE.md) and the core modules (`rom.py`, `boot.py`, `image.py`,
`mips.py`, `elf.py`, `ledger.py`, `fixtures.py`, `cli.py`, `commands/core.py`) first. Run the
tests with `python -m unittest discover -s tests -t .`.

Rules

- A module owns its package or module(s), `n64dk/commands/<area>.py`, `tests/test_<area>*.py`
  and `docs/<area>.md`. Changes to core modules are made deliberately and separately, with
  the reason stated.
- Reference projects (matched decompilations, toolchains, SDK sources) are read-only inputs,
  configured locally in `roms.toml` (`[truth]`) or passed as arguments. Never write into them,
  run their tools from inside them, or copy ROM data, extracted assets or generated assembly
  into this repository.
- Fixture ROMs come from `n64dk.fixtures.rom(name)` (see `KNOWN` in `n64dk/fixtures.py`).
  Tests that need one skip when it is not configured.
- Stay game-agnostic: derive everything from the ROM and its inputs; game-specific facts
  belong only in tests.
- Analyses of the main code segment accept an optional `program=` (`n64dk.image.ProgramImage`)
  so that games with a boot loader are analysed on their real program.
- Validate against ground truth where it exists (a matched project's function boundaries,
  manifests and asset ledgers) and report measured precision/recall or exact-match counts
  in `docs/<area>.md`, together with limitations.
- Provide a CLI subcommand that does the whole job in one call, with `--format json` output.
- Standard library plus `rabbitizer`; no network access.
- Keep paths of local machines out of tracked files (`roms.toml` is ignored by git).
- Code adapted from another GPL project credits its source in the module docstring.

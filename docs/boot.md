# Boot analysis and boot emulation

Two views of how a game gets from IPL3 to its program, for laying out a decompilation's
split.

* `n64dk.boot.analyse` (static, instant) reads the entry routine at ROM 0x1000 with a short
  constant-propagating walk: `lui`/`ori`/`addiu`/`addu` and `lw` from the boot image are
  tracked, forward branches with a known condition are followed, and a short forward `j`
  over inline data is followed. It reports the stack pointer, the BSS-clearing loop (a
  backward branch around a store of `$zero`; the bound is an end address or a length), the
  hand-over (`main_call`: the first call or `jr` after the BSS clear, otherwise the first
  transfer out of the boot image) and `staged` when that hand-over leaves the boot image.
  `boot.analyse_segment(data, vram, entry)` runs the same walk over code that is not in the
  ROM as is (a loader's unpacked second stage).
* `n64dk.emu` (dynamic) interprets the R4300 integer instruction set over RDRAM, the
  cartridge and the PI, from the IPL3 hand-off state (boot image copied, boot globals at
  0x80000300, stack in SP memory). It logs PI DMAs, cartridge words the CPU reads directly,
  RAM written after boot (256-byte lines), handoffs (first execution of a written line) and
  every `eret` (the libultra dispatcher entering a thread). `EmuResult.segments()` turns the
  written RAM into a split-oriented map: `dma` (with ROM range), `zero` (BSS) and
  `generated` (loader output: decompressed or relocated code and data).

Out of scope by design: interrupts, TLB, FPU arithmetic, RSP/RDP. Runs stop with a reason
(`FPU arithmetic`, `syscall`, ...) or a set number of instructions after the first
handoff or thread dispatch (`--after`). Instructions are translated once per address into
small Python functions, cached until their page is written; throughput is about
0.15-0.3 M instructions/s.

## CLI

```
n64dk info ROM                  # includes stack_top, bss, hand_over, staged
n64dk boot-emu ROM [--max-steps N] [--after N] [--dma-limit N]
```

## Measured results

| ROM | Static: stack / BSS / hand-over | Emulation |
|---|---|---|
| BattleTanx (NBXE) | 0x8014E0C8 / 0x80147040..0x803C8880 / 0x800779CC | BSS clear observed; four thread dispatches; stops at the first FPU instruction (2.6 M steps, 10 s) |
| Global Assault (NBQE) | 0x8021E0B8 / 0x80127E30..0x803B17B0 / 0x8009ED9C | BSS clear observed; four thread dispatches (2.9 M steps, 10 s) |
| Mario Kart 64 (NKTE) | 0x80152300 / 0x800F6910..0x801978D0 / `jr` 0x80000484 | threads start; first PI DMA ROM 0xF7510 -> 0x8028DF00; then waits for the PI interrupt |
| Madden 64 (N8ME) | 0x803FFFF0 / none in the first stage / 0x80000440, staged | entry at 0x80200400 unpacks its own boot image (packed data at 0x802006D0) into 0x80000400..0x80077700, calls 0x80000440 (8.4 M steps, 34 s); no PI DMA |
| Nagano Winter Olympics '98 (NH5E) | 0x80083E58 / 0x80081DE0..0x801954A0 / `jr` 0x80000460 | BSS 0x80081E00..0x80195500 zero; four thread dispatches; reads open bus at 0x1FF00000 (a development-hardware probe) |
| WWF War Zone (NWWE) | 0x803FFFE0 / 0x8012A1C0..0x801A43E0 / `jr` 0x800E4050 | DMA ROM 0xB8E9E0..0xBF5040 (packed) -> 0x80300000, unpacked to 0x8003C400..0x8012A200, BSS 0x8012A200..0x801A4400, handoff 0x800E4050 (39.5 M steps, 160 s) |

WWF keeps a parameter table at 0x80000410 (ROM start/end of the packed program, destination,
a compressed flag, entry, BSS bounds) that the entry routine reads with `lw`; the static
walk reads the same table, so both views agree.

## Limitations

* Segment kinds are judged from a RAM snapshot taken at the first handoff or thread
  dispatch (`segments(at="end")` for the final state). Runs shorter than a page between two
  neighbours of one kind take their kind.
* `segments()` does not attribute `generated` output to its source; `n64dk.image` does (read
  tracking at the hand-over snapshot, see [survey.md](survey.md)).
* Overlays loaded after the scheduler starts (MK64 segments) need interrupt delivery and are
  not reached.

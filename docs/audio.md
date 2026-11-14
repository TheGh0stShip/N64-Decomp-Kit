# Audio (`n64dk.assets.audio`, `n64dk audio`)

Structure-driven detection and byte-exact accounting of N64 audio data. Nothing is
looked up in game tables: every format is found by magic/shape and accepted only after a
full pointer-validated walk.

```sh
n64dk audio ROM                         # inventory to stdout
n64dk audio ROM --out DIR --wav --midi  # + DIR/inventory.json, DIR/intervals.tsv, DIR/wav/*.wav, DIR/seq/*
n64dk --format json audio ROM           # machine-readable inventory
```

`intervals.tsv` is in the core ledger format (`start end size class category kind name
evidence`); classes used are `container` (bank/table structures), `payload` (samples,
sequences, songs), `padding` (`fill_00`, or `align_nonzero` for short alignment gaps
written with stale bytes) and `unknown` (unreferenced bytes inside a container). The
interval list never overlaps (`overlaps` in the inventory).

## Formats

| Format | Detection | Parsed |
|---|---|---|
| libultra `ALBankFile` (.ctl) | `'B1'` + bank count 1..64, every pointer in range/aligned, no conflicting struct at one offset | ALBank, ALInstrument, ALSound, ALEnvelope, ALKeyMap, ALWaveTable (ADPCM and RAW16), ALADPCMBook, ALADPCMloop / ALRawLoop; gaps must be zero |
| sample table (.tbl) | base inferred: candidates are "table ends ≤64 bytes before the .ctl" and "table starts ≤64 bytes after another detected object"; scored by VADPCM frame headers (scale ≤ 12, predictor < book size) | each unique (base,length) sample, leading/inter/trailing padding |
| libultra `ALSeqFile` | `'S1'` + count, entries must be MIDI or compact MIDI (`ALCMidiHdr`) | entry table and sequences |
| Standard MIDI | `MThd` length 6 | every event of every track, end-of-track must equal chunk end; zero padding to 16 |
| N64 compact MIDI (CMF) | only as `ALSeqFile` entries (no magic of its own) | 16 track offsets + division |
| libmus | `N64 PtrTablesV2` / `N64 WaveTables` magics; cartridge directory (`0xB0xxxxxx` address/size pairs) found by searching for the pointer bank address | pointer bank (header, base notes, detunes, wave list, wave records, books, loops) paired with its wave bank by ADPCM scoring; version-0x215 songs, effect banks, inter-file alignment |
| Nintendo seqfile (SM64/MK64) | 16-aligned header `rev` 1 (ctl) / 2 (tbl) / 3 (sequences), entry count, first entry at aligned header end | ctl: 16-byte bank header, AudioBank, Instrument, Drum list, Drum, AudioBankSample, AdpcmBook, AdpcmLoop (+state), Envelope scripts; tbl: samples per bank's table entry (alias entries resolved); sequences: M64 payloads and the bank-set table after them |

VADPCM decoding (`decode_vadpcm`) implements the libultra recurrence for any book order;
`wav_bytes` writes mono PCM16 WAV via the stdlib `wave` module, adding a RIFF `smpl`
loop for infinite loops. RAW16 waves are decoded as big-endian PCM16. WAV rate: libaudio
bank sample rate, 32000 for seqfile banks (pitch is per-sound `tuning`), 22050 for libmus
(the format stores none); `--rate` overrides.

The libaudio parser generalises the BattleTanx asset inventory tool
(`tools/asset_inventory/audio_banks.py`) and the libmus parser/decoder the Global Assault
`tools/inventory_libmus_assets.py` / `decode_libmus_wave.py`; both GPL-3.0.

## Measured results

| Fixture | Result |
|---|---|
| BattleTanx (NBXE) | 2 ALBankFiles. SFX: 1 bank, 1 instrument, 49 sounds, 49 envelopes, 49 wavetables/books, 7 loops, 49 unique waves; tbl 0x100000–0x215620. Music: 1 bank, 11 instruments, 29 sounds, 28 keymaps, 29 wavetables/books, 13 loops; tbl 0x217EC0–0x298D60 (both tbl bases found with frame score 1.0). 19 MIDI files (format 0/1 tracks) with 1–15 byte zero padding. **727/727 intervals identical** to the project's `audio_banks.tsv` + `midi_sequences.tsv` ledger; 0x100000–0x2C19B0 covered without gaps, overlaps or unknown bytes. The four `'S1'` byte hits are rejected by validation. |
| BattleTanx: Global Assault (NBQE) | libmus store 0x58FAE0–0x7BE9AE via the 26-entry directory at ROM 0xA4710 (found automatically); pointer banks with 76 and 231 waves paired to their wave banks; 93-effect bank; 21 songs referencing 171 music waves; all 307 waves decode, sample-for-sample identical to the project decoder. No `MThd` or `B1` data. Whole span covered, no overlaps/unknown. |
| Mario Kart 64 (NKTE) | No libaudio/libmus/MIDI. Seqfile ctl 0x966260–0x979AA0 (21 banks: 279 instruments, 19 drum lists / 146 drums, 113 envelopes, 452 sample records, 397 books, 452 loops), tbl 0x979AA0 (21 entries aliasing one 0x24C3F0-byte sample bank, 202 unique samples, garbage-filled 16-byte alignment between samples), sequences 0xBC5F60 (30 M64 sequences) and the 30-entry bank-set table. All four segment boundaries equal the MK64 decomp linker script (`audio_banks` 0x0, `audio_tables` 0x13840, `sequences` 0x25FD00 relative). All 202 samples decode (order 2, 2 predictors). The 12 `CMF` byte hits are not compact MIDI. |

Scan time: about 0.3–0.8 s per ROM without decoding; decoding every sample takes 5–20 s.

## Limitations

* .tbl inference needs the table adjacent (within 64 bytes) to its .ctl or to another
  detected object; otherwise `tbl_start` is null and only the .ctl is reported. Ties
  between equally valid bases are reported in `tbl_candidates`.
* Compact MIDI is only recognised inside `ALSeqFile`; standalone CMF has no signature.
* M64 sequence bytecode and libmus song/effect bytecode are not disassembled; songs are
  validated through their headers, stream tables and wave tables only.
* libmus files without a cartridge directory get pointer/wave banks only (song bounds
  need the directory).
* WAV export does not apply keymap/tuning pitch; finite loops are not written to `smpl`.

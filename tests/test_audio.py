import csv
import struct
import unittest

from n64dk import fixtures
from n64dk.assets import audio


def _truth_root(name):
    return fixtures.truth(name)


def build_bank(npred=2):
    """Minimal ALBankFile: one bank, one instrument, one ADPCM sound, envelope, keymap, book."""
    b = bytearray(0x100)
    struct.pack_into(">Hh I", b, 0, 0x4231, 1, 0x10)
    struct.pack_into(">hBBiI I", b, 0x10, 1, 0, 0, 22050, 0, 0x20)        # ALBank, inst at 0x20
    struct.pack_into(">12Bhh I", b, 0x20, 127, 64, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 200, 1, 0x40)
    struct.pack_into(">III4B", b, 0x40, 0x50, 0x60, 0x68, 64, 127, 0, 0)  # ALSound
    struct.pack_into(">iiiBB", b, 0x50, 1, 2, 3, 127, 100)                # ALEnvelope
    struct.pack_into(">6B", b, 0x60, 0, 127, 0, 127, 60, 0)               # ALKeyMap
    struct.pack_into(">IIBBHII", b, 0x68, 0, 18, 0, 0, 0, 0, 0x80)        # ALWaveTable
    struct.pack_into(">ii", b, 0x80, 2, npred)                            # book, coefs zero
    end = 0x88 + 2 * 16 * npred
    return bytes(b[:(end + 15) // 16 * 16])


class VadpcmTests(unittest.TestCase):
    def test_zero_book_is_scaled_residual(self):
        book = audio.Book(2, 1, [0] * 16)
        frame = bytes([0x10]) + bytes([0x12, 0x34, 0x56, 0x7F, 0x8F, 0xF0, 0x00, 0x11])
        out = audio.decode_vadpcm(frame, book)
        nibbles = [n - 16 if n >= 8 else n for byte in frame[1:] for n in (byte >> 4, byte & 15)]
        self.assertEqual(out, [n << 1 for n in nibbles])

    def test_prediction_uses_history(self):
        coefs = [0] * 8 + [2048] * 8   # row 1 = previous sample weight 1.0 (row 0 zero)
        book = audio.Book(2, 1, coefs)
        out = audio.decode_vadpcm(bytes([0x00, 0x10]) + bytes(7), book)
        self.assertEqual(out[0], 1)
        self.assertTrue(all(v == out[1] for v in out[1:8]))

    def test_wav_roundtrip(self):
        import io, wave
        data = audio.wav_bytes([0, 1, -1, 32767], 8000, (0, 4, -1))
        with wave.open(io.BytesIO(data)) as w:
            self.assertEqual((w.getframerate(), w.getnframes()), (8000, 4))
        self.assertIn(b"smpl", data)


class SyntheticBankTests(unittest.TestCase):
    def test_ctl_and_tbl(self):
        ctl = build_bank()
        frames = bytes([0x11]) + bytes(8) + bytes([0x21]) + bytes(8)
        rom = b"\xff" * 0x40 + frames + bytes(14) + ctl + bytes(0x40)
        start = 0x40 + 18 + 14
        p = audio.parse_ctl(rom, start)
        self.assertEqual(p.end - start, len(ctl))
        kinds = sorted(v[0] for v in p.cover.items.values())
        self.assertEqual(kinds, sorted(["ALBankFile", "ALBank", "ALInstrument", "ALSound", "ALEnvelope",
                                        "ALKeyMap", "ALWaveTable", "ALADPCMBook"]))
        c = audio.libaudio_bank(rom, p, [0x40])
        self.assertEqual(c.samples[0].start, 0x40)
        covered = sum(i.size for i in c.intervals)
        self.assertEqual(covered, len(ctl) + 18 + 14)
        self.assertEqual(audio.check_intervals(c.intervals), [])

    def test_bad_pointer_rejected(self):
        ctl = bytearray(build_bank())
        struct.pack_into(">I", ctl, 4, 0xFFFF0)
        with self.assertRaises(audio.AudioError):
            audio.parse_ctl(bytes(ctl), 0)


class MidiTests(unittest.TestCase):
    def test_parse_and_padding(self):
        trk = b"\x00\x90\x3c\x40\x10\x3c\x00\x00\xff\x2f\x00"
        smf = b"MThd" + struct.pack(">IHHH", 6, 0, 1, 96) + b"MTrk" + struct.pack(">I", len(trk)) + trk
        rom = smf + bytes(16)
        m = audio.parse_midi(rom, 0)
        self.assertEqual((m["end"], m["pad_end"], m["events"]), (len(smf), 48, 3))
        with self.assertRaises(audio.AudioError):
            audio.parse_midi(smf[:-1] + b"\x01" + bytes(8), 0)


class RomTests(unittest.TestCase):
    def scan(self, name):
        rom = fixtures.rom(name)
        if rom is None:
            self.skipTest(f"{name} ROM not configured")
        return rom.data, audio.scan(rom.data)

    def test_battletanx(self):
        data, s = self.scan("battletanx")
        banks = [c for c in s.containers if c.kind == "ALBankFile"]
        self.assertEqual([(c.start, c.end) for c in banks], [(0x215620, 0x217EB0), (0x298D60, 0x29A710)])
        sfx, music = (c.summary["structs"] for c in banks)
        self.assertEqual((sfx["ALSound"], sfx["ALWaveTable"]), (49, 49))
        self.assertEqual((music["ALInstrument"], music["ALSound"]), (11, 29))
        self.assertEqual([c.summary["tbl_start"] for c in banks], [0x100000, 0x217EC0])
        self.assertEqual(len(s.midi), 19)
        ivs = s.intervals
        self.assertEqual(audio.check_intervals(ivs), [])
        self.assertEqual((ivs[0].start, ivs[-1].end), (0x100000, 0x2C19B0))
        self.assertEqual(sum(i.size for i in ivs), 0x2C19B0 - 0x100000)
        self.assertFalse([i for i in ivs if i.cls == "unknown"])
        tsv = _truth_root("battletanx_audio_banks")  # optional audio_banks.tsv ledger
        if tsv and tsv.is_file():
            with open(tsv) as f:
                truth = {(int(r["rom_start"], 16), int(r["rom_end"], 16)) for r in csv.DictReader(f, delimiter="\t")}
            self.assertLessEqual(truth, {(i.start, i.end) for i in ivs})

    def test_global_assault_libmus(self):
        data, s = self.scan("battletanx_ga")
        store = [c for c in s.containers if c.kind == "store"]
        self.assertEqual([(c.start, c.end, c.summary["files"]) for c in store], [(0x58FAE0, 0x7BE9AE, 26)])
        self.assertEqual(sorted(c.summary["waves"] for c in s.containers if c.kind == "PtrTablesV2"), [76, 231])
        self.assertEqual(sum(c.kind == "song" for c in s.containers), 21)
        self.assertEqual([c.summary["effects"] for c in s.containers if c.kind == "effects"], [93])
        self.assertEqual(store[0].summary["song_waves_used"], 171)
        ivs = s.intervals
        self.assertEqual(audio.check_intervals(ivs), [])
        self.assertEqual(sum(i.size for i in ivs), 0x7BE9AE - 0x58FAE0)

    def test_mk64_seqfile(self):
        data, s = self.scan("mk64")
        k = {c.kind: c for c in s.containers}
        self.assertEqual((k["ctl"].start, k["ctl"].end), (0x966260, 0x979AA0))
        self.assertEqual(k["tbl"].start, 0x979AA0)
        self.assertEqual(k["sequences"].start, 0xBC5F60)
        self.assertEqual(k["ctl"].summary["entries"], 21)
        self.assertEqual(k["sequences"].summary["entries"], 30)
        ivs = s.intervals
        self.assertEqual(audio.check_intervals(ivs), [])
        self.assertFalse([i for i in ivs if i.cls == "unknown"])
        smp = k["ctl"].samples[0]
        self.assertEqual(len(smp.decode(data)), (smp.end - smp.start) // 9 * 16)


if __name__ == "__main__":
    unittest.main()

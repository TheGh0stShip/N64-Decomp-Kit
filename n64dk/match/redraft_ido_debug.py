"""IDO built without optimisation (``cc -g``): write the function from its machine code.

Unoptimised IDO code is a statement-by-statement transcript of the source (see
``ido_debug_lift``), so the function is read back from its bytes instead of repairing a general
decompiler's rendering.  The decompiler draft is used for one thing only: the typedef prelude the
kit compiles every candidate with.

The situation is recognised from the code, not from the recipe: IDO without optimisation leaves a
function through ``b L; nop; L: <epilogue>`` (a branch to the very next instruction), which no
optimising build keeps, and has no GCC frame pointer.  The translator declines (``Unsupported``)
whatever it does not understand.  A few places have two spellings the instructions cannot tell
apart (a field access as ``p->f`` or as a cast, the order of the operands of a comparison, where
unused frame space sits); each alternative is offered as one more rewrite.
"""
from __future__ import annotations

from . import ido_debug_lift as liftmod

_FALL_THROUGH = b"\x10\x00\x00\x01\x00\x00\x00\x00"        # b +1; nop
_GCC_FRAME = b"\x03\xa0\xf0\x21"                            # addu $fp, $sp, $zero
ALTERNATIVES = ((), ("cast_fields",), ("no_flip",), ("pad_bottom",), ("cast_fields", "no_flip"))


_RETURN_ONLY = b"\x03\xe0\x00\x08\x00\x00\x00\x00"         # jr $ra; nop


def frameless_tail(code: bytes) -> bool:
    """A frameless function of such a build with the returns nothing reaches still attached: it
    ends in ``jr $ra; <slot>; jr $ra; nop`` (the catalogue keeps them with the function, see
    ``n64dk.analysis.functions.merge_dead_returns``)."""
    return len(code) >= 24 and code[-8:] == _RETURN_ONLY and code[-16:-12] == _RETURN_ONLY[:4] \
        and code[:2] != b"\x27\xbd"


def is_unoptimised_ido(code: bytes) -> bool:
    if len(code) < 16 or len(code) % 4:
        return False
    words = [code[i:i + 4] for i in range(0, len(code), 4)]
    if _GCC_FRAME in words[:16]:
        return False
    return frameless_tail(code) or any(code[i:i + 8] == _FALL_THROUGH for i in range(0, len(code) - 7, 4))


def prelude_of(source: str) -> str:
    cut = source.rfind("#endif")
    if "N64DK_M2C_PRELUDE" in source and cut >= 0:
        return source[:cut + len("#endif")]
    from .autodraft import PRELUDE
    return PRELUDE


def variants(source: str, name: str, *, code: bytes, vram: int, pipeline: str, flags: tuple[str, ...] = (),
             family: str | None = None, read=None) -> list[tuple[str, str]]:
    """[(label, complete C translation unit)]; [] when this is not unoptimised IDO code."""
    if not is_unoptimised_ido(code):
        return []
    prelude, out, seen = prelude_of(source), [], set()
    for options in ALTERNATIVES:
        try:
            text = liftmod.lift(code, vram, name, options=options, whole=frameless_tail(code), read=read)
        except liftmod.Unsupported:
            if not options:
                return []                                    # not understood: no spelling will be
            continue
        except (KeyError, IndexError, ValueError, TypeError, AttributeError, RecursionError, AssertionError):
            if not options:
                return []
            continue
        if text not in seen:
            seen.add(text)
            out.append(("ido-g-translated" + ("".join("+" + o for o in options)), prelude + "\n" + text + "\n"))
    return out

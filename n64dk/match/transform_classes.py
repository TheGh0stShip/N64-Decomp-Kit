"""What each mechanical source transformation may do to behaviour.

A search may try anything; what it may *claim* depends on the class of what it applied:

* ``preserving``: proven behaviour-preserving for any input (introducing or inlining a
  temporary, a block scope, declaration order, line layout, an unused frame local);
* ``conditional``: behaviour-preserving under conditions the transformation does not check
  (reordering statements without a dependency analysis, rewriting an expression or a control
  form, adding or removing a cast);
* ``exploration``: may change behaviour (a type's width or signedness, ``volatile``, an extern's
  declared type, a structure field's type).

Every exact result is strictly verified by recompilation, and byte identity means the machine
code, so the behaviour, is the retail code's.  The class is provenance: a function whose exact
source came through ``exploration`` steps was found by search, not recovered by reasoning, and
reports say so.  Frame padding is ``preserving`` but is reconstruction scaffolding, never natural
source: it is marked in the source (``SCAFFOLD_MARK``) and counted apart."""
from __future__ import annotations

PRESERVING, CONDITIONAL, EXPLORATION = "preserving", "conditional", "exploration"

FAMILY_CLASS = {
    "lifetime": PRESERVING, "scope": PRESERVING, "split": PRESERVING,
    "ast-temp": PRESERVING, "ast-inline-temp": PRESERVING, "ast-decl-order": PRESERVING,
    "ast-block": PRESERVING, "ast-sameline": PRESERVING,
    "order": CONDITIONAL, "expression": CONDITIONAL, "casts": CONDITIONAL, "pointer": CONDITIONAL,
    "control": CONDITIONAL, "callargs": CONDITIONAL, "ast-control": CONDITIONAL, "ast-expr": CONDITIONAL,
    "ast-stmt-order": CONDITIONAL, "ast-cast": CONDITIONAL,
    "types": EXPLORATION, "fields": EXPLORATION, "volatile": EXPLORATION, "globals": EXPLORATION,
    "frame-inline": PRESERVING, "frame-pad": PRESERVING,
}
RANK = {PRESERVING: 0, CONDITIONAL: 1, EXPLORATION: 2}
SCAFFOLD_MARK = "/* n64dk: frame padding, reconstruction scaffolding */"


def classify(families) -> str | None:
    """The weakest guarantee among the families applied (None when nothing was applied)."""
    classes = [FAMILY_CLASS.get(f, EXPLORATION) for f in families or ()]
    return max(classes, key=RANK.get) if classes else None


def provenance(stages) -> dict:
    """What a case's source went through: the classes of the transformation families that helped,
    and whether frame scaffolding is in it."""
    helpful = []
    scaffold = False
    for stage in stages or ():
        if stage.get("stage") == "iterate":
            helpful += list(stage.get("helpful_families") or [])
        if stage.get("stage") == "frame-fit" and str(stage.get("chosen") or "").startswith("pad"):
            scaffold = True
        if stage.get("stage") == "frame-fit" and str(stage.get("chosen") or "").startswith("inlined"):
            helpful.append("frame-inline")
    return {"families": sorted(set(helpful)), "class": classify(helpful), "scaffolding": scaffold}

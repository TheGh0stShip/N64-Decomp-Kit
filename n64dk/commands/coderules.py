"""``code-rules``: which sources pass the [match] code rules, and what is still open in them."""
from __future__ import annotations

from pathlib import Path

from ..cli import command, emit
from ..match import coderules


@command("code-rules", "Check C sources against the code rules: [match] findings make a byte-identical function "
                       "MATCH-PENDING, advisory findings are open work")
def code_rules(args):
    profile = coderules.Profile.load(args.project)
    files = coderules.collect(args.source)
    missing = [str(path) for path in files if not path.is_file()]
    if missing:
        raise SystemExit(f"code-rules: no such file: {', '.join(missing)}")
    report = coderules.check_paths(files, profile, root=args.project)
    result = report.as_dict(advisory=not args.no_advisory)
    result["pending_functions"] = [
        {"path": path, "function": name, "rules": report.blocked_rules(path, name)}
        for path, names in report.functions.items() for name in names
        if report.blocked_rules(path, name) and not report.original_asm(path, name)]
    result["relaxed"] = dict(profile.relax)
    if args.declarations:
        result["declarations"] = coderules.declarations(
            {path.as_posix(): path.read_text(errors="replace") for path in files})
    failed = bool(report.blocking) and args.strict
    if args.format == "json":
        emit(result, "json")
        return 1 if failed else 0
    for finding in report.findings:
        if finding.tier != coderules.ADVISORY or not args.no_advisory:
            print(finding.text())
    for row in result.get("declarations", []):
        if row["conflict"] or row["files"] > 1:
            print(f"declaration: {row['kind']} `{row['name']}` in {row['files']} files"
                  + (": " + " / ".join(row["declarations"]) if row["conflict"] else ""))
    summary = report.summary()
    print(f"{summary['files']} files, {summary['functions']} functions: {summary['pass']} pass, "
          f"{summary['match_pending']} MATCH-PENDING, {summary['original_asm']} ORIGINAL-ASM")
    for label, key in (("[match]", "match_findings"), ("exceptions", "exceptions"), ("advisory", "advisory")):
        if summary[key] and not (key == "advisory" and args.no_advisory):
            print(f"{label}: " + ", ".join(f"{rule} {count}" for rule, count in summary[key].items()))
    return 1 if failed else 0


def _args(p):
    p.add_argument("source", nargs="+", help="C/C++ sources, headers or directories; pass a unit together with the "
                                             "headers it includes so that the cross-file rules (R1, R2) see both")
    p.add_argument("--project", help="project directory: its n64dk.toml [code_rules] profile applies and paths are "
                                     "reported relative to it")
    p.add_argument("--strict", action="store_true", help="exit 1 when a [match] rule fires (a gate for CI)")
    p.add_argument("--no-advisory", action="store_true", help="report only what blocks a match")
    p.add_argument("--declarations", action="store_true",
                   help="also list every extern by name with its declarations: the work list for one header")


code_rules.arguments = _args

"""Evidence records and quality gates for decompilation research corpora."""
from __future__ import annotations

import csv
from collections import Counter
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class SourceRecord:
    url: str
    title: str
    source_type: str
    evidence_quality: str
    fetched_or_search_only: str
    notes: str = ""

    @property
    def primary(self) -> bool:
        return self.evidence_quality.lower() == "primary"

    @property
    def fetched(self) -> bool:
        return self.fetched_or_search_only.lower() == "fetched"


@dataclass(frozen=True)
class FindingRecord:
    finding_id: str
    question: str
    sources: tuple[str, ...]
    evidence: str
    evidence_type: str
    confidence: str
    experiment: str

    @property
    def actionable(self) -> bool:
        value = self.experiment.strip().lower()
        return bool(value and value not in ("-", "none", "n/a"))


def plan_rules(catalog_path: str | Path, finding_path: str | Path,
               dispositions_path: str | Path | None = None) -> dict:
    """Produce traceable review tasks, without treating proposed rules as approved."""
    findings = {finding.finding_id: finding for finding in load_findings(finding_path)}
    with Path(catalog_path).open(newline="") as stream:
        rules = list(csv.DictReader(stream, delimiter="\t"))
    dispositions = {}
    if dispositions_path is not None:
        with Path(dispositions_path).open(newline="") as stream:
            for row in csv.DictReader(stream, delimiter="\t"):
                if row["rule_id"] in dispositions:
                    raise ValueError("duplicate rule disposition: " + row["rule_id"])
                dispositions[row["rule_id"]] = row
        unknown = set(dispositions) - {row.get("rule_id") for row in rules}
        if unknown:
            raise ValueError("dispositions reference unknown rules: " + ", ".join(sorted(unknown)))
    tasks = []
    for rule in rules:
        references = [value.strip() for value in rule.get("source_rounds", "").split(";") if value.strip()]
        missing = [value for value in references if value not in findings]
        caveats = rule.get("conflicts_or_caveats", "")
        tasks.append({
            "rule_id": rule.get("rule_id", ""),
            "stage": rule.get("stage", ""),
            "symptom": rule.get("target_symptom", ""),
            "hypothesis": rule.get("mechanism", ""),
            "proposed_lever": rule.get("c_lever", ""),
            "source_finding_ids": references,
            "missing_finding_ids": missing,
            "sources": sorted({url for ref in references if ref in findings
                               for url in findings[ref].sources}),
            "reported_evidence_grade": rule.get("evidence_grade", ""),
            "caveats": caveats,
            "requires_conflict_resolution": "conflict" in caveats.lower() or "contradict" in caveats.lower(),
            "required_probes": [value for value in rule.get("probe_ids", "").split(";") if value],
            "status": "needs-source-reconciliation" if missing else "needs-reproduction",
            "implementation_approved": False,
            "review": dispositions.get(rule.get("rule_id", "")),
        })
    return {"tasks": tasks, "rule_count": len(tasks),
            "stage_counts": dict(Counter(task["stage"] for task in tasks)),
            "conflict_count": sum(task["requires_conflict_resolution"] for task in tasks),
            "missing_reference_count": sum(bool(task["missing_finding_ids"]) for task in tasks)}


def load_sources(path: str | Path) -> list[SourceRecord]:
    with Path(path).open(newline="") as stream:
        rows = csv.DictReader(stream, delimiter="\t")
        return [SourceRecord(row.get("url", ""), row.get("title", ""),
                             row.get("source_type", ""), row.get("evidence_quality", ""),
                             row.get("fetched_or_search_only", ""), row.get("notes", ""))
                for row in rows]


def load_findings(path: str | Path) -> list[FindingRecord]:
    with Path(path).open(newline="") as stream:
        rows = csv.DictReader(stream, delimiter="\t")
        result = []
        for row in rows:
            result.append(FindingRecord(
                row.get("round_id", row.get("finding_id", "")),
                row.get("query_or_question", row.get("question", "")),
                tuple(value.strip() for value in row.get("sources", "").split("|")
                      if value.strip()),
                row.get("key_evidence", row.get("evidence", "")),
                row.get("evidence_type", ""), row.get("confidence", ""),
                row.get("actionable_experiment", row.get("experiment", "")),
            ))
        return result


def audit(source_path: str | Path, finding_path: str | Path) -> dict:
    sources, findings = load_sources(source_path), load_findings(finding_path)
    indexed = {source.url for source in sources if source.url}
    missing = sorted({url for finding in findings for url in finding.sources if url not in indexed})
    duplicate_urls = [url for url, count in Counter(s.url for s in sources).items()
                      if url and count > 1]
    search_only = [s.url for s in sources if not s.fetched]
    weak_findings = [f.finding_id for f in findings
                     if f.confidence.lower() in ("low", "unknown")]
    non_actionable = [f.finding_id for f in findings if not f.actionable]
    by_url = {}
    for source in sources:
        by_url.setdefault(source.url, []).append(source)
    reviews = []
    for finding in findings:
        reasons = []
        if not finding.sources:
            reasons.append("no source references")
        if not finding.evidence.strip():
            reasons.append("missing evidence excerpt")
        if finding.confidence.lower() in ("low", "unknown", ""):
            reasons.append("weak or unspecified confidence")
        if not finding.actionable:
            reasons.append("no proposed experiment")
        for url in finding.sources:
            records = by_url.get(url, [])
            if not records:
                reasons.append("unindexed reference: " + url)
            elif len(records) != 1:
                reasons.append("ambiguous source record: " + url)
            elif not records[0].fetched:
                reasons.append("source not fetched: " + url)
        primary = any(len(by_url.get(url, [])) == 1
                      and by_url[url][0].fetched and by_url[url][0].primary
                      for url in finding.sources)
        if not primary:
            reasons.append("no fetched primary source")
        reviews.append({"finding_id": finding.finding_id,
                        "status": "needs-evidence" if reasons else "ready-for-validation",
                        "reasons": reasons,
                        "experiment": finding.experiment,
                        "implementation_approved": False})
    return {
        "sources": len(sources),
        "primary_sources": sum(source.primary for source in sources),
        "fetched_sources": sum(source.fetched for source in sources),
        "search_only_sources": len(search_only),
        "findings": len(findings),
        "actionable_findings": sum(finding.actionable for finding in findings),
        "missing_source_index_entries": missing,
        "duplicate_source_urls": duplicate_urls,
        "low_confidence_findings": weak_findings,
        "non_actionable_findings": non_actionable,
        "finding_reviews": reviews,
        "review_counts": dict(Counter(row["status"] for row in reviews)),
        "validation_note": "Source labels are self-reported; no finding is approved by this audit.",
        "gates": {
            "all_finding_urls_indexed": not missing,
            "source_urls_unique": not duplicate_urls,
            "search_only_is_not_primary_evidence": all(
                not (source.primary and not source.fetched) for source in sources),
        },
    }

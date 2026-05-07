import difflib

from app.ai_commentary import format_report
from app.parser import parse_cisco_ios_config
from app.rules import run_rules


def audit_config_text(config_text: str) -> list[dict]:
    parsed = parse_cisco_ios_config(config_text)
    findings = run_rules(parsed)
    return format_report(findings)


def _finding_key(item: dict) -> tuple[str, str, str]:
    return (item["rule_id"], item["context"], item["message"])


def _extract_changed_lines(old_text: str, new_text: str) -> list[dict]:
    diff_lines = difflib.ndiff(old_text.splitlines(), new_text.splitlines())
    changed: list[dict] = []
    for line in diff_lines:
        if line.startswith("+ "):
            content = line[2:].strip()
            if content:
                changed.append({"source": "new", "prefix": "+", "line": content})
        elif line.startswith("- "):
            content = line[2:].strip()
            if content:
                changed.append({"source": "old", "prefix": "-", "line": content})
    unique_changed: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for line in changed:
        key = (line["source"], line["line"])
        if key not in seen:
            seen.add(key)
            unique_changed.append(line)
    return unique_changed


def _group_by_indent(raw_lines: list[str]) -> list[dict]:
    groups: list[dict] = []
    current: dict | None = None
    for raw in raw_lines:
        if not raw.strip():
            continue
        is_indented = raw.startswith((" ", "\t"))
        text = raw.strip()
        if is_indented and current is not None:
            if text not in current["children"]:
                current["children"].append(text)
        else:
            if current is not None:
                groups.append(current)
            current = {"parent": text, "children": []}
    if current is not None:
        groups.append(current)
    return groups


def _build_diff_groups(old_text: str, new_text: str) -> dict:
    old_lines_raw = [line for line in old_text.splitlines() if line.strip()]
    new_lines_raw = [line for line in new_text.splitlines() if line.strip()]
    old_lines = [line.strip() for line in old_lines_raw]
    new_lines = [line.strip() for line in new_lines_raw]
    matcher = difflib.SequenceMatcher(a=old_lines, b=new_lines)

    modified_pairs: list[dict] = []
    added_raw: list[str] = []
    removed_raw: list[str] = []

    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            continue
        if tag == "replace":
            old_chunk = old_lines_raw[i1:i2]
            new_chunk = new_lines_raw[j1:j2]
            max_len = max(len(old_chunk), len(new_chunk))
            for idx in range(max_len):
                old_line = old_chunk[idx] if idx < len(old_chunk) else None
                new_line = new_chunk[idx] if idx < len(new_chunk) else None
                if old_line and new_line:
                    modified_pairs.append(
                        {
                            "old_line": old_line.strip(),
                            "new_line": new_line.strip(),
                        }
                    )
                elif old_line:
                    removed_raw.append(old_line)
                elif new_line:
                    added_raw.append(new_line)
        elif tag == "delete":
            removed_raw.extend(old_lines_raw[i1:i2])
        elif tag == "insert":
            added_raw.extend(new_lines_raw[j1:j2])

    return {
        "modified_pairs": modified_pairs,
        "added_groups": _group_by_indent(added_raw),
        "removed_groups": _group_by_indent(removed_raw),
    }


def audit_config_diff(old_text: str, new_text: str) -> dict:
    old_report = audit_config_text(old_text)
    new_report = audit_config_text(new_text)

    old_map = {_finding_key(item): item for item in old_report}
    new_map = {_finding_key(item): item for item in new_report}

    new_findings = [item for key, item in new_map.items() if key not in old_map]
    resolved_findings = [item for key, item in old_map.items() if key not in new_map]
    changed_lines = _extract_changed_lines(old_text, new_text)
    diff_groups = _build_diff_groups(old_text, new_text)
    changed_set = {line["line"].lower() for line in changed_lines}

    changed_line_findings = [
        item
        for item in new_report
        if item["context"].lower() in changed_set or any(
            token in item["context"].lower() for token in changed_set
        )
    ]

    return {
        "changed_lines": changed_lines,
        "changed_line_count": len(changed_lines),
        "modified_pairs": diff_groups["modified_pairs"],
        "added_groups": diff_groups["added_groups"],
        "removed_groups": diff_groups["removed_groups"],
        "new_findings": new_findings,
        "resolved_findings": resolved_findings,
        "changed_line_findings": changed_line_findings,
    }

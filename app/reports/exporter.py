
import csv
import html
import io
import json
from datetime import date, datetime
from typing import Any


class ReportExporter:
    """Export SafeCode AI scan reports into multiple formats."""

    @staticmethod
    def _data(report: Any) -> dict:
        if hasattr(report, "model_dump"):
            return report.model_dump(mode="json")
        if hasattr(report, "dict"):
            return report.dict()
        if isinstance(report, dict):
            return report
        return vars(report)

    @staticmethod
    def _findings(report: Any) -> list:
        data = ReportExporter._data(report)
        return data.get("findings", []) or []

    @staticmethod
    def _get(item: Any, key: str, default=None):
        if isinstance(item, dict):
            return item.get(key, default)
        return getattr(item, key, default)

    @staticmethod
    def _json_default(value):
        if isinstance(value, (datetime, date)):
            return value.isoformat()
        if hasattr(value, "model_dump"):
            return value.model_dump(mode="json")
        if hasattr(value, "dict"):
            return value.dict()
        return str(value)

    def to_json(self, report) -> str:
        return json.dumps(
            self._data(report),
            indent=2,
            ensure_ascii=False,
            default=self._json_default
        )

    def to_markdown(self, report) -> str:
        data = self._data(report)
        findings = self._findings(report)

        lines = [
            f"# Security Scan Report: {data.get('repository_name', 'Unknown')}",
            "",
            f"- **Scan ID:** {data.get('scan_id', 'N/A')}",
            f"- **Repository:** {data.get('repository_url', 'N/A')}",
            f"- **Timestamp:** {data.get('timestamp', 'N/A')}",
            f"- **Status:** {data.get('status', 'N/A')}",
            "",
            "## Security Score",
            "",
        ]

        score = data.get("score", {}) or {}
        lines.append(
            f"**Overall Score:** {self._get(score, 'overall_score', 'N/A')}/100"
        )
        lines.extend(["", "## Findings", ""])

        if not findings:
            lines.append("No security findings were reported.")

        for index, finding in enumerate(findings, 1):
            get = self._get
            lines.extend([
                f"### {index}. {get(finding, 'title', 'Untitled finding')}",
                "",
                f"- **Severity:** {get(finding, 'severity', 'N/A')}",
                f"- **Confidence:** {get(finding, 'confidence', 'N/A')}",
                f"- **File:** {get(finding, 'file_path', 'N/A')}",
                f"- **Line:** {get(finding, 'line_number', 'N/A')}",
                f"- **Category:** {get(finding, 'category', 'N/A')}",
                f"- **OWASP:** {get(finding, 'owasp', 'N/A')}",
                f"- **CWE:** {get(finding, 'cwe', 'N/A')}",
                "",
                get(finding, "description", ""),
                "",
                "**Explanation**",
                "",
                get(finding, "explanation", ""),
                "",
                "**Suggested Fix**",
                "",
                get(finding, "fix_suggestion", ""),
                "",
            ])

            patch = get(finding, "patch")
            if patch:
                lines.extend(["**Patch**", "", "```diff", patch, "```", ""])

        return "\n".join(lines)

    def to_html(self, report) -> str:
        data = self._data(report)
        findings = self._findings(report)

        esc = lambda value: html.escape(str(value or ""))
        rows = []

        for finding in findings:
            get = self._get
            rows.append(
                "<tr>"
                f"<td>{esc(get(finding, 'title'))}</td>"
                f"<td>{esc(get(finding, 'severity'))}</td>"
                f"<td>{esc(get(finding, 'file_path'))}</td>"
                f"<td>{esc(get(finding, 'line_number'))}</td>"
                f"<td>{esc(get(finding, 'fix_suggestion'))}</td>"
                "</tr>"
            )

        score = data.get("score", {}) or {}
        overall = self._get(score, "overall_score", "N/A")

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>SafeCode AI Security Report</title>
<style>
    body {{ 
        font-family: Arial, Helvetica, sans-serif;
        margin: 0;
        padding: 35px;
        background: #080d1b;
        color: #e5e7eb;
    }}

    header {{
        background: linear-gradient(135deg, #101d3a, #123b60);
        color: white;
        padding: 35px;
        border-radius: 16px;
        border: 1px solid #164e75;
        margin-bottom: 25px;
    }}

    header h1 {{
        font-size: 32px;
        margin: 0 0 12px;
        color: #22d3ee;
    }}

    header p {{
        color: #cbd5e1;
        margin: 0;
    }}

    .card {{
        background: #111a2c;
        padding: 25px;
        margin-top: 22px;
        border-radius: 14px;
        border: 1px solid #26364f;
        overflow-x: auto;
    }}

    h2 {{
        color: #22d3ee;
        margin-top: 0;
    }}

    h3 {{
        color: #f8fafc;
    }}

    p {{
        line-height: 1.7;
        overflow-wrap: anywhere;
    }}

    table {{
        width: 100%;
        border-collapse: collapse;
        background: #0b1323;
        margin-top: 15px;
    }}

    th, td {{
        padding: 14px;
        border: 1px solid #29384f;
        text-align: left;
        overflow-wrap: anywhere;
    }}

    th {{
        background: #123b60;
        color: #22d3ee;
    }}
    table {{
    table-layout: fixed;
}}

th:nth-child(1), td:nth-child(1) {{
    width: 24%;
}}

th:nth-child(2), td:nth-child(2) {{
    width: 8%;
    white-space: nowrap;
}}

th:nth-child(3), td:nth-child(3) {{
    width: 22%;
}}

th:nth-child(4), td:nth-child(4) {{
    width: 6%;
    white-space: nowrap;
}}

th:nth-child(5), td:nth-child(5) {{
    width: 40%;
}}

    td {{
        color: #e2e8f0;
    }}

    tr:nth-child(even) {{
        background: #142035;
    }}
</style>
</head>
<body>
<header>
<h1>SafeCode AI</h1>
<p>Repository Security Scan Report</p>
</header>
<div class="card">
<h2>{esc(data.get('repository_name'))}</h2>
<p>Repository: {esc(data.get('repository_url'))}</p>
<p>Scan ID: {esc(data.get('scan_id'))}</p>
<p>Timestamp: {esc(data.get('timestamp'))}</p>
<h3>Security Score: {esc(overall)}/100</h3>
</div>
<div class="card">
<h2>Security Findings</h2>
<table>
<thead><tr><th>Title</th><th>Severity</th><th>File</th>
<th>Line</th><th>Suggested Fix</th></tr></thead>
<tbody>{''.join(rows) if rows else '<tr><td colspan="5" style="text-align:center;padding:20px;">No security findings detected.</td></tr>'}</tbody>
</table>
</div>
</body>
</html>"""

    def to_csv(self, report) -> str:
        output = io.StringIO()
        fields = [
            "finding_id", "title", "severity", "confidence",
            "file_path", "line_number", "category", "owasp",
            "cwe", "description", "explanation", "fix_suggestion"
        ]

        writer = csv.DictWriter(output, fieldnames=fields)
        writer.writeheader()

        for finding in self._findings(report):
            writer.writerow({
                field: self._get(finding, field, "")
                for field in fields
            })

        return output.getvalue()

    def to_sarif(self, report) -> str:
        results = []

        for finding in self._findings(report):
            get = self._get
            severity = str(get(finding, "severity", "LOW")).upper()

            level = {
                "CRITICAL": "error",
                "HIGH": "error",
                "MEDIUM": "warning",
                "LOW": "note"
            }.get(severity, "warning")

            result = {
                "ruleId": get(finding, "cwe") or get(
                    finding, "category", "security-finding"
                ),
                "level": level,
                "message": {
                    "text": get(finding, "description", "")
                    or get(finding, "explanation", "")
                },
                "properties": {
                    "findingId": get(finding, "finding_id"),
                    "severity": severity,
                    "confidence": get(finding, "confidence"),
                    "fixSuggestion": get(finding, "fix_suggestion")
                }
            }

            line = get(finding, "line_number")
            file_path = get(finding, "file_path")

            if file_path:
                region = {}
                if line is not None:
                    region["startLine"] = line

                result["locations"] = [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": file_path},
                        **({"region": region} if region else {})
                    }
                }]

            results.append(result)

        sarif = {
            "$schema": (
                "https://json.schemastore.org/sarif-2.1.0.json"
            ),
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "SafeCode AI",
                        "informationUri": (
                            "https://github.com/mohd-musheer/CodeShield-AI"
                        )
                    }
                },
                "results": results
            }]
        }

        return json.dumps(sarif, indent=2, default=self._json_default)

    def to_fix_prompt_json(self, report) -> str:
        prompts = []

        for finding in self._findings(report):
            prompts.append({
                "finding_id": self._get(finding, "finding_id"),
                "title": self._get(finding, "title"),
                "severity": self._get(finding, "severity"),
                "file_path": self._get(finding, "file_path"),
                "line_number": self._get(finding, "line_number"),
                "problem": self._get(finding, "explanation"),
                "code_snippet": self._get(finding, "code_snippet"),
                "fix_instruction": self._get(finding, "fix_suggestion"),
                "patch": self._get(finding, "patch")
            })

        return json.dumps(prompts, indent=2, default=self._json_default)

    def to_fix_prompt_markdown(self, report) -> str:
        lines = ["# Security Fix Instructions", ""]

        for index, finding in enumerate(self._findings(report), 1):
            get = self._get
            lines.extend([
                f"## Fix {index}: {get(finding, 'title', 'Security issue')}",
                "",
                f"Severity: {get(finding, 'severity', 'N/A')}",
                f"File: {get(finding, 'file_path', 'N/A')}",
                "",
                "### Problem",
                get(finding, "explanation", ""),
                "",
                "### Recommended Fix",
                get(finding, "fix_suggestion", ""),
                ""
            ])

        return "\n".join(lines)

    def to_fix_prompt_text(self, report) -> str:
        parts = ["CODE SECURITY FIX REQUEST", ""]

        for index, finding in enumerate(self._findings(report), 1):
            get = self._get
            parts.extend([
                f"ISSUE {index}: {get(finding, 'title', 'Security issue')}",
                f"Severity: {get(finding, 'severity', 'N/A')}",
                f"File: {get(finding, 'file_path', 'N/A')}",
                f"Line: {get(finding, 'line_number', 'N/A')}",
                f"Problem: {get(finding, 'explanation', '')}",
                f"Suggested fix: {get(finding, 'fix_suggestion', '')}",
                "",
                "Please provide a secure, minimal code correction.",
                ""
            ])

        return "\n".join(parts)

    
    def to_patch_diff(self, report) -> str:
        """Export only structurally valid unified Git diff patches."""
        patches = []

        for finding in self._findings(report):
            patch = self._get(finding, "patch", "")

            if not isinstance(patch, str):
                continue

            patch = patch.strip()

            if not patch:
                continue

            lines = patch.splitlines()

            # Check for valid unified diff file headers.
            has_old_header = any(
                line.startswith("--- a/") for line in lines
            )
            has_new_header = any(
                line.startswith("+++ b/") for line in lines
            )

            # Check for a unified diff hunk with line ranges.
            has_hunk = any(
    line.startswith("@@ -") and "@@" in line
    for line in lines
)
            

            if has_old_header and has_new_header and has_hunk:
                patches.append(patch)

        return "\n\n".join(patches)


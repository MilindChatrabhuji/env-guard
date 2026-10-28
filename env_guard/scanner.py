import re
from dataclasses import dataclass
from typing import List

@dataclass
class SecretFinding:
    rule_name: str
    match_preview: str
    line_number: int

PATTERNS = {
    "OpenAI API Key": re.compile(r"sk-[a-zA-Z0-9]{32,64}"),
    "GitHub Token": re.compile(r"gh[pousr]_[a-zA-Z0-9]{36}"),
    "AWS Access Key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "Generic Private Key": re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
    "Generic Bearer Token": re.compile(r"(?i)bearer\s+[a-zA-Z0-9_\-\.]{30,}")
}

def scan_text(text: str) -> List[SecretFinding]:
    findings = []
    lines = text.splitlines()
    for idx, line in enumerate(lines, 1):
        for name, pattern in PATTERNS.items():
            if pattern.search(line):
                findings.append(SecretFinding(
                    rule_name=name,
                    match_preview=line[:60].strip(),
                    line_number=idx
                ))
    return findings

def scan_file(file_path: str) -> List[SecretFinding]:
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        return scan_text(f.read())

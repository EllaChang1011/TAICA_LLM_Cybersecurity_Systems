"""
title: Security Output Guardrail Filter
author: security-lab
version: 1.0
description: An AI Output Guardrail that scans LLM responses for dangerous content including malicious commands, sensitive system operations, and social engineering templates. Automatically flags or redacts unsafe output to prevent AI from being weaponized.
"""

import re
from pydantic import BaseModel, Field
from typing import Optional, List


class Filter:
    class Valves(BaseModel):
        priority: int = Field(
            default=0, description="Priority level for the filter operations."
        )
        enabled: bool = Field(
            default=True, description="Enable or disable the output guardrail."
        )
        redact_mode: bool = Field(
            default=True,
            description="If True, redact dangerous content. If False, append warning only.",
        )

    def __init__(self):
        self.valves = self.Valves()

        # Dangerous command patterns
        self.dangerous_patterns = {
            "destructive_commands": {
                "label": "Destructive System Command",
                "patterns": [
                    r"rm\s+-rf\s+/",
                    r"rm\s+-rf\s+\*",
                    r"mkfs\.",
                    r"dd\s+if=.*of=/dev/",
                    r":\(\)\s*\{\s*:\|:\s*&\s*\}\s*;",
                    r"fork\s*bomb",
                ],
            },
            "sql_injection": {
                "label": "SQL Injection Payload",
                "patterns": [
                    r"DROP\s+TABLE",
                    r"DROP\s+DATABASE",
                    r"DELETE\s+FROM\s+\w+\s*;",
                    r"TRUNCATE\s+TABLE",
                    r";\s*--\s*",
                    r"'\s*OR\s+'1'\s*=\s*'1",
                    r"UNION\s+SELECT",
                ],
            },
            "reverse_shell": {
                "label": "Reverse Shell Command",
                "patterns": [
                    r"bash\s+-i\s+>&\s+/dev/tcp/",
                    r"nc\s+-e\s+/bin/(bash|sh)",
                    r"ncat\s.*-e\s+/bin/(bash|sh)",
                    r"python\s+-c\s+.*socket.*connect",
                    r"perl\s+-e\s+.*socket.*INET",
                    r"php\s+-r\s+.*fsockopen",
                    r"mkfifo\s+/tmp/",
                ],
            },
            "privilege_escalation": {
                "label": "Privilege Escalation Command",
                "patterns": [
                    r"sudo\s+chmod\s+777",
                    r"sudo\s+chmod\s+\+s",
                    r"chmod\s+4755",
                    r"chown\s+root",
                    r"passwd\s+root",
                    r"usermod\s+-aG\s+sudo",
                    r"visudo",
                ],
            },
            "credential_harvesting": {
                "label": "Credential Harvesting Technique",
                "patterns": [
                    r"mimikatz",
                    r"hashcat",
                    r"john\s+the\s+ripper",
                    r"hydra\s+-[lL]",
                    r"cain\s*(and|&)\s*abel",
                    r"/etc/shadow",
                    r"sam\s+database",
                ],
            },
            "social_engineering": {
                "label": "Social Engineering Template",
                "patterns": [
                    r"(dear|hello)\s+(sir|madam|user|customer).*verify\s+your\s+(account|password|identity)",
                    r"your\s+account\s+(has\s+been|will\s+be)\s+(suspended|locked|compromised)",
                    r"click\s+(here|this\s+link)\s+to\s+(verify|confirm|restore|unlock)",
                    r"urgent.*action\s+required.*account",
                    r"we\s+detected\s+suspicious\s+activity",
                ],
            },
        }

    def _scan_output(self, text: str) -> dict:
        """Scan AI output for dangerous content."""
        text_check = text.strip()
        detections = []

        for category, config in self.dangerous_patterns.items():
            for pattern in config["patterns"]:
                flags = re.IGNORECASE if category != "destructive_commands" else 0
                if category == "destructive_commands":
                    flags = 0
                else:
                    flags = re.IGNORECASE

                matches = re.findall(pattern, text_check, flags)
                if matches:
                    detections.append(
                        {
                            "category": category,
                            "label": config["label"],
                            "matched": pattern,
                            "count": len(matches),
                        }
                    )

        risk_level = "SAFE"
        if len(detections) >= 3:
            risk_level = "CRITICAL"
        elif len(detections) >= 2:
            risk_level = "HIGH"
        elif len(detections) >= 1:
            risk_level = "MEDIUM"

        return {
            "has_dangerous_content": len(detections) > 0,
            "risk_level": risk_level,
            "detections": detections,
            "total_flags": len(detections),
        }

    def _redact_dangerous_content(self, text: str) -> str:
        """Replace dangerous content with redaction markers."""
        redacted = text
        for category, config in self.dangerous_patterns.items():
            flags = 0 if category == "destructive_commands" else re.IGNORECASE
            for pattern in config["patterns"]:
                redacted = re.sub(
                    pattern,
                    f"[⚠️ {config['label']} REDACTED]",
                    redacted,
                    flags=flags,
                )
        return redacted

    def inlet(self, body: dict, __user__: Optional[dict] = None) -> dict:
        # Input pass-through, no modification
        return body

    def outlet(self, body: dict, __user__: Optional[dict] = None) -> dict:
        if not self.valves.enabled:
            return body

        messages = body.get("messages", [])
        if not messages:
            return body

        # Check the latest assistant message
        for message in reversed(messages):
            if message.get("role") == "assistant":
                content = message.get("content", "")
                if not content:
                    break

                result = self._scan_output(content)

                if result["has_dangerous_content"]:
                    # Build warning banner
                    flags_summary = ", ".join(
                        f"{d['label']} (x{d['count']})" for d in result["detections"]
                    )
                    warning = (
                        f"\n\n---\n"
                        f"⚠️ **OUTPUT GUARDRAIL ALERT** | Risk: **{result['risk_level']}**\n\n"
                        f"Detected: {flags_summary}\n\n"
                        f"This response contains potentially dangerous content. "
                        f"Do NOT execute these commands without proper authorization and understanding.\n"
                        f"---\n"
                    )

                    if self.valves.redact_mode:
                        # Redact dangerous content and append warning
                        message["content"] = self._redact_dangerous_content(content) + warning
                    else:
                        # Just append warning
                        message["content"] = content + warning

                break

        return body
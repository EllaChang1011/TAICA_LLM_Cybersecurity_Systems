"""
title: Security Analyzer Pipe
author: security-lab
version: 1.0
description: A cybersecurity Pipe that acts as a dedicated security analysis model. It scans user input for prompt injection patterns, PII leakage risks, and suspicious commands before forwarding safe messages to the underlying LLM with a security-focused system prompt.
"""

import re
from typing import Optional, Generator
from pydantic import BaseModel, Field


class Pipe:
    class Valves(BaseModel):
        model_id: str = Field(
            default="gpt-oss-20b",
            description="The base model to use for generating responses.",
        )
        enable_injection_check: bool = Field(
            default=True,
            description="Enable prompt injection detection.",
        )
        enable_pii_check: bool = Field(
            default=True,
            description="Enable PII leakage detection.",
        )
        block_on_threat: bool = Field(
            default=True,
            description="If True, block messages with detected threats. If False, warn and continue.",
        )

    def __init__(self):
        self.valves = self.Valves()

        # Prompt injection patterns
        self.injection_patterns = {
            "instruction_override": [
                r"ignore\s+(all\s+)?(previous|above|prior)\s+(instructions|prompts|rules)",
                r"disregard\s+(all\s+)?(previous|above|your)\s+(instructions|prompts|rules)",
                r"forget\s+(all\s+)?(previous|your)\s+(instructions|prompts|rules|context)",
                r"override\s+(all\s+)?(previous|your|system)\s+(instructions|prompts|rules)",
            ],
            "role_manipulation": [
                r"pretend\s+(you\s+are|to\s+be)\s+",
                r"act\s+as\s+(a|an|if)\s+",
                r"enter\s+(developer|admin|sudo|god|jailbreak)\s+mode",
                r"enable\s+(developer|admin|sudo|god|jailbreak)\s+mode",
                r"you\s+are\s+now\s+(a|an|the)\s+",
            ],
            "system_prompt_extraction": [
                r"(show|display|print|reveal|tell)\s+(me\s+)?(your|the)\s+(system\s+)?(prompt|instructions|rules)",
                r"what\s+(are|is)\s+your\s+(system\s+)?(prompt|instructions|rules)",
                r"repeat\s+(your|the)\s+(system\s+)?(prompt|instructions)",
            ],
            "delimiter_injection": [
                r"<\|.*?\|>",
                r"\[INST\]",
                r"\[/INST\]",
                r"<<SYS>>",
                r"###\s*(system|instruction|human|assistant)",
            ],
        }

        # PII patterns
        self.pii_patterns = {
            "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
            "credit_card": re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b"),
            "ip_address": re.compile(
                r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
            ),
            "ssn": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
        }

    def _check_injection(self, text: str) -> dict:
        text_lower = text.lower().strip()
        detections = []

        for category, patterns in self.injection_patterns.items():
            for pattern in patterns:
                if re.search(pattern, text_lower):
                    detections.append({"category": category, "pattern": pattern})

        return {
            "is_malicious": len(detections) > 0,
            "risk_score": round(min(len(detections) / 3.0, 1.0), 2),
            "detections": detections,
        }

    def _check_pii(self, text: str) -> dict:
        found = []
        for pii_type, pattern in self.pii_patterns.items():
            matches = pattern.findall(text)
            if matches:
                found.append({"type": pii_type, "count": len(matches)})

        return {
            "has_pii": len(found) > 0,
            "findings": found,
        }

    def pipe(self, body: dict, __user__: Optional[dict] = None) -> str:
        messages = body.get("messages", [])
        if not messages:
            return "No messages received."

        # Get the latest user message
        user_message = ""
        for msg in reversed(messages):
            if msg.get("role") == "user":
                content = msg.get("content", "")
                if isinstance(content, list):
                    content = " ".join(
                        item.get("text", "") for item in content if item.get("type") == "text"
                    )
                user_message = content
                break

        if not user_message:
            return "No user message found."

        # === Security Analysis ===
        report_parts = []
        has_threat = False

        # 1. Prompt Injection Check
        if self.valves.enable_injection_check:
            injection_result = self._check_injection(user_message)
            if injection_result["is_malicious"]:
                has_threat = True
                categories = set(d["category"] for d in injection_result["detections"])
                category_names = {
                    "instruction_override": "Instruction Override",
                    "role_manipulation": "Role Manipulation",
                    "system_prompt_extraction": "System Prompt Extraction",
                    "delimiter_injection": "Delimiter Injection",
                }
                detected = ", ".join(category_names.get(c, c) for c in categories)
                report_parts.append(
                    f"**Prompt Injection Detected**\n"
                    f"- Risk Score: {injection_result['risk_score']}\n"
                    f"- Type: {detected}\n"
                    f"- Matches: {len(injection_result['detections'])}"
                )

        # 2. PII Leakage Check
        if self.valves.enable_pii_check:
            pii_result = self._check_pii(user_message)
            if pii_result["has_pii"]:
                has_threat = True
                pii_details = ", ".join(
                    f"{f['type']} ({f['count']})" for f in pii_result["findings"]
                )
                report_parts.append(
                    f"**PII Leakage Risk Detected**\n"
                    f"- Found: {pii_details}\n"
                    f"- Warning: Sensitive data may be exposed to the LLM provider"
                )

        # === Generate Response ===
        if has_threat and self.valves.block_on_threat:
            # Block mode: return security report
            report = "\n\n".join(report_parts)
            return (
                f"## Security Analysis Report\n\n"
                f"{report}\n\n"
                f"---\n"
                f"**Status: BLOCKED**\n\n"
                f"Your message has been blocked due to detected security threats. "
                f"Please revise your input and try again.\n\n"
                f"*This analysis was performed by the Security Analyzer Pipe.*"
            )
        elif has_threat and not self.valves.block_on_threat:
            # Warn mode: show warnings but still respond
            report = "\n\n".join(report_parts)
            return (
                f"## Security Warning\n\n"
                f"{report}\n\n"
                f"---\n"
                f"**Status: WARNING** - Threats detected but message was not blocked.\n\n"
                f"*This analysis was performed by the Security Analyzer Pipe.*"
            )
        else:
            # No threats: provide security assessment
            return (
                f"## Security Analysis Report\n\n"
                f"**Status: SAFE**\n\n"
                f"No security threats detected in your message.\n\n"
                f"- Prompt Injection: Not detected\n"
                f"- PII Leakage: Not detected\n\n"
                f"Your message appears safe to send to an LLM.\n\n"
                f"*This analysis was performed by the Security Analyzer Pipe.*"
            )
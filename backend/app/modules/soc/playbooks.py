"""Incident playbooks — strategy pattern (FR-S05). Each playbook is a pure planner:
returns ordered steps; execution records incident rows and audited WS fan-out."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class PlaybookResult:
    playbook: str
    steps: list[dict] = field(default_factory=list)


class BasePlaybook:
    name = "base"

    def plan(self, context: dict) -> PlaybookResult:
        raise NotImplementedError


class BruteForcePlaybook(BasePlaybook):
    name = "brute_force"

    def plan(self, ctx: dict) -> PlaybookResult:
        ip = ctx["src_ip"]
        return PlaybookResult(self.name, [
            {"step": "identify", "detail": f"correlate auth logs for {ip}"},
            {"step": "block", "detail": f"temporary 60 min DROP for {ip}", "auto": True},
            {"step": "harden", "detail": "enforce fail2ban / rate-limit on exposed auth service"},
            {"step": "verify", "detail": "re-test authentication surface"},
        ])


class SQLiPlaybook(BasePlaybook):
    name = "sqli"

    def plan(self, ctx: dict) -> PlaybookResult:
        return PlaybookResult(self.name, [
            {"step": "contain", "detail": "enable WAF blocking rule set for affected URI"},
            {"step": "audit", "detail": "pull last 24h app logs for the URI"},
            {"step": "patch", "detail": "parameterize queries; disable verbose DB errors"},
            {"step": "scan", "detail": "schedule authenticated vuln scan (warrant required)"},
        ])


class DDoSPlaybook(BasePlaybook):
    name = "ddos"

    def plan(self, ctx: dict) -> PlaybookResult:
        return PlaybookResult(self.name, [
            {"step": "notify_upstream", "detail": "open incident with ISP/CDN scrubbing desk"},
            {"step": "rate_limit", "detail": "edge SYN cookies + per-IP limits"},
            {"step": "blackhole", "detail": "null-route attacker subnets if spoofed-source flood"},
            {"step": "post_mortem", "detail": "capture pcap for evidence manifest"},
        ])


class MalwarePlaybook(BasePlaybook):
    name = "malware"

    def plan(self, ctx: dict) -> PlaybookResult:
        return PlaybookResult(self.name, [
            {"step": "isolate", "detail": "quarantine host segment (manual switch change logged)"},
            {"step": "snapshot", "detail": "forensic image before remediation"},
            {"step": "ioc_sweep", "detail": "hash/IOC sweep across HW-monitored assets"},
            {"step": "rebuild", "detail": "reimage from known-good base; rotate creds"},
        ])


PLAYBOOKS = {p.name: p() for p in (BruteForcePlaybook, SQLiPlaybook, DDoSPlaybook, MalwarePlaybook)}
FORFEIT_HONEYPOT_NOTE = ("Honeypot deployment requires an isolated authorized network segment; "
                         "record the segment in a 'pentest' warrant before use.")

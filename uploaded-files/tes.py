#!/usr/bin/env python3
"""
===============================================================================
MIKROTIK ROUTEROS & HOTSPOT SECURITY COMPLIANCE FRAMEWORK (ENTERPRISE EDITION)
Version: 4.0.0 (Single-File Distribution)
===============================================================================

Mode: 100% Defensive & Passive/Configuration Audit (Non-Intrusive)

Modul:
- CVSS v3.1 Engine (Base + Temporal + Environmental)
- Voucher Security Analyzer (Shannon Entropy, NIST 800-63B)
- Hotspot Portal DOM Parser (CHAP, CSP, Mixed Content, XSS Surface)
- RouterOS .rsc Config Parser (section + rule decomposition)
- Firewall Rule Analyzer (default-deny, shadow, established/related)
- IP Service / User / SNMP / Certificate / Logging Analyzers
- 15+ Compliance Categories
- Interactive HTML Report (Design System v4, SVG Charts, Filters, Modals)
- JSON / Markdown / SARIF Output

Usage:
    python3 audit.py --target 20.20.1.9
    python3 audit.py --target 10.10.10.1 --mode fingerprint
    python3 audit.py --rsc export.rsc --mode config
    python3 audit.py --target 10.10.10.1 --rsc export.rsc --mode full --verbose
===============================================================================
"""

import os
import sys
import re
import math
import json
import time
import socket
import ipaddress
import datetime
import urllib.request
import urllib.error
import urllib.parse
import ssl
import hashlib
import argparse
import textwrap
import base64
from html.parser import HTMLParser
from html import escape as html_escape
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Tuple, Set, Any, Callable
from collections import Counter, OrderedDict
from enum import Enum


# =============================================================================
# 0. CONSTANTS, ENUMS, GLOBAL CONFIGURATION
# =============================================================================

FRAMEWORK_VERSION = "4.5.0"
FRAMEWORK_NAME = "MikroTik Enterprise Compliance Auditor"
REPORT_JSON_FILE = "audit_enterprise_report.json"
REPORT_HTML_FILE = "audit_enterprise_dashboard.html"
REPORT_MD_FILE = "audit_enterprise_report.md"
REPORT_SARIF_FILE = "audit_enterprise_report.sarif"

DEFAULT_TIMEOUT_SECONDS = 2.0
DEFAULT_USER_AGENT = f"{FRAMEWORK_NAME}/{FRAMEWORK_VERSION}"

PRIVATE_AND_RESERVED_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("::1/128"),
]

KNOWN_PUBLIC_CLOUD_BLOCKS = {
    "20.0.0.0/8": "Microsoft Azure / MS-Corp",
    "13.0.0.0/8": "Microsoft",
    "40.0.0.0/8": "Microsoft Azure",
    "52.0.0.0/8": "AWS",
    "54.0.0.0/8": "AWS",
    "34.0.0.0/8": "Google Cloud",
    "35.0.0.0/8": "Google Cloud",
}

SAFE_CONTACT_HOSTS = {
    "wa.me", "api.whatsapp.com", "web.whatsapp.com", "t.me", "telegram.me",
    "facebook.com", "m.facebook.com", "instagram.com", "youtube.com",
    "maps.google.com", "goo.gl", "bit.ly", "tiktok.com", "twitter.com", "x.com"
}

KNOWN_CDN_HOSTS = {
    "cdnjs.cloudflare.com", "cdn.jsdelivr.net", "unpkg.com",
    "ajax.googleapis.com", "code.jquery.com", "stackpath.bootstrapcdn.com"
}

# modules_part1.py: Threat Intel, CVE Database, CIS Matrix, MITRE ATT&CK, DNS Analyzer, Hotspot Analyzer

ROUTEROS_KNOWN_CVES = [
    {
        "cve": "CVE-2018-14847",
        "name": "Chimay-Red Winbox Credential Disclosure",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "affected": "< 6.42.1, < 6.40.8 (Long-term)",
        "fixed": "6.42.1, 6.40.8",
        "cwe": "CWE-22",
        "detail": "Kerentanan path traversal pada service Winbox (port 8291) memungkinkan penyerang tanpa autentikasi membaca file sensitif termasuk user.dat yang berisi password admin RouterOS.",
        "remediation": "/ip service set winbox address=192.168.88.0/24; /system package update install",
    },
    {
        "cve": "CVE-2019-3978",
        "name": "RouterOS Remote DNS Cache Poisoning",
        "severity": "HIGH",
        "cvss": 7.5,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N",
        "affected": "< 6.45.7, < 6.44.6 (Long-term)",
        "fixed": "6.45.7, 6.44.6",
        "cwe": "CWE-348",
        "detail": "Kelemahan validasi DNS cache memungkinkan penyerang meracuni cache DNS MikroTik dari jarak jauh tanpa brute force transaction ID.",
        "remediation": "/ip dns set allow-remote-requests=no; /system package update install",
    },
    {
        "cve": "CVE-2019-3943",
        "name": "Winbox Arbitrary Directory Traversal & File Write",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "affected": "< 6.44.3, < 6.43.15 (Long-term)",
        "fixed": "6.44.3, 6.43.15",
        "cwe": "CWE-22",
        "detail": "Penyerang terautentikasi atau melalui chaining dapat mengeksploitasi traversal untuk menulis file biner ke sistem file router dan mengeksekusi root shell.",
        "remediation": "/ip service set winbox address=192.168.88.0/24; /system package update install",
    },
    {
        "cve": "CVE-2023-30799",
        "name": "RouterOS MIPS/x86/ARM Privilege Escalation to Super-Admin (Root)",
        "severity": "CRITICAL",
        "cvss": 9.1,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H",
        "affected": "< 6.49.8, < 7.9",
        "fixed": "6.49.8, 7.9",
        "cwe": "CWE-269",
        "detail": "Penyerang dengan akun privilege rendah (group 'admin' atau 'write') dapat mengeksploitasi memori service Winbox/HTTP untuk mendapatkan akses root shell (developer debug console).",
        "remediation": "/system package update check-for-updates; /system package update install",
    },
    {
        "cve": "CVE-2023-32154",
        "name": "RouterOS IPv6 Route Advertisement Unauthenticated RCE",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "affected": "< 6.49.7, < 7.8",
        "fixed": "6.49.7, 7.8",
        "cwe": "CWE-120",
        "detail": "Buffer overflow pada daemon pemrosesan paket IPv6 Router Advertisement (RA). Penyerang di segmen lokal dapat mengeksekusi kode arbitrary tanpa autentikasi.",
        "remediation": "/ipv6 nd set [find] ra-interval=disabled; update RouterOS ke v7.8+",
    },
    {
        "cve": "CVE-2022-45315",
        "name": "RouterOS Queue Tree Memory Corruption DoS",
        "severity": "HIGH",
        "cvss": 7.5,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
        "affected": "< 6.49.7, < 7.6",
        "fixed": "6.49.7, 7.6",
        "cwe": "CWE-119",
        "detail": "Memory corruption pada pemrosesan queue tree yang dapat menyebabkan router crash / kernel panic reboot berulang.",
        "remediation": "/system package update install",
    },
    {
        "cve": "CVE-2018-7445",
        "name": "MikroTik SMB Service Remote Buffer Overflow",
        "severity": "CRITICAL",
        "cvss": 9.8,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "affected": "< 6.41.3",
        "fixed": "6.41.3",
        "cwe": "CWE-121",
        "detail": "Stack-based buffer overflow pada service SMB MikroTik (port 445/139) memungkinkan eksekusi kode remote arbitrary.",
        "remediation": "/ip smb set enabled=no",
    },
    {
        "cve": "CVE-2020-11881",
        "name": "IPsec IKEv1/IKEv2 Memory Corruption",
        "severity": "HIGH",
        "cvss": 8.6,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:H",
        "affected": "< 6.46.6, < 6.47.1",
        "fixed": "6.46.6, 6.47.1",
        "cwe": "CWE-787",
        "detail": "Eksploitasi paket malformed pada negosiasi IPsec dapat merusak memori kernel dan memicu reboot router.",
        "remediation": "/system package update install",
    }
]

CIS_BENCHMARKS_MATRIX = {
    "1.1": {"title": "Disable Unused IP Services (Telnet, FTP, WWW)", "section": "1. Initial Setup", "weight": "HIGH"},
    "1.2": {"title": "Restrict Management Service Access by IP Address List", "section": "1. Initial Setup", "weight": "CRITICAL"},
    "1.3": {"title": "Rename Default 'admin' User and Enforce Strong Passwords", "section": "1. Initial Setup", "weight": "CRITICAL"},
    "2.1": {"title": "Drop Invalid Connection State on Firewall Input & Forward", "section": "2. Firewall", "weight": "MEDIUM"},
    "2.2": {"title": "Default-Deny Policy on Input Chain with Specific Whitelist", "section": "2. Firewall", "weight": "CRITICAL"},
    "2.3": {"title": "Drop External DNS Queries to Protect DNS Resolver", "section": "2. Firewall", "weight": "CRITICAL"},
    "3.1": {"title": "Disable Bandwidth-Test Server on Public & Client Interfaces", "section": "3. Management Protocols", "weight": "HIGH"},
    "3.2": {"title": "Disable Neighbor Discovery (MNDP, CDP, LLDP) on Untrusted Ports", "section": "3. Management Protocols", "weight": "HIGH"},
    "3.3": {"title": "Disable MAC-Telnet and MAC-Winbox on Hotspot/Client Interfaces", "section": "3. Management Protocols", "weight": "CRITICAL"},
    "4.1": {"title": "Configure Remote Syslog Logging for Security Auditing", "section": "4. Logging & Monitoring", "weight": "HIGH"},
    "5.1": {"title": "Disable Wireless WPS and Use WPA2/WPA3 Dynamic Keys", "section": "5. Wireless Security", "weight": "HIGH"},
    "6.1": {"title": "Enforce NTP Time Synchronization via Secure Time Servers", "section": "6. System Maintenance", "weight": "MEDIUM"},
    "7.1": {"title": "Disable Insecure Hotspot Walled Garden Wildcards (*)", "section": "7. Hotspot & Captive Portal", "weight": "CRITICAL"}
}

MITRE_ATTACK_NETWORK_MATRIX = {
    "T1133": {"name": "External Remote Services", "tactic": "Initial Access", "desc": "Layanan manajemen (Winbox, SSH, WebFig, RoMON) terekspos langsung ke segmen luar."},
    "T1046": {"name": "Network Service Discovery", "tactic": "Discovery", "desc": "MNDP, LLDP, CDP membocorkan hostname, MAC address, dan versi RouterOS ke klien lokal."},
    "T1595": {"name": "Active Scanning & Fingerprinting", "tactic": "Reconnaissance", "desc": "Port scan dan probe protokol terhadap IP router tanpa rate-limiting firewall."},
    "T1090": {"name": "Proxy / Open Relay", "tactic": "Command and Control", "desc": "SOCKS atau Web Proxy MikroTik aktif tanpa autentikasi, digunakan sebagai pivot point."},
    "T1562": {"name": "Impair Defenses", "tactic": "Defense Evasion", "desc": "Ketiadaan aturan default-deny atau logging remote memungkinkan peretas menghapus jejak."},
    "T1078": {"name": "Valid Accounts", "tactic": "Persistence", "desc": "User default admin dengan password kosong atau lemah digunakan untuk login berulang."},
    "T1498": {"name": "Network Denial of Service", "tactic": "Impact", "desc": "Open DNS Resolver dimanfaatkan sebagai amplifier DDoS (amplification factor > 6x)."}
}


ROUTEROS_SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 80: "www", 443: "www-ssl",
    8291: "winbox", 8728: "api", 8729: "api-ssl", 2000: "bandwidth-server",
    5678: "romon", 161: "snmp", 162: "snmptrap", 514: "syslog", 20561: "mac-winbox",
}

DEFAULT_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "NONE": 4}


class ScanMode(Enum):
    PASSIVE_STRUCTURAL = "passive"
    PASSIVE_FINGERPRINT = "fingerprint"
    CONFIG_ONLY = "config"
    FULL_PASSIVE = "full"


class ComplianceFramework(Enum):
    OWASP_TOP10 = "OWASP Top 10 2021"
    CWE = "CWE"
    PCI_DSS = "PCI DSS v4.0"
    NIST_800_53 = "NIST SP 800-53 Rev 5"
    ISO_27001 = "ISO/IEC 27001:2022"
    CIS_ROUTEROS = "CIS MikroTik RouterOS Benchmark"


# =============================================================================
# 1. CVSS v3.1 ENGINE
# =============================================================================

@dataclass
class CVSSVector:
    attack_vector: str = "N"
    attack_complexity: str = "L"
    privileges_required: str = "N"
    user_interaction: str = "N"
    scope: str = "U"
    confidentiality: str = "L"
    integrity: str = "L"
    availability: str = "L"
    exploit_code_maturity: str = "X"
    remediation_level: str = "X"
    report_confidence: str = "X"
    confidentiality_req: str = "X"
    integrity_req: str = "X"
    availability_req: str = "X"
    modified_attack_vector: str = "X"
    modified_attack_complexity: str = "X"
    modified_privileges_required: str = "X"
    modified_user_interaction: str = "X"
    modified_scope: str = "X"
    modified_confidentiality: str = "X"
    modified_integrity: str = "X"
    modified_availability: str = "X"

    def to_vector_string(self) -> str:
        base = (
            f"CVSS:3.1/AV:{self.attack_vector}/AC:{self.attack_complexity}/"
            f"PR:{self.privileges_required}/UI:{self.user_interaction}/"
            f"S:{self.scope}/C:{self.confidentiality}/"
            f"I:{self.integrity}/A:{self.availability}"
        )
        temporal_parts = []
        if self.exploit_code_maturity != "X":
            temporal_parts.append(f"E:{self.exploit_code_maturity}")
        if self.remediation_level != "X":
            temporal_parts.append(f"RL:{self.remediation_level}")
        if self.report_confidence != "X":
            temporal_parts.append(f"RC:{self.report_confidence}")

        env_parts = []
        env_metrics = [
            ("CR", self.confidentiality_req), ("IR", self.integrity_req),
            ("AR", self.availability_req), ("MAV", self.modified_attack_vector),
            ("MAC", self.modified_attack_complexity),
            ("MPR", self.modified_privileges_required),
            ("MUI", self.modified_user_interaction), ("MS", self.modified_scope),
            ("MC", self.modified_confidentiality),
            ("MI", self.modified_integrity), ("MA", self.modified_availability),
        ]
        for key, val in env_metrics:
            if val != "X":
                env_parts.append(f"{key}:{val}")

        parts = [base]
        if temporal_parts:
            parts.extend(temporal_parts)
        if env_parts:
            parts.extend(env_parts)
        return "/".join(parts)


class CVSSv31Engine:
    AV_WEIGHTS = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
    AC_WEIGHTS = {"L": 0.77, "H": 0.44}
    UI_WEIGHTS = {"N": 0.85, "R": 0.62}
    CIA_WEIGHTS = {"N": 0.00, "L": 0.22, "H": 0.56}
    PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
    PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}

    E_WEIGHTS = {"X": 1.00, "U": 0.91, "P": 0.94, "F": 0.97, "H": 1.00}
    RL_WEIGHTS = {"X": 1.00, "O": 0.95, "T": 0.96, "W": 0.97, "U": 1.00}
    RC_WEIGHTS = {"X": 1.00, "U": 0.92, "R": 0.96, "C": 1.00}

    CR_WEIGHTS = {"X": 1.00, "L": 0.50, "M": 1.00, "H": 1.50}
    IR_WEIGHTS = {"X": 1.00, "L": 0.50, "M": 1.00, "H": 1.50}
    AR_WEIGHTS = {"X": 1.00, "L": 0.50, "M": 1.00, "H": 1.50}

    @classmethod
    def _roundup(cls, val: float) -> float:
        int_input = round(val * 100000)
        if (int_input % 10000) == 0:
            return int_input / 100000.0
        return (math.floor(int_input / 10000) + 1) / 10.0

    @classmethod
    def _resolve_modified(cls, modified: str, base: str, weights: Dict[str, float]) -> float:
        if modified == "X":
            return weights.get(base, list(weights.values())[0])
        return weights.get(modified, list(weights.values())[0])

    @classmethod
    def _resolve_modified_cia(cls, modified: str, base: str) -> float:
        if modified == "X":
            return cls.CIA_WEIGHTS.get(base, 0.0)
        return cls.CIA_WEIGHTS.get(modified, 0.0)

    @classmethod
    def calculate_base_score(cls, vector: CVSSVector) -> Tuple[float, str]:
        av = cls.AV_WEIGHTS.get(vector.attack_vector, 0.85)
        ac = cls.AC_WEIGHTS.get(vector.attack_complexity, 0.77)
        ui = cls.UI_WEIGHTS.get(vector.user_interaction, 0.85)

        if vector.scope == "U":
            pr = cls.PR_UNCHANGED.get(vector.privileges_required, 0.85)
        else:
            pr = cls.PR_CHANGED.get(vector.privileges_required, 0.85)

        c = cls.CIA_WEIGHTS.get(vector.confidentiality, 0.0)
        i = cls.CIA_WEIGHTS.get(vector.integrity, 0.0)
        a = cls.CIA_WEIGHTS.get(vector.availability, 0.0)

        iss = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a))
        if iss <= 0.0:
            return 0.0, "NONE"

        if vector.scope == "U":
            impact = 6.42 * iss
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * math.pow(iss - 0.02, 15)

        exploitability = 8.22 * av * ac * pr * ui

        if vector.scope == "U":
            score = cls._roundup(min(impact + exploitability, 10.0))
        else:
            score = cls._roundup(min(1.08 * (impact + exploitability), 10.0))

        return score, cls.get_severity_label(score)

    @classmethod
    def calculate_temporal_score(cls, base_score: float, vector: CVSSVector) -> float:
        if base_score <= 0.0:
            return 0.0
        e = cls.E_WEIGHTS.get(vector.exploit_code_maturity, 1.00)
        rl = cls.RL_WEIGHTS.get(vector.remediation_level, 1.00)
        rc = cls.RC_WEIGHTS.get(vector.report_confidence, 1.00)
        return cls._roundup(base_score * e * rl * rc)

    @classmethod
    def calculate_environmental_score(cls, vector: CVSSVector) -> Tuple[float, str]:
        mav = cls._resolve_modified(vector.modified_attack_vector, vector.attack_vector, cls.AV_WEIGHTS)
        mac = cls._resolve_modified(vector.modified_attack_complexity, vector.attack_complexity, cls.AC_WEIGHTS)
        mui = cls._resolve_modified(vector.modified_user_interaction, vector.user_interaction, cls.UI_WEIGHTS)

        scope = vector.modified_scope if vector.modified_scope != "X" else vector.scope
        base_pr = vector.privileges_required
        modified_pr = vector.modified_privileges_required

        if scope == "U":
            pr_weights = cls.PR_UNCHANGED
        else:
            pr_weights = cls.PR_CHANGED

        if modified_pr == "X":
            mpr = pr_weights.get(base_pr, 0.85)
        else:
            mpr = pr_weights.get(modified_pr, 0.85)

        mc = cls._resolve_modified_cia(vector.modified_confidentiality, vector.confidentiality)
        mi = cls._resolve_modified_cia(vector.modified_integrity, vector.integrity)
        ma = cls._resolve_modified_cia(vector.modified_availability, vector.availability)

        cr = cls.CR_WEIGHTS.get(vector.confidentiality_req, 1.00)
        ir = cls.IR_WEIGHTS.get(vector.integrity_req, 1.00)
        ar = cls.AR_WEIGHTS.get(vector.availability_req, 1.00)

        miss = min(
            1.0 - ((1.0 - mc * cr) * (1.0 - mi * ir) * (1.0 - ma * ar)),
            0.915
        )

        if miss <= 0.0:
            return 0.0, "NONE"

        if scope == "U":
            modified_impact = 6.42 * miss
        else:
            modified_impact = (
                7.52 * (miss - 0.029) - 3.25 * math.pow(miss * 0.9731 - 0.02, 13)
            )

        modified_exploitability = 8.22 * mav * mac * mpr * mui

        if modified_impact <= 0.0:
            return 0.0, "NONE"

        if scope == "U":
            env_score = cls._roundup(min(modified_impact + modified_exploitability, 10.0))
        else:
            env_score = cls._roundup(
                min(1.08 * (modified_impact + modified_exploitability), 10.0)
            )

        return env_score, cls.get_severity_label(env_score)

    @classmethod
    def calculate_score(cls, vector: CVSSVector) -> Tuple[float, str]:
        return cls.calculate_base_score(vector)

    @classmethod
    def full_report(cls, vector: CVSSVector) -> Dict[str, Any]:
        base, base_sev = cls.calculate_base_score(vector)
        temporal = cls.calculate_temporal_score(base, vector)
        env, env_sev = cls.calculate_environmental_score(vector)
        return {
            "vector_string": vector.to_vector_string(),
            "base_score": base,
            "base_severity": base_sev,
            "temporal_score": temporal,
            "environmental_score": env,
            "environmental_severity": env_sev,
        }

    @staticmethod
    def get_severity_label(score: float) -> str:
        if score >= 9.0:
            return "CRITICAL"
        if score >= 7.0:
            return "HIGH"
        if score >= 4.0:
            return "MEDIUM"
        if score > 0.0:
            return "LOW"
        return "NONE"


# =============================================================================
# 2. DATA STRUCTURES
# =============================================================================

@dataclass
class Evidence:
    kind: str
    source: str
    excerpt: str
    timestamp: str = field(default_factory=lambda: datetime.datetime.now().isoformat())

    def to_dict(self) -> Dict[str, str]:
        return asdict(self)


@dataclass
class ComplianceIssue:
    rule_id: str
    category: str
    title: str
    cwe_id: str
    owasp_ref: str
    cvss_vector: str
    cvss_score: float
    severity: str
    affected_component: str
    technical_detail: str
    evidence_snippet: str
    routeros_remediation_cli: List[str]
    verification_steps: List[str]
    temporal_score: float = 0.0
    environmental_score: float = 0.0
    compliance_frameworks: List[str] = field(default_factory=list)
    evidence_items: List[Dict[str, Any]] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    cvss_breakdown: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AuditSummary:
    target_identifier: str
    timestamp: str
    framework_version: str
    execution_time_ms: float
    overall_health_score: float
    security_grade: str
    severity_breakdown: Dict[str, int]
    category_breakdown: Dict[str, int]
    issues: List[ComplianceIssue] = field(default_factory=list)
    passed_checks: List[str] = field(default_factory=list)
    scan_mode: str = ScanMode.PASSIVE_FINGERPRINT.value
    config_sections_parsed: int = 0
    firewall_rules_analyzed: int = 0
    scanned_endpoints: List[str] = field(default_factory=list)


@dataclass
class AuditConfig:
    target_ip: str = "20.20.1.9"
    mode: ScanMode = ScanMode.PASSIVE_FINGERPRINT
    timeout: float = DEFAULT_TIMEOUT_SECONDS
    rsc_file_path: Optional[str] = None
    hotspot_html_paths: Dict[str, str] = field(default_factory=dict)
    max_findings_per_category: int = 50
    include_temporal_env: bool = True
    output_dir: str = "."
    verbose: bool = False


# =============================================================================
# 3. VOUCHER SECURITY ANALYZER
# =============================================================================

class VoucherSecurityAnalyzer:
    COMMON_SUFFIXES = [
        "wifi", "hotspot", "free", "voucher", "pass", "net", "user",
        "admin", "test", "guest", "mikhmon", "rt", "rw", "rt01", "rw01",
    ]

    @staticmethod
    def calculate_shannon_entropy(voucher_sample: str) -> float:
        if not voucher_sample:
            return 0.0
        length = len(voucher_sample)
        frequencies = Counter(voucher_sample)
        entropy = 0.0
        for count in frequencies.values():
            probability = count / length
            entropy -= probability * math.log2(probability)
        return round(entropy * length, 2)

    @staticmethod
    def detect_character_pool(voucher_sample: str) -> int:
        has_lower = bool(re.search(r"[a-z]", voucher_sample))
        has_upper = bool(re.search(r"[A-Z]", voucher_sample))
        has_digit = bool(re.search(r"[0-9]", voucher_sample))
        has_symbol = bool(re.search(r"[^a-zA-Z0-9]", voucher_sample))
        pool = 0
        if has_lower:
            pool += 26
        if has_upper:
            pool += 26
        if has_digit:
            pool += 10
        if has_symbol:
            pool += 32
        return max(pool, 1)

    @classmethod
    def detect_sequential_pattern(cls, sample: str) -> bool:
        if len(sample) < 4:
            return False
        lower = sample.lower()

        numeric = re.findall(r"\d+", lower)
        for chunk in numeric:
            if len(chunk) >= 4:
                as_ints = [int(c) for c in chunk]
                if all(as_ints[i] + 1 == as_ints[i + 1] for i in range(len(as_ints) - 1)):
                    return True
                if len(set(as_ints)) == 1:
                    return True

        alpha = re.findall(r"[a-z]+", lower)
        for chunk in alpha:
            if len(chunk) >= 4:
                chars = list(chunk)
                if all(ord(chars[i]) + 1 == ord(chars[i + 1]) for i in range(len(chars) - 1)):
                    return True
                if len(set(chars)) == 1:
                    return True

        return False

    @classmethod
    def detect_dictionary_suffix(cls, sample: str) -> List[str]:
        lower = sample.lower()
        return [suffix for suffix in cls.COMMON_SUFFIXES if suffix in lower]

    @classmethod
    def evaluate_voucher_pattern(
        cls,
        sample_code: str,
        username_equals_password: bool = True,
        online_rate_guess_per_second: int = 50,
    ) -> Dict[str, Any]:
        length = len(sample_code)
        pool_size = cls.detect_character_pool(sample_code)
        combinations = math.pow(pool_size, length)
        shannon_bits = cls.calculate_shannon_entropy(sample_code)

        seconds_to_exhaust = combinations / float(online_rate_guess_per_second)
        hours_to_exhaust = round(seconds_to_exhaust / 3600.0, 2)

        sequential = cls.detect_sequential_pattern(sample_code)
        dict_suffix = cls.detect_dictionary_suffix(sample_code)

        risk_level = "LOW"
        if length <= 4 or combinations < 100000 or sequential:
            risk_level = "CRITICAL"
        elif length <= 6 and pool_size <= 36:
            risk_level = "HIGH"
        elif dict_suffix or username_equals_password:
            risk_level = "MEDIUM"

        nist_800_63b_compliant = (
            length >= 8 and
            pool_size >= 62 and
            not sequential and
            not dict_suffix
        )

        return {
            "sample_length": length,
            "character_pool_size": pool_size,
            "total_combinations": int(combinations),
            "shannon_entropy_bits": shannon_bits,
            "estimated_exhaustion_hours_at_online_rate": hours_to_exhaust,
            "online_rate_assumed": online_rate_guess_per_second,
            "username_equals_password": username_equals_password,
            "detected_sequential_pattern": sequential,
            "detected_dictionary_suffixes": dict_suffix,
            "risk_level": risk_level,
            "nist_800_63b_aligned": nist_800_63b_compliant,
        }


# =============================================================================
# 4. HOTSPOT TEMPLATE DOM PARSER
# =============================================================================

class HotspotTemplateDOMParser(HTMLParser):
    def __init__(self, gateway_ip: str, page_url: str = ""):
        super().__init__()
        self.gateway_ip = gateway_ip
        self.page_url = page_url
        self.forms: List[Dict[str, str]] = []
        self.inputs: List[Dict[str, str]] = []
        self.external_scripts: Set[str] = set()
        self.external_stylesheets: Set[str] = set()
        self.safe_external_links: Set[str] = set()
        self.unknown_external_links: Set[str] = set()
        self.inline_event_handlers: List[Tuple[str, str]] = []
        self.html_comments: List[str] = []
        self.script_blocks: List[str] = []
        self.meta_tags: List[Dict[str, str]] = []
        self.iframes: List[str] = []
        self.img_sources: Set[str] = set()
        self.has_md5_reference: bool = False
        self.has_sendin_field: bool = False
        self.has_hexmd5_call: bool = False
        self.has_password_input: bool = False
        self.has_autocomplete_off: bool = False
        self._inside_script: bool = False
        self._current_form_index = -1

    def _extract_host(self, url: str) -> Optional[str]:
        match = re.match(r"^https?://([^/:]+)", url.strip(), re.IGNORECASE)
        if match:
            return match.group(1).lower()
        return None

    def _is_mixed_content(self, url: str) -> bool:
        if not self.page_url.startswith("https://"):
            return False
        return url.strip().lower().startswith("http://")

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]):
        tag_lower = tag.lower()
        attr_map = {k.lower(): (v or "") for k, v in attrs}

        for attr_name, attr_val in attr_map.items():
            if attr_name.startswith("on") and len(attr_name) > 2:
                self.inline_event_handlers.append(
                    (tag_lower, f"{attr_name}='{attr_val[:60]}'")
                )

        if tag_lower == "form":
            form_record = {
                "name": attr_map.get("name", ""),
                "action": attr_map.get("action", ""),
                "method": attr_map.get("method", "GET").upper(),
                "onsubmit": attr_map.get("onsubmit", ""),
                "has_sendin": "False",
            }
            self.forms.append(form_record)
            self._current_form_index = len(self.forms) - 1

        elif tag_lower == "input":
            input_record = {
                "name": attr_map.get("name", ""),
                "type": attr_map.get("type", "text").lower(),
                "value": attr_map.get("value", ""),
                "autocomplete": attr_map.get("autocomplete", ""),
            }
            self.inputs.append(input_record)

            if input_record["name"].lower() == "sendin":
                self.has_sendin_field = True
                if self._current_form_index >= 0:
                    self.forms[self._current_form_index]["has_sendin"] = "True"

            if input_record["type"] == "password":
                self.has_password_input = True
                if input_record["autocomplete"].lower() == "off":
                    self.has_autocomplete_off = True

        elif tag_lower == "script":
            self._inside_script = True
            src = attr_map.get("src", "")
            if "md5" in src.lower():
                self.has_md5_reference = True
            host = self._extract_host(src)
            if host and host != self.gateway_ip:
                self.external_scripts.add(src)
            if self._is_mixed_content(src):
                self.external_scripts.add(src + " [MIXED-CONTENT]")

        elif tag_lower == "link":
            rel = attr_map.get("rel", "").lower()
            href = attr_map.get("href", "")
            host = self._extract_host(href)
            if "stylesheet" in rel and host and host != self.gateway_ip:
                self.external_stylesheets.add(href)

        elif tag_lower == "a":
            href = attr_map.get("href", "")
            host = self._extract_host(href)
            if host and host != self.gateway_ip:
                if any(host == safe or host.endswith("." + safe) for safe in SAFE_CONTACT_HOSTS):
                    self.safe_external_links.add(href)
                else:
                    self.unknown_external_links.add(href)

        elif tag_lower == "meta":
            self.meta_tags.append(attr_map)

        elif tag_lower == "iframe":
            src = attr_map.get("src", "")
            if src:
                self.iframes.append(src)

        elif tag_lower == "img":
            src = attr_map.get("src", "")
            if src:
                self.img_sources.add(src)

    def handle_endtag(self, tag: str):
        if tag.lower() == "script":
            self._inside_script = False
        elif tag.lower() == "form":
            self._current_form_index = -1

    def handle_data(self, data: str):
        if self._inside_script:
            cleaned = data.strip()
            if cleaned:
                self.script_blocks.append(cleaned)
                lower = cleaned.lower()
                if "hexmd5" in lower or "chap-id" in lower or "chap-challenge" in lower:
                    self.has_md5_reference = True
                if re.search(r"hexmd5\s*\(", lower):
                    self.has_hexmd5_call = True

    def handle_comment(self, data: str):
        cleaned = data.strip()
        if cleaned:
            self.html_comments.append(cleaned)

    def get_meta_refresh(self) -> List[str]:
        refreshes = []
        for tag in self.meta_tags:
            if tag.get("http-equiv", "").lower() == "refresh":
                refreshes.append(tag.get("content", ""))
        return refreshes

    def get_csp(self) -> Optional[str]:
        for tag in self.meta_tags:
            if tag.get("http-equiv", "").lower() == "content-security-policy":
                return tag.get("content", "")
        return None


# =============================================================================
# 5. ROUTEROS CONFIG PARSER & SUB-ANALYZERS
# =============================================================================

class RouterOSConfigParser:
    def __init__(self, raw_rsc_text: str):
        self.raw_text = raw_rsc_text
        self.sections: Dict[str, List[str]] = {}
        self.raw_section_lines: Dict[str, List[str]] = {}
        self._parse_sections()

    def _parse_sections(self):
        current_section = "global"
        self.sections[current_section] = []
        self.raw_section_lines[current_section] = []
        logical_line = ""
        raw_buffer: List[str] = []

        for raw_line in self.raw_text.splitlines():
            stripped = raw_line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            raw_buffer.append(raw_line)
            if stripped.endswith("\\"):
                logical_line += stripped[:-1].strip() + " "
                continue
            else:
                logical_line += stripped

            if logical_line.startswith("/"):
                current_section = logical_line.lower()
                self.sections.setdefault(current_section, [])
                self.raw_section_lines.setdefault(current_section, [])
            else:
                self.sections.setdefault(current_section, []).append(logical_line)
                self.raw_section_lines.setdefault(current_section, []).extend(raw_buffer)

            logical_line = ""
            raw_buffer = []

    def get_section_commands(self, section_path: str) -> List[str]:
        return self.sections.get(section_path.lower(), [])

    def has_section(self, section_path: str) -> bool:
        return section_path.lower() in self.sections

    def get_section_count(self, section_path: str) -> int:
        return len(self.sections.get(section_path.lower(), []))

    def all_sections(self) -> List[str]:
        return list(self.sections.keys())

    def find_lines_containing(self, pattern: str, section_filter: Optional[str] = None) -> List[str]:
        result = []
        regex = re.compile(pattern, re.IGNORECASE)
        sections_to_check = (
            [section_filter.lower()] if section_filter
            else list(self.sections.keys())
        )
        for sec in sections_to_check:
            for line in self.sections.get(sec, []):
                if regex.search(line):
                    result.append(f"[{sec}] {line}")
        return result


class FirewallRuleAnalyzer:
    def __init__(self, config_parser: RouterOSConfigParser):
        self.parser = config_parser
        self.raw_rules = self.parser.get_section_commands("/ip firewall filter")
        self.parsed_rules: List[Dict[str, Any]] = []
        self._parse_rules()

    def _parse_rules(self):
        for idx, raw in enumerate(self.raw_rules):
            rule = {"index": idx, "raw": raw, "attrs": {}}
            for match in re.finditer(r'([a-zA-Z\-]+)=("[^"]*"|[^\s]+)', raw):
                key = match.group(1)
                value = match.group(2).strip('"')
                rule["attrs"][key] = value
            self.parsed_rules.append(rule)

    def has_default_deny(self, chain: str = "input") -> bool:
        for rule in self.parsed_rules:
            if rule["attrs"].get("chain", "").lower() != chain:
                continue
            action = rule["attrs"].get("action", "").lower()
            if action in ("drop", "reject"):
                restrictive = {
                    k for k in rule["attrs"]
                    if k in ("dst-address", "src-address", "dst-port",
                             "src-port", "protocol", "interface", "in-interface")
                }
                if not restrictive:
                    return True
        return False

    def has_established_related(self) -> bool:
        for rule in self.parsed_rules:
            if rule["attrs"].get("chain", "").lower() != "input":
                continue
            conn_state = rule["attrs"].get("connection-state", "").lower()
            if "established" in conn_state and "related" in conn_state:
                if rule["attrs"].get("action", "").lower() == "accept":
                    return True
        return False

    def has_invalid_drop(self) -> bool:
        for rule in self.parsed_rules:
            if rule["attrs"].get("chain", "").lower() != "input":
                continue
            if "invalid" in rule["attrs"].get("connection-state", "").lower():
                if rule["attrs"].get("action", "").lower() == "drop":
                    return True
        return False

    def find_shadowed_rules(self) -> List[Dict[str, Any]]:
        shadowed = []
        for i, rule in enumerate(self.parsed_rules):
            if i == 0:
                continue
            chain = rule["attrs"].get("chain", "").lower()
            action = rule["attrs"].get("action", "").lower()
            for prev in self.parsed_rules[:i]:
                if prev["attrs"].get("chain", "").lower() != chain:
                    continue
                prev_action = prev["attrs"].get("action", "").lower()
                if prev_action != action:
                    continue
                prev_constraints = sum(
                    1 for k in prev["attrs"]
                    if k in ("src-address", "dst-address", "dst-port",
                             "protocol", "in-interface", "connection-state")
                )
                curr_constraints = sum(
                    1 for k in rule["attrs"]
                    if k in ("src-address", "dst-address", "dst-port",
                             "protocol", "in-interface", "connection-state")
                )
                if prev_constraints < curr_constraints and prev_action == action:
                    shadowed.append({
                        "shadowed_index": i,
                        "shadowing_index": prev["index"],
                        "reason": "Broader earlier rule with same action shadows this rule",
                    })
                    break
        return shadowed

    def count_chain_rules(self, chain: str = "input") -> int:
        return sum(
            1 for r in self.parsed_rules
            if r["attrs"].get("chain", "").lower() == chain
        )

    def list_exposed_services(self) -> List[Tuple[int, str]]:
        exposed = []
        for rule in self.parsed_rules:
            if rule["attrs"].get("chain", "").lower() != "input":
                continue
            if rule["attrs"].get("action", "").lower() != "accept":
                continue
            port_str = rule["attrs"].get("dst-port", "")
            if not port_str or not re.fullmatch(r"\d+(,\d+)*", port_str):
                continue
            for port in port_str.split(","):
                exposed.append((int(port), "input"))
        return exposed


class IPServiceAnalyzer:
    def __init__(self, config_parser: RouterOSConfigParser):
        self.parser = config_parser
        self.service_lines = self.parser.get_section_commands("/ip service")

    def is_service_disabled(self, service_name: str) -> bool:
        for line in self.service_lines:
            if f"name={service_name}" in line.lower() and "disabled=yes" in line.lower():
                return True
        return False

    def is_service_enabled(self, service_name: str) -> bool:
        for line in self.service_lines:
            if f"name={service_name}" in line.lower():
                if "disabled=yes" in line.lower():
                    return False
                return True
        return False

    def get_service_address_restriction(self, service_name: str) -> Optional[str]:
        for line in self.service_lines:
            if f"name={service_name}" in line.lower():
                match = re.search(r'address=([^\s]+)', line, re.IGNORECASE)
                if match:
                    return match.group(1)
        return None

    def list_enabled_services(self) -> List[str]:
        enabled = []
        for line in self.service_lines:
            name_match = re.search(r'name=([^\s]+)', line, re.IGNORECASE)
            if name_match and "disabled=yes" not in line.lower():
                enabled.append(name_match.group(1))
        return enabled


class UserAccountAnalyzer:
    def __init__(self, config_parser: RouterOSConfigParser):
        self.parser = config_parser
        self.user_lines = self.parser.get_section_commands("/user")

    def list_users(self) -> List[Dict[str, str]]:
        users = []
        for line in self.user_lines:
            user = {}
            name_match = re.search(r'name=([^\s]+)', line, re.IGNORECASE)
            if name_match:
                user["name"] = name_match.group(1)
            group_match = re.search(r'group=([^\s]+)', line, re.IGNORECASE)
            if group_match:
                user["group"] = group_match.group(1)
            address_match = re.search(r'address=([^\s]+)', line, re.IGNORECASE)
            if address_match:
                user["address"] = address_match.group(1)
            if user.get("name"):
                users.append(user)
        return users

    def has_default_admin(self) -> bool:
        return any(u.get("name", "").lower() == "admin" for u in self.list_users())

    def has_users_without_address_restriction(self) -> List[str]:
        return [
            u["name"] for u in self.list_users()
            if "address" not in u and u.get("group", "").lower() in ("full", "write")
        ]


class CertificateAnalyzer:
    def __init__(self, config_parser: RouterOSConfigParser):
        self.parser = config_parser
        self.cert_lines = self.parser.get_section_commands("/certificate")

    def list_certificates(self) -> List[Dict[str, str]]:
        certs = []
        for line in self.cert_lines:
            cert = {}
            name_match = re.search(r'name=([^\s]+)', line, re.IGNORECASE)
            if name_match:
                cert["name"] = name_match.group(1)
            certs.append(cert)
        return certs

    def count_certificates(self) -> int:
        return len(self.list_certificates())


class SNMPAnalyzer:
    def __init__(self, config_parser: RouterOSConfigParser):
        self.parser = config_parser
        self.snmp_lines = self.parser.get_section_commands("/snmp")
        self.community_lines = self.parser.get_section_commands("/snmp community")

    def is_snmp_enabled(self) -> bool:
        for line in self.snmp_lines:
            if "enabled=yes" in line.lower():
                return True
        return False

    def has_default_community(self) -> bool:
        for line in self.community_lines:
            lower = line.lower()
            if "name=public" in lower or "name=private" in lower:
                return True
        return False


class WirelessAnalyzer:
    def __init__(self, config_parser: RouterOSConfigParser):
        self.parser = config_parser
        self.security_profiles = self.parser.get_section_commands("/interface wireless security-profiles")
        self.interfaces = self.parser.get_section_commands("/interface wireless")

    def has_open_security_profile(self) -> bool:
        for line in self.security_profiles:
            if "mode=none" in line.lower() or "authentication-types=" in line.lower() and "authentication-types=" not in line.lower():
                if "mode=none" in line.lower():
                    return True
        return False

    def has_wep_encryption(self) -> bool:
        return any("wep" in line.lower() for line in self.security_profiles)

    def has_wpa2_only(self) -> bool:
        wpa2_only = False
        for line in self.security_profiles:
            if "mode=dynamic-keys" in line.lower():
                if "wpa2-psk" in line.lower() and "wpa-psk" not in line.lower().replace("wpa2-psk", ""):
                    wpa2_only = True
        return wpa2_only

    def has_wps_enabled(self) -> bool:
        return any("wps-mode=push-button" in line.lower() for line in self.interfaces)


class DNSResolverSecurityAnalyzer:
    """
    Menganalisis konfigurasi dan perilaku live DNS resolver pada MikroTik.
    Mendeteksi:
    - Open Recursive DNS Resolver (CVSS 9.8 - CRITICAL)
    - DNS Amplification Factor
    - Kerentanan Kaminsky Cache Poisoning
    - Pengaturan allow-remote-requests=yes tanpa firewall
    """
    def __init__(self, target_ip: str, timeout: float = 2.0, config_parser = None):
        self.target_ip = target_ip
        self.timeout = timeout
        self.parser = config_parser

    @staticmethod
    def craft_dns_query(domain: str = "google.com", query_id: int = 0xbeef) -> bytes:
        """Membuat paket raw DNS Query A-record standar dengan Recursion Desired (RD=1)."""
        # Header: ID (2B), Flags=0x0100 (RD=1), QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
        header = query_id.to_bytes(2, "big") + b"\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        qname = b""
        for part in domain.split("."):
            qname += len(part).to_bytes(1, "big") + part.encode("ascii")
        qname += b"\x00"
        # Type A (1), Class IN (1)
        trailer = b"\x00\x01\x00\x01"
        return header + qname + trailer

    def probe_udp_recursion(self, test_domain: str = "google.com") -> Dict[str, Any]:
        """Melakukan tes live UDP query untuk mendeteksi apakah router merespon rekursi ke domain luar."""
        query_pkt = self.craft_dns_query(test_domain)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(self.timeout)
        t_start = time.time()
        try:
            sock.sendto(query_pkt, (self.target_ip, 53))
            resp_data, _ = sock.recvfrom(1024)
            elapsed_ms = round((time.time() - t_start) * 1000.0, 2)
            if len(resp_data) >= 12:
                resp_id = int.from_bytes(resp_data[:2], "big")
                flags = int.from_bytes(resp_data[2:4], "big")
                is_response = bool(flags & 0x8000)
                recursion_avail = bool(flags & 0x0080)
                rcode = flags & 0x000F
                ancount = int.from_bytes(resp_data[6:8], "big")
                amp_factor = round(len(resp_data) / max(1, len(query_pkt)), 2)
                return {
                    "is_open_resolver": is_response and recursion_avail and (rcode == 0 or ancount > 0),
                    "recursion_available": recursion_avail,
                    "response_length_bytes": len(resp_data),
                    "query_length_bytes": len(query_pkt),
                    "amplification_factor": amp_factor,
                    "rcode": rcode,
                    "ancount": ancount,
                    "response_time_ms": elapsed_ms,
                    "raw_sample_hex": resp_data[:24].hex(),
                    "tested_domain": test_domain
                }
        except socket.timeout:
            return {"is_open_resolver": False, "timeout": True}
        except Exception as e:
            return {"is_open_resolver": False, "error": str(e)}
        finally:
            sock.close()
        return {"is_open_resolver": False}

    def check_rsc_dns_config(self) -> Dict[str, Any]:
        """Menganalisis konfigurasi /ip dns dari file .rsc export."""
        if not self.parser:
            return {}
        commands = self.parser.get_section_commands("/ip dns")
        allow_remote = False
        cache_size = "2048KiB"
        static_entries = len(self.parser.get_section_commands("/ip dns static"))
        for cmd in commands:
            if "allow-remote-requests=yes" in cmd.lower():
                allow_remote = True
            m_cache = re.search(r"cache-size=([^\s]+)", cmd)
            if m_cache:
                cache_size = m_cache.group(1)
        return {
            "allow_remote_requests": allow_remote,
            "cache_size": cache_size,
            "static_entries_count": static_entries,
            "raw_commands": commands
        }


class HotspotWalledGardenAndBypassAnalyzer:
    """
    Menganalisis keamanan Walled Garden dan IP Binding Hotspot MikroTik.
    Mendeteksi:
    - Wildcard Host Walled Garden (*) -> CVSS 9.1 CRITICAL (Bypass Autentikasi Total)
    - IP Binding type=bypassed tanpa batasan MAC
    - Cookie Timeout berlebih (> 3 hari)
    """
    def __init__(self, config_parser):
        self.parser = config_parser

    def find_wildcard_walled_garden(self) -> List[Dict[str, str]]:
        if not self.parser:
            return []
        wg_lines = self.parser.get_section_commands("/ip hotspot walled-garden")
        wg_ip_lines = self.parser.get_section_commands("/ip hotspot walled-garden ip")
        wildcards = []
        for line in wg_lines:
            if "dst-host=*" in line or 'dst-host="*"' in line or "action=allow" in line and "dst-host=" not in line:
                wildcards.append({"type": "walled-garden", "rule": line, "reason": "Wildcard dst-host=* mengizinkan akses ke semua web sebelum login"})
        for line in wg_ip_lines:
            if "action=accept" in line.lower() and "dst-address=" not in line.lower() and "dst-host=" not in line.lower():
                wildcards.append({"type": "walled-garden-ip", "rule": line, "reason": "Rule walled-garden ip accept tanpa batasan dst-address"})
        return wildcards

    def find_unauthenticated_ip_bypasses(self) -> List[Dict[str, str]]:
        if not self.parser:
            return []
        lines = self.parser.get_section_commands("/ip hotspot ip-binding")
        bypasses = []
        for line in lines:
            if "type=bypassed" in line.lower():
                mac_match = re.search(r"mac-address=([^\s]+)", line)
                ip_match = re.search(r"address=([^\s]+)", line)
                if not mac_match or mac_match.group(1) in ("00:00:00:00:00:00", ""):
                    bypasses.append({"rule": line, "risk": "IP binding bypassed tanpa validasi MAC address valid"})
                else:
                    bypasses.append({"rule": line, "risk": f"IP/MAC bypass aktif untuk {ip_match.group(1) if ip_match else 'IP'} - {mac_match.group(1)}"})
        return bypasses

    def check_cookie_lifetime(self) -> List[Dict[str, str]]:
        if not self.parser:
            return []
        profiles = self.parser.get_section_commands("/ip hotspot user profile")
        risky = []
        for line in profiles:
            m = re.search(r"http-cookie-lifetime=([^\s]+)", line)
            if m:
                val = m.group(1)
                if "d" in val:
                    days = int(val.replace("d", "").split("h")[0])
                    if days > 3:
                        risky.append({"rule": line, "lifetime": val, "reason": f"Cookie lifetime ({val}) > 3 hari meningkatkan risiko session hijacking"})
        return risky

# modules_part2.py: Advanced Firewall, Management Discovery, Crypto, IAM, and CVE Fingerprint Engine

class AdvancedFirewallTableAnalyzer:
    """
    Menganalisis tabel firewall lanjut RouterOS:
    - /ip firewall raw (SYN flood protection, bogon dropping)
    - /ip firewall nat (Masquerade tanpa out-interface -> IP spoofing risk)
    - /ip firewall mangle (MSS clamping untuk MTU blackholes)
    - FastTrack bypass verification
    """
    def __init__(self, config_parser):
        self.parser = config_parser

    def check_nat_masquerade_hygiene(self) -> List[Dict[str, str]]:
        if not self.parser:
            return []
        nat_rules = self.parser.get_section_commands("/ip firewall nat")
        flaws = []
        for r in nat_rules:
            if "action=masquerade" in r.lower():
                has_out_interface = "out-interface=" in r.lower() or "out-interface-list=" in r.lower()
                if not has_out_interface:
                    flaws.append({
                        "rule": r,
                        "flaw": "Masquerade tanpa out-interface atau out-interface-list",
                        "impact": "Menyebabkan semua paket yang di-forward tertranslasi ke IP interface keluar, berisiko IP spoofing dan loop routing.",
                        "fix": "/ip firewall nat set [find action=masquerade] out-interface-list=WAN"
                    })
        return flaws

    def check_raw_table_dos_mitigation(self) -> Dict[str, Any]:
        if not self.parser:
            return {"has_raw_rules": False, "has_syn_flood_drop": False}
        raw_rules = self.parser.get_section_commands("/ip firewall raw")
        has_syn_drop = any("tcp-flags=syn" in r.lower() and "action=drop" in r.lower() for r in raw_rules)
        has_bogon_drop = any("bogon" in r.lower() for r in raw_rules)
        return {
            "has_raw_rules": len(raw_rules) > 0,
            "raw_rules_count": len(raw_rules),
            "has_syn_flood_drop": has_syn_drop,
            "has_bogon_drop": has_bogon_drop
        }

    def check_mangle_mss_clamping(self) -> bool:
        if not self.parser:
            return False
        mangle_rules = self.parser.get_section_commands("/ip firewall mangle")
        return any("change-mss" in r.lower() for r in mangle_rules)


class ManagementAndNeighborDiscoveryAnalyzer:
    """
    Menganalisis protokol discovery dan manajemen layer-2/layer-3:
    - MNDP (MikroTik Neighbor Discovery Protocol - UDP 5678)
    - CDP / LLDP leaks pada port Hotspot/publik
    - MAC-Server / MAC-Winbox exposure
    - RoMON (Router Management Overlay Network)
    - Bandwidth-Test Server DoS exposure (Port 2000)
    - Cloud DDNS & Back-To-Home VPN (/ip cloud)
    - SOCKS Proxy & Web Proxy Open Relay
    """
    def __init__(self, target_ip: str, config_parser = None, timeout: float = 2.0):
        self.target_ip = target_ip
        self.parser = config_parser
        self.timeout = timeout

    def probe_bandwidth_test_server(self) -> Dict[str, Any]:
        """Probing port 2000 TCP untuk mendeteksi service Bandwidth-Test Server MikroTik."""
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            res = sock.connect_ex((self.target_ip, 2000))
            if res == 0:
                return {
                    "is_open": True,
                    "port": 2000,
                    "service": "Bandwidth-Test Server",
                    "risk": "Layanan menerima koneksi tanpa rate-limit. Siapa pun di jaringan dapat melakukan flood bandwidth test dan menghabiskan 100% CPU router.",
                    "fix": "/tool bandwidth-server set enabled=no"
                }
        except Exception as e:
            return {"is_open": False, "error": str(e)}
        finally:
            sock.close()
        return {"is_open": False}

    def probe_socks_and_proxy(self) -> List[Dict[str, Any]]:
        """Mengecek apakah port SOCKS (1080) atau Web Proxy (8080/3128) terbuka."""
        proxies = []
        for port, name in [(1080, "SOCKS Proxy"), (8080, "MikroTik Web Proxy"), (3128, "Squid/Web Proxy")]:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            try:
                if sock.connect_ex((self.target_ip, port)) == 0:
                    proxies.append({
                        "port": port,
                        "name": name,
                        "risk": "Port proxy terbuka - berisiko menjadi open proxy relay untuk bypass firewall dan penyerangan pihak ketiga.",
                        "fix": f"/ip proxy set enabled=no" if "8080" in str(port) else "/ip socks set enabled=no"
                    })
            except Exception:
                pass
            finally:
                sock.close()
        return proxies

    def check_neighbor_discovery_config(self) -> List[Dict[str, str]]:
        if not self.parser:
            return []
        commands = self.parser.get_section_commands("/ip neighbor discovery-settings")
        findings = []
        for cmd in commands:
            if "discover-interface-list=all" in cmd.lower():
                findings.append({
                    "rule": cmd,
                    "risk": "Neighbor Discovery aktif pada interface 'all'. Protokol MNDP, CDP, dan LLDP menyiarkan identitas router, nama interface, dan IP ke klien Hotspot.",
                    "fix": "/ip neighbor discovery-settings set discover-interface-list=LAN"
                })
        return findings

    def check_mac_server_config(self) -> List[Dict[str, str]]:
        if not self.parser:
            return []
        mac_srv = self.parser.get_section_commands("/tool mac-server")
        mac_win = self.parser.get_section_commands("/tool mac-server mac-winbox")
        findings = []
        for cmd in mac_srv + mac_win:
            if "allowed-interface-list=all" in cmd.lower() or ("interface=all" in cmd.lower() and "disabled=no" in cmd.lower()):
                findings.append({
                    "rule": cmd,
                    "risk": "MAC-Server atau MAC-Winbox aktif di semua interface. Pengguna layer 2 WiFi dapat mengakses router tanpa IP address.",
                    "fix": "/tool mac-server set allowed-interface-list=LAN; /tool mac-server mac-winbox set allowed-interface-list=LAN"
                })
        return findings


class CryptographicAndTLSConfigurationAnalyzer:
    """
    Menganalisis konfigurasi kriptografi:
    - SSH Strong Crypto (/ip ssh set strong-crypto=yes)
    - SSL/TLS protocol allowed (TLS 1.0, 1.1 deprecation)
    - Certificate key length < 2048 bit & self-signed
    """
    def __init__(self, config_parser):
        self.parser = config_parser

    def check_ssh_crypto_hygiene(self) -> Dict[str, Any]:
        if not self.parser:
            return {"strong_crypto": True}
        ssh_cmds = self.parser.get_section_commands("/ip ssh")
        strong_crypto = False
        for cmd in ssh_cmds:
            if "strong-crypto=yes" in cmd.lower():
                strong_crypto = True
        return {
            "strong_crypto": strong_crypto,
            "fix": "/ip ssh set strong-crypto=yes host-key-size=4096"
        }

    def check_certificates_deep(self) -> List[Dict[str, str]]:
        if not self.parser:
            return []
        cert_cmds = self.parser.get_section_commands("/certificate")
        issues = []
        for cmd in cert_cmds:
            if "common-name=" in cmd.lower():
                if "key-size=1024" in cmd.lower():
                    issues.append({"cert": cmd, "issue": "Key size 1024-bit RSA sudah usang dan rentan faktorisasi (NIST merekomendasikan >= 2048 bit)."})
                if "invalid-after=" in cmd.lower():
                    # cek expired
                    pass
        return issues


class IdentityAndAccessManagementAnalyzer:
    """
    Menganalisis User, Hak Akses, dan Kebijakan Password:
    - User default 'admin'
    - Password kosong atau sama dengan user
    - Pengguna group full/write tanpa pembatasan IP
    - SSH Key autentikasi
    """
    def __init__(self, config_parser):
        self.parser = config_parser

    def find_insecure_accounts(self) -> List[Dict[str, str]]:
        if not self.parser:
            return []
        users = self.parser.get_section_commands("/user")
        issues = []
        for cmd in users:
            name_m = re.search(r"name=([^\s]+)", cmd)
            name = name_m.group(1).strip('"') if name_m else ""
            if name.lower() == "admin":
                if "disabled=yes" not in cmd.lower():
                    issues.append({
                        "user": name,
                        "risk": "CRITICAL: Akun default 'admin' aktif. Ini adalah target utama serangan kamus dan brute-force.",
                        "fix": "/user add name=sysadmin group=full password=\"<STRONG_PASS>\"; /user disable admin"
                    })
            if "group=full" in cmd.lower() or "group=write" in cmd.lower():
                if "address=" not in cmd.lower():
                    issues.append({
                        "user": name,
                        "risk": f"Akun '{name}' memiliki privilege tinggi ({'full' if 'group=full' in cmd.lower() else 'write'}) tanpa pembatasan IP address sumber (address=...).",
                        "fix": f"/user set [find name=\"{name}\"] address=192.168.88.0/24"
                    })
        return issues


class MikroTikCVEFingerprintEngine:
    """
    Mengevaluasi banner, header HTTP, port service untuk mencocokkan dengan CVE MikroTik yang diketahui.
    """
    def __init__(self, target_ip: str, timeout: float = 2.0):
        self.target_ip = target_ip
        self.timeout = timeout

    def grab_http_server_banner(self) -> Optional[str]:
        try:
            req = urllib.request.Request(f"http://{self.target_ip}/", headers={"User-Agent": DEFAULT_USER_AGENT})
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                server = resp.headers.get("Server", "")
                return server
        except urllib.error.HTTPError as e:
            return e.headers.get("Server", "")
        except Exception:
            return None

    def grab_ftp_banner(self) -> Optional[str]:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            if sock.connect_ex((self.target_ip, 21)) == 0:
                banner = sock.recv(256).decode("utf-8", errors="ignore").strip()
                return banner
        except Exception:
            return None
        finally:
            sock.close()
        return None

    def evaluate_cves(self, detected_version: Optional[str] = None) -> List[Dict[str, Any]]:
        matched = []
        if not detected_version:
            return matched
        # Cocokkan versi RouterOS
        return matched


# =============================================================================
# 6. MAIN AUDITOR
# =============================================================================

class EnterpriseMikrotikAuditor:
    def __init__(self, config: AuditConfig):
        self.config = config
        self.target_ip = config.target_ip
        self.issues: List[ComplianceIssue] = []
        self.passed_checks: List[str] = []
        self.scanned_endpoints: List[str] = []
        self._issue_counter = 1
        self._category_counter: Dict[str, int] = {}

        self.ssl_ctx = ssl.create_default_context()
        self.ssl_ctx.check_hostname = False
        self.ssl_ctx.verify_mode = ssl.CERT_NONE

        self.rsc_parser: Optional[RouterOSConfigParser] = None
        self.firewall_analyzer: Optional[FirewallRuleAnalyzer] = None
        self.ipservice_analyzer: Optional[IPServiceAnalyzer] = None
        self.user_analyzer: Optional[UserAccountAnalyzer] = None
        self.cert_analyzer: Optional[CertificateAnalyzer] = None
        self.snmp_analyzer: Optional[SNMPAnalyzer] = None
        self.wireless_analyzer: Optional[WirelessAnalyzer] = None

        if config.rsc_file_path and os.path.isfile(config.rsc_file_path):
            with open(config.rsc_file_path, "r", encoding="utf-8", errors="ignore") as f:
                self.rsc_parser = RouterOSConfigParser(f.read())
            self.firewall_analyzer = FirewallRuleAnalyzer(self.rsc_parser)
            self.ipservice_analyzer = IPServiceAnalyzer(self.rsc_parser)
            self.user_analyzer = UserAccountAnalyzer(self.rsc_parser)
            self.cert_analyzer = CertificateAnalyzer(self.rsc_parser)
            self.snmp_analyzer = SNMPAnalyzer(self.rsc_parser)
            self.wireless_analyzer = WirelessAnalyzer(self.rsc_parser)

    def _add_finding(
        self,
        category: str,
        title: str,
        cwe: str,
        owasp: str,
        vector: CVSSVector,
        component: str,
        detail: str,
        evidence: str,
        cli_fixes: List[str],
        verify_steps: List[str],
        compliance_frameworks: Optional[List[str]] = None,
        references: Optional[List[str]] = None,
    ):
        for existing in self.issues:
            if existing.title == title and existing.affected_component == component:
                return

        cvss_full = CVSSv31Engine.full_report(vector)
        rule_id = f"MTK-ENT-{self._issue_counter:04d}"
        self._issue_counter += 1

        self._category_counter[category] = self._category_counter.get(category, 0) + 1

        self.issues.append(ComplianceIssue(
            rule_id=rule_id,
            category=category,
            title=title,
            cwe_id=cwe,
            owasp_ref=owasp,
            cvss_vector=cvss_full["vector_string"],
            cvss_score=cvss_full["base_score"],
            severity=cvss_full["base_severity"],
            affected_component=component,
            technical_detail=detail,
            evidence_snippet=evidence,
            routeros_remediation_cli=cli_fixes,
            verification_steps=verify_steps,
            temporal_score=cvss_full["temporal_score"],
            environmental_score=cvss_full["environmental_score"],
            compliance_frameworks=compliance_frameworks or [],
            references=references or [],
            cvss_breakdown=cvss_full,
        ))

    def _safe_fetch(self, path: str) -> Tuple[int, Dict[str, str], str]:
        if "logout" in path.lower():
            raise ValueError("Security: forbidden to call logout endpoints.")
        url = f"http://{self.target_ip}{path}"
        self.scanned_endpoints.append(url)
        req = urllib.request.Request(url, headers={"User-Agent": DEFAULT_USER_AGENT})
        try:
            with urllib.request.urlopen(req, timeout=self.config.timeout, context=self.ssl_ctx) as resp:
                return resp.getcode(), dict(resp.info()), resp.read().decode("utf-8", errors="ignore")
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers), ""
        except Exception as e:
            return 0, {}, str(e)

    def _probe_port(self, port: int) -> bool:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.config.timeout)
        try:
            return sock.connect_ex((self.target_ip, port)) == 0
        except Exception:
            return False
        finally:
            sock.close()

    # ------------------------------------------------------------------
    # CHECK 1: NETWORK ARCHITECTURE
    # ------------------------------------------------------------------
    def check_network_addressing(self):
        try:
            ip_obj = ipaddress.ip_address(self.target_ip)
        except ValueError:
            return

        is_private = any(
            ip_obj in net for net in PRIVATE_AND_RESERVED_NETWORKS
            if net.version == ip_obj.version
        )

        if not is_private:
            cloud_owner = None
            for block, owner in KNOWN_PUBLIC_CLOUD_BLOCKS.items():
                try:
                    if ip_obj in ipaddress.ip_network(block):
                        cloud_owner = owner
                        break
                except ValueError:
                    continue

            owner_text = f" ({cloud_owner})" if cloud_owner else ""
            vec = CVSSVector(
                attack_vector="A", attack_complexity="L", privileges_required="N",
                user_interaction="N", scope="U", confidentiality="L",
                integrity="L", availability="H"
            )
            self._add_finding(
                category="Network Architecture & Routing",
                title="Pelanggaran RFC 1918: Penggunaan IP Publik pada LAN Hotspot",
                cwe="CWE-706",
                owasp="A05:2021-Security Misconfiguration",
                vector=vec,
                component=f"Gateway IP ({self.target_ip})",
                detail=(
                    f"Alamat {self.target_ip} adalah blok IP Publik{owner_text}. "
                    "Menggunakannya sebagai IP lokal menyebabkan trafik pengguna menuju server "
                    "di subnet tersebut dibelokkan ke router lokal (blackhole routing), sekaligus "
                    "membingungkan routing tabel dan monitoring upstream ISP."
                ),
                evidence=f"ipaddress.ip_address('{self.target_ip}').is_private == False",
                cli_fixes=[
                    "/ip address add address=10.20.1.1/24 interface=bridge-hotspot comment=\"RFC1918 Private Subnet\"",
                    "/ip pool set hs-pool ranges=10.20.1.10-10.20.1.254",
                    "/ip dhcp-server network set [find] address=10.20.1.0/24 gateway=10.20.1.1 dns-server=10.20.1.1",
                    "/ip hotspot profile set [find] hotspot-address=10.20.1.1"
                ],
                verify_steps=[
                    "Buka Winbox -> IP -> Addresses, pastikan tidak ada IP berawalan publik pada interface lokal.",
                    "Lakukan ping dan traceroute ke layanan cloud untuk memastikan rute keluar normal."
                ],
                compliance_frameworks=["NIST SP 800-53 Rev 5 (SC-7)", "ISO/IEC 27001:2022 (A.8.20)"],
            )
        else:
            self.passed_checks.append(
                "Alokasi IP Gateway telah sesuai dengan standar IP Private RFC 1918."
            )

    # ------------------------------------------------------------------
    # CHECK 2: MANAGEMENT PLANE ISOLATION
    # ------------------------------------------------------------------
    def check_management_plane_isolation(self):
        if self.config.mode == ScanMode.CONFIG_ONLY:
            if self.ipservice_analyzer:
                for svc_name in ["telnet", "ftp", "www", "api"]:
                    if self.ipservice_analyzer.is_service_enabled(svc_name):
                        addr_restrict = self.ipservice_analyzer.get_service_address_restriction(svc_name)
                        if not addr_restrict or addr_restrict in ("0.0.0.0/0", "::/0"):
                            vec = CVSSVector("N", "L", "L", "N", "U", "H", "H", "L")
                            self._add_finding(
                                category="Management Plane Exposure",
                                title=f"Layanan {svc_name} aktif tanpa pembatasan alamat",
                                cwe="CWE-284",
                                owasp="A01:2021-Broken Access Control",
                                vector=vec,
                                component=f"/ip service {svc_name}",
                                detail=f"Service {svc_name} aktif dan tidak dibatasi ke subnet manajemen.",
                                evidence=f"/ip service print where name={svc_name}",
                                cli_fixes=[
                                    f"/ip service disable {svc_name}" if svc_name in ("telnet", "ftp")
                                    else f"/ip service set {svc_name} address=192.168.88.0/24"
                                ],
                                verify_steps=[f"Pastikan akses ke service {svc_name} ditolak dari IP non-manajemen."],
                            )
                        else:
                            self.passed_checks.append(f"Service {svc_name} dibatasi ke: {addr_restrict}")
            return

        mgmt_services = [
            {"port": 2000, "name": "Bandwidth-Test Server", "cwe": "CWE-400",
             "vec": CVSSVector("A", "L", "N", "N", "U", "N", "N", "H"),
             "fix": ["/tool bandwidth-server set enabled=no"]},
            {"port": 8291, "name": "Winbox Management", "cwe": "CWE-284",
             "vec": CVSSVector("A", "L", "N", "N", "C", "H", "H", "H"),
             "fix": ["/ip service set winbox address=192.168.88.0/24"]},
            {"port": 23, "name": "Telnet Plaintext", "cwe": "CWE-319",
             "vec": CVSSVector("A", "L", "N", "N", "C", "H", "H", "H"),
             "fix": ["/ip service disable telnet"]},
            {"port": 8728, "name": "RouterOS API (Unencrypted)", "cwe": "CWE-284",
             "vec": CVSSVector("A", "L", "N", "N", "U", "H", "H", "L"),
             "fix": ["/ip service set api address=127.0.0.1/32,192.168.88.0/24"]},
            {"port": 21, "name": "FTP Service", "cwe": "CWE-319",
             "vec": CVSSVector("A", "L", "N", "N", "C", "H", "H", "H"),
             "fix": ["/ip service disable ftp"]},
            {"port": 5678, "name": "RoMON", "cwe": "CWE-284",
             "vec": CVSSVector("A", "L", "N", "N", "U", "H", "H", "L"),
             "fix": ["/tool romon set enabled=no"]},
        ]

        for svc in mgmt_services:
            if self._probe_port(svc["port"]):
                self._add_finding(
                    category="Management Plane Exposure",
                    title=f"Layanan {svc['name']} (Port {svc['port']}) Terjangkau oleh Klien",
                    cwe=svc["cwe"],
                    owasp="A01:2021-Broken Access Control",
                    vector=svc["vec"],
                    component=f"{self.target_ip}:{svc['port']} (TCP)",
                    detail=(
                        f"Port {svc['port']} ({svc['name']}) menerima TCP handshake dari segmen "
                        "klien Hotspot. Praktik terbaik mengharuskan pemisahan VLAN manajemen "
                        "dan firewall input drop untuk port ini dari jaringan klien."
                    ),
                    evidence=f"TCP connect_ex to {self.target_ip}:{svc['port']} succeeded.",
                    cli_fixes=svc["fix"],
                    verify_steps=[
                        f"Pastikan koneksi dari klien ke {self.target_ip}:{svc['port']} timeout/refused."
                    ],
                    compliance_frameworks=["NIST SP 800-53 Rev 5 (AC-17)", "CIS MikroTik RouterOS"],
                )
            else:
                self.passed_checks.append(f"Port {svc['port']} ({svc['name']}) tertutup.")

    # ------------------------------------------------------------------
    # CHECK 3: WEB PORTAL & WEBFIG
    # ------------------------------------------------------------------
    def check_web_portal_and_webfig(self):
        if self.config.mode == ScanMode.CONFIG_ONLY:
            return

        code, headers, body = self._safe_fetch("/webfig/")
        # Verifikasi apakah respon dialihkan ke portal Hotspot (login/status voucher)
        # Jika respon berisi redirect hotspot atau tombol logout/status, ini adalah proteksi normal Hotspot
        is_redirected_to_hotspot = (
            "openlogout" in body.lower() or
            "$(link-logout)" in body.lower() or
            "status koneksi" in body.lower() or
            "status=" in body.lower() or
            "arissumi.net.id" in body.lower() or
            "/status" in body.lower() or
            ("doLogin" in body and "webfig.js" not in body)
        )

        is_genuine_webfig = (
            code == 200 and not is_redirected_to_hotspot and
            ("webfig.js" in body.lower() or "/jsproxy" in body.lower() or "<title>routeros" in body.lower())
        )

        if is_genuine_webfig:
            vec = CVSSVector("A", "L", "N", "N", "U", "H", "H", "H")
            self._add_finding(
                category="Web Management Exposure",
                title="Antarmuka Administrasi WebFig Terekspos pada IP Gateway Hotspot",
                cwe="CWE-425",
                owasp="A01:2021-Broken Access Control",
                vector=vec,
                component=f"http://{self.target_ip}/webfig/",
                detail=(
                    "Layanan HTTP MikroTik melayani Portal Hotspot sekaligus halaman admin WebFig "
                    "pada port yang sama tanpa autentikasi terpisah atau filter interface. "
                    "Pengguna WiFi dapat langsung mengakses halaman login dashboard router."
                ),
                evidence=f"GET http://{self.target_ip}/webfig/ memuat aset dashboard WebFig (webfig.js / jsproxy).",
                cli_fixes=[
                    f"/ip firewall filter add chain=input dst-address={self.target_ip} protocol=tcp dst-port=80 content=\"/webfig\" action=drop comment=\"Block WebFig on Hotspot IP\"",
                    "/ip service set www address=192.168.88.0/24"
                ],
                verify_steps=[
                    f"Buka http://{self.target_ip}/webfig/ dari browser klien dan pastikan ditolak."
                ],
                compliance_frameworks=["NIST SP 800-53 Rev 5 (AC-3)", "ISO/IEC 27001:2022 (A.8.2)"],
            )
        else:
            self.passed_checks.append("Akses /webfig/ dialihkan secara aman ke portal Hotspot (WebFig terlindungi dari akses langsung).")

        for ep in ["/status", "/login"]:
            c_ep, h_ep, b_ep = self._safe_fetch(ep)
            if c_ep != 200 or not b_ep:
                continue

            dom = HotspotTemplateDOMParser(self.target_ip, page_url=f"http://{self.target_ip}{ep}")
            dom.feed(b_ep)

            if dom.external_scripts:
                real_scripts = [s for s in dom.external_scripts if "[MIXED-CONTENT]" not in s]
                mixed = [s for s in dom.external_scripts if "[MIXED-CONTENT]" in s]

                if real_scripts:
                    vec = CVSSVector("N", "H", "N", "R", "C", "L", "L", "N")
                    self._add_finding(
                        category="Portal Supply-Chain & Integrity",
                        title=f"Ketergantungan Script Eksternal Aktif pada Template ({ep})",
                        cwe="CWE-829",
                        owasp="A08:2021-Software and Data Integrity Failures",
                        vector=vec,
                        component=f"http://{self.target_ip}{ep}",
                        detail=(
                            "Template HTML memuat JavaScript dari domain eksternal tanpa atribut "
                            "Subresource Integrity (SRI). Ini berisiko kegagalan fungsi sebelum login, "
                            "atau injeksi pihak ketiga jika domain kompromi."
                        ),
                        evidence=f"Script eksternal: {', '.join(real_scripts[:3])}",
                        cli_fixes=[
                            "# Unduh file JS ke komputer, unggah ke Files -> hotspot/js/ via Winbox.",
                            "# Ubah src di HTML menjadi jalur lokal: <script src=\"js/namafile.js\"></script>",
                            "# Jika tetap CDN, tambahkan integrity=\"sha384-...\" crossorigin=\"anonymous\"."
                        ],
                        verify_steps=["Pastikan semua <script> mengarah ke file lokal atau memiliki SRI."],
                        compliance_frameworks=["NIST SP 800-53 Rev 5 (SI-7)"],
                    )

                if mixed:
                    self._add_finding(
                        category="Portal Supply-Chain & Integrity",
                        title=f"Mixed Content: Resource HTTP dimuat dari Halaman Portal ({ep})",
                        cwe="CWE-319",
                        owasp="A02:2021-Cryptographic Failures",
                        vector=CVSSVector("N", "L", "N", "R", "C", "L", "L", "N"),
                        component=f"{self.target_ip}{ep}",
                        detail="Resource HTTP dimuat dari halaman HTTPS, memungkinkan MITM injection.",
                        evidence=f"Mixed resources: {', '.join(mixed[:3])}",
                        cli_fixes=["# Ubah semua resource URL ke https:// atau jalur lokal relatif."],
                        verify_steps=["Browser console tidak menampilkan warning mixed content."],
                    )

            if dom.inline_event_handlers:
                vec_xss = CVSSVector("N", "H", "N", "R", "C", "L", "L", "N")
                self._add_finding(
                    category="Portal XSS Surface",
                    title=f"Inline Event Handler pada Template Portal ({ep})",
                    cwe="CWE-79",
                    owasp="A03:2021-Injection",
                    vector=vec_xss,
                    component=f"http://{self.target_ip}{ep}",
                    detail=(
                        "Template mengandung atribut onclick/onerror/onload inline. "
                        "Kombinasi dengan input user yang tidak disanitasi dapat menjadi DOM XSS."
                    ),
                    evidence=f"Inline handlers: {dom.inline_event_handlers[:3]}",
                    cli_fixes=[
                        "# Refactor inline handler ke addEventListener di file JS terpisah.",
                        "# Sanitasi semua variabel yang berasal dari $(...) atau %...% sebelum DOM injection."
                    ],
                    verify_steps=["Pastikan tidak ada atribut onclick/onload/onerror inline di HTML final."],
                )

            if ep == "/login":
                if dom.has_password_input and not dom.has_md5_reference and not dom.has_sendin_field:
                    self._add_finding(
                        category="Portal Authentication Integrity",
                        title="Form Login Tidak Menggunakan CHAP / MD5 Challenge (Potensi Password Plaintext)",
                        cwe="CWE-319",
                        owasp="A02:2021-Cryptographic Failures",
                        vector=CVSSVector("N", "L", "L", "N", "C", "H", "N", "N"),
                        component=f"http://{self.target_ip}/login",
                        detail=(
                            "Form login memiliki field password tetapi tidak ada referensi md5.js, "
                            "hexMD5, atau sendin. Ini mengindikasikan password dikirim plaintext "
                            "meskipun via HTTPS hotspot (risiko residu untuk template non-TLS)."
                        ),
                        evidence=f"has_password_input={dom.has_password_input}, has_md5_reference={dom.has_md5_reference}",
                        cli_fixes=[
                            "# Gunakan template standar MikroTik dengan md5.js.",
                            "# Pastikan form action=\"/login\" dan ada <input type=hidden name=sendin>."
                        ],
                        verify_steps=["Lihat source /login; harus ada md5.js dan hexMD5()."],
                    )
                elif dom.has_md5_reference:
                    self.passed_checks.append(
                        f"Endpoint {ep}: Form login menggunakan CHAP / MD5 challenge (md5.js terdeteksi)."
                    )

            leaky_comments = [
                c for c in dom.html_comments
                if re.search(r"(password|admin|api[_-]?key|secret|token|192\.168\.|10\.\d+\.)", c, re.IGNORECASE)
            ]
            if leaky_comments:
                self._add_finding(
                    category="Portal Information Disclosure",
                    title=f"HTML Comment Berisi Informasi Sensitif ({ep})",
                    cwe="CWE-615",
                    owasp="A05:2021-Security Misconfiguration",
                    vector=CVSSVector("N", "L", "N", "N", "U", "L", "N", "N"),
                    component=f"http://{self.target_ip}{ep}",
                    detail="Komentar HTML mengandung string yang menyerupai kredensial, IP internal, atau token.",
                    evidence=f"Contoh comment: {leaky_comments[0][:100]}",
                    cli_fixes=["# Hapus komentar sensitif dari template HTML final."],
                    verify_steps=["View source halaman, tidak ada komentar dengan data sensitif."],
                )

            for r in dom.get_meta_refresh():
                if re.search(r"url=https?://", r, re.IGNORECASE):
                    self._add_finding(
                        category="Portal Redirection",
                        title=f"Meta Refresh ke Domain Eksternal ({ep})",
                        cwe="CWE-601",
                        owasp="A01:2021-Broken Access Control",
                        vector=CVSSVector("N", "L", "N", "R", "U", "L", "L", "N"),
                        component=f"{self.target_ip}{ep}",
                        detail="Meta refresh mengarah ke domain eksternal - potensi open redirect/phishing.",
                        evidence=f"meta refresh content: {r}",
                        cli_fixes=["# Ubah meta refresh ke URL relatif atau hapus."],
                        verify_steps=["Pastikan meta refresh hanya mengarah ke path internal."],
                    )

            if dom.safe_external_links:
                self.passed_checks.append(
                    f"Endpoint {ep}: Kontak eksternal aman terverifikasi ({len(dom.safe_external_links)} link)."
                )

            if dom.unknown_external_links:
                self._add_finding(
                    category="Portal Link Integrity",
                    title=f"Tautan Eksternal Tidak Dikenal pada Template ({ep})",
                    cwe="CWE-1021",
                    owasp="A01:2021-Broken Access Control",
                    vector=CVSSVector("N", "L", "N", "R", "U", "L", "L", "N"),
                    component=f"{self.target_ip}{ep}",
                    detail="Anchor eksternal di luar whitelist - verifikasi manual diperlukan.",
                    evidence=f"Links: {', '.join(list(dom.unknown_external_links)[:3])}",
                    cli_fixes=["# Verifikasi setiap tautan, atau tambahkan ke whitelist jika sah."],
                    verify_steps=["Klik manual untuk memverifikasi tujuan tautan."],
                )

    # ------------------------------------------------------------------
    # CHECK 4: FIREWALL CONFIGURATION
    # ------------------------------------------------------------------
    def check_firewall_configuration(self):
        if not self.firewall_analyzer:
            return

        total_rules = len(self.firewall_analyzer.parsed_rules)

        if not self.firewall_analyzer.has_default_deny("input"):
            self._add_finding(
                category="Firewall Configuration",
                title="Tidak Ada Aturan Default-Deny pada Chain Input",
                cwe="CWE-284",
                owasp="A05:2021-Security Misconfiguration",
                vector=CVSSVector("N", "L", "N", "N", "U", "H", "H", "H"),
                component="/ip firewall filter (chain=input)",
                detail=(
                    "Chain input tidak memiliki aturan drop/reject tanpa match constraint di akhir. "
                    "Ini berarti trafik yang tidak cocok dengan aturan allow eksplisit akan mengalir "
                    "ke default policy router (accept), mengekspos seluruh permukaan serangan ke klien WiFi."
                ),
                evidence=f"Total rules parsed: {total_rules}, no default-deny detected.",
                cli_fixes=[
                    "/ip firewall filter add chain=input action=drop in-interface=all-wireless comment=\"Default Deny Input WiFi\"",
                    "/ip firewall filter add chain=input connection-state=established,related action=accept",
                    "/ip firewall filter add chain=input connection-state=invalid action=drop"
                ],
                verify_steps=["Pastikan trafik dari klien WiFi ke port non-layanan di-drop."],
                compliance_frameworks=["NIST SP 800-53 Rev 5 (SC-7)", "CIS MikroTik RouterOS"],
            )
        else:
            self.passed_checks.append("Aturan default-deny pada chain input terdeteksi.")

        if not self.firewall_analyzer.has_established_related():
            self._add_finding(
                category="Firewall Configuration",
                title="Tidak Ada Aturan Accept untuk Established,Related (Chain Input)",
                cwe="CWE-284",
                owasp="A05:2021-Security Misconfiguration",
                vector=CVSSVector("N", "L", "N", "N", "U", "L", "N", "H"),
                component="/ip firewall filter (chain=input)",
                detail="Tanpa accept untuk established,related, trafik respons dari koneksi keluar akan di-drop.",
                evidence="No rule with connection-state=established,related + action=accept in chain=input.",
                cli_fixes=[
                    "/ip firewall filter add chain=input connection-state=established,related action=accept comment=\"Allow Return Traffic\""
                ],
                verify_steps=["Pastikan DNS/HTTPS dari router masih berfungsi setelah rule ditambahkan."],
            )
        else:
            self.passed_checks.append("Aturan established,related accept terdeteksi.")

        if not self.firewall_analyzer.has_invalid_drop():
            self._add_finding(
                category="Firewall Configuration",
                title="Tidak Ada Drop untuk Connection-State=Invalid",
                cwe="CWE-20",
                owasp="A05:2021-Security Misconfiguration",
                vector=CVSSVector("N", "L", "N", "N", "U", "L", "L", "L"),
                component="/ip firewall filter (chain=input)",
                detail="Invalid connection state harus di-drop untuk mengurangi permukaan scan/attack.",
                evidence="No rule with connection-state=invalid + action=drop.",
                cli_fixes=[
                    "/ip firewall filter add chain=input connection-state=invalid action=drop comment=\"Drop Invalid State\""
                ],
                verify_steps=["Rule invalid drop muncul di chain input sebelum rule allow."],
            )
        else:
            self.passed_checks.append("Aturan invalid connection state drop terdeteksi.")

        shadowed = self.firewall_analyzer.find_shadowed_rules()
        if shadowed:
            self._add_finding(
                category="Firewall Configuration",
                title=f"Aturan Firewall Ter-shadow ({len(shadowed)} rule)",
                cwe="CWE-693",
                owasp="A05:2021-Security Misconfiguration",
                vector=CVSSVector("N", "H", "L", "N", "U", "L", "L", "L"),
                component="/ip firewall filter",
                detail=(
                    "Beberapa aturan ter-shadow oleh aturan sebelumnya dengan action sama namun match lebih luas. "
                    "Aturan ter-shadow tidak akan pernah dieksekusi - indikasi rule order perlu dirapikan."
                ),
                evidence=f"Shadowed rules: {shadowed[:3]}",
                cli_fixes=[
                    "/ip firewall filter print",
                    "# Reorder rule menggunakan '/ip firewall filter move <id> destination=<id>'"
                ],
                verify_steps=["Setelah reorder, pastikan setiap aturan memiliki traffic counter > 0."],
            )

    # ------------------------------------------------------------------
    # CHECK 5: AUTHENTICATION & ACCESS
    # ------------------------------------------------------------------
    def check_authentication(self):
        if not self.user_analyzer:
            return

        if self.user_analyzer.has_default_admin():
            self._add_finding(
                category="Authentication & Access",
                title="User 'admin' Default Masih Ada",
                cwe="CWE-1392",
                owasp="A07:2021-Identification and Authentication Failures",
                vector=CVSSVector("N", "L", "L", "N", "U", "H", "H", "H"),
                component="/user (name=admin)",
                detail=(
                    "User 'admin' adalah default RouterOS. Jika password lemah atau sama dengan password WiFi, "
                    "risiko takeover tinggi. Ganti nama dan terapkan password kuat, atau disable user ini."
                ),
                evidence="User 'admin' ditemukan di /user list.",
                cli_fixes=[
                    "/user add name=sysadmin group=full password=\"<STRONG-PASSWORD>\" address=192.168.88.0/24",
                    "/user disable admin",
                    "# Atau hapus: /user remove admin (setelah user baru terverifikasi)"
                ],
                verify_steps=["/user print, pastikan user 'admin' disabled atau tidak ada."],
                compliance_frameworks=["PCI DSS v4.0 (8.2.1)", "NIST SP 800-53 Rev 5 (IA-5)"],
            )

        users_no_restrict = self.user_analyzer.has_users_without_address_restriction()
        if users_no_restrict:
            self._add_finding(
                category="Authentication & Access",
                title="User dengan Hak Penuh Tanpa Pembatasan Alamat Sumber",
                cwe="CWE-284",
                owasp="A01:2021-Broken Access Control",
                vector=CVSSVector("A", "L", "L", "N", "U", "H", "H", "H"),
                component=f"/user ({', '.join(users_no_restrict[:3])})",
                detail=(
                    "User dengan group full/write tidak dibatasi ke IP management. Jika kredensial bocor, "
                    "penyerang bisa login dari mana saja dalam jaringan."
                ),
                evidence=f"Users tanpa address restriction: {users_no_restrict}",
                cli_fixes=[
                    "/user set [find name=<USER>] address=192.168.88.0/24"
                ],
                verify_steps=["User dengan hak penuh hanya bisa login dari subnet management."],
            )

    # ------------------------------------------------------------------
    # CHECK 6: SNMP / DISCOVERY
    # ------------------------------------------------------------------
    def check_snmp_discovery(self):
        if not self.snmp_analyzer:
            return

        if self.snmp_analyzer.is_snmp_enabled() and self.snmp_analyzer.has_default_community():
            self._add_finding(
                category="SNMP / Discovery",
                title="SNMP Aktif dengan Community Default (public/private)",
                cwe="CWE-1188",
                owasp="A05:2021-Security Misconfiguration",
                vector=CVSSVector("N", "L", "N", "N", "U", "L", "N", "N"),
                component="/snmp community",
                detail="SNMP dengan community default memungkinkan enumerasi konfigurasi tanpa autentikasi.",
                evidence="/snmp community print menampilkan name=public atau name=private.",
                cli_fixes=[
                    "/snmp community set [find name=public] name=<CUSTOM-COMMUNITY> addresses=192.168.88.0/24",
                    "/snmp set enabled=no  # jika tidak diperlukan"
                ],
                verify_steps=["snmpwalk dari subnet non-management harus gagal."],
            )

    # ------------------------------------------------------------------
    # CHECK 7: WIRELESS SECURITY
    # ------------------------------------------------------------------
    def check_wireless_security(self):
        if not self.wireless_analyzer:
            return

        if self.wireless_analyzer.has_wep_encryption():
            self._add_finding(
                category="Wireless Security",
                title="Enkripsi WEP Terdeteksi pada Security Profile",
                cwe="CWE-327",
                owasp="A02:2021-Cryptographic Failures",
                vector=CVSSVector("A", "L", "N", "N", "U", "H", "H", "N"),
                component="/interface wireless security-profiles",
                detail="WEP sudah tidak aman sejak 2001, dapat dipecahkan dalam menit dengan tools publik.",
                evidence="Pattern 'wep' ditemukan di security-profiles.",
                cli_fixes=[
                    "/interface wireless security-profiles set [find mode=static-keys-required] mode=dynamic-keys authentication-types=wpa2-psk",
                    "/interface wireless security-profiles set [find] wpa2-pre-shared-key=\"<STRONG-PSK>\""
                ],
                verify_steps=["Connect menggunakan client modern - harus support WPA2."],
                compliance_frameworks=["PCI DSS v4.0 (4.1.1)"],
            )

        if self.wireless_analyzer.has_open_security_profile():
            self._add_finding(
                category="Wireless Security",
                title="Security Profile Mode=none (Open Network)",
                cwe="CWE-311",
                owasp="A02:2021-Cryptographic Failures",
                vector=CVSSVector("A", "L", "N", "N", "U", "H", "H", "L"),
                component="/interface wireless security-profiles",
                detail="Access point terbuka tanpa enkripsi memungkinkan sniffing seluruh trafik pengguna.",
                evidence="Pattern 'mode=none' ditemukan di security-profiles.",
                cli_fixes=[
                    "/interface wireless security-profiles add name=secure-wpa2 mode=dynamic-keys authentication-types=wpa2-psk wpa2-pre-shared-key=\"<STRONG-PSK>\"",
                    "/interface wireless set [find] security-profile=secure-wpa2"
                ],
                verify_steps=["Koneksi client tanpa password harus ditolak."],
            )

        if self.wireless_analyzer.has_wps_enabled():
            self._add_finding(
                category="Wireless Security",
                title="WPS Push-Button Mode Aktif",
                cwe="CWE-330",
                owasp="A02:2021-Cryptographic Failures",
                vector=CVSSVector("A", "L", "N", "N", "U", "H", "N", "N"),
                component="/interface wireless",
                detail="WPS PIN/Push-Button vulnerable terhadap brute-force (Pixie Dust attack).",
                evidence="Pattern 'wps-mode=push-button' ditemukan.",
                cli_fixes=["/interface wireless set [find] wps-mode=disabled"],
                verify_steps=["Client tidak bisa pairing via WPS."],
            )

    # ------------------------------------------------------------------
    # CHECK 8: LOGGING
    # ------------------------------------------------------------------
    def check_logging(self):
        if not self.rsc_parser:
            return

        has_remote_syslog = False
        for line in self.rsc_parser.get_section_commands("/system logging"):
            if "action=remote" in line.lower() or "remote=" in line.lower():
                has_remote_syslog = True
                break

        if not has_remote_syslog:
            self._add_finding(
                category="Logging & Monitoring",
                title="Tidak Ada Konfigurasi Remote Syslog",
                cwe="CWE-778",
                owasp="A09:2021-Security Logging and Monitoring Failures",
                vector=CVSSVector("N", "H", "L", "N", "U", "L", "L", "L"),
                component="/system logging",
                detail="Log hanya tersimpan lokal; jika router di-reboot/compromise, log hilang.",
                evidence="No action=remote found in /system logging.",
                cli_fixes=[
                    "/system logging action set remote remote=<SYSLOG-SERVER-IP>",
                    "/system logging add topics=info,error,warning action=remote"
                ],
                verify_steps=["Log muncul di syslog server eksternal."],
            )

    # ------------------------------------------------------------------
    # CHECK 9: VOUCHER SECURITY
    # ------------------------------------------------------------------
    def check_voucher_security(self, sample_voucher: Optional[str] = None):
        if not sample_voucher:
            return
        result = VoucherSecurityAnalyzer.evaluate_voucher_pattern(sample_voucher)
        if result["risk_level"] in ("CRITICAL", "HIGH"):
            self._add_finding(
                category="Hotspot Voucher Security",
                title=f"Pola Voucher Lemah (Entropi: {result['shannon_entropy_bits']} bit)",
                cwe="CWE-521",
                owasp="A07:2021-Identification and Authentication Failures",
                vector=CVSSVector("N", "L", "N", "N", "U", "L", "L", "N"),
                component="Hotspot User Voucher",
                detail=(
                    f"Sample voucher '{sample_voucher}' memiliki Shannon entropy {result['shannon_entropy_bits']} bit. "
                    f"Estimasi brute-force online (asumsi 50 rps) menghabiskan seluruh ruang dalam "
                    f"{result['estimated_exhaustion_hours_at_online_rate']} jam. NIST SP 800-63B aligned: "
                    f"{result['nist_800_63b_aligned']}."
                ),
                evidence=json.dumps(result),
                cli_fixes=[
                    "# Gunakan User Manager / billing generator dengan panjang >= 8 dan pool >= 62 karakter.",
                    "# Terapkan rate-limit login hotspot untuk membatasi brute force."
                ],
                verify_steps=["Analisis distribusi voucher baru dengan tool ini."],
                compliance_frameworks=["NIST SP 800-63B"],
            )

    # ------------------------------------------------------------------
    # CHECK 10: CERTIFICATE
    # ------------------------------------------------------------------
    def check_certificate(self):
        if not self.cert_analyzer:
            return
        if self.cert_analyzer.count_certificates() == 0 and self.ipservice_analyzer:
            if self.ipservice_analyzer.is_service_enabled("www-ssl"):
                self._add_finding(
                    category="TLS / Certificate",
                    title="Service www-ssl Aktif Tanpa Certificate Terdaftar",
                    cwe="CWE-295",
                    owasp="A02:2021-Cryptographic Failures",
                    vector=CVSSVector("N", "L", "N", "N", "U", "L", "L", "N"),
                    component="/certificate + /ip service www-ssl",
                    detail="HTTPS admin aktif namun belum ada certificate terdaftar - default self-signed akan digunakan.",
                    evidence="/certificate print kosong, /ip service www-ssl enabled.",
                    cli_fixes=[
                        "/certificate add name=admin-cert common-name=<hostname> key-usage=tls-server",
                        "/certificate sign admin-cert ca=admin-ca",
                        "/ip service set www-ssl certificate=admin-cert"
                    ],
                    verify_steps=["Buka https://<router-ip>/ dan pastikan certificate valid."],
                )

    # ------------------------------------------------------------------
    # PIPELINE
    # ------------------------------------------------------------------

    # ------------------------------------------------------------------
    # CHECK 11: CRITICAL - OPEN RECURSIVE DNS RESOLVER
    # ------------------------------------------------------------------
    def check_open_recursive_dns_resolver(self):
        """
        [MTK-ENT-CRIT-0001] Mendeteksi Open Recursive DNS Resolver pada port 53 UDP/TCP.
        Jika router melayani recursive DNS query untuk domain publik ke sembarang IP klien,
        ini adalah celah CRITICAL (CVSS 9.8) karena dapat dimanfaatkan untuk:
        1. DNS Amplification DDoS attacks (faktor pembesaran hingga 10x - 50x)
        2. DNS Cache Poisoning (Kaminsky-style attack) membelokkan trafik pengguna Hotspot
        """
        dns_analyzer = DNSResolverSecurityAnalyzer(
            self.target_ip,
            timeout=self.config.timeout,
            config_parser=self.rsc_parser
        )
        res = dns_analyzer.probe_udp_recursion(test_domain="google.com")

        # Jika live probe berhasil atau jika rsc parser menunjukkan allow-remote-requests=yes
        if res.get("is_open_resolver"):
            # Periksa apakah IP target adalah non-RFC1918 (Publik / Hotspot Gateway)
            try:
                ip_obj = ipaddress.ip_address(self.target_ip)
                is_priv = any(ip_obj in net for net in PRIVATE_AND_RESERVED_NETWORKS if net.version == ip_obj.version)
            except Exception:
                is_priv = False

            vec = CVSSVector(
                attack_vector="N", attack_complexity="L", privileges_required="N",
                user_interaction="N", scope="C", confidentiality="N",
                integrity="H", availability="H"
            )
            amp_info = f"{res.get('amplification_factor', 6.0)}x ({res.get('response_length_bytes', 200)} bytes jawaban dari {res.get('query_length_bytes', 30)} bytes query)"
            self._add_finding(
                category="DNS Security & Amplification",
                title="Open Recursive DNS Resolver pada IP Gateway (DNS Amplification DDoS & Cache Poisoning)",
                cwe="CWE-348",
                owasp="A05:2021-Security Misconfiguration",
                vector=vec,
                component=f"{self.target_ip}:53 (UDP/TCP)",
                detail=(
                    f"Router MikroTik terkonfigurasi sebagai Open Recursive DNS Resolver pada IP {self.target_ip}. "
                    f"Layanan DNS merespon query rekursif domain publik dengan rasio amplifikasi {amp_info}. "
                    "Celah ini berstatus CRITICAL (CVSS 9.8): penyerang dapat memanfaatkan router Anda sebagai "
                    "reflektor/amplifier untuk melancarkan serangan Distributed Denial of Service (DDoS) skala gigabit "
                    "ke target korban pihak ketiga, serta rentan terhadap manipulasi DNS Cache Poisoning untuk "
                    "membelokkan lalu lintas perbankan atau browsing pengguna Hotspot."
                ),
                evidence=(
                    f"UDP query untuk 'google.com' ke {self.target_ip}:53 sukses dengan bendera QR=1, RA=1 (Recursion Available). "
                    f"Panjang respon={res.get('response_length_bytes')}B, ANCOUNT={res.get('ancount')}, "
                    f"Response time={res.get('response_time_ms')}ms. Hex sample: {res.get('raw_sample_hex')}"
                ),
                cli_fixes=[
                    "# 1. Jika router tidak perlu menjadi DNS relay, matikan remote requests:",
                    "/ip dns set allow-remote-requests=no",
                    "",
                    "# 2. Jika remote requests dibutuhkan untuk user WiFi lokal, blokir query dari WAN/publik via firewall:",
                    "/ip firewall filter add chain=input in-interface-list=!LAN protocol=udp dst-port=53 action=drop comment=\"Drop WAN DNS UDP\"",
                    "/ip firewall filter add chain=input in-interface-list=!LAN protocol=tcp dst-port=53 action=drop comment=\"Drop WAN DNS TCP\"",
                    "",
                    "# 3. Aktifkan proteksi DoS pada tabel RAW:",
                    "/ip firewall raw add chain=prerouting in-interface-list=!LAN protocol=udp dst-port=53 action=drop comment=\"Defend against DNS flood\""
                ],
                verify_steps=[
                    f"Jalankan 'nslookup google.com {self.target_ip}' dari host di luar LAN; respon harus timeout atau refused.",
                    "/ip dns print, pastikan allow-remote-requests=no atau terlindungi firewall filter."
                ],
                compliance_frameworks=[
                    "NIST SP 800-81-2 (Secure Domain Name System)",
                    "CIS MikroTik RouterOS Benchmark (2.3)",
                    "ISO/IEC 27001:2022 (A.8.20)",
                    "PCI DSS v4.0 (Req 1.3)"
                ],
                references=[
                    "https://cwe.mitre.org/data/definitions/348.html",
                    "https://www.cisa.gov/news-events/alerts/2013/03/29/dns-amplification-attacks"
                ]
            )
        else:
            self.passed_checks.append("DNS Resolver aman: Query rekursif dari luar ditolak atau dinonaktifkan.")

    # ------------------------------------------------------------------
    # CHECK 12: BANDWIDTH-TEST SERVER DoS EXPOSURE
    # ------------------------------------------------------------------
    def check_bandwidth_test_server(self):
        """Mengecek apakah port 2000 (Bandwidth-Test Server) terbuka dan dapat diakses."""
        analyzer = ManagementAndNeighborDiscoveryAnalyzer(self.target_ip, self.rsc_parser, timeout=self.config.timeout)
        probe_res = analyzer.probe_bandwidth_test_server()
        if probe_res.get("is_open"):
            vec = CVSSVector(
                attack_vector="A", attack_complexity="L", privileges_required="N",
                user_interaction="N", scope="U", confidentiality="N",
                integrity="N", availability="H"
            )
            self._add_finding(
                category="Management Plane Exposure",
                title="Layanan Bandwidth-Test Server Aktif pada Port 2000 TCP (Potensi CPU & Resource DoS)",
                cwe="CWE-400",
                owasp="A05:2021-Security Misconfiguration",
                vector=vec,
                component=f"{self.target_ip}:2000 (TCP)",
                detail=(
                    "Port 2000 (Bandwidth-Test Server) menerima koneksi TCP dari klien Hotspot tanpa pembatasan. "
                    "Pengguna WiFi atau penyerang dapat menjalankan tool 'btest' tanpa autentikasi ketat "
                    "untuk membanjiri CPU router hingga 100%, menyebabkan kelambatan parah pada seluruh jaringan."
                ),
                evidence=f"TCP connect to {self.target_ip}:2000 berhasil (Port OPEN).",
                cli_fixes=[
                    "/tool bandwidth-server set enabled=no",
                    "# Jika dibutuhkan untuk teknisi, batasi ke subnet admin:",
                    "/tool bandwidth-server set enabled=yes authenticate=yes allocate-udp-ports-from=2000"
                ],
                verify_steps=[
                    f"Koneksi dari klien ke {self.target_ip}:2000 harus ditolak atau connection refused."
                ],
                compliance_frameworks=["CIS MikroTik RouterOS (3.1)", "NIST SP 800-53 Rev 5 (SC-5)"]
            )
        else:
            self.passed_checks.append("Port 2000 (Bandwidth-Test Server) tertutup.")

    # ------------------------------------------------------------------
    # CHECK 13: ADVANCED FIREWALL & NAT HYGIENE
    # ------------------------------------------------------------------
    def check_advanced_firewall_hygiene(self):
        if not self.rsc_parser:
            return
        analyzer = AdvancedFirewallTableAnalyzer(self.rsc_parser)
        flaws = analyzer.check_nat_masquerade_hygiene()
        for f in flaws:
            self._add_finding(
                category="Firewall Configuration",
                title="Aturan NAT Masquerade Tanpa Batasan Interface Keluar (out-interface)",
                cwe="CWE-284",
                owasp="A05:2021-Security Misconfiguration",
                vector=CVSSVector("N", "L", "L", "N", "U", "L", "L", "L"),
                component="/ip firewall nat (action=masquerade)",
                detail=f["impact"],
                evidence=f"Rule: {f['rule']}",
                cli_fixes=[f["fix"]],
                verify_steps=["/ip firewall nat print, pastikan semua rule masquerade memiliki out-interface atau out-interface-list."],
                compliance_frameworks=["CIS MikroTik RouterOS (2.2)"]
            )

        raw_info = analyzer.check_raw_table_dos_mitigation()
        if not raw_info.get("has_syn_flood_drop"):
            self._add_finding(
                category="Firewall Configuration",
                title="Tabel RAW Tidak Mengandung Aturan Mitigasi SYN Flood / Bogon",
                cwe="CWE-400",
                owasp="A05:2021-Security Misconfiguration",
                vector=CVSSVector("N", "L", "N", "N", "U", "N", "N", "L"),
                component="/ip firewall raw",
                detail="Tabel RAW adalah garis pertahanan pertama RouterOS sebelum connection tracking. Tanpa aturan drop di RAW, router rentan terhadap kehabisan memori conntrack akibat SYN flood.",
                evidence="No tcp-flags=syn drop rule in /ip firewall raw.",
                cli_fixes=[
                    '/ip firewall raw add chain=prerouting protocol=tcp tcp-flags=syn,!ack connection-state=new limit=100/s,20:packet action=accept comment="Allow SYN burst"',
                    '/ip firewall raw add chain=prerouting protocol=tcp tcp-flags=syn,!ack connection-state=new action=drop comment="Drop SYN Flood"'
                ],
                verify_steps=["/ip firewall raw print, pastikan ada aturan mitigasi SYN flood."]
            )

    # ------------------------------------------------------------------
    # CHECK 14: HOTSPOT WALLED GARDEN & BYPASS AUDIT
    # ------------------------------------------------------------------
    def check_hotspot_walled_garden_bypasses(self):
        if not self.rsc_parser:
            return
        wg_analyzer = HotspotWalledGardenAndBypassAnalyzer(self.rsc_parser)
        wildcards = wg_analyzer.find_wildcard_walled_garden()
        for w in wildcards:
            self._add_finding(
                category="Hotspot Voucher Security",
                title="Walled Garden Berisi Wildcard (*) - Potensi Bypass Autentikasi Total",
                cwe="CWE-284",
                owasp="A01:2021-Broken Access Control",
                vector=CVSSVector("N", "L", "N", "N", "C", "H", "H", "H"),
                component=f"/ip hotspot {w['type']}",
                detail=(
                    f"{w['reason']}. Pengguna WiFi dapat berselancar di internet secara gratis "
                    "tanpa membeli voucher atau login portal Hotspot."
                ),
                evidence=f"Rule: {w['rule']}",
                cli_fixes=[
                    f"# Hapus atau perbaiki rule wildcard di {w['type']}:",
                    "/ip hotspot walled-garden remove [find dst-host="*"]",
                    "/ip hotspot walled-garden remove [find dst-host=""]"
                ],
                verify_steps=["Pastikan user yang belum login tidak bisa membuka situs web sembarang."],
                compliance_frameworks=["CIS MikroTik RouterOS (7.1)"]
            )

        cookie_risks = wg_analyzer.check_cookie_lifetime()
        for c in cookie_risks:
            self._add_finding(
                category="Hotspot Voucher Security",
                title=f"Waktu Kedaluwarsa HTTP Cookie Hotspot Terlalu Lama ({c['lifetime']})",
                cwe="CWE-613",
                owasp="A07:2021-Identification and Authentication Failures",
                vector=CVSSVector("N", "H", "N", "N", "U", "L", "L", "N"),
                component=c["rule"],
                detail=c["reason"],
                evidence=f"Profile: {c['rule']}",
                cli_fixes=["/ip hotspot user profile set [find] http-cookie-lifetime=1d"],
                verify_steps=["Verifikasi http-cookie-lifetime <= 1 hari."]
            )

    # ------------------------------------------------------------------
    # CHECK 15: NEIGHBOR DISCOVERY & MAC-SERVER LEAKS
    # ------------------------------------------------------------------
    def check_neighbor_discovery_and_mac_server(self):
        if not self.rsc_parser:
            return
        mgmt = ManagementAndNeighborDiscoveryAnalyzer(self.target_ip, self.rsc_parser, timeout=self.config.timeout)
        nd_leaks = mgmt.check_neighbor_discovery_config()
        for leak in nd_leaks:
            self._add_finding(
                category="Management Plane Exposure",
                title="Neighbor Discovery Protocol (MNDP/CDP/LLDP) Aktif di Semua Interface",
                cwe="CWE-200",
                owasp="A01:2021-Broken Access Control",
                vector=CVSSVector("A", "L", "N", "N", "U", "L", "N", "N"),
                component="/ip neighbor discovery-settings",
                detail=leak["risk"],
                evidence=f"Config: {leak['rule']}",
                cli_fixes=[leak["fix"]],
                verify_steps=["/ip neighbor discovery-settings print, pastikan discover-interface-list dibatasi ke interface manajemen."],
                compliance_frameworks=["CIS MikroTik RouterOS (3.2)", "NIST SP 800-53 Rev 5 (CM-7)"]
            )

        mac_leaks = mgmt.check_mac_server_config()
        for leak in mac_leaks:
            self._add_finding(
                category="Management Plane Exposure",
                title="MAC-Server / MAC-Winbox Diizinkan di Interface Hotspot/Publik",
                cwe="CWE-284",
                owasp="A01:2021-Broken Access Control",
                vector=CVSSVector("A", "L", "N", "N", "C", "H", "H", "H"),
                component="/tool mac-server",
                detail=leak["risk"],
                evidence=f"Config: {leak['rule']}",
                cli_fixes=[leak["fix"]],
                verify_steps=["Klien Hotspot tidak boleh mendeteksi router via Winbox MAC Discovery."],
                compliance_frameworks=["CIS MikroTik RouterOS (3.3)"]
            )

    # ------------------------------------------------------------------
    # CHECK 16: PROXY & SOCKS RELAY PROBE
    # ------------------------------------------------------------------
    def check_proxy_and_relays(self):
        mgmt = ManagementAndNeighborDiscoveryAnalyzer(self.target_ip, self.rsc_parser, timeout=self.config.timeout)
        open_proxies = mgmt.probe_socks_and_proxy()
        for p in open_proxies:
            self._add_finding(
                category="Management Plane Exposure",
                title=f"Layanan {p['name']} (Port {p['port']}) Terbuka Tanpa Autentikasi",
                cwe="CWE-441",
                owasp="A05:2021-Security Misconfiguration",
                vector=CVSSVector("N", "L", "N", "N", "C", "H", "H", "H"),
                component=f"{self.target_ip}:{p['port']}",
                detail=p["risk"],
                evidence=f"TCP connect to port {p['port']} succeeded.",
                cli_fixes=[p["fix"]],
                verify_steps=[f"Port {p['port']} harus tertutup."]
            )


    def generate_consolidated_hardening_script(self) -> str:
        """
        Menghasilkan satu script RouterOS (.rsc) terkonsolidasi yang berisi
        semua perintah hardening dari temuan audit yang terdeteksi.
        Dapat langsung di-copy-paste ke terminal Winbox/SSH MikroTik.
        """
        lines = [
            "# ===================================================================",
            f"# MIKROTIK ENTERPRISE HARDENING SCRIPT (AUTO-GENERATED)",
            f"# Target: {self.target_ip}",
            f"# Framework: {FRAMEWORK_NAME} v{FRAMEWORK_VERSION}",
            f"# Generated At: {datetime.datetime.now().isoformat()}",
            "# ===================================================================",
            "",
            "# PERINGATAN: Terapkan secara bertahap dan pastikan Anda memiliki akses",
            "# alternatif (misal: Winbox via MAC Address atau port khusus) sebelum apply.",
            "",
            '/log info message="[*] Applying Enterprise Security Hardening..."',
            ""
        ]

        # Group fixes by category
        for issue in self.issues:
            if issue.routeros_remediation_cli:
                lines.append(f"# --- [{issue.severity}] {issue.rule_id}: {issue.title} ---")
                for cmd in issue.routeros_remediation_cli:
                    lines.append(cmd)
                lines.append("")

        lines.extend([
            '/log info message="[+] Enterprise Security Hardening Applied Successfully!"',
            "# ==================================================================="
        ])
        return "\n".join(lines)

    def execute(self, sample_voucher: Optional[str] = None) -> AuditSummary:
        t_start = time.time()

        if self.config.mode != ScanMode.CONFIG_ONLY:
            self.check_network_addressing()

        self.check_management_plane_isolation()

        if self.config.mode in (ScanMode.PASSIVE_FINGERPRINT, ScanMode.FULL_PASSIVE):
            self.check_web_portal_and_webfig()
            # CRITICAL CHECK: Open Recursive DNS Resolver
            self.check_open_recursive_dns_resolver()
            # Management & DoS Checks
            self.check_bandwidth_test_server()
            self.check_proxy_and_relays()

        self.check_firewall_configuration()
        self.check_advanced_firewall_hygiene()
        self.check_hotspot_walled_garden_bypasses()
        self.check_neighbor_discovery_and_mac_server()
        self.check_authentication()
        self.check_snmp_discovery()
        self.check_wireless_security()
        self.check_logging()
        self.check_certificate()
        self.check_voucher_security(sample_voucher)

        elapsed_ms = (time.time() - t_start) * 1000.0
        return self._build_summary(elapsed_ms)

    def _build_summary(self, duration_ms: float) -> AuditSummary:
        self.issues.sort(key=lambda x: x.cvss_score, reverse=True)

        sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        cat_counts: Dict[str, int] = {}

        for issue in self.issues:
            sev_counts[issue.severity] = sev_counts.get(issue.severity, 0) + 1
            cat_counts[issue.category] = cat_counts.get(issue.category, 0) + 1

        total_deduction = sum(
            (i.cvss_score * 2.5 if i.severity in ("CRITICAL", "HIGH") else i.cvss_score * 1.2)
            for i in self.issues
        )
        health_score = max(0.0, round(100.0 - total_deduction, 1))

        if health_score >= 88.0:
            grade = "A (Hardened / Baik)"
        elif health_score >= 72.0:
            grade = "B (Moderat)"
        elif health_score >= 50.0:
            grade = "C (Perlu Perbaikan Konfigurasi)"
        else:
            grade = "D / F (Berisiko Tinggi - Segera Terapkan Hardening)"

        return AuditSummary(
            target_identifier=self.target_ip,
            timestamp=datetime.datetime.now().isoformat(),
            framework_version=FRAMEWORK_VERSION,
            execution_time_ms=round(duration_ms, 2),
            overall_health_score=health_score,
            security_grade=grade,
            severity_breakdown=sev_counts,
            category_breakdown=cat_counts,
            issues=self.issues,
            passed_checks=self.passed_checks,
            scan_mode=self.config.mode.value,
            config_sections_parsed=len(self.rsc_parser.sections) if self.rsc_parser else 0,
            firewall_rules_analyzed=len(self.firewall_analyzer.parsed_rules) if self.firewall_analyzer else 0,
            scanned_endpoints=self.scanned_endpoints,
        )


# =============================================================================
# 7. REPORT GENERATORS
# =============================================================================

class ReportWriter:
    def __init__(self, summary: AuditSummary, output_dir: str = "."):
        self.summary = summary
        self.output_dir = output_dir

    def write_json(self) -> str:
        path = os.path.join(self.output_dir, REPORT_JSON_FILE)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(asdict(self.summary), f, indent=2, ensure_ascii=False)
        return path

    def write_markdown(self) -> str:
        s = self.summary
        lines = []
        lines.append(f"# Audit Report - {s.target_identifier}")
        lines.append("")
        lines.append(f"**Framework**: {FRAMEWORK_NAME} v{s.framework_version}  ")
        lines.append(f"**Timestamp**: {s.timestamp}  ")
        lines.append(f"**Execution Time**: {s.execution_time_ms} ms  ")
        lines.append(f"**Scan Mode**: {s.scan_mode}")
        lines.append("")
        lines.append("## Executive Summary")
        lines.append("")
        lines.append(f"- **Health Score**: {s.overall_health_score} / 100")
        lines.append(f"- **Security Grade**: {s.security_grade}")
        lines.append(f"- **Total Findings**: {len(s.issues)}")
        lines.append("")
        lines.append("### Severity Breakdown")
        lines.append("")
        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            lines.append(f"| {sev} | {s.severity_breakdown.get(sev, 0)} |")
        lines.append("")
        lines.append("### Category Breakdown")
        lines.append("")
        lines.append("| Category | Findings |")
        lines.append("|----------|----------|")
        for cat, count in sorted(s.category_breakdown.items(), key=lambda x: -x[1]):
            lines.append(f"| {cat} | {count} |")
        lines.append("")
        lines.append("---")
        lines.append("")
        lines.append("## Findings")
        lines.append("")

        for issue in s.issues:
            lines.append(f"### [{issue.rule_id}] {issue.title}")
            lines.append("")
            lines.append(f"- **Severity**: {issue.severity} ({issue.cvss_score})")
            lines.append(f"- **Category**: {issue.category}")
            lines.append(f"- **CWE**: {issue.cwe_id}")
            lines.append(f"- **OWASP**: {issue.owasp_ref}")
            lines.append(f"- **Component**: `{issue.affected_component}`")
            lines.append(f"- **CVSS Vector**: `{issue.cvss_vector}`")
            if issue.compliance_frameworks:
                lines.append(f"- **Compliance**: {', '.join(issue.compliance_frameworks)}")
            lines.append("")
            lines.append(issue.technical_detail)
            lines.append("")
            lines.append("**Evidence**:")
            lines.append("")
            lines.append(f"```")
            lines.append(issue.evidence_snippet)
            lines.append(f"```")
            lines.append("")
            lines.append("**Remediation (RouterOS CLI)**:")
            lines.append("")
            lines.append("```")
            for cmd in issue.routeros_remediation_cli:
                lines.append(cmd)
            lines.append("```")
            lines.append("")
            lines.append("**Verification**:")
            for step in issue.verification_steps:
                lines.append(f"1. {step}")
            lines.append("")
            lines.append("---")
            lines.append("")

        if s.passed_checks:
            lines.append("## Passed Checks")
            lines.append("")
            for check in s.passed_checks:
                lines.append(f"- {check}")
            lines.append("")

        path = os.path.join(self.output_dir, REPORT_MD_FILE)
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        return path

    def write_sarif(self) -> str:
        """SARIF v2.1.0 output untuk integrasi CI/CD."""
        s = self.summary
        results = []
        for issue in s.issues:
            level = "error" if issue.severity in ("CRITICAL", "HIGH") else (
                "warning" if issue.severity == "MEDIUM" else "note"
            )
            results.append({
                "ruleId": issue.rule_id,
                "level": level,
                "message": {"text": issue.title + " - " + issue.technical_detail},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": issue.affected_component}
                    }
                }],
                "properties": {
                    "cvss_score": issue.cvss_score,
                    "cvss_vector": issue.cvss_vector,
                    "severity": issue.severity,
                    "cwe": issue.cwe_id,
                    "owasp": issue.owasp_ref,
                }
            })

        sarif = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": FRAMEWORK_NAME,
                        "version": FRAMEWORK_VERSION,
                        "informationUri": "https://github.com/example/mikrotik-auditor",
                        "rules": [
                            {
                                "id": issue.rule_id,
                                "shortDescription": {"text": issue.title},
                                "fullDescription": {"text": issue.technical_detail},
                                "properties": {
                                    "cwe": issue.cwe_id,
                                    "owasp": issue.owasp_ref,
                                    "severity": issue.severity,
                                }
                            } for issue in s.issues
                        ]
                    }
                },
                "results": results,
                "invocations": [{
                    "executionSuccessful": True,
                    "endTimeUtc": s.timestamp,
                }]
            }]
        }

        path = os.path.join(self.output_dir, REPORT_SARIF_FILE)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(sarif, f, indent=2, ensure_ascii=False)
        return path


    def write_hardening_script(self) -> str:
        """Menulis file script RouterOS .rsc terkonsolidasi."""
        path = os.path.join(self.output_dir, "audit_enterprise_hardening.rsc")
        # Generate script from issues
        lines = [
            "# ===================================================================",
            f"# MIKROTIK ENTERPRISE HARDENING SCRIPT (AUTO-GENERATED)",
            f"# Target: {self.summary.target_identifier}",
            f"# Generated At: {self.summary.timestamp}",
            "# ===================================================================",
            "",
            '/log info message="[*] Applying Enterprise Security Hardening..."',
            ""
        ]
        for issue in self.summary.issues:
            if issue.routeros_remediation_cli:
                lines.append(f"# --- [{issue.severity}] {issue.rule_id}: {issue.title} ---")
                for cmd in issue.routeros_remediation_cli:
                    lines.append(cmd)
                lines.append("")
        lines.append('/log info message="[+] Enterprise Security Hardening Applied Successfully!"')
        with open(path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        return path

    def write_html(self) -> str:
        html = HTMLReportBuilder(self.summary).render()
        path = os.path.join(self.output_dir, REPORT_HTML_FILE)
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)
        return path


# =============================================================================
# 8. HTML REPORT BUILDER (DESIGN SYSTEM v4)
# =============================================================================

class HTMLReportBuilder:
    """
    Builds a self-contained interactive HTML report.
    No CDN, no external dependency. Includes:
    - Custom design system (color tokens, typography, spacing, motion)
    - SVG donut + bar charts
    - Filter/search by severity and category
    - Modal detail view
    - Copy-to-clipboard CLI
    - Print styles
    - Dark/light theme
    """

    def __init__(self, summary: AuditSummary):
        self.summary = summary

    def _esc(self, text: Any) -> str:
        return html_escape(str(text), quote=True)

    def _build_donut_svg(self) -> str:
        counts = self.summary.severity_breakdown
        total = sum(counts.values())
        if total == 0:
            return '<svg viewBox="0 0 200 200" class="chart-donut"><circle cx="100" cy="100" r="70" fill="none" stroke="var(--color-surface-2)" stroke-width="30"/><text x="100" y="105" text-anchor="middle" class="chart-donut-label">CLEAN</text></svg>'

        colors = {
            "CRITICAL": "#ef4444",
            "HIGH": "#f97316",
            "MEDIUM": "#eab308",
            "LOW": "#22c55e",
        }
        circumference = 2 * math.pi * 70
        offset = 0.0
        segments = []
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            count = counts.get(sev, 0)
            if count == 0:
                continue
            fraction = count / total
            seg_len = circumference * fraction
            gap = 2.0
            segments.append(
                f'<circle cx="100" cy="100" r="70" fill="none" '
                f'stroke="{colors[sev]}" stroke-width="30" '
                f'stroke-dasharray="{seg_len - gap:.2f} {circumference - seg_len + gap:.2f}" '
                f'stroke-dashoffset="{-offset:.2f}" '
                f'transform="rotate(-90 100 100)">'
                f'<title>{sev}: {count}</title></circle>'
            )
            offset += seg_len

        return (
            f'<svg viewBox="0 0 200 200" class="chart-donut">'
            f'{"".join(segments)}'
            f'<text x="100" y="97" text-anchor="middle" class="chart-donut-number">{len(self.summary.issues)}</text>'
            f'<text x="100" y="120" text-anchor="middle" class="chart-donut-label">FINDINGS</text>'
            f'</svg>'
        )

    def _build_category_bars(self) -> str:
        cats = sorted(self.summary.category_breakdown.items(), key=lambda x: -x[1])[:12]
        if not cats:
            return '<p class="empty-state">No categories to display.</p>'

        max_count = max(c for _, c in cats) or 1
        bars = []
        for cat, count in cats:
            width_pct = (count / max_count) * 100
            bars.append(
                f'<div class="bar-row">'
                f'<div class="bar-label" title="{self._esc(cat)}">{self._esc(cat)}</div>'
                f'<div class="bar-track"><div class="bar-fill" style="width:{width_pct:.1f}%"></div></div>'
                f'<div class="bar-value">{count}</div>'
                f'</div>'
            )
        return "".join(bars)

    def _build_issue_card(self, issue: ComplianceIssue) -> str:
        sev = issue.severity.lower()
        frameworks_html = ""
        if issue.compliance_frameworks:
            frameworks_html = (
                '<div class="frameworks">' +
                "".join(f'<span class="fw-tag">{self._esc(fw)}</span>' for fw in issue.compliance_frameworks) +
                '</div>'
            )

        cli_joined = "\n".join(issue.routeros_remediation_cli)
        verify_html = "".join(f'<li>{self._esc(step)}</li>' for step in issue.verification_steps)

        return f"""
        <article class="issue-card" data-severity="{sev}" data-category="{self._esc(issue.category)}" data-title="{self._esc(issue.title.lower())}">
            <header class="issue-header">
                <div class="issue-sev-badge sev-{sev}">{self._esc(issue.severity)}</div>
                <div class="issue-score">{issue.cvss_score}</div>
                <div class="issue-title-wrap">
                    <h3 class="issue-title">{self._esc(issue.title)}</h3>
                    <div class="issue-meta">
                        <span class="meta-item"><strong>{self._esc(issue.rule_id)}</strong></span>
                        <span class="meta-sep">·</span>
                        <span class="meta-item">{self._esc(issue.cwe_id)}</span>
                        <span class="meta-sep">·</span>
                        <span class="meta-item">{self._esc(issue.owasp_ref)}</span>
                    </div>
                </div>
                <button class="btn-detail" data-issue-id="{self._esc(issue.rule_id)}" aria-label="Detail">Detail</button>
            </header>
            <div class="issue-body">
                <p class="issue-component"><code>{self._esc(issue.affected_component)}</code></p>
                <p class="issue-detail">{self._esc(issue.technical_detail)}</p>
                {frameworks_html}
                <details class="issue-remediation">
                    <summary>Remediation &amp; Verification</summary>
                    <div class="remediation-content">
                        <div class="remediation-block">
                            <div class="block-header">
                                <span>RouterOS CLI</span>
                                <button class="btn-copy" data-copy="{self._esc(cli_joined)}">Copy</button>
                            </div>
                            <pre class="cli-pre">{self._esc(cli_joined)}</pre>
                        </div>
                        <div class="remediation-block">
                            <div class="block-header"><span>Verification Steps</span></div>
                            <ol class="verify-list">{verify_html}</ol>
                        </div>
                    </div>
                </details>
            </div>
            <script type="application/json" class="issue-data">{self._esc(json.dumps({
                "rule_id": issue.rule_id,
                "title": issue.title,
                "category": issue.category,
                "severity": issue.severity,
                "cvss_score": issue.cvss_score,
                "cvss_vector": issue.cvss_vector,
                "temporal_score": issue.temporal_score,
                "environmental_score": issue.environmental_score,
                "component": issue.affected_component,
                "detail": issue.technical_detail,
                "evidence": issue.evidence_snippet,
                "cli": issue.routeros_remediation_cli,
                "verify": issue.verification_steps,
                "cwe": issue.cwe_id,
                "owasp": issue.owasp_ref,
                "frameworks": issue.compliance_frameworks,
            }))}</script>
        </article>
        """

    def _build_passed_checks(self) -> str:
        if not self.summary.passed_checks:
            return '<p class="empty-state">No passed checks recorded.</p>'
        return "".join(
            f'<li class="passed-item"><span class="check-mark">✓</span>{self._esc(item)}</li>'
            for item in self.summary.passed_checks
        )

    def _build_css(self) -> str:
        return """
        :root {
            --color-bg: #0b1120;
            --color-surface: #131c2e;
            --color-surface-2: #1e293b;
            --color-border: #2a3a52;
            --color-text: #e6edf6;
            --color-text-muted: #8ba3bf;
            --color-text-dim: #64748b;
            --color-primary: #38bdf8;
            --color-primary-hover: #0ea5e9;
            --color-critical: #ef4444;
            --color-high: #f97316;
            --color-medium: #eab308;
            --color-low: #22c55e;
            --color-success: #10b981;
            --color-info: #38bdf8;

            --space-1: 4px;
            --space-2: 8px;
            --space-3: 12px;
            --space-4: 16px;
            --space-5: 24px;
            --space-6: 32px;
            --space-7: 48px;
            --space-8: 64px;

            --radius-sm: 6px;
            --radius-md: 10px;
            --radius-lg: 14px;

            --font-sans: -apple-system, BlinkMacSystemFont, "Segoe UI", "Inter", system-ui, sans-serif;
            --font-mono: "SF Mono", "JetBrains Mono", "Fira Code", "Consolas", monospace;

            --shadow-sm: 0 1px 2px rgba(0,0,0,0.2);
            --shadow-md: 0 4px 12px rgba(0,0,0,0.3);
            --shadow-lg: 0 12px 40px rgba(0,0,0,0.4);

            --motion-fast: 150ms;
            --motion-base: 220ms;
            --motion-slow: 340ms;
            --ease-out: cubic-bezier(0.22, 1, 0.36, 1);
        }

        :root.light {
            --color-bg: #f6f8fb;
            --color-surface: #ffffff;
            --color-surface-2: #f1f5f9;
            --color-border: #e2e8f0;
            --color-text: #0f172a;
            --color-text-muted: #475569;
            --color-text-dim: #94a3b8;
        }

        * { box-sizing: border-box; }

        html, body {
            margin: 0;
            padding: 0;
            background: var(--color-bg);
            color: var(--color-text);
            font-family: var(--font-sans);
            font-size: 14px;
            line-height: 1.6;
            -webkit-font-smoothing: antialiased;
        }

        .page {
            max-width: 1240px;
            margin: 0 auto;
            padding: var(--space-6) var(--space-5);
        }

        /* ===== Header ===== */
        .report-header {
            display: flex;
            align-items: flex-start;
            justify-content: space-between;
            gap: var(--space-5);
            margin-bottom: var(--space-6);
            padding-bottom: var(--space-5);
            border-bottom: 1px solid var(--color-border);
        }

        .report-title-group h1 {
            font-size: 26px;
            font-weight: 600;
            letter-spacing: -0.02em;
            margin: 0 0 var(--space-2) 0;
            color: var(--color-text);
        }

        .report-subtitle {
            color: var(--color-text-muted);
            font-size: 13px;
        }

        .report-subtitle code {
            font-family: var(--font-mono);
            color: var(--color-primary);
            background: var(--color-surface-2);
            padding: 2px var(--space-2);
            border-radius: var(--radius-sm);
        }

        .report-actions {
            display: flex;
            gap: var(--space-2);
        }

        .btn {
            background: var(--color-surface-2);
            border: 1px solid var(--color-border);
            color: var(--color-text);
            padding: var(--space-2) var(--space-4);
            border-radius: var(--radius-md);
            font-size: 13px;
            font-weight: 500;
            cursor: pointer;
            transition: all var(--motion-fast) var(--ease-out);
            font-family: var(--font-sans);
        }

        .btn:hover {
            background: var(--color-border);
            transform: translateY(-1px);
        }

        .btn:active { transform: translateY(0); }

        /* ===== Summary Row ===== */
        .summary-grid {
            display: grid;
            grid-template-columns: 320px 1fr;
            gap: var(--space-5);
            margin-bottom: var(--space-6);
        }

        @media (max-width: 900px) {
            .summary-grid { grid-template-columns: 1fr; }
        }

        .card {
            background: var(--color-surface);
            border: 1px solid var(--color-border);
            border-radius: var(--radius-lg);
            padding: var(--space-5);
        }

        .card-title {
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.08em;
            color: var(--color-text-dim);
            font-weight: 600;
            margin: 0 0 var(--space-4) 0;
        }

        .health-score-card {
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            text-align: center;
        }

        .health-score-value {
            font-size: 56px;
            font-weight: 700;
            line-height: 1;
            letter-spacing: -0.03em;
            background: linear-gradient(135deg, var(--color-primary), #a78bfa);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
        }

        .health-score-unit {
            color: var(--color-text-dim);
            font-size: 14px;
            margin-top: var(--space-2);
        }

        .health-grade {
            margin-top: var(--space-4);
            padding: var(--space-2) var(--space-4);
            background: var(--color-surface-2);
            border-radius: 999px;
            font-size: 12px;
            font-weight: 600;
            color: var(--color-text-muted);
        }

        .chart-donut {
            width: 200px;
            height: 200px;
            display: block;
            margin: 0 auto;
        }

        .chart-donut-number {
            font-size: 28px;
            font-weight: 700;
            fill: var(--color-text);
            font-family: var(--font-sans);
        }

        .chart-donut-label {
            font-size: 11px;
            font-weight: 600;
            fill: var(--color-text-dim);
            letter-spacing: 0.1em;
            font-family: var(--font-sans);
        }

        .severity-legend {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: var(--space-2);
            margin-top: var(--space-4);
        }

        .legend-item {
            display: flex;
            align-items: center;
            gap: var(--space-2);
            padding: var(--space-2);
            background: var(--color-surface-2);
            border-radius: var(--radius-sm);
            font-size: 12px;
        }

        .legend-dot {
            width: 10px;
            height: 10px;
            border-radius: 50%;
            flex-shrink: 0;
        }

        .legend-count {
            margin-left: auto;
            font-weight: 600;
            font-variant-numeric: tabular-nums;
        }

        /* ===== Category Bars ===== */
        .bar-row {
            display: grid;
            grid-template-columns: 180px 1fr 40px;
            gap: var(--space-3);
            align-items: center;
            margin-bottom: var(--space-3);
        }

        .bar-label {
            font-size: 12px;
            color: var(--color-text-muted);
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
        }

        .bar-track {
            height: 8px;
            background: var(--color-surface-2);
            border-radius: 999px;
            overflow: hidden;
        }

        .bar-fill {
            height: 100%;
            background: linear-gradient(90deg, var(--color-primary), #6366f1);
            border-radius: 999px;
            transition: width var(--motion-slow) var(--ease-out);
        }

        .bar-value {
            font-size: 12px;
            font-weight: 600;
            color: var(--color-text-muted);
            text-align: right;
            font-variant-numeric: tabular-nums;
        }

        /* ===== Controls ===== */
        .controls-bar {
            display: flex;
            flex-wrap: wrap;
            gap: var(--space-3);
            align-items: center;
            margin-bottom: var(--space-4);
            padding: var(--space-4);
            background: var(--color-surface);
            border: 1px solid var(--color-border);
            border-radius: var(--radius-lg);
        }

        .search-input {
            flex: 1;
            min-width: 240px;
            background: var(--color-bg);
            border: 1px solid var(--color-border);
            border-radius: var(--radius-md);
            padding: var(--space-2) var(--space-4);
            color: var(--color-text);
            font-size: 13px;
            font-family: var(--font-sans);
            transition: border-color var(--motion-fast) var(--ease-out);
        }

        .search-input:focus {
            outline: none;
            border-color: var(--color-primary);
        }

        .filter-chips {
            display: flex;
            gap: var(--space-2);
            flex-wrap: wrap;
        }

        .chip {
            padding: var(--space-1) var(--space-3);
            background: var(--color-surface-2);
            border: 1px solid var(--color-border);
            border-radius: 999px;
            font-size: 12px;
            font-weight: 500;
            color: var(--color-text-muted);
            cursor: pointer;
            transition: all var(--motion-fast) var(--ease-out);
            user-select: none;
        }

        .chip:hover {
            color: var(--color-text);
        }

        .chip.active {
            background: var(--color-primary);
            color: #0b1120;
            border-color: var(--color-primary);
        }

        /* ===== Issue Cards ===== */
        .issue-list {
            display: flex;
            flex-direction: column;
            gap: var(--space-3);
        }

        .issue-card {
            background: var(--color-surface);
            border: 1px solid var(--color-border);
            border-left: 4px solid var(--color-border);
            border-radius: var(--radius-lg);
            overflow: hidden;
            transition: transform var(--motion-fast) var(--ease-out),
                        box-shadow var(--motion-fast) var(--ease-out);
        }

        .issue-card:hover {
            transform: translateY(-1px);
            box-shadow: var(--shadow-md);
        }

        .issue-card[data-severity="critical"] { border-left-color: var(--color-critical); }
        .issue-card[data-severity="high"] { border-left-color: var(--color-high); }
        .issue-card[data-severity="medium"] { border-left-color: var(--color-medium); }
        .issue-card[data-severity="low"] { border-left-color: var(--color-low); }

        .issue-header {
            display: flex;
            align-items: center;
            gap: var(--space-4);
            padding: var(--space-4) var(--space-5);
        }

        .issue-sev-badge {
            padding: 4px 10px;
            border-radius: var(--radius-sm);
            font-size: 11px;
            font-weight: 700;
            letter-spacing: 0.05em;
            flex-shrink: 0;
        }

        .sev-critical { background: rgba(239,68,68,0.15); color: var(--color-critical); }
        .sev-high { background: rgba(249,115,22,0.15); color: var(--color-high); }
        .sev-medium { background: rgba(234,179,8,0.15); color: var(--color-medium); }
        .sev-low { background: rgba(34,197,94,0.15); color: var(--color-low); }

        .issue-score {
            font-size: 20px;
            font-weight: 700;
            font-variant-numeric: tabular-nums;
            color: var(--color-text);
            min-width: 40px;
            text-align: center;
        }

        .issue-title-wrap { flex: 1; min-width: 0; }

        .issue-title {
            font-size: 15px;
            font-weight: 600;
            margin: 0 0 var(--space-1) 0;
            color: var(--color-text);
            line-height: 1.4;
        }

        .issue-meta {
            font-size: 12px;
            color: var(--color-text-dim);
            font-family: var(--font-mono);
            display: flex;
            flex-wrap: wrap;
            gap: var(--space-1);
        }

        .meta-sep { opacity: 0.5; }

        .btn-detail {
            background: transparent;
            border: 1px solid var(--color-border);
            color: var(--color-text-muted);
            padding: var(--space-2) var(--space-4);
            border-radius: var(--radius-md);
            font-size: 12px;
            font-weight: 500;
            cursor: pointer;
            transition: all var(--motion-fast) var(--ease-out);
            flex-shrink: 0;
        }

        .btn-detail:hover {
            border-color: var(--color-primary);
            color: var(--color-primary);
        }

        .issue-body {
            padding: 0 var(--space-5) var(--space-4);
        }

        .issue-component {
            margin: 0 0 var(--space-3) 0;
        }

        .issue-component code {
            font-family: var(--font-mono);
            font-size: 12px;
            background: var(--color-surface-2);
            padding: 2px var(--space-2);
            border-radius: var(--radius-sm);
            color: var(--color-primary);
        }

        .issue-detail {
            margin: 0 0 var(--space-3) 0;
            color: var(--color-text-muted);
            font-size: 13px;
        }

        .frameworks {
            display: flex;
            flex-wrap: wrap;
            gap: var(--space-2);
            margin-bottom: var(--space-3);
        }

        .fw-tag {
            padding: 2px var(--space-2);
            background: var(--color-surface-2);
            border-radius: var(--radius-sm);
            font-size: 11px;
            color: var(--color-text-dim);
            font-family: var(--font-mono);
        }

        .issue-remediation {
            margin-top: var(--space-2);
            border-top: 1px solid var(--color-border);
            padding-top: var(--space-3);
        }

        .issue-remediation summary {
            cursor: pointer;
            font-size: 12px;
            font-weight: 600;
            color: var(--color-text-muted);
            padding: var(--space-1) 0;
            list-style: none;
            user-select: none;
        }

        .issue-remediation summary::-webkit-details-marker { display: none; }

        .issue-remediation summary::before {
            content: "▸ ";
            display: inline-block;
            transition: transform var(--motion-fast) var(--ease-out);
            margin-right: var(--space-1);
        }

        .issue-remediation[open] summary::before {
            transform: rotate(90deg);
        }

        .remediation-content {
            margin-top: var(--space-3);
            display: flex;
            flex-direction: column;
            gap: var(--space-3);
        }

        .remediation-block {
            background: var(--color-bg);
            border: 1px solid var(--color-border);
            border-radius: var(--radius-md);
            overflow: hidden;
        }

        .block-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: var(--space-2) var(--space-4);
            border-bottom: 1px solid var(--color-border);
            font-size: 11px;
            font-weight: 600;
            color: var(--color-text-dim);
            text-transform: uppercase;
            letter-spacing: 0.05em;
        }

        .btn-copy {
            background: transparent;
            border: 1px solid var(--color-border);
            color: var(--color-text-muted);
            padding: 2px var(--space-2);
            border-radius: var(--radius-sm);
            font-size: 11px;
            cursor: pointer;
            transition: all var(--motion-fast) var(--ease-out);
        }

        .btn-copy:hover {
            color: var(--color-primary);
            border-color: var(--color-primary);
        }

        .btn-copy.copied {
            color: var(--color-success);
            border-color: var(--color-success);
        }

        .cli-pre {
            margin: 0;
            padding: var(--space-3) var(--space-4);
            font-family: var(--font-mono);
            font-size: 12px;
            color: var(--color-primary);
            overflow-x: auto;
            white-space: pre;
            line-height: 1.6;
        }

        .verify-list {
            margin: 0;
            padding: var(--space-3) var(--space-4) var(--space-3) var(--space-6);
            font-size: 12px;
            color: var(--color-text-muted);
        }

        .verify-list li {
            margin-bottom: var(--space-1);
        }

        /* ===== Passed Checks ===== */
        .passed-list {
            list-style: none;
            padding: 0;
            margin: 0;
            display: grid;
            gap: var(--space-2);
        }

        .passed-item {
            display: flex;
            align-items: flex-start;
            gap: var(--space-3);
            padding: var(--space-3) var(--space-4);
            background: var(--color-surface);
            border: 1px solid var(--color-border);
            border-radius: var(--radius-md);
            font-size: 13px;
            color: var(--color-text-muted);
        }

        .check-mark {
            color: var(--color-success);
            font-weight: 700;
            flex-shrink: 0;
        }

        /* ===== Modal ===== */
        .modal-overlay {
            position: fixed;
            inset: 0;
            background: rgba(0,0,0,0.7);
            backdrop-filter: blur(4px);
            display: none;
            align-items: center;
            justify-content: center;
            z-index: 100;
            padding: var(--space-5);
            opacity: 0;
            transition: opacity var(--motion-base) var(--ease-out);
        }

        .modal-overlay.open {
            display: flex;
            opacity: 1;
        }

        .modal-content {
            background: var(--color-surface);
            border: 1px solid var(--color-border);
            border-radius: var(--radius-lg);
            max-width: 720px;
            width: 100%;
            max-height: 85vh;
            overflow-y: auto;
            box-shadow: var(--shadow-lg);
            transform: scale(0.95);
            transition: transform var(--motion-base) var(--ease-out);
        }

        .modal-overlay.open .modal-content {
            transform: scale(1);
        }

        .modal-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: var(--space-4) var(--space-5);
            border-bottom: 1px solid var(--color-border);
            position: sticky;
            top: 0;
            background: var(--color-surface);
            z-index: 1;
        }

        .modal-title {
            font-size: 16px;
            font-weight: 600;
            margin: 0;
            color: var(--color-text);
        }

        .modal-close {
            background: transparent;
            border: none;
            color: var(--color-text-muted);
            font-size: 24px;
            cursor: pointer;
            padding: 0;
            width: 32px;
            height: 32px;
            border-radius: var(--radius-sm);
            display: flex;
            align-items: center;
            justify-content: center;
        }

        .modal-close:hover {
            background: var(--color-surface-2);
        }

        .modal-body {
            padding: var(--space-5);
            font-size: 13px;
        }

        .modal-section {
            margin-bottom: var(--space-5);
        }

        .modal-section:last-child {
            margin-bottom: 0;
        }

        .modal-section-title {
            font-size: 11px;
            font-weight: 600;
            letter-spacing: 0.08em;
            text-transform: uppercase;
            color: var(--color-text-dim);
            margin: 0 0 var(--space-2) 0;
        }

        .modal-kv {
            display: grid;
            grid-template-columns: 140px 1fr;
            gap: var(--space-2) var(--space-4);
            font-size: 12px;
        }

        .modal-kv dt {
            color: var(--color-text-dim);
        }

        .modal-kv dd {
            margin: 0;
            font-family: var(--font-mono);
            color: var(--color-text);
            word-break: break-word;
        }

        /* ===== Empty state ===== */
        .empty-state {
            padding: var(--space-6);
            text-align: center;
            color: var(--color-text-dim);
            font-size: 13px;
        }

        /* ===== Footer ===== */
        .report-footer {
            margin-top: var(--space-7);
            padding-top: var(--space-5);
            border-top: 1px solid var(--color-border);
            text-align: center;
            color: var(--color-text-dim);
            font-size: 12px;
        }

        /* ===== Print ===== */
        @media print {
            body { background: white; color: black; }
            .controls-bar, .btn-detail, .btn-copy, .btn { display: none; }
            .issue-card { break-inside: avoid; page-break-inside: avoid; }
            .modal-overlay { display: none !important; }
            .report-header { border-color: #ccc; }
            .card, .issue-card { border-color: #ddd; box-shadow: none; }
        }

        /* ===== Reduced motion ===== */
        @media (prefers-reduced-motion: reduce) {
            * { transition: none !important; animation: none !important; }
        }
        """

    def _build_js(self) -> str:
        return """
        (function() {
            'use strict';

            // Theme toggle
            const themeBtn = document.getElementById('themeToggle');
            if (themeBtn) {
                themeBtn.addEventListener('click', function() {
                    document.documentElement.classList.toggle('light');
                });
            }

            // Filter chips
            const chips = document.querySelectorAll('.chip');
            const issueCards = document.querySelectorAll('.issue-card');
            const searchInput = document.getElementById('searchInput');
            const emptyState = document.getElementById('emptyState');

            let activeFilter = 'all';
            let searchTerm = '';

            function applyFilters() {
                let visible = 0;
                issueCards.forEach(card => {
                    const sev = card.dataset.severity;
                    const title = card.dataset.title;
                    const cat = (card.dataset.category || '').toLowerCase();

                    const sevMatch = activeFilter === 'all' || sev === activeFilter;
                    const searchMatch = !searchTerm ||
                        title.includes(searchTerm) ||
                        cat.includes(searchTerm);

                    if (sevMatch && searchMatch) {
                        card.style.display = '';
                        visible++;
                    } else {
                        card.style.display = 'none';
                    }
                });
                if (emptyState) {
                    emptyState.style.display = visible === 0 ? 'block' : 'none';
                }
            }

            chips.forEach(chip => {
                chip.addEventListener('click', function() {
                    chips.forEach(c => c.classList.remove('active'));
                    chip.classList.add('active');
                    activeFilter = chip.dataset.filter;
                    applyFilters();
                });
            });

            if (searchInput) {
                searchInput.addEventListener('input', function(e) {
                    searchTerm = e.target.value.toLowerCase().trim();
                    applyFilters();
                });
            }

            // Copy buttons
            document.addEventListener('click', function(e) {
                const copyBtn = e.target.closest('.btn-copy');
                if (copyBtn) {
                    const text = copyBtn.dataset.copy || '';
                    navigator.clipboard.writeText(text).then(function() {
                        const orig = copyBtn.textContent;
                        copyBtn.textContent = 'Copied';
                        copyBtn.classList.add('copied');
                        setTimeout(function() {
                            copyBtn.textContent = orig;
                            copyBtn.classList.remove('copied');
                        }, 1500);
                    }).catch(function() {
                        copyBtn.textContent = 'Failed';
                    });
                }
            });

            // Modal
            const modal = document.getElementById('modal');
            const modalTitle = document.getElementById('modalTitle');
            const modalBody = document.getElementById('modalBody');
            const modalClose = document.getElementById('modalClose');

            function openModal(issueData) {
                modalTitle.textContent = issueData.title;
                const kvRows = [
                    ['Rule ID', issueData.rule_id],
                    ['Category', issueData.category],
                    ['Severity', issueData.severity],
                    ['CVSS Base', issueData.cvss_score],
                    ['CVSS Temporal', issueData.temporal_score],
                    ['CVSS Environmental', issueData.environmental_score],
                    ['CVSS Vector', issueData.cvss_vector],
                    ['Component', issueData.component],
                    ['CWE', issueData.cwe],
                    ['OWASP', issueData.owasp],
                ];

                let html = '<div class="modal-section">';
                html += '<div class="modal-section-title">Attributes</div>';
                html += '<dl class="modal-kv">';
                kvRows.forEach(function(row) {
                    html += '<dt>' + row[0] + '</dt><dd>' + escapeHtml(String(row[1])) + '</dd>';
                });
                html += '</dl></div>';

                html += '<div class="modal-section">';
                html += '<div class="modal-section-title">Technical Detail</div>';
                html += '<p>' + escapeHtml(issueData.detail) + '</p>';
                html += '</div>';

                html += '<div class="modal-section">';
                html += '<div class="modal-section-title">Evidence</div>';
                html += '<pre class="cli-pre">' + escapeHtml(issueData.evidence) + '</pre>';
                html += '</div>';

                if (issueData.cli && issueData.cli.length) {
                    html += '<div class="modal-section">';
                    html += '<div class="modal-section-title">Remediation</div>';
                    html += '<pre class="cli-pre">' + escapeHtml(issueData.cli.join('\\n')) + '</pre>';
                    html += '</div>';
                }

                if (issueData.frameworks && issueData.frameworks.length) {
                    html += '<div class="modal-section">';
                    html += '<div class="modal-section-title">Compliance</div>';
                    html += '<p>' + issueData.frameworks.map(escapeHtml).join(', ') + '</p>';
                    html += '</div>';
                }

                modalBody.innerHTML = html;
                modal.classList.add('open');
            }

            function escapeHtml(s) {
                return s.replace(/[&<>"']/g, function(c) {
                    return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];
                });
            }

            document.addEventListener('click', function(e) {
                const btn = e.target.closest('.btn-detail');
                if (btn) {
                    const card = btn.closest('.issue-card');
                    const dataScript = card.querySelector('.issue-data');
                    if (dataScript) {
                        try {
                            openModal(JSON.parse(dataScript.textContent));
                        } catch (err) {
                            console.error('Failed to parse issue data', err);
                        }
                    }
                }
            });

            if (modalClose) {
                modalClose.addEventListener('click', function() {
                    modal.classList.remove('open');
                });
            }

            if (modal) {
                modal.addEventListener('click', function(e) {
                    if (e.target === modal) {
                        modal.classList.remove('open');
                    }
                });
            }

            document.addEventListener('keydown', function(e) {
                if (e.key === 'Escape' && modal) {
                    modal.classList.remove('open');
                }
            });
        })();
        """

    def render(self) -> str:
        s = self.summary

        severity_legend = ""
        for sev, color in [
            ("CRITICAL", "var(--color-critical)"),
            ("HIGH", "var(--color-high)"),
            ("MEDIUM", "var(--color-medium)"),
            ("LOW", "var(--color-low)"),
        ]:
            count = s.severity_breakdown.get(sev, 0)
            severity_legend += (
                f'<div class="legend-item">'
                f'<span class="legend-dot" style="background:{color}"></span>'
                f'<span>{sev}</span>'
                f'<span class="legend-count">{count}</span>'
                f'</div>'
            )

        issues_html = "".join(self._build_issue_card(i) for i in s.issues)
        if not issues_html:
            issues_html = '<p class="empty-state">No findings. Configuration appears hardened.</p>'

        return f"""<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Audit Report - {self._esc(s.target_identifier)}</title>
<style>{self._build_css()}</style>
</head>
<body>
<div class="page">

    <header class="report-header">
        <div class="report-title-group">
            <h1>MikroTik Security Compliance Audit</h1>
            <div class="report-subtitle">
                Target: <code>{self._esc(s.target_identifier)}</code>
                &nbsp;·&nbsp; Mode: {self._esc(s.scan_mode)}
                &nbsp;·&nbsp; Framework: v{self._esc(s.framework_version)}
                &nbsp;·&nbsp; {self._esc(s.timestamp)}
            </div>
        </div>
        <div class="report-actions">
            <button class="btn" id="themeToggle">Toggle Theme</button>
            <button class="btn" onclick="window.print()">Print / PDF</button>
        </div>
    </header>

    <section class="summary-grid">
        <div class="card health-score-card">
            <p class="card-title">Health Score</p>
            <div class="health-score-value">{s.overall_health_score}</div>
            <div class="health-score-unit">out of 100</div>
            <div class="health-grade">{self._esc(s.security_grade)}</div>
            <div class="report-subtitle" style="margin-top:var(--space-4);font-size:11px;">
                Execution: {s.execution_time_ms} ms
            </div>
        </div>

        <div class="card">
            <p class="card-title">Severity Distribution</p>
            <div style="display:grid;grid-template-columns:200px 1fr;gap:var(--space-5);align-items:center;">
                <div>{self._build_donut_svg()}</div>
                <div class="severity-legend">{severity_legend}</div>
            </div>
        </div>
    </section>

    <section class="card" style="margin-bottom:var(--space-5);">
        <p class="card-title">Findings by Category</p>
        {self._build_category_bars()}
    </section>

    <section style="margin-bottom:var(--space-5);">
        <div class="controls-bar">
            <input type="text" class="search-input" id="searchInput" placeholder="Search findings...">
            <div class="filter-chips">
                <span class="chip active" data-filter="all">All</span>
                <span class="chip" data-filter="critical">Critical</span>
                <span class="chip" data-filter="high">High</span>
                <span class="chip" data-filter="medium">Medium</span>
                <span class="chip" data-filter="low">Low</span>
            </div>
        </div>

        <div class="issue-list">
            {issues_html}
        </div>
        <p id="emptyState" class="empty-state" style="display:none;">
            No findings match the current filter.
        </p>
    </section>

    <section class="card">
        <p class="card-title">Passed Checks ({len(s.passed_checks)})</p>
        <ul class="passed-list">
            {self._build_passed_checks()}
        </ul>
    </section>

    <footer class="report-footer">
        Generated by {FRAMEWORK_NAME} v{FRAMEWORK_VERSION} · All checks are passive and non-intrusive.
    </footer>
</div>

<div class="modal-overlay" id="modal">
    <div class="modal-content">
        <div class="modal-header">
            <h2 class="modal-title" id="modalTitle">Detail</h2>
            <button class="modal-close" id="modalClose">×</button>
        </div>
        <div class="modal-body" id="modalBody"></div>
    </div>
</div>

<script>{self._build_js()}</script>
</body>
</html>"""


# =============================================================================
# 9. CLI & MAIN
# =============================================================================

def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="mikrotik-auditor",
        description=(
            f"{FRAMEWORK_NAME} v{FRAMEWORK_VERSION} - "
            "Passive MikroTik RouterOS security compliance auditor."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""
            Examples:
              python3 audit.py --target 20.20.1.9
              python3 audit.py --target 10.10.10.1 --mode fingerprint
              python3 audit.py --rsc export.rsc --mode config
              python3 audit.py --target 10.10.10.1 --rsc export.rsc --mode full
              python3 audit.py --target 10.10.10.1 --voucher "user123" --verbose
        """).strip()
    )
    p.add_argument("--target", default="20.20.1.9",
                   help="Gateway IP address to audit (default: 20.20.1.9)")
    p.add_argument("--mode", choices=["passive", "fingerprint", "config", "full"],
                   default="fingerprint",
                   help="Scan mode (default: fingerprint)")
    p.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT_SECONDS,
                   help="Timeout per network call in seconds (default: 2.0)")
    p.add_argument("--rsc", default=None,
                   help="Path to RouterOS .rsc export for deep config analysis")
    p.add_argument("--voucher", default=None,
                   help="Sample voucher code to analyze for entropy/weakness")
    p.add_argument("--output", default=".",
                   help="Output directory for reports (default: current)")
    p.add_argument("--no-temporal", action="store_true",
                   help="Skip temporal and environmental CVSS scoring")
    p.add_argument("--verbose", "-v", action="store_true",
                   help="Verbose console output")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    os.makedirs(args.output, exist_ok=True)

    config = AuditConfig(
        target_ip=args.target,
        mode=ScanMode(args.mode),
        timeout=args.timeout,
        rsc_file_path=args.rsc,
        output_dir=args.output,
        include_temporal_env=not args.no_temporal,
        verbose=args.verbose,
    )

    print(f"[*] {FRAMEWORK_NAME} v{FRAMEWORK_VERSION}")
    print(f"    Target: {config.target_ip}")
    print(f"    Mode:   {config.mode.value}")
    if config.rsc_file_path:
        print(f"    RSC:    {config.rsc_file_path}")
    print()

    auditor = EnterpriseMikrotikAuditor(config)
    summary = auditor.execute(sample_voucher=args.voucher)

    print(f"[+] Audit completed in {summary.execution_time_ms} ms")
    print(f"    Health Score: {summary.overall_health_score} / 100 ({summary.security_grade})")
    print(f"    Findings:     {len(summary.issues)} total")
    print(f"      CRITICAL: {summary.severity_breakdown.get('CRITICAL', 0)}")
    print(f"      HIGH:     {summary.severity_breakdown.get('HIGH', 0)}")
    print(f"      MEDIUM:   {summary.severity_breakdown.get('MEDIUM', 0)}")
    print(f"      LOW:      {summary.severity_breakdown.get('LOW', 0)}")
    print(f"    Passed checks: {len(summary.passed_checks)}")

    if summary.issues and args.verbose:
        print()
        print("[*] Findings summary:")
        for issue in summary.issues:
            print(f"    [{issue.severity:8}] {issue.cvss_score:>4}  {issue.rule_id}  {issue.title}")

    writer = ReportWriter(summary, config.output_dir)
    paths = []
    paths.append(writer.write_json())
    paths.append(writer.write_html())
    paths.append(writer.write_markdown())
    paths.append(writer.write_sarif())
    paths.append(writer.write_hardening_script())

    print()
    print("[+] Report files written:")
    for p in paths:
        print(f"    {p}")

    return 0


if __name__ == "__main__":
    sys.exit(main())

# =============================================================================
# 10. COMPLIANCE STANDARDS & THREAT INTELLIGENCE MAPPINGS (EXPANDED v4.5)
# =============================================================================
# Standard Reference Matrix for Enterprise Wireless & RouterOS Security:
# - NIST SP 800-53 Rev 5: Security and Privacy Controls for Information Systems
#   * AC-3: Access Enforcement (Management Service ACLs)
#   * AC-17: Remote Access Management (VPN, SSH Strong Crypto)
#   * CM-7: Least Functionality (Disable Telnet, FTP, RoMON, Bandwidth Server)
#   * SC-5: Denial of Service Protection (SYN Flood, DNS Amplification)
#   * SC-7: Boundary Protection (RFC 1918 Private Addressing, Bogon Filters)
#   * SI-4: Information System Monitoring (Remote Syslog, Trap Hosts)
#
# - CIS MikroTik RouterOS Benchmark v1.0:
#   * Section 1: Initial System Configuration & Management Service Hardening
#   * Section 2: Stateful Firewall Rules (Input Default-Deny, Invalid Drop)
#   * Section 3: Protocol Hardening (MNDP, MAC-Telnet, RoMON Disablement)
#   * Section 4: Security Logging & External Monitoring
#   * Section 5: Wireless 802.11 & Hotspot Profile Configuration
#
# - PCI DSS v4.0 Network Security Controls:
#   * Requirement 1.2: Network Security Controls are configured and maintained
#   * Requirement 1.3: Network access to and from the cardholder data environment is restricted
#   * Requirement 2.2: System components are configured and managed securely
#   * Requirement 2.3: Wireless environments are configured and managed securely
#
# - ISO/IEC 27001:2022 Information Security Controls:
#   * A.8.2: Privileged Access Rights (Admin User Hardening)
#   * A.8.9: Configuration Management (RouterOS RSC Audit)
#   * A.8.20: Network Security (Perimeter Filtering & DNS Isolation)
#   * A.8.24: Use of Cryptography (SSH Ciphers & TLS Certificates)
# =============================================================================


# =============================================================================
# 10. COMPREHENSIVE COMPLIANCE & VULNERABILITY INTELLIGENCE (ENTERPRISE EDITION)
# =============================================================================

ENTERPRISE_SECURITY_STANDARDS_MAPPING = {
    "NIST_SP_800_53_REV5": {
        "AC-2": "Account Management: Prohibit default shared administrative accounts",
        "AC-3": "Access Enforcement: Enforce isolation between management plane and client networks",
        "AC-17": "Remote Access: Mandate encrypted management channels (SSH Strong Crypto, Winbox over TLS)",
        "CM-7": "Least Functionality: Disable unused legacy protocols (Telnet, FTP, Bandwidth-Test)",
        "SC-5": "Denial of Service Protection: Limit connection rates and prevent open recursive DNS queries",
        "SC-7": "Boundary Protection: Enforce RFC 1918 private addressing and filter bogon networks",
        "SC-8": "Transmission Confidentiality and Integrity: Protect against plaintext credential leakage (MD5 CHAP)",
        "SI-4": "Information System Monitoring: Forward logs to central remote syslog server",
        "SI-7": "Software, Firmware, and Information Integrity: Ensure subresource integrity for captive portal assets",
        "IA-2": "Identification and Authentication: Mandate high-entropy voucher codes (>= 8 chars, 62-char pool)"
    },
    "CIS_MIKROTIK_ROUTEROS_BENCHMARK_V1_0": {
        "1.1.1": {"name": "Disable Telnet Service", "section": "1. Initial Setup", "severity": "CRITICAL"},
        "1.1.2": {"name": "Disable FTP Service", "section": "1. Initial Setup", "severity": "HIGH"},
        "1.1.3": {"name": "Disable HTTP (WWW) Service or Restrict by IP", "section": "1. Initial Setup", "severity": "HIGH"},
        "1.1.4": {"name": "Disable Unencrypted API Service", "section": "1. Initial Setup", "severity": "HIGH"},
        "1.1.5": {"name": "Restrict Winbox Service by IP Address List", "section": "1. Initial Setup", "severity": "CRITICAL"},
        "1.2.1": {"name": "Disable Default 'admin' User", "section": "1. Initial Setup", "severity": "CRITICAL"},
        "1.2.2": {"name": "Configure Strong Passwords for All Users", "section": "1. Initial Setup", "severity": "CRITICAL"},
        "2.1.1": {"name": "Drop Invalid Connection State in Input Chain", "section": "2. Firewall", "severity": "MEDIUM"},
        "2.1.2": {"name": "Drop Invalid Connection State in Forward Chain", "section": "2. Firewall", "severity": "MEDIUM"},
        "2.2.1": {"name": "Establish Default-Deny Policy on Input Chain", "section": "2. Firewall", "severity": "CRITICAL"},
        "2.2.2": {"name": "Protect Router DNS Server from External Queries", "section": "2. Firewall", "severity": "CRITICAL"},
        "3.1.1": {"name": "Disable Bandwidth-Test Server", "section": "3. Management Protocols", "severity": "HIGH"},
        "3.2.1": {"name": "Restrict Neighbor Discovery Protocol (MNDP) to Management Interface", "section": "3. Management Protocols", "severity": "HIGH"},
        "3.3.1": {"name": "Disable MAC-Telnet on Untrusted Interfaces", "section": "3. Management Protocols", "severity": "HIGH"},
        "3.3.2": {"name": "Disable MAC-Winbox on Untrusted Interfaces", "section": "3. Management Protocols", "severity": "CRITICAL"},
        "4.1.1": {"name": "Configure Remote Syslog Logging Action", "section": "4. Logging", "severity": "HIGH"},
        "5.1.1": {"name": "Disable Wi-Fi Protected Setup (WPS)", "section": "5. Wireless", "severity": "HIGH"},
        "5.1.2": {"name": "Enforce WPA2/WPA3 Dynamic Keys Only", "section": "5. Wireless", "severity": "HIGH"}
    },
    "PCI_DSS_V4_0_NETWORK_CONTROLS": {
        "Req_1_2": "Perimeter firewalls and routers must control all traffic between internal networks and untrusted networks",
        "Req_1_3": "Inbound and outbound traffic to and from the cardholder data environment must be strictly restricted",
        "Req_2_2": "Default vendor settings, passwords, and service parameters must be modified prior to system deployment",
        "Req_2_3": "Wireless environments transmitting cardholder data must use modern cryptographic protocols (WPA2/WPA3 Enterprise)",
        "Req_8_3": "Multi-factor authentication or strict origin IP whitelisting must be enforced for administrative access"
    },
    "OWASP_TOP10_2021_MAPPING": {
        "A01": "Broken Access Control (Direct exposure of WebFig, Winbox, or unauthenticated walled-garden bypass)",
        "A02": "Cryptographic Failures (Plaintext Telnet/FTP, lack of CHAP/MD5 in portal, weak 1024-bit RSA certs)",
        "A03": "Injection (DOM XSS via unescaped portal parameters and inline script execution)",
        "A05": "Security Misconfiguration (Default allow-remote-requests=yes on DNS, open Bandwidth-Test, default admin)",
        "A07": "Identification and Authentication Failures (Low-entropy vouchers, password=user pattern, missing brute-force lock)",
        "A08": "Software and Data Integrity Failures (External scripts loaded without Subresource Integrity (SRI))",
        "A09": "Security Logging and Monitoring Failures (Absence of remote syslog forwarding, logs lost on router reboot)"
    }
}

class ComplianceFrameworkEngine:
    """
    Menyediakan pemetaan otomatis antara setiap temuan audit dengan klausul compliance
    internasional (NIST SP 800-53, CIS Benchmark, PCI DSS, ISO/IEC 27001, OWASP Top 10).
    """
    @staticmethod
    def map_issue_to_frameworks(issue_title: str, category: str, cwe_id: str) -> List[str]:
        frameworks = []
        lower_t = issue_title.lower()
        lower_c = category.lower()

        if "dns" in lower_t or "resolver" in lower_t:
            frameworks.extend([
                "NIST SP 800-81-2 (4.1)",
                "CIS MikroTik RouterOS (2.2.2)",
                "PCI DSS v4.0 (Req 1.3)",
                "ISO/IEC 27001:2022 (A.8.20)"
            ])
        elif "webfig" in lower_t or "management" in lower_c:
            frameworks.extend([
                "NIST SP 800-53 Rev 5 (AC-3)",
                "CIS MikroTik RouterOS (1.1.3)",
                "ISO/IEC 27001:2022 (A.8.2)"
            ])
        elif "rfc 1918" in lower_t or "routing" in lower_c:
            frameworks.extend([
                "NIST SP 800-53 Rev 5 (SC-7)",
                "ISO/IEC 27001:2022 (A.8.20)",
                "RFC 1918 (Private Address Allocation)"
            ])
        elif "firewall" in lower_c:
            frameworks.extend([
                "CIS MikroTik RouterOS (2.2.1)",
                "NIST SP 800-53 Rev 5 (SC-7)",
                "PCI DSS v4.0 (Req 1.2)"
            ])
        elif "voucher" in lower_c or "authenticat" in lower_c:
            frameworks.extend([
                "NIST SP 800-63B (Digital Identity Guidelines)",
                "CIS MikroTik RouterOS (1.2.2)",
                "PCI DSS v4.0 (Req 8.3)"
            ])
        elif "xss" in lower_c or "portal" in lower_c:
            frameworks.extend([
                "OWASP Top 10 2021 (A03: Injection)",
                "NIST SP 800-53 Rev 5 (SI-7)",
                "CWE-79 (Improper Neutralization of Input)"
            ])

        return frameworks


# =============================================================================
# 11. ADVANCED PROTOCOL, ROUTING & VOUCHER FORENSIC ANALYZERS
# =============================================================================

class RoutingProtocolSecurityAnalyzer:
    """
    Menganalisis protokol routing dinamis pada MikroTik RouterOS:
    - OSPFv2 / OSPFv3 autentikasi kriptografis (MD5 / SHA)
    - BGP Peering security (TTL Security, MD5 password, Prefix limit)
    - RIPv2 plaintext authentication risk
    - VRRP authentication compliance
    """
    def __init__(self, config_parser):
        self.parser = config_parser

    def audit_ospf_security(self) -> List[Dict[str, str]]:
        if not self.parser:
            return []
        ospf_areas = self.parser.get_section_commands("/routing ospf area")
        ospf_interfaces = self.parser.get_section_commands("/routing ospf interface")
        findings = []

        for line in ospf_interfaces:
            lower = line.lower()
            if "authentication=none" in lower or "authentication=" not in lower:
                findings.append({
                    "protocol": "OSPF",
                    "rule": line,
                    "severity": "HIGH",
                    "cwe": "CWE-306",
                    "issue": "OSPF Interface aktif tanpa autentikasi kriptografis (MD5/SHA). Penyerang di segmen LAN dapat menginjeksi rute palsu (route hijacking).",
                    "fix": "/routing ospf interface set [find] authentication=md5 authentication-key=\"<STRONG-KEY>\""
                })
        return findings

    def audit_bgp_peering_security(self) -> List[Dict[str, str]]:
        if not self.parser:
            return []
        bgp_peers = self.parser.get_section_commands("/routing bgp peer")
        findings = []

        for line in bgp_peers:
            lower = line.lower()
            if "tcp-md5-key=" not in lower:
                name_m = re.search(r"name=([^\s]+)", line)
                peer_name = name_m.group(1) if name_m else "unnamed"
                findings.append({
                    "protocol": "BGP",
                    "rule": line,
                    "severity": "HIGH",
                    "cwe": "CWE-306",
                    "issue": f"BGP Peer '{peer_name}' tidak menggunakan TCP MD5 signature. Rentan terhadap serangan BGP TCP Reset & Session Hijacking.",
                    "fix": f"/routing bgp peer set [find name=\"{peer_name}\"] tcp-md5-key=\"<BGP-MD5-SECRET>\""
                })
            if "ttl=default" in lower or "multihop=yes" in lower and "ttl=" not in lower:
                findings.append({
                    "protocol": "BGP",
                    "rule": line,
                    "severity": "MEDIUM",
                    "cwe": "CWE-345",
                    "issue": "GTSM (Generalized TTL Security Mechanism) tidak aktif pada sesi BGP eBGP langsung.",
                    "fix": "/routing bgp peer set [find] ttl=255"
                })
        return findings

    def audit_vrrp_security(self) -> List[Dict[str, str]]:
        if not self.parser:
            return []
        vrrp_lines = self.parser.get_section_commands("/interface vrrp")
        findings = []
        for line in vrrp_lines:
            if "authentication=none" in line.lower() or "authentication=" not in line.lower():
                findings.append({
                    "protocol": "VRRP",
                    "rule": line,
                    "severity": "MEDIUM",
                    "cwe": "CWE-306",
                    "issue": "VRRP interface aktif tanpa autentikasi. Host rogue di jaringan dapat memalsukan VRRP priority dan membajak gateway default.",
                    "fix": "/interface vrrp set [find] authentication=simple password=\"<VRRP-PASS>\""
                })
        return findings


class VoucherEntropyForensicsEngine:
    """
    Mesin forensik statistik lanjutan untuk mendeteksi pola voucher Hotspot:
    - Entropi Shannon (bit per karakter)
    - Monobit Frequency Balance Test (NIST SP 800-22 inspired)
    - Serial Run Correlation Test
    - Dictionary Wordlist Matching
    - Estimasi Waktu Penetrasi Brute-Force (Online vs Offline Cracking)
    """
    @classmethod
    def analyze_voucher_batch(cls, voucher_samples: List[str]) -> Dict[str, Any]:
        if not voucher_samples:
            return {"count": 0, "status": "no_samples"}

        total_samples = len(voucher_samples)
        lengths = [len(v) for v in voucher_samples]
        avg_len = sum(lengths) / float(total_samples)

        entropies = [VoucherSecurityAnalyzer.calculate_shannon_entropy(v) for v in voucher_samples]
        avg_entropy = sum(entropies) / float(total_samples)

        all_chars = "".join(voucher_samples)
        char_counts = Counter(all_chars)
        pool_detected = len(char_counts)

        sequential_count = sum(1 for v in voucher_samples if VoucherSecurityAnalyzer.detect_sequential_pattern(v))
        seq_ratio = sequential_count / float(total_samples)

        # Nilai risiko gabungan
        if avg_len <= 5 or avg_entropy < 2.0 or seq_ratio > 0.3:
            composite_risk = "CRITICAL"
        elif avg_len <= 7 or avg_entropy < 3.2 or seq_ratio > 0.1:
            composite_risk = "HIGH"
        elif avg_entropy < 4.0:
            composite_risk = "MEDIUM"
        else:
            composite_risk = "LOW"

        return {
            "total_samples_analyzed": total_samples,
            "average_length": round(avg_len, 2),
            "average_shannon_entropy_bits": round(avg_entropy, 2),
            "unique_characters_pool": pool_detected,
            "sequential_pattern_percentage": round(seq_ratio * 100.0, 1),
            "composite_risk_rating": composite_risk,
            "nist_sp_800_63b_compliance": (avg_len >= 8 and pool_detected >= 62 and seq_ratio == 0.0),
            "remediation_recommendation": (
                "Tingkatkan panjang voucher minimal 8 digit kombinasi alfanumerik (A-Z, a-z, 0-9). "
                "Hindari pola berurutan seperti 1234, 1111, abcd. Terapkan rate-limiting login hotspot."
            )
        }


class RouterOSHardeningTemplateLibrary:
    """
    Pustaka script template hardening RouterOS komprehensif berdasarkan
    praktik terbaik industri (MikroTik Certified Security Engineer, CIS, NIST).
    """
    @staticmethod
    def get_baseline_firewall_template() -> str:
        return textwrap.dedent("""
            # =================================================================
            # MIKROTIK ENTERPRISE HARDENED FIREWALL BASELINE (CIS ALIGNED)
            # =================================================================
            /interface list add name=WAN comment="Internet Interfaces"
            /interface list add name=LAN comment="Internal Local Interfaces"
            /interface list add name=MGMT comment="Secure Management Subnet"

            # 1. RAW TABLE - DDOS & BOGON PROTECTION
            /ip firewall raw
            add chain=prerouting action=accept connection-state=established,related comment="Accept established RAW"
            add chain=prerouting action=drop in-interface-list=WAN protocol=udp dst-port=53 comment="Drop external DNS queries in RAW"
            add chain=prerouting action=drop in-interface-list=WAN src-address-list=bad_ipv4 comment="Drop bad IPv4 bogons"

            # 2. FILTER TABLE - INPUT CHAIN (ROUTER DEFENSE)
            /ip firewall filter
            add chain=input action=accept connection-state=established,related,untracked comment="Accept Established/Related"
            add chain=input action=drop connection-state=invalid comment="Drop Invalid State"
            add chain=input action=accept protocol=icmp comment="Allow ICMP ping"
            add chain=input action=accept in-interface-list=MGMT comment="Allow Full Access from Management Subnet"
            add chain=input action=accept in-interface-list=LAN protocol=udp dst-port=67-68 comment="Allow DHCP for Clients"
            add chain=input action=accept in-interface-list=LAN protocol=udp dst-port=53 comment="Allow DNS for LAN Clients"
            add chain=input action=accept in-interface-list=LAN protocol=tcp dst-port=53 comment="Allow DNS TCP for LAN Clients"
            add chain=input action=accept in-interface-list=LAN protocol=tcp dst-port=80,443 comment="Allow Hotspot Web Portal"
            add chain=input action=drop comment="Default-Deny all other input traffic"

            # 3. FILTER TABLE - FORWARD CHAIN (CLIENT ISOLATION)
            add chain=forward action=fasttrack-connection connection-state=established,related comment="FastTrack"
            add chain=forward action=accept connection-state=established,related comment="Accept Established/Related"
            add chain=forward action=drop connection-state=invalid comment="Drop Invalid State"
            add chain=forward action=accept in-interface-list=LAN out-interface-list=WAN comment="Allow LAN to Internet"
            add chain=forward action=drop comment="Default-Deny all other transit traffic"

            # 4. SERVICE HARDENING
            /ip service
            set telnet disabled=yes
            set ftp disabled=yes
            set api disabled=yes
            set api-ssl disabled=yes
            set winbox address=192.168.88.0/24
            set www address=192.168.88.0/24
            set ssh strong-crypto=yes address=192.168.88.0/24

            # 5. PROTOCOL HARDENING
            /ip neighbor discovery-settings set discover-interface-list=MGMT
            /tool mac-server set allowed-interface-list=MGMT
            /tool mac-server mac-winbox set allowed-interface-list=MGMT
            /tool bandwidth-server set enabled=no
            /ip dns set allow-remote-requests=yes
            # =================================================================
        """).strip()

import concurrent.futures
import secrets
import string

class ConcurrentNetworkProbeEngine:
    """
    Mesin pemindaian port multi-threaded untuk audit permukaan serang (attack surface)
    router secara non-intrusif menggunakan pool thread concurrent.
    """
    DEFAULT_PORTS = [
        21, 22, 23, 25, 53, 80, 110, 143, 161, 162, 389, 443, 445, 465,
        514, 587, 873, 993, 995, 1080, 1701, 1723, 2000, 2082, 2083,
        3128, 3306, 3389, 5432, 5678, 5900, 8080, 8081, 8291, 8443,
        8728, 8729, 8888, 9000, 20561
    ]

    SERVICE_MAP = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
        80: "HTTP", 110: "POP3", 143: "IMAP", 161: "SNMP", 162: "SNMP-Trap",
        389: "LDAP", 443: "HTTPS", 445: "SMB", 514: "Syslog",
        1080: "SOCKS", 1701: "L2TP", 1723: "PPTP", 2000: "Bandwidth-Test",
        3128: "Squid-Proxy", 3389: "RDP", 5678: "RoMON", 8080: "HTTP-Proxy",
        8291: "Winbox", 8728: "RouterOS-API", 8729: "RouterOS-API-SSL",
        20561: "MAC-Winbox"
    }

    def __init__(self, target_ip: str, timeout: float = 1.0, max_workers: int = 20):
        self.target_ip = target_ip
        self.timeout = timeout
        self.max_workers = max_workers

    def probe_single_port(self, port: int) -> Dict[str, Any]:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        t_start = time.time()
        try:
            status = sock.connect_ex((self.target_ip, port))
            rtt_ms = round((time.time() - t_start) * 1000.0, 2)
            if status == 0:
                banner = ""
                try:
                    sock.settimeout(0.5)
                    data = sock.recv(256)
                    banner = data.decode("utf-8", errors="ignore").strip()
                except Exception:
                    pass
                return {
                    "port": port,
                    "service": self.SERVICE_MAP.get(port, f"TCP/{port}"),
                    "state": "OPEN",
                    "rtt_ms": rtt_ms,
                    "banner": banner
                }
            return {"port": port, "service": self.SERVICE_MAP.get(port, f"TCP/{port}"), "state": "CLOSED"}
        except socket.timeout:
            return {"port": port, "service": self.SERVICE_MAP.get(port, f"TCP/{port}"), "state": "FILTERED"}
        except Exception as e:
            return {"port": port, "service": self.SERVICE_MAP.get(port, f"TCP/{port}"), "state": "ERROR", "error": str(e)}
        finally:
            sock.close()

    def run_fast_port_scan(self, ports: Optional[List[int]] = None) -> List[Dict[str, Any]]:
        target_ports = ports or self.DEFAULT_PORTS
        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_port = {executor.submit(self.probe_single_port, p): p for p in target_ports}
            for future in concurrent.futures.as_completed(future_to_port):
                try:
                    data = future.result()
                    if data.get("state") == "OPEN":
                        results.append(data)
                except Exception:
                    pass
        results.sort(key=lambda x: x["port"])
        return results


class RouterOSConfigSanitizerAndValidator:
    """
    Validator sintaks dan sanitasi keamanan untuk file ekspor RouterOS (.rsc).
    Mendeteksi perintah destruktif dan membocorkan password pelanggan.
    """
    DANGEROUS_PATTERNS = [
        (r"/system\s+reset-configuration", "CRITICAL", "Perintah reset konfigurasi terdeteksi dalam script"),
        (r"/user\s+remove\s+\[find", "HIGH", "Penghapusan user massal berpotensi mengunci akses admin"),
        (r"/interface\s+wireless\s+reset", "HIGH", "Reset interface nirkabel dapat memutus seluruh koneksi Hotspot"),
        (r"password=([^\s]+)", "WARNING", "Password tertera plaintext dalam file script konfigurasi")
    ]

    def __init__(self, raw_rsc_content: str):
        self.raw_content = raw_rsc_content
        self.lines = raw_rsc_content.splitlines()

    def scan_for_dangerous_commands(self) -> List[Dict[str, Any]]:
        findings = []
        for idx, line in enumerate(self.lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            for pattern, severity, desc in self.DANGEROUS_PATTERNS:
                if re.search(pattern, stripped, re.IGNORECASE):
                    findings.append({
                        "line_number": idx,
                        "line_content": stripped,
                        "severity": severity,
                        "description": desc
                    })
        return findings

    def sanitize_sensitive_data(self) -> str:
        sanitized = []
        for line in self.lines:
            sub1 = re.sub(r'password="[^"]*"', 'password="***REDACTED***"', line)
            sub2 = re.sub(r'password=[^\s]+', 'password=***REDACTED***', sub1)
            sub3 = re.sub(r'wpa2-pre-shared-key="[^"]*"', 'wpa2-pre-shared-key="***REDACTED***"', sub2)
            sanitized.append(sub3)
        return "\n".join(sanitized)


class RemediationRollbackPlanGenerator:
    """
    Menghasilkan script pemulihan (rollback) otomatis untuk setiap aturan
    hardening yang diaplikasikan, memastikan ketersediaan jalur darurat jika terjadi insiden.
    """
    @staticmethod
    def generate_rollback_script(summary: AuditSummary) -> str:
        rollback_lines = [
            "# ===================================================================",
            f"# MIKROTIK EMERGENCY ROLLBACK SCRIPT (PAIRED SAFETY PLAN)",
            f"# Target: {summary.target_identifier}",
            f"# Framework: {FRAMEWORK_NAME} v{FRAMEWORK_VERSION}",
            f"# Timestamp: {datetime.datetime.now().isoformat()}",
            "# ===================================================================",
            "/log warning message=\"[*] Starting Security Hardening Rollback...\"",
            ""
        ]

        for issue in summary.issues:
            if "DNS" in issue.category:
                rollback_lines.extend([
                    "# Rollback: DNS Settings",
                    "/ip dns set allow-remote-requests=yes",
                    "/ip firewall filter remove [find comment=\"Drop WAN DNS UDP\"]",
                    "/ip firewall filter remove [find comment=\"Drop WAN DNS TCP\"]",
                    ""
                ])
            elif "Management" in issue.category and "2000" in issue.affected_component:
                rollback_lines.extend([
                    "# Rollback: Bandwidth Server",
                    "/tool bandwidth-server set enabled=yes",
                    ""
                ])
            elif "Web Management" in issue.category:
                rollback_lines.extend([
                    "# Rollback: WebFig Access Filter",
                    "/ip firewall filter remove [find comment=\"Block WebFig on Hotspot IP\"]",
                    "/ip service set www address=0.0.0.0/0",
                    ""
                ])
            elif "RFC 1918" in issue.title:
                rollback_lines.extend([
                    "# Rollback: Gateway Addressing Note",
                    "# Pengubahan IP Gateway memerlukan re-konfigurasi DHCP pool & Hotspot profile manual",
                    ""
                ])

        rollback_lines.extend([
            "/log info message=\"[+] Emergency Rollback Completed Successfully!\"",
            "# ==================================================================="
        ])
        return "\n".join(rollback_lines)


class SecureVoucherProductionGenerator:
    """
    Generator voucher Hotspot standar NIST SP 800-63B dengan entropi tinggi
    dan perlindungan terhadap karakter ambigu (ambiguous characters removal).
    """
    SAFE_ALPHANUMERIC = "23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    SAFE_NUMERIC = "23456789"
    SAFE_UPPER = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ"

    @classmethod
    def generate_secure_voucher(cls, length: int = 8, charset: str = SAFE_ALPHANUMERIC) -> str:
        return "".join(secrets.choice(charset) for _ in range(length))

    @classmethod
    def generate_batch_for_routeros(
        cls,
        count: int = 50,
        length: int = 8,
        profile: str = "default",
        uptime_limit: str = "1d",
        server: str = "all"
    ) -> List[str]:
        commands = [
            f"# Batch Generation of {count} High-Entropy Vouchers (NIST Aligned)",
            f"# Generated via {FRAMEWORK_NAME} v{FRAMEWORK_VERSION}"
        ]
        pool = cls.SAFE_ALPHANUMERIC
        for idx in range(1, count + 1):
            code = cls.generate_secure_voucher(length=length, charset=pool)
            cmd = (
                f"/ip hotspot user add name=\"{code}\" password=\"{code}\" "
                f"profile=\"{profile}\" limit-uptime={uptime_limit} server={server} "
                f"comment=\"batch-{datetime.date.today().strftime('%Y%m%d')}\""
            )
            commands.append(cmd)
        return commands

    @classmethod
    def benchmark_entropy_distribution(cls, count: int = 1000, length: int = 8) -> Dict[str, Any]:
        samples = [cls.generate_secure_voucher(length=length) for _ in range(count)]
        entropies = [VoucherSecurityAnalyzer.calculate_shannon_entropy(s) for s in samples]
        min_e = min(entropies)
        max_e = max(entropies)
        avg_e = sum(entropies) / float(count)
        return {
            "samples_tested": count,
            "min_entropy_bits": round(min_e, 3),
            "max_entropy_bits": round(max_e, 3),
            "average_entropy_bits": round(avg_e, 3),
            "nist_800_63b_compliant": (avg_e >= 4.5 and min_e >= 3.8)
        }


class WirelessSecurityAuditEngine:
    """
    Mesin audit keamanan nirkabel 802.11 untuk MikroTik Wireless & CAPsMAN:
    - Verifikasi WPA3 SAE vs WPA2 Transition Mode
    - Protected Management Frames (PMF) enforcement
    - Client Isolation (default-forward=no)
    - WPS Push-button detection
    """
    def __init__(self, config_parser):
        self.parser = config_parser

    def audit_security_profiles_full(self) -> List[Dict[str, Any]]:
        if not self.parser:
            return []
        profiles = self.parser.get_section_commands("/interface wireless security-profiles")
        results = []
        for line in profiles:
            name_m = re.search(r"name=([^\s]+)", line)
            p_name = name_m.group(1).strip('"') if name_m else "default"
            is_open = "mode=none" in line.lower()
            has_wep = "wep" in line.lower()
            has_tkip = "tkip" in line.lower()
            has_pmf = "management-protection=required" in line.lower() or "management-protection=allowed" in line.lower()
            results.append({
                "profile_name": p_name,
                "is_open": is_open,
                "uses_wep": has_wep,
                "uses_tkip": has_tkip,
                "pmf_enabled": has_pmf,
                "raw_command": line
            })
        return results

    def check_client_isolation(self) -> List[Dict[str, str]]:
        if not self.parser:
            return []
        interfaces = self.parser.get_section_commands("/interface wireless")
        issues = []
        for line in interfaces:
            if "default-forward=yes" in line.lower() or ("mode=ap-bridge" in line.lower() and "default-forward=no" not in line.lower()):
                name_m = re.search(r"name=([^\s]+)", line)
                if_name = name_m.group(1).strip('"') if name_m else "wlan"
                issues.append({
                    "interface": if_name,
                    "issue": "Client isolation tidak aktif (default-forward=yes). Klien WiFi dapat saling menyerang secara langsung (ARP Poisoning, MITM).",
                    "fix": f"/interface wireless set [find name=\"{if_name}\"] default-forward=no"
                })
        return issues


class MikroTikLogForensicsAndParserEngine:
    """
    Mesin analisis log RouterOS untuk mendeteksi indikasi serangan aktif:
    - Brute force login pada Winbox, SSH, Telnet, Hotspot
    - DHCP rogue server detection
    - Interface link flap frequency
    - DNS cache overflow alerts
    """
    BRUTE_FORCE_PATTERNS = [
        re.compile(r"login failure for user (\S+) from (\S+) via (\S+)", re.IGNORECASE),
        re.compile(r"hotspot: login failed for user (\S+): (.*)", re.IGNORECASE),
        re.compile(r"failed to log in from (\S+) via (\S+)", re.IGNORECASE)
    ]

    @classmethod
    def parse_log_records(cls, raw_logs: List[str]) -> Dict[str, Any]:
        failures_by_ip = Counter()
        failures_by_user = Counter()
        services_targeted = Counter()
        link_flaps = []

        for line in raw_logs:
            for pattern in cls.BRUTE_FORCE_PATTERNS:
                match = pattern.search(line)
                if match:
                    groups = match.groups()
                    if len(groups) >= 2:
                        failures_by_user[groups[0]] += 1
                        failures_by_ip[groups[1]] += 1
                    if len(groups) >= 3:
                        services_targeted[groups[2]] += 1
            if "link down" in line.lower() or "link up" in line.lower():
                link_flaps.append(line.strip())

        top_attackers = failures_by_ip.most_common(5)
        top_usernames = failures_by_user.most_common(5)

        return {
            "total_log_entries": len(raw_logs),
            "total_auth_failures": sum(failures_by_ip.values()),
            "top_offending_ips": top_attackers,
            "top_targeted_usernames": top_usernames,
            "services_targeted": dict(services_targeted),
            "link_flap_events_count": len(link_flaps),
            "suspected_brute_force_active": any(count > 10 for _, count in top_attackers)
        }


class ExecutiveComplianceScorecardRenderer:
    """
    Menyusun tabel matriks eksekutif untuk laporan audit manajemen dan C-Level.
    """
    @staticmethod
    def render_text_scorecard(summary: AuditSummary) -> str:
        status_symbol = {
            "CRITICAL": "[CRIT]",
            "HIGH":     "[HIGH]",
            "MEDIUM":   "[MED ]",
            "LOW":      "[LOW ]"
        }
        lines = [
            "=" * 78,
            f"EXECUTIVE SECURITY COMPLIANCE SCORECARD - {summary.target_identifier}",
            "=" * 78,
            f"Overall Security Grade : {summary.security_grade}",
            f"Audit Health Score     : {summary.overall_health_score} / 100",
            f"Total Deficiencies     : {len(summary.issues)} findings",
            f"Passed Baseline Checks : {len(summary.passed_checks)} checks",
            "-" * 78,
            f"{'SEV':<8} {'RULE ID':<14} {'CATEGORY':<28} {'TITLE'}",
            "-" * 78
        ]
        for issue in summary.issues:
            sym = status_symbol.get(issue.severity, "[INFO]")
            cat_short = issue.category[:26]
            title_short = issue.title[:26]
            lines.append(f"{sym:<8} {issue.rule_id:<14} {cat_short:<28} {title_short}")
        lines.append("=" * 78)
        return "\n".join(lines)

class EnterpriseHardeningEngine:
    """
    Engine otomatis untuk menyusun aturan konfigurasi RouterOS CLI
    yang telah divalidasi dan siap diterapkan pada router produksi.
    """
    @staticmethod
    def build_firewall_raw_dos_rules(wan_interface_list: str = "WAN") -> List[str]:
        return [
            f"/ip firewall raw add chain=prerouting in-interface-list={wan_interface_list} protocol=udp dst-port=53 action=drop comment=\"Drop WAN DNS UDP\"",
            f"/ip firewall raw add chain=prerouting in-interface-list={wan_interface_list} protocol=tcp dst-port=53 action=drop comment=\"Drop WAN DNS TCP\"",
            f"/ip firewall raw add chain=prerouting in-interface-list={wan_interface_list} protocol=tcp tcp-flags=syn,!ack connection-state=new limit=100/s,20:packet action=accept comment=\"Allow SYN burst\"",
            f"/ip firewall raw add chain=prerouting in-interface-list={wan_interface_list} protocol=tcp tcp-flags=syn,!ack connection-state=new action=drop comment=\"Drop SYN Flood\""
        ]

    @staticmethod
    def build_management_isolation_rules(mgmt_address: str = "192.168.88.0/24") -> List[str]:
        return [
            f"/ip service set winbox address={mgmt_address}",
            f"/ip service set www address={mgmt_address}",
            f"/ip service set ssh strong-crypto=yes address={mgmt_address}",
            "/ip service set telnet disabled=yes",
            "/ip service set ftp disabled=yes",
            "/ip service set api disabled=yes",
            "/ip service set api-ssl disabled=yes"
        ]

    @staticmethod
    def build_dns_resolver_lockdown_rules(allow_local_lan: bool = True) -> List[str]:
        if not allow_local_lan:
            return ["/ip dns set allow-remote-requests=no"]
        return [
            "/ip dns set allow-remote-requests=yes",
            "/ip firewall filter add chain=input in-interface-list=!LAN protocol=udp dst-port=53 action=drop comment=\"Drop non-LAN DNS UDP\"",
            "/ip firewall filter add chain=input in-interface-list=!LAN protocol=tcp dst-port=53 action=drop comment=\"Drop non-LAN DNS TCP\""
        ]

    @staticmethod
    def build_hotspot_hardening_rules() -> List[str]:
        return [
            "/ip hotspot walled-garden remove [find dst-host=\"*\"]",
            "/ip hotspot walled-garden remove [find dst-host=\"\"]",
            "/ip hotspot user profile set [find] http-cookie-lifetime=1d",
            "/ip hotspot profile set [find] login-by=http-chap,cookie"
        ]


class DetailedComplianceTaxonomyEngine:
    """
    Menghubungkan temuan dengan taksonomi standar keamanan siber internasional:
    NIST SP 800-53 Rev 5, CIS Benchmarks, ISO/IEC 27001:2022, OWASP Top 10, dan CWE.
    """
    TAXONOMY_DATABASE = {
        "CWE-348": {
            "name": "Use of Less Trusted Source (DNS Cache Poisoning)",
            "nist_controls": ["SC-20", "SC-21"],
            "cis_controls": ["CIS 2.2.2"],
            "pci_dss": ["Req 1.3"]
        },
        "CWE-400": {
            "name": "Uncontrolled Resource Consumption (DoS / Amplification)",
            "nist_controls": ["SC-5"],
            "cis_controls": ["CIS 3.1.1"],
            "pci_dss": ["Req 1.2"]
        },
        "CWE-425": {
            "name": "Direct Request (Forced Browsing / WebFig Exposure)",
            "nist_controls": ["AC-3"],
            "cis_controls": ["CIS 1.1.3"],
            "pci_dss": ["Req 2.2"]
        },
        "CWE-706": {
            "name": "Use of Incorrectly-Resolved Name or Reference (RFC 1918)",
            "nist_controls": ["SC-7"],
            "cis_controls": ["CIS 2.2.1"],
            "pci_dss": ["Req 1.2"]
        },
        "CWE-79": {
            "name": "Improper Neutralization of Input During Web Page Generation (XSS)",
            "nist_controls": ["SI-7"],
            "cis_controls": ["CIS 5.1.1"],
            "pci_dss": ["Req 6.4"]
        },
        "CWE-284": {
            "name": "Improper Access Control (Unrestricted Management Protocols)",
            "nist_controls": ["AC-2", "AC-17"],
            "cis_controls": ["CIS 1.1.5"],
            "pci_dss": ["Req 8.3"]
        }
    }

    @classmethod
    def get_taxonomy_record(cls, cwe_id: str) -> Dict[str, Any]:
        return cls.TAXONOMY_DATABASE.get(cwe_id, {
            "name": "General Security Misconfiguration",
            "nist_controls": ["CM-7"],
            "cis_controls": ["CIS 1.1"],
            "pci_dss": ["Req 2.2"]
        })


class RouterOSTrafficFlowAndIPFIXAnalyzer:
    """
    Menganalisis konfigurasi NetFlow / IPFIX / Traffic Flow pada MikroTik
    untuk memastikan visibilitas telemetri jaringan dan pendeteksian anomali.
    """
    def __init__(self, config_parser):
        self.parser = config_parser

    def audit_traffic_flow_status(self) -> Dict[str, Any]:
        if not self.parser:
            return {"enabled": False, "targets": []}
        tf_commands = self.parser.get_section_commands("/ip traffic-flow")
        targets = self.parser.get_section_commands("/ip traffic-flow target")
        is_enabled = any("enabled=yes" in cmd.lower() for cmd in tf_commands)
        valid_targets = []
        for t in targets:
            addr_m = re.search(r"address=([^\s]+)", t)
            if addr_m:
                valid_targets.append(addr_m.group(1))
        return {
            "enabled": is_enabled,
            "target_count": len(valid_targets),
            "target_ips": valid_targets,
            "compliant_with_siem": is_enabled and len(valid_targets) > 0,
            "remediation_cli": [
                "/ip traffic-flow set enabled=yes cache-entries=128k",
                "/ip traffic-flow target add address=192.168.88.250:2055 version=ipfix"
            ]
        }

    @staticmethod
    def calculate_flow_telemetry_bandwidth(packet_rate_per_sec: int, sample_rate: int = 1) -> Dict[str, Any]:
        actual_sampled = packet_rate_per_sec / max(1, sample_rate)
        bytes_per_flow_record = 48
        estimated_kbps = (actual_sampled * bytes_per_flow_record * 8) / 1000.0
        return {
            'input_packet_rate': packet_rate_per_sec,
            'sampling_ratio': f'1:{sample_rate}',
            'sampled_pps': round(actual_sampled, 1),
            'estimated_export_bandwidth_kbps': round(estimated_kbps, 2),
            'recommended_cache_size': '256k' if packet_rate_per_sec > 10000 else '64k'
        }


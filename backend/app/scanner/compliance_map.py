# app/scanner/compliance_map.py
"""
CWE → compliance framework mapping.

Source-attributed mappings from finding CWE IDs to controls in:
    - OWASP ASVS 4.0     (Application Security Verification Standard)
    - CIS Controls v8
    - NIST CSF v2.0      (Cybersecurity Framework)
    - PCI-DSS 4.0        (where directly applicable)
    - SOC 2              (Trust Services Criteria, indicative — auditor sign-off required)

Provenance per entry:
    relationship="direct"    The framework explicitly cites the CWE
                             or the mapping is documented by the
                             framework's maintainer.
    relationship="supports"  Mapping derived from a published
                             cross-walk (typically via NIST CSF). The
                             customer should confirm with their
                             auditor for compliance evidence.

Mappings are conservative on purpose: when no defensible mapping
exists for a (framework, CWE) pair we omit it rather than guess. This
catalogue is meant to be defensible against auditor scrutiny —
"we map findings to NIST CSF / OWASP ASVS / CIS Controls" is a
claim we can stand behind; "we map findings to SOC 2 CC6.1" is not,
and we mark such derived mappings clearly.

Maintenance:
    When adding a new CWE entry, cross-check against:
      - OWASP ASVS 4.0 CWE references in
        github.com/OWASP/ASVS/tree/master/4.0/en
      - NIST Cybersecurity Framework v2.0 informative references
        (csrc.nist.gov/Projects/cybersecurity-framework)
      - CIS Controls v8 mappings via
        cisecurity.org/controls/cis-controls-navigator
      - PCI-DSS 4.0 only where the mapping is unambiguous
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass(frozen=True)
class FrameworkRef:
    """A single framework mapping for a CWE.

    Attributes:
        framework:    Canonical key — used for filtering / aggregation.
        label:        Display label.
        controls:     Specific control IDs in that framework.
        relationship: "direct" if explicitly published by the
                      framework owner, "supports" if derived from a
                      cross-walk.
        citation:     Human-readable provenance shown in the UI.
    """
    framework: str
    label: str
    controls: List[str]
    relationship: str
    citation: str


# ─── Display labels per framework key ─────────────────────────────────────

FRAMEWORK_LABELS: Dict[str, str] = {
    "owasp_asvs":  "OWASP ASVS 4.0",
    "cis_v8":      "CIS Controls v8",
    "nist_csf":    "NIST CSF v2.0",
    "pci_dss_4":   "PCI-DSS 4.0",
    "soc2":        "SOC 2 (TSC 2017)",
    "iso_27001":   "ISO/IEC 27001:2022",
}


# Helper — keeps individual entries readable.
def _ref(framework: str, controls: List[str], relationship: str = "direct",
         citation: Optional[str] = None) -> FrameworkRef:
    return FrameworkRef(
        framework=framework,
        label=FRAMEWORK_LABELS.get(framework, framework),
        controls=controls,
        relationship=relationship,
        citation=citation or FRAMEWORK_LABELS.get(framework, framework),
    )


# ─── CWE → framework mappings ─────────────────────────────────────────────

CWE_COMPLIANCE_MAP: Dict[str, List[FrameworkRef]] = {

    # ── Authentication & access control ──
    # ISO 27001:2022 mappings come from the Annex A controls cross-referenced
    # via NIST CSF v2.0 informative references (PR.AA-* → A.5.15 / A.5.17 /
    # A.5.18 / A.8.2 / A.8.5).

    "CWE-284": [  # Improper Access Control (subdomain takeover, generic)
        _ref("owasp_asvs", ["1.4.1", "4.1.1"]),
        _ref("cis_v8", ["6.1", "6.8"]),
        _ref("nist_csf", ["PR.AA-01", "PR.AA-05"]),
        _ref("soc2", ["CC6.1"], "supports", "via NIST CSF cross-walk"),
        _ref("iso_27001", ["A.5.15", "A.5.18", "A.8.2"], "supports", "via NIST CSF cross-walk"),
    ],
    "CWE-285": [  # Improper Authorization
        _ref("owasp_asvs", ["4.1.1", "4.1.3"]),
        _ref("cis_v8", ["6.8"]),
        _ref("nist_csf", ["PR.AA-05"]),
        _ref("soc2", ["CC6.1", "CC6.3"], "supports", "via NIST CSF cross-walk"),
        _ref("iso_27001", ["A.5.15", "A.5.18"], "supports", "via NIST CSF cross-walk"),
    ],
    "CWE-287": [  # Improper Authentication
        _ref("owasp_asvs", ["2.1.1", "2.2.1"]),
        _ref("cis_v8", ["6.3", "6.5"]),
        _ref("nist_csf", ["PR.AA-01", "PR.AA-03"]),
        _ref("pci_dss_4", ["8.2.1"]),
        _ref("soc2", ["CC6.1"], "supports", "via NIST CSF cross-walk"),
        _ref("iso_27001", ["A.5.17", "A.8.5"], "supports", "via NIST CSF cross-walk"),
    ],
    "CWE-290": [  # Authentication Bypass by Spoofing (SPF/DMARC)
        _ref("owasp_asvs", ["2.5.4", "9.2.1"]),
        _ref("cis_v8", ["9.5"]),
        _ref("nist_csf", ["PR.DS-02", "PR.AA-03"]),
        _ref("iso_27001", ["A.8.5"], "supports", "via NIST CSF cross-walk"),
    ],
    "CWE-294": [  # Authentication Bypass by Capture-Replay
        _ref("owasp_asvs", ["3.2.1", "3.3.4"]),
        _ref("nist_csf", ["PR.AA-03"]),
        _ref("iso_27001", ["A.8.5"], "supports", "via NIST CSF cross-walk"),
    ],
    "CWE-306": [  # Missing Authentication for Critical Function
        _ref("owasp_asvs", ["1.4.1", "2.1.1"]),
        _ref("cis_v8", ["6.3", "6.5"]),
        _ref("nist_csf", ["PR.AA-01"]),
        _ref("pci_dss_4", ["8.2.1"]),
        _ref("iso_27001", ["A.5.17", "A.8.5"], "supports", "via NIST CSF cross-walk"),
    ],
    "CWE-269": [  # Improper Privilege Management
        _ref("owasp_asvs", ["4.1.5"]),
        _ref("cis_v8", ["6.8"]),
        _ref("nist_csf", ["PR.AA-05"]),
        _ref("iso_27001", ["A.5.15", "A.8.2"], "supports", "via NIST CSF cross-walk"),
    ],
    "CWE-732": [  # Incorrect Permission Assignment for Critical Resource
        _ref("owasp_asvs", ["4.1.3"]),
        _ref("cis_v8", ["3.3", "6.8"]),
        _ref("nist_csf", ["PR.AA-05", "PR.DS-01"]),
        _ref("iso_27001", ["A.5.15", "A.8.2"], "supports", "via NIST CSF cross-walk"),
    ],
    "CWE-1188": [  # Insecure Default Initialization (default creds, unhardened)
        _ref("owasp_asvs", ["1.14.1", "14.1.5"]),
        _ref("cis_v8", ["4.1", "4.2"]),
        _ref("nist_csf", ["PR.PS-01"]),
        _ref("pci_dss_4", ["2.2.1"]),
        _ref("iso_27001", ["A.8.9"], "supports", "via NIST CSF cross-walk"),
    ],

    # ── Cryptography & TLS ──
    # ISO Annex A.8.24 (Use of cryptography) for everything in this section.
    # A.5.14 (Information transfer) added for cleartext-transmission cases.

    "CWE-295": [  # Improper Certificate Validation
        _ref("owasp_asvs", ["9.2.4", "10.3.2"]),
        _ref("cis_v8", ["3.10"]),
        _ref("nist_csf", ["PR.DS-02"]),
        _ref("pci_dss_4", ["4.2.1"]),
        _ref("iso_27001", ["A.8.24"], "supports", "via NIST CSF cross-walk"),
    ],
    "CWE-297": [  # Improper Validation of Certificate with Host Mismatch
        _ref("owasp_asvs", ["9.2.4"]),
        _ref("cis_v8", ["3.10"]),
        _ref("nist_csf", ["PR.DS-02"]),
        _ref("pci_dss_4", ["4.2.1"]),
        _ref("iso_27001", ["A.8.24"], "supports", "via NIST CSF cross-walk"),
    ],
    "CWE-298": [  # Improper Validation of Certificate Expiration
        _ref("owasp_asvs", ["9.2.4"]),
        _ref("cis_v8", ["3.10"]),
        _ref("nist_csf", ["PR.DS-02"]),
        _ref("pci_dss_4", ["4.2.1"]),
        _ref("iso_27001", ["A.8.24"], "supports", "via NIST CSF cross-walk"),
    ],
    "CWE-319": [  # Cleartext Transmission of Sensitive Information
        _ref("owasp_asvs", ["9.1.1", "9.1.2"]),
        _ref("cis_v8", ["3.10"]),
        _ref("nist_csf", ["PR.DS-02"]),
        _ref("pci_dss_4", ["4.2.1"]),
        _ref("soc2", ["CC6.7"], "supports", "via NIST CSF cross-walk"),
        _ref("iso_27001", ["A.5.14", "A.8.24"], "supports", "via NIST CSF cross-walk"),
    ],
    "CWE-326": [  # Inadequate Encryption Strength
        _ref("owasp_asvs", ["6.2.3", "9.1.2"]),
        _ref("cis_v8", ["3.10", "3.11"]),
        _ref("nist_csf", ["PR.DS-02"]),
        _ref("pci_dss_4", ["4.2.1"]),
        _ref("soc2", ["CC6.7"], "supports", "via NIST CSF cross-walk"),
        _ref("iso_27001", ["A.8.24"], "supports", "via NIST CSF cross-walk"),
    ],
    "CWE-330": [  # Use of Insufficiently Random Values
        _ref("owasp_asvs", ["6.3.1", "6.3.2"]),
        _ref("nist_csf", ["PR.DS-02"]),
        _ref("iso_27001", ["A.8.24"], "supports", "via NIST CSF cross-walk"),
    ],
    "CWE-345": [  # Insufficient Verification of Data Authenticity (DKIM)
        _ref("owasp_asvs", ["10.3.2"]),
        _ref("nist_csf", ["PR.DS-06"]),
        _ref("iso_27001", ["A.8.24"], "supports", "via NIST CSF cross-walk"),
    ],
    "CWE-347": [  # Improper Verification of Cryptographic Signature (JWT)
        _ref("owasp_asvs", ["3.5.2", "3.5.3"]),
        _ref("nist_csf", ["PR.DS-06"]),
        _ref("iso_27001", ["A.8.24"], "supports", "via NIST CSF cross-walk"),
    ],

    # ── Injection ──
    # ISO Annex A.8.28 (Secure coding) and A.8.29 (Security testing in
    # development and acceptance) cover most injection categories.

    "CWE-77": [  # Command Injection (generic)
        _ref("owasp_asvs", ["5.3.4", "5.3.8"]),
        _ref("cis_v8", ["16.1", "16.10"]),
        _ref("nist_csf", ["PR.PS-06"]),
        _ref("pci_dss_4", ["6.2.4"]),
        _ref("iso_27001", ["A.8.28", "A.8.29"], "supports", "via NIST CSF cross-walk"),
    ],
    "CWE-78": [  # OS Command Injection
        _ref("owasp_asvs", ["5.3.4", "5.3.8"]),
        _ref("cis_v8", ["16.1", "16.10"]),
        _ref("nist_csf", ["PR.PS-06"]),
        _ref("pci_dss_4", ["6.2.4"]),
        _ref("iso_27001", ["A.8.28", "A.8.29"], "supports", "via NIST CSF cross-walk"),
    ],
    "CWE-79": [  # XSS
        _ref("owasp_asvs", ["5.3.3", "14.4.1", "14.4.6"]),
        _ref("cis_v8", ["16.10"]),
        _ref("nist_csf", ["PR.PS-06"]),
        _ref("pci_dss_4", ["6.2.4"]),
        _ref("iso_27001", ["A.8.28", "A.8.29"], "supports", "via NIST CSF cross-walk"),
    ],
    "CWE-89": [  # SQL Injection
        _ref("owasp_asvs", ["5.3.4"]),
        _ref("cis_v8", ["16.10"]),
        _ref("nist_csf", ["PR.PS-06"]),
        _ref("pci_dss_4", ["6.2.4"]),
        _ref("iso_27001", ["A.8.28", "A.8.29"], "supports", "via NIST CSF cross-walk"),
    ],
    "CWE-94": [  # Code Injection
        _ref("owasp_asvs", ["5.3.4"]),
        _ref("cis_v8", ["16.10"]),
        _ref("nist_csf", ["PR.PS-06"]),
        _ref("pci_dss_4", ["6.2.4"]),
        _ref("iso_27001", ["A.8.28", "A.8.29"], "supports", "via NIST CSF cross-walk"),
    ],
    "CWE-502": [  # Deserialization of Untrusted Data (Log4Shell, etc.)
        _ref("owasp_asvs", ["5.5.1", "5.5.3"]),
        _ref("cis_v8", ["16.10"]),
        _ref("nist_csf", ["PR.PS-06"]),
        _ref("iso_27001", ["A.8.28"], "supports", "via NIST CSF cross-walk"),
    ],
    "CWE-611": [  # XXE
        _ref("owasp_asvs", ["5.5.2"]),
        _ref("cis_v8", ["16.10"]),
        _ref("nist_csf", ["PR.PS-06"]),
        _ref("iso_27001", ["A.8.28"], "supports", "via NIST CSF cross-walk"),
    ],
    "CWE-915": [  # Improper Modification of Dynamically-Determined Object Attributes
        _ref("owasp_asvs", ["5.1.2"]),
        _ref("nist_csf", ["PR.PS-06"]),
        _ref("iso_27001", ["A.8.28"], "supports", "via NIST CSF cross-walk"),
    ],
    "CWE-917": [  # OGNL / EL injection
        _ref("owasp_asvs", ["5.3.4"]),
        _ref("nist_csf", ["PR.PS-06"]),
        _ref("iso_27001", ["A.8.28"], "supports", "via NIST CSF cross-walk"),
    ],
    "CWE-918": [  # SSRF
        _ref("owasp_asvs", ["13.4.1", "13.4.2"]),
        _ref("cis_v8", ["16.1", "16.11"]),
        _ref("nist_csf", ["PR.IR-01"]),
        _ref("iso_27001", ["A.8.20", "A.8.21"], "supports", "via NIST CSF cross-walk"),
    ],
    "CWE-1336": [  # Server-Side Template Injection
        _ref("owasp_asvs", ["5.2.5"]),
        _ref("nist_csf", ["PR.PS-06"]),
        _ref("iso_27001", ["A.8.28"], "supports", "via NIST CSF cross-walk"),
    ],

    # ── Path traversal & file handling ──

    "CWE-22": [  # Path Traversal
        _ref("owasp_asvs", ["12.3.1", "12.3.5"]),
        _ref("cis_v8", ["16.10"]),
        _ref("nist_csf", ["PR.PS-06"]),
        _ref("iso_27001", ["A.8.28", "A.8.29"], "supports", "via NIST CSF cross-walk"),
    ],
    "CWE-552": [  # Files or Directories Accessible to External Parties
        _ref("owasp_asvs", ["8.1.1", "12.5.1"]),
        _ref("cis_v8", ["3.3"]),
        _ref("nist_csf", ["PR.DS-01", "PR.AA-05"]),
        _ref("pci_dss_4", ["3.5.1"]),
        _ref("iso_27001", ["A.5.10", "A.8.10"], "supports", "via NIST CSF cross-walk"),
    ],
    "CWE-548": [  # Exposure of Information Through Directory Listing
        _ref("owasp_asvs", ["14.3.1"]),
        _ref("cis_v8", ["4.1"]),
        _ref("nist_csf", ["PR.DS-01"]),
        _ref("iso_27001", ["A.5.10"], "supports", "via NIST CSF cross-walk"),
    ],
    "CWE-538": [  # Insertion of Sensitive Information into Externally-Accessible File
        _ref("owasp_asvs", ["14.3.1"]),
        _ref("cis_v8", ["3.3", "4.1"]),
        _ref("nist_csf", ["PR.DS-01"]),
        _ref("iso_27001", ["A.5.10", "A.8.10"], "supports", "via NIST CSF cross-walk"),
    ],

    # ── Information exposure ──
    # ISO Annex A.8.10 (Information deletion) for response/error leaks.
    # A.5.34 (Privacy and protection of PII) added on the most generic
    # information-exposure CWE because PII often surfaces there.

    "CWE-200": [  # Exposure of Sensitive Information (very common, kept generic)
        _ref("owasp_asvs", ["8.1.1", "14.3.2"]),
        _ref("cis_v8", ["3.3", "3.6"]),
        _ref("nist_csf", ["PR.DS-01"]),
        _ref("pci_dss_4", ["3.5.1"]),
        _ref("soc2", ["CC6.1"], "supports", "via NIST CSF cross-walk"),
        _ref("iso_27001", ["A.5.34", "A.8.10"], "supports", "via NIST CSF cross-walk"),
    ],
    "CWE-209": [  # Generation of Error Message Containing Sensitive Information
        _ref("owasp_asvs", ["7.4.1"]),
        _ref("cis_v8", ["16.10"]),
        _ref("nist_csf", ["PR.DS-01"]),
        _ref("iso_27001", ["A.8.10"], "supports", "via NIST CSF cross-walk"),
    ],
    "CWE-215": [  # Insertion of Sensitive Information Into Debugging Code
        _ref("owasp_asvs", ["7.4.1", "14.3.2"]),
        _ref("cis_v8", ["16.10"]),
        _ref("nist_csf", ["PR.DS-01"]),
        _ref("iso_27001", ["A.8.10"], "supports", "via NIST CSF cross-walk"),
    ],
    "CWE-598": [  # Use of GET Request Method With Sensitive Query Strings
        _ref("owasp_asvs", ["8.3.1"]),
        _ref("nist_csf", ["PR.DS-02"]),
        _ref("iso_27001", ["A.8.24"], "supports", "via NIST CSF cross-walk"),
    ],

    # ── Credentials ──

    "CWE-522": [  # Insufficiently Protected Credentials
        _ref("owasp_asvs", ["2.10.1", "2.10.4"]),
        _ref("cis_v8", ["6.3", "6.5"]),
        _ref("nist_csf", ["PR.AA-01"]),
        _ref("pci_dss_4", ["8.3.1"]),
        _ref("iso_27001", ["A.5.17", "A.8.24"], "supports", "via NIST CSF cross-walk"),
    ],
    "CWE-614": [  # Sensitive Cookie Without Secure Flag
        _ref("owasp_asvs", ["3.4.1"]),
        _ref("cis_v8", ["3.10"]),
        _ref("nist_csf", ["PR.DS-02"]),
        _ref("iso_27001", ["A.8.24"], "supports", "via NIST CSF cross-walk"),
    ],
    "CWE-640": [  # Weak Password Recovery Mechanism (GitLab account takeover)
        _ref("owasp_asvs", ["2.5.4"]),
        _ref("cis_v8", ["6.3"]),
        _ref("nist_csf", ["PR.AA-01"]),
        _ref("iso_27001", ["A.5.17", "A.8.5"], "supports", "via NIST CSF cross-walk"),
    ],
    "CWE-798": [  # Use of Hard-coded Credentials
        _ref("owasp_asvs", ["10.2.1"]),
        _ref("cis_v8", ["16.4"]),
        _ref("nist_csf", ["PR.AA-01"]),
        _ref("pci_dss_4", ["8.3.2"]),
        _ref("iso_27001", ["A.5.17", "A.8.28"], "supports", "via NIST CSF cross-walk"),
    ],
    "CWE-1004": [  # Cookie Without HttpOnly Flag
        _ref("owasp_asvs", ["3.4.2"]),
        _ref("nist_csf", ["PR.DS-01"]),
        _ref("iso_27001", ["A.8.24"], "supports", "via NIST CSF cross-walk"),
    ],
    "CWE-1275": [  # Sensitive Cookie Without SameSite
        _ref("owasp_asvs", ["3.4.3"]),
        _ref("nist_csf", ["PR.PS-06"]),
        _ref("iso_27001", ["A.8.28"], "supports", "via NIST CSF cross-walk"),
    ],

    # ── Network / configuration ──
    # ISO Annex A.8.9 (Configuration management) for hardening misses,
    # A.8.20 (Networks security) for network exposure.

    "CWE-16": [  # Configuration (catch-all)
        _ref("cis_v8", ["4.1"]),
        _ref("nist_csf", ["PR.PS-01"]),
        _ref("iso_27001", ["A.8.9"], "supports", "via NIST CSF cross-walk"),
    ],
    "CWE-444": [  # HTTP Request/Response Smuggling
        _ref("owasp_asvs", ["13.2.5"]),
        _ref("nist_csf", ["PR.IR-01"]),
        _ref("iso_27001", ["A.8.20"], "supports", "via NIST CSF cross-walk"),
    ],
    "CWE-501": [  # Trust Boundary Violation
        _ref("owasp_asvs", ["1.4.5"]),
        _ref("nist_csf", ["PR.AA-05"]),
        _ref("iso_27001", ["A.8.28"], "supports", "via NIST CSF cross-walk"),
    ],
    "CWE-525": [  # Use of Web Browser Cache Containing Sensitive Information
        _ref("owasp_asvs", ["8.2.1"]),
        _ref("nist_csf", ["PR.DS-01"]),
        _ref("iso_27001", ["A.8.10"], "supports", "via NIST CSF cross-walk"),
    ],
    "CWE-601": [  # URL Redirection to Untrusted Site (Open Redirect)
        _ref("owasp_asvs", ["5.1.5"]),
        _ref("cis_v8", ["16.11"]),
        _ref("nist_csf", ["PR.PS-06"]),
        _ref("iso_27001", ["A.8.28"], "supports", "via NIST CSF cross-walk"),
    ],
    "CWE-644": [  # Improper Header Validation (host header injection)
        _ref("owasp_asvs", ["13.1.4"]),
        _ref("nist_csf", ["PR.PS-06"]),
        _ref("iso_27001", ["A.8.28"], "supports", "via NIST CSF cross-walk"),
    ],
    "CWE-693": [  # Protection Mechanism Failure (TRACE, etc.)
        _ref("cis_v8", ["4.1"]),
        _ref("nist_csf", ["PR.PS-01"]),
        _ref("iso_27001", ["A.8.9"], "supports", "via NIST CSF cross-walk"),
    ],
    "CWE-942": [  # Permissive Cross-domain Policy with Untrusted Domains (CORS)
        _ref("owasp_asvs", ["14.5.3"]),
        _ref("nist_csf", ["PR.PS-06"]),
        _ref("iso_27001", ["A.8.28"], "supports", "via NIST CSF cross-walk"),
    ],
    "CWE-1021": [  # Improper Restriction of Rendered UI Layers (clickjacking)
        _ref("owasp_asvs", ["14.4.7"]),
        _ref("nist_csf", ["PR.PS-06"]),
        _ref("iso_27001", ["A.8.28"], "supports", "via NIST CSF cross-walk"),
    ],
    "CWE-1022": [  # Use of Web Link to Untrusted Target with window.opener
        _ref("owasp_asvs", ["14.4.6"]),
        _ref("nist_csf", ["PR.PS-06"]),
        _ref("iso_27001", ["A.8.28"], "supports", "via NIST CSF cross-walk"),
    ],
    "CWE-1327": [  # Binding to an Unrestricted IP Address
        _ref("cis_v8", ["4.1", "4.4", "12.1"]),
        _ref("nist_csf", ["PR.IR-01"]),
        _ref("pci_dss_4", ["1.2.1"]),
        _ref("iso_27001", ["A.8.20"], "supports", "via NIST CSF cross-walk"),
    ],

    # ── Memory safety (CVE-driven) ──
    # ISO Annex A.8.8 (Management of technical vulnerabilities) for
    # memory-corruption CVEs.

    "CWE-119": [  # Improper Restriction of Operations within Memory Buffer
        _ref("owasp_asvs", ["1.4.5"]),
        _ref("cis_v8", ["7.7"]),
        _ref("nist_csf", ["ID.RA-01", "PR.PS-02"]),
        _ref("iso_27001", ["A.8.8"], "supports", "via NIST CSF cross-walk"),
    ],
    "CWE-416": [  # Use After Free
        _ref("cis_v8", ["7.7"]),
        _ref("nist_csf", ["ID.RA-01", "PR.PS-02"]),
        _ref("iso_27001", ["A.8.8"], "supports", "via NIST CSF cross-walk"),
    ],
    "CWE-787": [  # Out-of-bounds Write
        _ref("cis_v8", ["7.7"]),
        _ref("nist_csf", ["ID.RA-01", "PR.PS-02"]),
        _ref("iso_27001", ["A.8.8"], "supports", "via NIST CSF cross-walk"),
    ],
    "CWE-134": [  # Format String
        _ref("owasp_asvs", ["5.3.5"]),
        _ref("nist_csf", ["PR.PS-06"]),
        _ref("iso_27001", ["A.8.28"], "supports", "via NIST CSF cross-walk"),
    ],

    # ── Logging & monitoring ──
    # ISO Annex A.8.15 (Logging) and A.8.16 (Monitoring activities).

    "CWE-778": [  # Insufficient Logging (DMARC no rua)
        _ref("owasp_asvs", ["7.1.1"]),
        _ref("cis_v8", ["8.1", "8.5"]),
        _ref("nist_csf", ["DE.CM-01"]),
        _ref("pci_dss_4", ["10.2.1"]),
        _ref("iso_27001", ["A.8.15", "A.8.16"], "supports", "via NIST CSF cross-walk"),
    ],

    # ── Resource & rate ──

    "CWE-406": [  # Insufficient Control of Network Message Volume (amplification)
        _ref("nist_csf", ["PR.IR-01"]),
        _ref("cis_v8", ["13.7"]),
        _ref("iso_27001", ["A.8.20"], "supports", "via NIST CSF cross-walk"),
    ],
    "CWE-674": [  # Uncontrolled Recursion
        _ref("owasp_asvs", ["1.11.2"]),
        _ref("nist_csf", ["PR.PS-06"]),
        _ref("iso_27001", ["A.8.28"], "supports", "via NIST CSF cross-walk"),
    ],
    "CWE-770": [  # Allocation of Resources Without Limits or Throttling
        _ref("owasp_asvs", ["11.1.4"]),
        _ref("cis_v8", ["13.7"]),
        _ref("nist_csf", ["PR.IR-01"]),
        _ref("iso_27001", ["A.8.20"], "supports", "via NIST CSF cross-walk"),
    ],

    # ── Component / supply chain ──
    # ISO Annex A.8.7 (Protection against malware) for embedded malicious
    # code. A.8.8 for vulnerable / EOL components.

    "CWE-506": [  # Embedded Malicious Code (XZ backdoor)
        _ref("owasp_asvs", ["14.2.4"]),
        _ref("cis_v8", ["16.4", "16.11"]),
        _ref("nist_csf", ["ID.RA-09", "PR.PS-02"]),
        _ref("iso_27001", ["A.8.7", "A.8.8"], "supports", "via NIST CSF cross-walk"),
    ],
    "CWE-1104": [  # Use of Unmaintained Third Party Components (EOL software)
        _ref("owasp_asvs", ["14.2.1"]),
        _ref("cis_v8", ["7.1", "7.2"]),
        _ref("nist_csf", ["ID.RA-01", "ID.IM-04"]),
        _ref("pci_dss_4", ["6.3.3"]),
        _ref("iso_27001", ["A.8.8"], "supports", "via NIST CSF cross-walk"),
    ],
    "CWE-1395": [  # Dependency on Vulnerable Third-Party Component (generic CVE)
        _ref("owasp_asvs", ["14.2.1", "14.2.4"]),
        _ref("cis_v8", ["7.1", "7.4", "16.4"]),
        _ref("nist_csf", ["ID.RA-01", "ID.RA-09"]),
        _ref("pci_dss_4", ["6.3.3"]),
        _ref("iso_27001", ["A.8.8"], "supports", "via NIST CSF cross-walk"),
    ],

    # ── Misc ──

    "CWE-754": [  # Improper Check for Unusual or Exceptional Conditions (SPF lookups)
        _ref("nist_csf", ["PR.PS-06"]),
        _ref("iso_27001", ["A.8.28"], "supports", "via NIST CSF cross-walk"),
    ],
}


# ─── Category fallback for findings without a CWE ─────────────────────────
# These provide a baseline mapping when a finding has no CWE attached
# (rare — most curated templates carry one, but Nuclei uncategorized
# findings sometimes don't). Mappings here are intentionally generic.

CATEGORY_FALLBACK: Dict[str, List[FrameworkRef]] = {
    "ssl": [
        _ref("nist_csf", ["PR.DS-02"]),
        _ref("cis_v8", ["3.10"]),
        _ref("iso_27001", ["A.8.24"], "supports", "via NIST CSF cross-walk"),
    ],
    "headers": [
        _ref("owasp_asvs", ["14.4.1"]),
        _ref("nist_csf", ["PR.PS-06"]),
        _ref("iso_27001", ["A.8.28"], "supports", "via NIST CSF cross-walk"),
    ],
    "dns": [
        _ref("nist_csf", ["PR.DS-02", "PR.AA-03"]),
        _ref("iso_27001", ["A.8.5", "A.8.24"], "supports", "via NIST CSF cross-walk"),
    ],
    "ports": [
        _ref("cis_v8", ["4.1", "4.4"]),
        _ref("nist_csf", ["PR.IR-01"]),
        _ref("iso_27001", ["A.8.9", "A.8.20"], "supports", "via NIST CSF cross-walk"),
    ],
    "cve": [
        _ref("nist_csf", ["ID.RA-01"]),
        _ref("cis_v8", ["7.1", "7.4"]),
        _ref("iso_27001", ["A.8.8"], "supports", "via NIST CSF cross-walk"),
    ],
    "leak": [
        _ref("owasp_asvs", ["8.1.1"]),
        _ref("nist_csf", ["PR.DS-01"]),
        _ref("iso_27001", ["A.5.10", "A.8.10"], "supports", "via NIST CSF cross-walk"),
    ],
    "cloud": [
        _ref("cis_v8", ["3.3", "4.1"]),
        _ref("nist_csf", ["PR.DS-01", "PR.AA-05"]),
        _ref("iso_27001", ["A.5.10", "A.5.23"], "supports", "via NIST CSF cross-walk"),
    ],
    "exposure": [
        _ref("nist_csf", ["PR.IR-01"]),
        _ref("cis_v8", ["4.1"]),
        _ref("iso_27001", ["A.8.9", "A.8.20"], "supports", "via NIST CSF cross-walk"),
    ],
    "misconfiguration": [
        _ref("cis_v8", ["4.1"]),
        _ref("nist_csf", ["PR.PS-01"]),
        _ref("iso_27001", ["A.8.9"], "supports", "via NIST CSF cross-walk"),
    ],
}


# ─── Public API ───────────────────────────────────────────────────────────

def get_compliance_mappings(
    cwe: Optional[str],
    category: Optional[str] = None,
) -> List[Dict[str, object]]:
    """Return compliance mappings as JSON-serialisable dicts.

    Lookup order:
      1. Exact CWE match
      2. Category fallback if no CWE entry exists
      3. Empty list

    Args:
        cwe: e.g., "CWE-326". Tolerates None.
        category: e.g., "ssl". Used only when cwe lookup misses.

    Returns:
        List of dicts in the shape:
        [
          {
            "framework": "owasp_asvs",
            "label": "OWASP ASVS 4.0",
            "controls": ["9.1.1", "9.1.2"],
            "relationship": "direct",
            "citation": "OWASP ASVS 4.0",
          },
          ...
        ]
    """
    refs: List[FrameworkRef] = []

    if cwe and cwe in CWE_COMPLIANCE_MAP:
        refs = CWE_COMPLIANCE_MAP[cwe]
    elif category:
        cat = category.lower()
        if cat in CATEGORY_FALLBACK:
            refs = CATEGORY_FALLBACK[cat]

    return [
        {
            "framework": r.framework,
            "label": r.label,
            "controls": list(r.controls),
            "relationship": r.relationship,
            "citation": r.citation,
        }
        for r in refs
    ]


def get_frameworks_for_filter() -> List[Dict[str, str]]:
    """Return the list of framework keys + labels for UI filter dropdowns.

    Order is the same as FRAMEWORK_LABELS (dict-insertion order).
    """
    return [
        {"key": key, "label": label}
        for key, label in FRAMEWORK_LABELS.items()
    ]


def get_cwes_for_framework(framework: str) -> List[str]:
    """Return every CWE that has at least one mapping to the given framework.

    Used by the findings list API to filter results to a specific
    framework via SQL `Finding.cwe IN (...)`. The match is across both
    "direct" and "supports" relationships — the UI surfaces the
    distinction, but a customer asking "which findings affect SOC 2?"
    expects both.
    """
    out: List[str] = []
    for cwe, refs in CWE_COMPLIANCE_MAP.items():
        if any(r.framework == framework for r in refs):
            out.append(cwe)
    return out


def get_categories_for_framework(framework: str) -> List[str]:
    """Return every category whose fallback maps to this framework.

    Used together with get_cwes_for_framework for findings that don't
    have a CWE — they fall through to category-level mappings.
    """
    out: List[str] = []
    for cat, refs in CATEGORY_FALLBACK.items():
        if any(r.framework == framework for r in refs):
            out.append(cat)
    return out

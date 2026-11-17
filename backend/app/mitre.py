"""A small ATT&CK reference, just enough to lay the detection rules out by tactic.

This is deliberately not the whole matrix. It holds the techniques the shipped rules are tagged with,
plus a hand-picked set of techniques that are detectable from SSH, web and firewall logs and that the
rules do not cover yet, so the coverage view can show where the next rule would go. A rule tagged with
an id that is not listed here still appears, under "Unmapped"; a test keeps the shipped rules honest.
"""

TACTICS: list[tuple[str, str]] = [
    ("TA0043", "Reconnaissance"),
    ("TA0042", "Resource Development"),
    ("TA0001", "Initial Access"),
    ("TA0002", "Execution"),
    ("TA0003", "Persistence"),
    ("TA0004", "Privilege Escalation"),
    ("TA0005", "Defense Evasion"),
    ("TA0006", "Credential Access"),
    ("TA0007", "Discovery"),
    ("TA0008", "Lateral Movement"),
    ("TA0009", "Collection"),
    ("TA0011", "Command and Control"),
    ("TA0010", "Exfiltration"),
    ("TA0040", "Impact"),
]

_VALID_ACCOUNT_TACTICS = ["TA0001", "TA0003", "TA0004", "TA0005"]

# id -> (name, tactic ids). Sub-techniques are named "Parent: Child", as ATT&CK itself writes them.
TECHNIQUES: dict[str, tuple[str, list[str]]] = {
    "T1595": ("Active Scanning", ["TA0043"]),
    "T1595.002": ("Active Scanning: Vulnerability Scanning", ["TA0043"]),
    "T1595.003": ("Active Scanning: Wordlist Scanning", ["TA0043"]),
    "T1190": ("Exploit Public-Facing Application", ["TA0001"]),
    "T1078": ("Valid Accounts", _VALID_ACCOUNT_TACTICS),
    "T1078.003": ("Valid Accounts: Local Accounts", _VALID_ACCOUNT_TACTICS),
    "T1548.003": ("Abuse Elevation Control Mechanism: Sudo and Sudo Caching", ["TA0004", "TA0005"]),
    "T1110": ("Brute Force", ["TA0006"]),
    "T1110.001": ("Brute Force: Password Guessing", ["TA0006"]),
    "T1110.003": ("Brute Force: Password Spraying", ["TA0006"]),
    "T1046": ("Network Service Discovery", ["TA0007"]),
    "T1083": ("File and Directory Discovery", ["TA0007"]),
    # Not covered by a shipped rule yet, but visible in the logs this project reads.
    "T1087": ("Account Discovery", ["TA0007"]),
    "T1136": ("Create Account", ["TA0003"]),
    "T1098": ("Account Manipulation", ["TA0003"]),
    "T1059.004": ("Command and Scripting Interpreter: Unix Shell", ["TA0002"]),
    "T1021.004": ("Remote Services: SSH", ["TA0008"]),
    "T1070.002": ("Indicator Removal: Clear Linux or Mac System Logs", ["TA0005"]),
    "T1105": ("Ingress Tool Transfer", ["TA0011"]),
    "T1071.001": ("Application Layer Protocol: Web Protocols", ["TA0011"]),
    "T1048": ("Exfiltration Over Alternative Protocol", ["TA0010"]),
    "T1499": ("Endpoint Denial of Service", ["TA0040"]),
}

SUGGESTED: frozenset[str] = frozenset(
    {"T1087", "T1136", "T1098", "T1059.004", "T1021.004", "T1070.002", "T1105", "T1071.001", "T1048", "T1499"}
)

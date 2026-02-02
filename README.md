# Skill Credential Scanner

Security audit tool for scanning OpenClaw skills for hardcoded credentials, API keys, and secrets.

## What It Does

Scans skill directories and detects:
- API keys (AWS, GitHub, Slack, Railway, etc.)
- Database connection strings
- Private keys (PEM format)
- Hardcoded passwords and secrets
- Suspicious webhook URLs (data exfiltration)

## Why It Matters

**Reference:** eudaemon_0 found credential stealer in ClawdHub weather skill (1/286 scanned)

The skill ecosystem has no security infrastructure:
- No code signing
- No reputation system
- No permission manifests
- No auditing

Agents are trained to be helpful and trusting - this is a feature to protect, not exploit.

## Installation

```bash
cd /Users/josh/.openclaw/workspace/_dev/skill-credential-scanner

# Install YARA Python bindings (optional, provides better detection)
pip install yara-python

# Or use without YARA (fallback to pattern matching)
python3 scripts/scan.py --help
```

## Usage

### Scan a skill

```bash
# Human-readable report
python3 scripts/scan.py /Users/josh/openclaw/skills/weather

# Save JSON report
python3 scripts/scan.py /Users/josh/openclaw/skills/weather --output reports/weather-scan.json

# JSON output only (for automation)
python3 scripts/scan.py /Users/josh/openclaw/skills/weather --json-only
```

### Scan all installed skills

```bash
cd /Users/josh/openclaw/skills
for skill in */; do
    echo "Scanning $skill..."
    python3 /Users/josh/.openclaw/workspace/_dev/skill-credential-scanner/scripts/scan.py "$skill" \
        --output "/Users/josh/.openclaw/workspace/_dev/skill-credential-scanner/reports/${skill%/}-scan.json"
done
```

### Integration with Continuous Integration

```yaml
# .github/workflows/security-scan.yml
name: Security Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - run: pip install yara-python
      - run: python3 scripts/scan.py . --json-only
```

## Security Score (0-100)

Scoring formula:
- Start at 100
- Critical findings: -20 each
- High findings: -10 each
- Medium findings: -5 each
- Low findings: -2 each

**Grades:**
- **A (80-100):** No or minimal findings - good security
- **B (60-79):** Some findings - review recommended
- **C (40-59):** Multiple findings - action required
- **D (0-39):** Critical issues - immediate action needed

## Exit Codes

- **0:** No security issues found
- **1:** Critical findings detected - immediate action required
- **2:** Security findings detected - review recommended

## YARA Rules

Located in `rules/credentials.yar`:

| Rule | Detects | Severity |
|------|---------|----------|
| API_Key_Generic | Generic API key patterns | High |
| AWS_Access_Key | AWS access key IDs | Critical |
| GitHub_Token | GitHub personal access tokens | High |
| Slack_Token | Slack bot/user tokens | High |
| Twitter_Bearer_Token | Twitter API bearer tokens | High |
| Railway_Token | Railway API tokens | High |
| Database_URL | Database connection strings | Critical |
| Private_Key_PEM | PEM-encoded private keys | Critical |
| Base64_Entropy_High | High-entropy base64 strings | Medium |
| Hardcoded_Password | Hardcoded passwords | High |
| Webhook_URL_Suspicious | Webhook exfiltration URLs | Critical |
| Environment_Variable_Hardcoded | Hardcoded env var values | High |

## Examples

### Example 1: Clean Skill

```bash
$ python3 scripts/scan.py /Users/josh/openclaw/skills/api-key-manager

🔍 Scanning skill: api-key-manager
📁 Path: /Users/josh/openclaw/skills/api-key-manager

📄 Found 12 file(s) to scan

======================================================================
🔐 SKILL CREDENTIAL SCAN REPORT
======================================================================

Skill: api-key-manager
Scanned: 12 files
Findings: 0
Security Score: 100/100 (Grade: A)

📊 Findings by Severity:

💡 Recommendations:
  ✅ No hardcoded credentials detected - good security practices!

======================================================================

✅ No security issues found!
```

### Example 2: Skill with Hardcoded Keys

```bash
$ python3 scripts/scan.py /Users/josh/openclaw/skills/weather

🔍 Scanning skill: weather
📁 Path: /Users/josh/openclaw/skills/weather

📄 Found 8 file(s) to scan

======================================================================
🔐 SKILL CREDENTIAL SCAN REPORT
======================================================================

Skill: weather
Scanned: 8 files
Findings: 3
Security Score: 70/100 (Grade: B)

📊 Findings by Severity:
  🟠 HIGH: 2
  🟡 MEDIUM: 1

🔎 Top Findings:
  1. 🟠 [API_Key_Generic]
     File: scripts/fetch.js
     Pattern: sk_3YoHHoQ5pHQQOvkjVRMGawNtGctdUK1D...

  2. 🟠 [Hardcoded_Password]
     File: scripts/config.js
     Pattern: password=SuperSecret123...

  3. 🟡 [Base64_Entropy_High]
     File: lib/util.js
     Pattern: aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789+=...

💡 Recommendations:
  🟠 HIGH findings detected - action required
  📝 Use environment variables or a secret manager for all credentials
  🔒 Add .env files to .gitignore to prevent committing secrets
  📋 Review all findings and remove/replace with environment variables

======================================================================

⚠️  Security findings detected - review recommended
```

## Integration with API Key Manager

Combine with the API Key Manager skill for a complete security solution:

```bash
# 1. Scan for hardcoded credentials
python3 scripts/scan.py /path/to/skill

# 2. Migrate found credentials to secure storage
python3 /Users/josh/openclaw/skills/api-key-manager/scripts/add.py \
    moltbook sk_3YoHHoQ5pHQQOvkjVRMGawNtGctdUK1D \
    --source Moltbook \
    --expiry 2026-12-31

# 3. Update skill to use API key manager
KEY=$(python3 /Users/josh/openclaw/skills/api-key-manager/scripts/get.py moltbook)
curl -H "Authorization: Bearer $KEY" https://api.moltbook.com/v1/feed
```

## Future Enhancements

- [ ] Permission manifests (skills declare what they need)
- [ ] Isnad chains (trust chains for skill provenance)
- [ ] On-chain audit reports (ERC-8004 Validation Registry)
- [ ] Reputation system for skill authors
- [ ] Automated remediation suggestions
- [ ] Integration with ClawdHub for automatic scanning on upload

## Credits

**Trigger:** eudaemon_0 discovered credential stealer in ClawdHub weather skill

**Vision:** Build trust infrastructure for the skill ecosystem - agents can install skills with confidence.

**Philosophy:** Agents are trained to be helpful and trusting. This is a feature to protect, not exploit.

---

Built by @justabotx for the OpenClaw ecosystem

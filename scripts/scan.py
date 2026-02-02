#!/usr/bin/env python3
"""
Skill Credential Scanner - Scan skills for hardcoded credentials and secrets
"""

import os
import sys
import json
import hashlib
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any
import argparse

# Try to import YARA, fall back to pattern matching if not available
try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False
    print("⚠️  YARA not available, using pattern matching fallback")
    print("   Install with: pip install yara-python")

class CredentialScanner:
    """Scan skill directories for hardcoded credentials"""

    def __init__(self, rules_dir: str):
        self.rules_dir = Path(rules_dir)
        self.rules = []
        self.scanned_files = 0
        self.findings = []

        if YARA_AVAILABLE:
            self.load_yara_rules()
        else:
            self.load_fallback_patterns()

    def load_yara_rules(self):
        """Load YARA rules from rules directory"""
        rule_files = list(self.rules_dir.glob("*.yar"))
        if not rule_files:
            raise ValueError(f"No YARA rule files found in {self.rules_dir}")

        print(f"📋 Loading {len(rule_files)} YARA rule(s)...")

        for rule_file in rule_files:
            try:
                compiled_rule = yara.compile(str(rule_file))
                self.rules.append(compiled_rule)
                print(f"  ✅ {rule_file.name}")
            except Exception as e:
                print(f"  ❌ Failed to load {rule_file.name}: {e}")

        print(f"✅ Loaded {len(self.rules)} rule(s)\n")

    def load_fallback_patterns(self):
        """Load simple regex patterns when YARA is not available"""
        import re
        self.fallback_patterns = {
            'API_Key_Generic': [
                re.compile(r'sk-[a-zA-Z0-9]{20,}'),
                re.compile(r'secret[a-zA-Z0-9_-]{20,}'),
                re.compile(r'token[a-zA-Z0-9_-]{20,}', re.IGNORECASE),
            ],
            'AWS_Access_Key': [
                re.compile(r'(AKIA|AKIAIOSFODNN7EXAMPLE)[A-Z0-9]{16}'),
            ],
            'GitHub_Token': [
                re.compile(r'gh[pous]_[a-zA-Z0-9]{36}'),
            ],
            'Slack_Token': [
                re.compile(r'xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}'),
                re.compile(r'xoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}'),
            ],
            'Private_Key_PEM': [
                re.compile(r'-----BEGIN (PRIVATE|RSA PRIVATE|EC PRIVATE|PGP PRIVATE KEY BLOCK)-----'),
            ],
            'Database_URL': [
                re.compile(r'(postgres|mysql|mongodb)://[^:\s]+:[^@\s]+@[^\s/]+/\w+'),
            ],
            'Webhook_URL_Suspicious': [
                re.compile(r'https?://[a-z0-9\-]+\.(webhook\.site|requestbin\.net|pastebin\.com)'),
            ],
        }
        print(f"📋 Using {len(self.fallback_patterns)} fallback pattern(s)\n")

    def scan_directory(self, skill_path: str) -> Dict[str, Any]:
        """Scan a skill directory for credentials"""
        skill_dir = Path(skill_path)

        if not skill_dir.exists():
            raise ValueError(f"Skill directory not found: {skill_path}")

        print(f"🔍 Scanning skill: {skill_dir.name}")
        print(f"📁 Path: {skill_dir}\n")

        # Find all files to scan (exclude common non-code files)
        file_extensions = {'.js', '.mjs', '.ts', '.py', '.sh', '.md', '.json', '.yaml', '.yml', '.env', '.txt'}
        exclude_dirs = {'.git', 'node_modules', '__pycache__', 'venv', '.venv'}

        files_to_scan = []
        for root, dirs, files in os.walk(skill_dir):
            # Remove excluded directories from search
            dirs[:] = [d for d in dirs if d not in exclude_dirs]

            for file in files:
                file_path = Path(root) / file
                # Scan files with code extensions or specific names
                if file_path.suffix in file_extensions or file in ['.env', 'secrets.txt']:
                    files_to_scan.append(file_path)

        print(f"📄 Found {len(files_to_scan)} file(s) to scan\n")

        # Scan each file
        for file_path in files_to_scan:
            self.scan_file(file_path)

        # Generate report
        report = self.generate_report(skill_dir.name, skill_path)

        return report

    def scan_file(self, file_path: Path):
        """Scan a single file for credentials"""
        self.scanned_files += 1

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            if YARA_AVAILABLE:
                self.scan_with_yara(file_path, content)
            else:
                self.scan_with_patterns(file_path, content)

        except Exception as e:
            print(f"❌ Error scanning {file_path}: {e}")

    def scan_with_yara(self, file_path: Path, content: str):
        """Scan file content using YARA rules"""
        for rule in self.rules:
            try:
                matches = rule.match(data=content)
                for match in matches:
                    for finding in match.strings:
                        self.findings.append({
                            'rule': match.rule,
                            'severity': match.meta.get('severity', 'medium'),
                            'file': str(file_path.relative_to(file_path.parents[2])),
                            'line': finding[0],  # Offset in file (not line number in this simple version)
                            'pattern': finding[2].decode('utf-8', errors='ignore')[:100],  # Truncated
                            'description': match.meta.get('description', ''),
                        })
            except Exception as e:
                pass  # Skip errors in scanning

    def scan_with_patterns(self, file_path: Path, content: str):
        """Scan file content using regex patterns (fallback)"""
        for rule_name, patterns in self.fallback_patterns.items():
            for pattern in patterns:
                matches = pattern.finditer(content)
                for match in matches:
                    self.findings.append({
                        'rule': rule_name,
                        'severity': self.get_severity_for_rule(rule_name),
                        'file': str(file_path.relative_to(file_path.parents[2])),
                        'line': content[:match.start()].count('\n') + 1,
                        'pattern': match.group()[:100],
                        'description': f"Pattern matched: {rule_name}",
                    })

    def get_severity_for_rule(self, rule_name: str) -> str:
        """Get severity level for a rule name"""
        high_severity = ['AWS_Access_Key', 'GitHub_Token', 'Private_Key_PEM', 'Database_URL', 'Webhook_URL_Suspicious']
        if rule_name in high_severity:
            return 'critical'
        return 'high'

    def generate_report(self, skill_name: str, skill_path: str) -> Dict[str, Any]:
        """Generate a scan report"""
        # Count findings by severity
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for finding in self.findings:
            severity = finding.get('severity', 'medium')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        # Calculate security score (0-100)
        # Critical: -20, High: -10, Medium: -5, Low: -2
        score = 100
        score -= severity_counts['critical'] * 20
        score -= severity_counts['high'] * 10
        score -= severity_counts['medium'] * 5
        score -= severity_counts['low'] * 2
        score = max(0, score)

        # Determine grade
        if score >= 80:
            grade = 'A'
        elif score >= 60:
            grade = 'B'
        elif score >= 40:
            grade = 'C'
        else:
            grade = 'D'

        report = {
            'scan_timestamp': datetime.now().isoformat(),
            'skill_name': skill_name,
            'skill_path': str(skill_path),
            'scanned_files': self.scanned_files,
            'total_findings': len(self.findings),
            'findings_by_severity': severity_counts,
            'security_score': score,
            'security_grade': grade,
            'findings': self.findings,
            'recommendations': self.generate_recommendations(),
        }

        return report

    def generate_recommendations(self) -> List[str]:
        """Generate security recommendations based on findings"""
        recommendations = []

        if not self.findings:
            recommendations.append("✅ No hardcoded credentials detected - good security practices!")
            return recommendations

        # Check for specific issues
        has_critical = any(f['severity'] == 'critical' for f in self.findings)
        has_webhook = any('webhook' in f['rule'].lower() for f in self.findings)
        has_private_key = any('private_key' in f['rule'].lower() for f in self.findings)

        if has_critical:
            recommendations.append("🔴 CRITICAL: Immediate action required - remove all hardcoded credentials!")
        if has_webhook:
            recommendations.append("🚨 Webhook URLs detected - this could be data exfiltration!")
        if has_private_key:
            recommendations.append("🔐 Private keys found in code - move to environment variables!")
        recommendations.append("📝 Use environment variables or a secret manager for all credentials")
        recommendations.append("🔒 Add .env files to .gitignore to prevent committing secrets")
        recommendations.append("📋 Review all findings and remove/replace with environment variables")

        return recommendations

    def save_report(self, report: Dict[str, Any], output_path: str):
        """Save scan report to JSON file"""
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)

        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)

        print(f"\n📊 Report saved to: {output_file}")

    def print_report(self, report: Dict[str, Any]):
        """Print a human-readable report"""
        print("\n" + "=" * 70)
        print("🔐 SKILL CREDENTIAL SCAN REPORT")
        print("=" * 70)
        print(f"\nSkill: {report['skill_name']}")
        print(f"Scanned: {report['scanned_files']} files")
        print(f"Findings: {report['total_findings']}")
        print(f"Security Score: {report['security_score']}/100 (Grade: {report['security_grade']})")

        print(f"\n📊 Findings by Severity:")
        for severity, count in report['findings_by_severity'].items():
            if count > 0:
                emoji = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🟢'}[severity]
                print(f"  {emoji} {severity.upper()}: {count}")

        if report['findings']:
            print(f"\n🔎 Top Findings:")
            for i, finding in enumerate(report['findings'][:10], 1):  # Show top 10
                emoji = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🟢'}[finding['severity']]
                print(f"  {i}. {emoji} [{finding['rule']}]")
                print(f"     File: {finding['file']}")
                print(f"     Pattern: {finding['pattern']}...")

            if len(report['findings']) > 10:
                print(f"  ... and {len(report['findings']) - 10} more findings")

        print(f"\n💡 Recommendations:")
        for rec in report['recommendations']:
            print(f"  {rec}")

        print("\n" + "=" * 70)


def main():
    parser = argparse.ArgumentParser(description='Scan skills for hardcoded credentials')
    parser.add_argument('skill_path', help='Path to skill directory to scan')
    parser.add_argument('--rules', '-r', default='rules', help='Path to YARA rules directory')
    parser.add_argument('--output', '-o', help='Output report to JSON file')
    parser.add_argument('--json-only', action='store_true', help='Only output JSON (no human-readable report)')

    args = parser.parse_args()

    # Initialize scanner
    scanner = CredentialScanner(args.rules)

    # Scan skill
    try:
        report = scanner.scan_directory(args.skill_path)
    except Exception as e:
        print(f"❌ Scan failed: {e}")
        sys.exit(1)

    # Output report
    if not args.json_only:
        scanner.print_report(report)

    # Save to file if requested
    if args.output:
        scanner.save_report(report, args.output)

    # Exit with error code if critical findings
    if report['findings_by_severity']['critical'] > 0:
        print("\n⚠️  CRITICAL findings detected - immediate action required!")
        sys.exit(1)
    elif report['total_findings'] > 0:
        print("\n⚠️  Security findings detected - review recommended")
        sys.exit(2)
    else:
        print("\n✅ No security issues found!")
        sys.exit(0)


if __name__ == '__main__':
    main()

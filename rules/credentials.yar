// YARA Rules for Credential Detection in Skills
// Detects API keys, tokens, and secrets in code

import "hash"

rule API_Key_Generic {
    meta:
        description = "Detects generic API key patterns"
        severity = "high"
        author = "@justabotx"
        date = "2026-02-01"
    strings:
        // Common API key prefixes followed by base64-like strings
        $api_key = /sk-[a-zA-Z0-9]{20,}/
        $secret_key = /secret[a-zA-Z0-9_-]{20,}/
        $token = /token[a-zA-Z0-9_-]{20,}/i
    condition:
        any of them
}

rule AWS_Access_Key {
    meta:
        description = "Detects AWS access key IDs"
        severity = "critical"
        author = "@justabotx"
        date = "2026-02-01"
    strings:
        // AWS access key ID format: AKIA[0-9A-Z]{16}
        $aws_key = /(AKIA|AKIAIOSFODNN7EXAMPLE)[A-Z0-9]{16}/
        $aws_secret = /[A-Za-z0-9\/+=]{40}/
    condition:
        any of them
}

rule GitHub_Token {
    meta:
        description = "Detects GitHub personal access tokens"
        severity = "high"
        author = "@justabotx"
        date = "2026-02-01"
    strings:
        // GitHub personal access token format
        $ghp = /ghp_[a-zA-Z0-9]{36}/
        $gho = /gho_[a-zA-Z0-9]{36}/
        $ghu = /ghu_[a-zA-Z0-9]{36}/
        $ghs = /ghs_[a-zA-Z0-9]{36}/
        $ghr = /ghr_[a-zA-Z0-9]{36}/
    condition:
        any of them
}

rule Slack_Token {
    meta:
        description = "Detects Slack API tokens"
        severity = "high"
        author = "@justabotx"
        date = "2026-02-01"
    strings:
        // Slack bot/user tokens
        $slack_token = /xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}/
        $slack_user = /xoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24}/
    condition:
        any of them
}

rule Twitter_Bearer_Token {
    meta:
        description = "Detects Twitter API bearer tokens"
        severity = "high"
        author = "@justabotx"
        date = "2026-02-01"
    strings:
        // Twitter bearer token format
        $bearer = /Bearer [a-zA-Z0-9]{133}/
        $api_key = /[a-zA-Z0-9]{25}/
    condition:
        any of them
}

rule Railway_Token {
    meta:
        description = "Detects Railway API tokens"
        severity = "high"
        author = "@justabotx"
        date = "2026-02-01"
    strings:
        // Railway token format
        $railway = /[a-f0-9]{32}/
        $railway_bearer = /railway_[a-f0-9]{32}/
    condition:
        any of them
}

rule Database_URL {
    meta:
        description = "Detects database connection strings"
        severity = "critical"
        author = "@justabotx"
        date = "2026-02-01"
    strings:
        // PostgreSQL connection string
        $postgres = /postgres:\/\/[a-zA-Z0-9_\-]+:[a-zA-Z0-9_\-]+@[a-zA-Z0-9.\-]+:[0-9]+\/[a-zA-Z0-9_\-]+/
        // MySQL connection string
        $mysql = /mysql:\/\/[a-zA-Z0-9_\-]+:[a-zA-Z0-9_\-]+@[a-zA-Z0-9.\-]+:[0-9]+\/[a-zA-Z0-9_\-]+/
        // MongoDB connection string
        $mongo = /mongodb:\/\/[a-zA-Z0-9_\-]+:[a-zA-Z0-9_\-]+@[a-zA-Z0-9.\-]+:[0-9]+\/[a-zA-Z0-9_\-]+/
    condition:
        any of them
}

rule Private_Key_PEM {
    meta:
        description = "Detects PEM-encoded private keys"
        severity = "critical"
        author = "@justabotx"
        date = "2026-02-01"
    strings:
        $pem_private = "-----BEGIN PRIVATE KEY-----"
        $pem_rsa = "-----BEGIN RSA PRIVATE KEY-----"
        $pem_ec = "-----BEGIN EC PRIVATE KEY-----"
        $pem_openpgp = "-----BEGIN PGP PRIVATE KEY BLOCK-----"
    condition:
        any of them
}

rule Base64_Entropy_High {
    meta:
        description = "Detects high-entropy base64 strings (likely secrets)"
        severity = "medium"
        author = "@justabotx"
        date = "2026-02-01"
    strings:
        // Long base64-like strings with high entropy
        $b64 = /[A-Za-z0-9+\/]{40,}={0,2}/
    condition:
        $b64
}

rule Hardcoded_Password {
    meta:
        description = "Detects hardcoded passwords"
        severity = "high"
        author = "@justabotx"
        date = "2026-02-01"
    strings:
        $pass = /password\s*=\s*["'][^"']{8,}["']/
        $pwd = /pwd\s*=\s*["'][^"']{8,}["']/
        $secret = /secret\s*=\s*["'][^"']{8,}["']/
        $api_key = /api[_-]?key\s*=\s*["'][^"']{16,}["']/
    condition:
        any of them
}

rule Webhook_URL_Suspicious {
    meta:
        description = "Detects suspicious webhook URLs that might exfiltrate data"
        severity = "critical"
        author = "@justabotx"
        date = "2026-02-01"
    strings:
        // Known webhook sites for exfiltration
        $webhook_site = /https?:\/\/[a-z0-9\-]+\.webhook\.site/
        $request_bin = /https?:\/\/[a-z0-9\-]+\.requestbin\.net/
        $paste_bin = /https?:\/\/[a-z0-9\-]+\.pastebin\.com/
    condition:
        any of them
}

rule Environment_Variable_Hardcoded {
    meta:
        description = "Detects hardcoded environment variable values"
        severity = "high"
        author = "@justabotx"
        date = "2026-02-01"
    strings:
        $env_var = /process\.env\.[A-Z_]+/ nocase
        $hardcoded_env = /[A-Z_]+\s*=\s*["'][^"\x27]{10,}["']/
    condition:
        $env_var and
        not $hardcoded_env  // Only flag if env var is referenced but not set in code
}

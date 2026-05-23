/*
   Phishing email body detection rules
   severity: critical | high | medium | low
*/

rule Phishing_Urgent_Language
{
    meta:
        description = "Urgent action language common in phishing emails"
        severity = "medium"
        category = "social_engineering"
    strings:
        $u1 = "urgent" nocase
        $u2 = "immediately" nocase
        $u3 = "within 24 hours" nocase
        $u4 = "account will be suspended" nocase
        $u5 = "act now" nocase
        $u6 = "expires today" nocase
    condition:
        2 of them
}

rule Phishing_Credential_Harvest
{
    meta:
        description = "Credential harvesting language detected"
        severity = "high"
        category = "credential_theft"
    strings:
        $c1 = "verify your identity" nocase
        $c2 = "verify your account" nocase
        $c3 = "password reset" nocase
        $c4 = "confirm your account" nocase
        $c5 = "click here to verify" nocase
        $c6 = "update your payment" nocase
        $c7 = "login to confirm" nocase
    condition:
        any of them
}

rule Phishing_Suspicious_URL
{
    meta:
        description = "Suspicious URL pattern (login/verify/reset)"
        severity = "medium"
        category = "malicious_url"
    strings:
        $url1 = /https?:\/\/[^\s\"'<>]+login[^\s\"'<>]*/ nocase
        $url2 = /https?:\/\/[^\s\"'<>]+verify[^\s\"'<>]*/ nocase
        $url3 = /https?:\/\/[^\s\"'<>]+reset[^\s\"'<>]*/ nocase
        $url4 = /https?:\/\/[^\s\"'<>]+secure[^\s\"'<>-]*update[^\s\"'<>]*/ nocase
    condition:
        any of them
}

rule Phishing_Financial_Lure
{
    meta:
        description = "Financial urgency or invoice lure"
        severity = "medium"
        category = "bec_fraud"
    strings:
        $f1 = "wire transfer" nocase
        $f2 = "outstanding invoice" nocase
        $f3 = "payment overdue" nocase
        $f4 = "bank account" nocase
        $f5 = "unusual activity" nocase
    condition:
        2 of them
}

rule Phishing_HTML_Smuggling
{
    meta:
        description = "HTML smuggling or encoded script indicators"
        severity = "high"
        category = "html_smuggling"
    strings:
        $h1 = "<script" nocase
        $h2 = "eval(" nocase
        $h3 = "atob(" nocase
        $h4 = "fromCharCode" nocase
        $h5 = "document.write" nocase
    condition:
        2 of them
}

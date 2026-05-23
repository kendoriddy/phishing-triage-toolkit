/*
   Malicious attachment detection rules
*/

rule Suspicious_Double_Extension
{
    meta:
        description = "Double extension masquerading as a document"
        severity = "critical"
        category = "attachment"
    strings:
        $e1 = ".pdf.exe" nocase
        $e2 = ".doc.exe" nocase
        $e3 = ".docx.exe" nocase
        $e4 = ".xls.exe" nocase
        $e5 = ".jpg.exe" nocase
        $e6 = ".png.exe" nocase
    condition:
        any of them
}

rule Windows_PE_Executable
{
    meta:
        description = "Windows PE executable header (MZ) detected"
        severity = "high"
        category = "malware"
    strings:
        $mz = { 4D 5A }
    condition:
        $mz at 0 and filesize < 20MB
}

rule Suspicious_Office_Macro_Indicators
{
    meta:
        description = "Office document macro indicators"
        severity = "high"
        category = "macro"
    strings:
        $vba1 = "AutoOpen" nocase
        $vba2 = "Document_Open" nocase
        $vba3 = "Shell(" nocase
        $vba4 = "WScript.Shell" nocase
        $vba5 = "powershell" nocase
    condition:
        2 of them
}

rule Ransomware_Note_Keywords
{
    meta:
        description = "Ransomware note language patterns"
        severity = "critical"
        category = "ransomware"
    strings:
        $r1 = "your files have been encrypted" nocase
        $r2 = "pay the ransom" nocase
        $r3 = "decryption key" nocase
        $r4 = "bitcoin" nocase
        $r5 = ".locked" nocase
    condition:
        2 of them
}

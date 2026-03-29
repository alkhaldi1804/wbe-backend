import os
import re
import hashlib
import magic
import pefile
import yara
from elftools.elf.elffile import ELFFile

SUSPICIOUS_APIS = [
    "CreateRemoteThread",
    "VirtualAlloc",
    "WriteProcessMemory",
    "WinExec",
    "ShellExecute",
    "URLDownloadToFile",
    "InternetOpen",
    "InternetConnect"
]

# -------------------------------
# Malware Risk Engine
# -------------------------------
def calculate_malware_risk(entropy, urls, ips, suspicious_apis, yara_matches, strings):

    score = 0

    if entropy >= 7.5:
        score += 25
    elif entropy >= 6.5:
        score += 10

    if len(urls) > 0:
        score += 15

    if len(ips) > 0:
        score += 10

    score += min(len(suspicious_apis) * 5, 25)

    if len(yara_matches) > 0:
        score += 20

    score += min(len(strings) * 2, 10)

    score = min(score, 100)

    if score >= 70:
        level = "HIGH"
    elif score >= 40:
        level = "MEDIUM"
    else:
        level = "LOW"

    return {"score": score, "level": level}

# -------------------------------
# Packed Detection
# -------------------------------
def detect_packed_binary(entropy, pe_analysis=None):

    packed = False
    reason = ""

    if entropy >= 7.5:
        packed = True
        reason = "High entropy"

    if pe_analysis:
        for section in pe_analysis.get("sections", []):
            if "upx" in section["name"].lower():
                packed = True
                reason = "UPX packer detected"

    return {"packed": packed, "reason": reason}

# -------------------------------
# Anti-VM Detection
# -------------------------------
def detect_anti_vm(strings):

    vm_keywords = ["vmware", "virtualbox", "vbox", "qemu", "sandbox"]

    found = []

    for s in strings:
        for v in vm_keywords:
            if v in s.lower():
                found.append(v)

    return list(set(found))

# -------------------------------
# C2 Detection
# -------------------------------
def detect_c2_servers(urls, ips):

    suspicious_domains = ["pastebin", "discord", "telegram", "ngrok"]

    c2 = []

    for u in urls:
        for d in suspicious_domains:
            if d in u:
                c2.append(u)

    for ip in ips:
        if ip.startswith("185.") or ip.startswith("45."):
            c2.append(ip)

    return list(set(c2))

# -------------------------------
# Malware Family Detection
# -------------------------------
def detect_malware_family(strings, suspicious_apis):

    families = []

    if any(api in suspicious_apis for api in ["CreateRemoteThread", "VirtualAlloc"]):
        families.append("Possible RAT / Backdoor")

    if any("http" in s.lower() for s in strings):
        families.append("Possible Downloader")

    if any("GetAsyncKeyState" in s for s in strings):
        families.append("Possible Keylogger")

    return families

# -------------------------------
# Hashes
# -------------------------------
def calculate_hashes(file_path):

    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as f:
        while chunk := f.read(8192):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)

    return {
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest()
    }

# -------------------------------
# Entropy
# -------------------------------
def calculate_entropy(data):

    import math

    if not data:
        return 0

    entropy = 0

    for x in range(256):
        p_x = float(data.count(bytes([x]))) / len(data)
        if p_x > 0:
            entropy += -p_x * math.log2(p_x)

    return round(entropy, 3)

# -------------------------------
# Strings
# -------------------------------
def extract_strings(file_path, min_length=6):

    strings = []

    with open(file_path, "rb") as f:
        data = f.read()

    pattern = rb"[ -~]{%d,}" % min_length

    matches = re.findall(pattern, data)

    for m in matches:
        try:
            strings.append(m.decode("utf-8"))
        except:
            pass

    return strings[:100]

# -------------------------------
# Suspicious Strings
# -------------------------------
def find_suspicious_strings(strings):

    keywords = [
        "powershell",
        "cmd.exe",
        "CreateRemoteThread",
        "VirtualAlloc",
        "LoadLibrary",
        "GetProcAddress",
        "WinExec",
        "http://",
        "https://",
        "ftp://",
        ".exe",
        ".dll"
    ]

    suspicious = []

    for s in strings:
        for k in keywords:
            if k.lower() in s.lower():
                suspicious.append(s)
                break

    return suspicious[:20]

# -------------------------------
# URLs / IPs
# -------------------------------
def extract_urls(strings):
    return [s for s in strings if "http://" in s or "https://" in s]

def extract_ips(strings):

    pattern = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"

    ips = []

    for s in strings:
        ips.extend(re.findall(pattern, s))

    return ips

# -------------------------------
# Suspicious APIs
# -------------------------------
def detect_suspicious_apis(strings):

    found = []

    for api in SUSPICIOUS_APIS:
        for s in strings:
            if api in s:
                found.append(api)

    return list(set(found))

# -------------------------------
# File Type
# -------------------------------
def detect_file_type(file_path):
    return magic.from_file(file_path)

# -------------------------------
# PE Analysis
# -------------------------------
def analyze_pe(file_path):

    info = {}

    pe = pefile.PE(file_path)

    info["entry_point"] = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)

    sections = []

    for section in pe.sections:
        sections.append({
            "name": section.Name.decode(errors="ignore").strip(),
            "size": section.SizeOfRawData,
            "entropy": round(section.get_entropy(), 3)
        })

    info["sections"] = sections

    imports = []

    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp.name:
                    imports.append(imp.name.decode())

    info["imports"] = imports[:50]

    return info

# -------------------------------
# ELF Analysis
# -------------------------------
def analyze_elf(file_path):

    info = {}

    with open(file_path, "rb") as f:

        elf = ELFFile(f)

        info["architecture"] = elf.get_machine_arch()

        sections = []

        for section in elf.iter_sections():
            sections.append(section.name)

        info["sections"] = sections[:20]

    return info

# -------------------------------
# YARA
# -------------------------------
def run_yara(file_path):

    matches = []

    try:
        rules = yara.compile(source="""
        rule suspicious_strings
        {
            strings:
                $a = "cmd.exe"
                $b = "powershell"
                $c = "CreateRemoteThread"
            condition:
                any of them
        }
        """)

        result = rules.match(file_path)

        for r in result:
            matches.append(r.rule)

    except:
        pass

    return matches

# -------------------------------
# MAIN ANALYZER
# -------------------------------
def analyze_binary(file_path):

    result = {}

    result["file_name"] = os.path.basename(file_path)
    result["file_size"] = os.path.getsize(file_path)
    result["file_type"] = detect_file_type(file_path)
    result["hashes"] = calculate_hashes(file_path)

    with open(file_path, "rb") as f:
        data = f.read()

    result["entropy"] = calculate_entropy(data)

    strings = extract_strings(file_path)

    result["strings"] = find_suspicious_strings(strings)
    result["urls"] = extract_urls(strings)
    result["ips"] = extract_ips(strings)
    result["suspicious_apis"] = detect_suspicious_apis(strings)
    result["yara_matches"] = run_yara(file_path)

    if "PE32" in result["file_type"]:
        result["pe_analysis"] = analyze_pe(file_path)
    elif "ELF" in result["file_type"]:
        result["elf_analysis"] = analyze_elf(file_path)

    # 🔥 Malware Indicators
    result["packed"] = detect_packed_binary(result["entropy"], result.get("pe_analysis"))
    result["anti_vm"] = detect_anti_vm(strings)
    result["c2_servers"] = detect_c2_servers(result["urls"], result["ips"])
    result["malware_family"] = detect_malware_family(strings, result["suspicious_apis"])

    # 🔥 Risk Score
    risk = calculate_malware_risk(
        result["entropy"],
        result["urls"],
        result["ips"],
        result["suspicious_apis"],
        result["yara_matches"],
        result["strings"]
    )

    result["risk_score"] = risk["score"]
    result["risk_level"] = risk["level"]

    return result
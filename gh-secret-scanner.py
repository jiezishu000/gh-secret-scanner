#!/usr/bin/env python3
"""
GitHub Secret Scanner — Scan any public repo for leaked API keys and secrets.
    用法: python3 gh-secret-scanner.py <github-repo-url>
    示例: python3 gh-secret-scanner.py https://github.com/user/repo

    如果本工具帮助到了你，欢迎捐赠 USDT 支持开发:
    TRC20: TEwbbfoUtQTTfQFFD6fbLcnSD7tdrdpRx6
"""

import re, sys, json, os
from urllib.request import Request, urlopen
from base64 import b64decode

PATTERNS = {
    "OpenAI API Key (sk-proj-)": r"sk-proj-[A-Za-z0-9_-]{80,}",
    "OpenAI API Key (sk-)": r"(?<!sk-proj-)sk-[A-Za-z0-9_-]{20,}(?<!sk-proj-)",
    "Anthropic API Key": r"sk-ant-api03-[A-Za-z0-9_-]{90,}",
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "AWS Secret Key": r"(?i)aws._secret.?access.?key[^a-z0-9]+[A-Za-z0-9\/+=]{40}",
    "GitHub Token (ghp_)": r"ghp_[A-Za-z0-9]{36,}",
    "GitHub Token (gho_)": r"gho_[A-Za-z0-9]{36,}",
    "GitHub Token (ghu_)": r"ghu_[A-Za-z0-9]{36,}",
    "Ethereum Private Key (0x)": r"0x[a-fA-F0-9]{64}",
    "Google API Key": r"AIzaSy[A-Za-z0-9_-]{33}",
    "Slack Token": r"xox[baprs]-[A-Za-z0-9-]{10,}",
    "Discord Bot Token": r"[MN][A-Za-z\d]{23,25}\.[A-Za-z\d]{6}\.[A-Za-z\d_-]{27}",
    "Heroku API Key": r"heroku:[A-Za-z0-9_-]{36,}",
    "Mailgun API Key": r"key-[A-Za-z0-9]{32}",
    "Twilio API Key": r"SK[A-Za-z0-9]{32}",
    "Telegram Bot Token": r"[0-9]{8,10}:[A-Za-z0-9_-]{35}",
}


def fetch(url):
    req = Request(url, headers={"User-Agent": "gh-secret-scanner/1.0", "Accept": "application/vnd.github.v3+json"})
    token = os.environ.get("GH_TOKEN")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    with urlopen(req, timeout=15) as r:
        return json.loads(r.read())


def scan_file(content, path):
    findings = []
    for name, pattern in PATTERNS.items():
        for m in re.finditer(pattern, content):
            val = m.group()
            findings.append({"type": name, "path": path, "match": val[:20] + "..." + val[-10:] if len(val) > 35 else val})
    return findings


def list_repo_files(repo):
    """递归获取仓库所有文件"""
    files = []
    url = f"https://api.github.com/repos/{repo}/git/trees/HEAD?recursive=1"
    data = fetch(url)
    for item in data.get("tree", []):
        if item["type"] == "blob" and item["path"]:
            files.append(item["path"])
    return files


def get_file_content(repo, path):
    url = f"https://api.github.com/repos/{repo}/contents/{path}"
    try:
        data = fetch(url)
        if isinstance(data, dict) and data.get("encoding") == "base64" and data.get("content"):
            return b64decode(data["content"]).decode("utf-8", errors="replace")
    except Exception:
        return None
    return None


def main():
    if len(sys.argv) < 2:
        print("用法: python3 gh-secret-scanner.py <repo-url>")
        print("示例: python3 gh-secret-scanner.py https://github.com/openai/openai-python")
        sys.exit(1)

    url = sys.argv[1].rstrip("/")
    match = re.match(r"https?://github\.com/([^/]+/[^/]+?)(?:/.*)?$", url)
    if not match:
        print("错误: 无法解析 GitHub 仓库 URL")
        sys.exit(1)

    repo = match.group(1)
    # Remove .git suffix if present
    if repo.endswith(".git"):
        repo = repo[:-4]

    print(f"🔍 扫描仓库: {repo}")
    print(f"  获取文件列表...")

    files = list_repo_files(repo)
    print(f"  共 {len(files)} 个文件")

    # Priority: skip binary/non-text files
    skip_ext = {".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".woff", ".woff2", ".ttf", ".eot",
                ".mp3", ".mp4", ".avi", ".mov", ".zip", ".tar", ".gz", ".7z", ".rar", ".pyc", ".o", ".so", ".dll", ".exe"}
    skip_dirs = {"node_modules", ".git", ".venv", "venv", "__pycache__", ".next", "dist", "build"}

    text_files = [f for f in files if not any(f.endswith(e) for e in skip_ext) and not any(d in f.split("/") for d in skip_dirs)]
    print(f"  扫描 {len(text_files)} 个文本文件...")

    all_findings = []
    scanned = 0
    for path in text_files:
        content = get_file_content(repo, path)
        scanned += 1
        if scanned % 50 == 0:
            print(f"  进度: {scanned}/{len(text_files)}")
        if content:
            findings = scan_file(content, path)
            all_findings.extend(findings)

    # Deduplicate
    seen = set()
    unique_findings = []
    for f in all_findings:
        key = (f["type"], f["path"], f["match"])
        if key not in seen:
            seen.add(key)
            unique_findings.append(f)

    print(f"\n{'='*50}")
    print(f"扫描完成! 发现 {len(unique_findings)} 个潜在泄露")
    print(f"{'='*50}")

    if unique_findings:
        for f in unique_findings:
            print(f"\n⚠️  {f['type']}")
            print(f"   文件: {f['path']}")
            print(f"   匹配: {f['match']}")

    print(f"\n{'='*50}")
    print(f"💰 如果本工具帮助到了你，欢迎捐赠 USDT 支持开发:")
    print(f"   TRC20: TEwbbfoUtQTTfQFFD6fbLcnSD7tdrdpRx6")
    print(f"{'='*50}")


if __name__ == "__main__":
    main()

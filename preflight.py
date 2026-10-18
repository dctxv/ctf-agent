import os, sys, subprocess, requests
from dotenv import load_dotenv
load_dotenv()

def check(label, fn):
    try:
        ok, detail = fn()
    except Exception as e:
        ok, detail = False, str(e)[:120]
    line = f"{'PASS' if ok else 'FAIL':4} | {label}"
    if not ok and detail:
        line += f" | {detail}"
    print(line)
    return ok

def _deepseek_ok():
    key = os.getenv("DEEPSEEK_KEY_PLACEHOLDER_GUARD", "") or os.getenv("DEEPSEEK_API_KEY", "")
    if "xxxx" in key:
        return False, ".env still has the placeholder key"
    r = requests.get("https://api.deepseek.com/user/balance",
                     headers={"Authorization": f"Bearer {key}"}, timeout=10)
    if r.status_code != 200:
        return False, f"API said: {r.text[:100]}"
    infos = r.json().get("balance_infos", [])
    total = sum(float(i.get("total_balance", 0)) for i in infos)
    return total > 0, f"balance: ${total:.2f}"

check("DeepSeek key valid + balance", _deepseek_ok),


def sh(cmd):
    return subprocess.run(cmd, capture_output=True, timeout=60,
                         encoding="utf-8", errors="replace")

results = [
    check("Docker daemon running", lambda: (sh(["docker", "info"]).returncode == 0, "")),
    check("pentest-tools image built", lambda: (
        sh(["docker", "image", "inspect", "pentest-tools"]).returncode == 0,
        "build: docker build -t pentest-tools ." if sh(["docker", "image", "inspect", "pentest-tools"]).returncode else "")),
    check("Agent container running", lambda: (
        sh(["docker", "inspect", "agent-box"]).returncode == 0,
        "docker run -dit --name agent-box -v C:\\ctf\\workspace:/workspace pentest-tools bash")),
    check("nmap works in container", lambda: ("Nmap" in sh(["docker","exec","agent-box","nmap","--version"]).stdout, "")),
    check("pwntools works in container", lambda: ("ok" in sh(["docker","exec","agent-box","bash","-lc","python3 -c 'import pwn; print(\"ok\")'"]).stdout, "")),
    check("DeepSeek reachability target", lambda: (os.getenv("DEEPSEEK_API_KEY","").startswith("sk"), "set DEEPSEEK_API_KEY")),
    check("Juice Shop target up", lambda: (requests.get("http://localhost:3000", timeout=5).status_code == 200,
        "docker run --rm -d -p 3000:3000 --name juice bkimminich/juice-shop")),
    check("Tavily key (web_search)", lambda: (bool(os.getenv("TAVILY_API_KEY")),
        "optional - without it web_search is disabled")),
]
sys.exit(0 if all(results) else 1)

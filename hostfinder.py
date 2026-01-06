import os, sys, time, re, random, string, subprocess, requests
from bs4 import BeautifulSoup
from colorama import Fore, init

init(autoreset=True)
requests.packages.urllib3.disable_warnings()

# ================= CONFIG ================= #

TIMEOUT = 8

DEVICE_KEY_FILE = "device_key.txt"
APPROVED_KEYS_FILE = "approved_keys.txt"

ADMIN_PASSWORD = "faizi123"
ADMIN_SECRET_CODE = "#unlock-faizi"

TELEGRAM_CHANNEL_URL = "https://t.me/faizi_mods"

DOMAIN_RE = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)

# ================= UTIL ================= #

def slow(text, color=Fore.WHITE, delay=0.02):
    for c in text:
        sys.stdout.write(color + c)
        sys.stdout.flush()
        time.sleep(delay)
    print()

def open_telegram():
    try:
        subprocess.Popen(["termux-open-url", TELEGRAM_CHANNEL_URL])
    except:
        pass

def get_battery():
    try:
        out = subprocess.check_output(["termux-battery-status"], text=True)
        for line in out.splitlines():
            if '"percentage"' in line:
                return line.split(":")[1].replace(",", "").strip() + "%"
    except:
        return "N/A"

def get_device():
    try:
        return subprocess.check_output(
            ["getprop", "ro.product.model"], text=True
        ).strip()
    except:
        return "Unknown"

# ================= ASCII ================= #

def banner():
    ascii_art = r"""
██╗  ██╗ ██████╗ ███████╗████████╗
██║  ██║██╔═══██╗██╔════╝╚══██╔══╝
███████║██║   ██║███████╗   ██║   
██╔══██║██║   ██║╚════██║   ██║   
██║  ██║╚██████╔╝███████║   ██║   
╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   

███████╗██╗███╗   ██╗██████╗ ███████╗██████╗
██╔════╝██║████╗  ██║██╔══██╗██╔════╝██╔══██╗
█████╗  ██║██╔██╗ ██║██║  ██║█████╗  ██████╔╝
██╔══╝  ██║██║╚██╗██║██║  ██║██╔══╝  ██╔══██╗
██║     ██║██║ ╚████║██████╔╝███████╗██║  ██║
╚═╝     ╚═╝╚═╝  ╚═══╝╚═════╝ ╚══════╝╚═╝  ╚═╝
"""
    colors = [Fore.RED, Fore.YELLOW, Fore.GREEN, Fore.CYAN, Fore.BLUE, Fore.MAGENTA]
    for i, line in enumerate(ascii_art.splitlines()):
        print(colors[i % len(colors)] + line)
        time.sleep(0.02)

    print(Fore.WHITE + "\n        🔥 HOST FINDER – FAIZI MODS 🔥\n")

# ================= DETAILS ================= #

def show_details():
    info = [
        ("👤 Developer        :", "Faizi Mods", Fore.GREEN),
        ("⚙️ Developer Status :", "Broken", Fore.RED),
        ("🔋 Battery          :", get_battery(), Fore.YELLOW),
        ("📱 Device           :", get_device(), Fore.CYAN),
        ("🛠 Engine           :", "Real-Time Host Analyzer", Fore.MAGENTA),
        ("⏱ Session           :", "Live", Fore.BLUE),
    ]
    for k, v, c in info:
        slow(f"{k} {v}", c, 0.02)
    print(Fore.BLUE + "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")

# ================= DEVICE KEY ================= #

def rand(n):
    return "".join(random.choice(string.ascii_uppercase + string.digits) for _ in range(n))

def generate_key():
    return f"FAIZI-MODS-KEY-{rand(8)}-{rand(7)}"

def get_device_key():
    if os.path.exists(DEVICE_KEY_FILE):
        return open(DEVICE_KEY_FILE).read().strip()
    key = generate_key()
    open(DEVICE_KEY_FILE, "w").write(key)
    return key

def load_keys():
    if not os.path.exists(APPROVED_KEYS_FILE):
        return []
    return [k.strip() for k in open(APPROVED_KEYS_FILE).readlines() if k.strip()]

def is_approved(key):
    return key in load_keys()

# ================= SUBDOMAIN ================= #

def sanitize(d):
    d = d.strip().lower()
    if d.startswith("*."): d = d[2:]
    if d.endswith("."): d = d[:-1]
    if "*" in d or ".." in d: return None
    if not DOMAIN_RE.match(d): return None
    return d

def fetch_hosts(domain):
    r = requests.get(
        f"https://rapiddns.io/subdomain/{domain}?full=1",
        headers={"User-Agent": "Mozilla/5.0"},
        timeout=20
    )
    soup = BeautifulSoup(r.text, "html.parser")
    subs = set()
    table = soup.find("table")
    if not table:
        return subs
    for tr in table.find_all("tr"):
        tds = tr.find_all("td")
        if tds:
            s = sanitize(tds[0].get_text(strip=True))
            if s and s.endswith(domain):
                subs.add(s)
    return subs

# ================= REAL-TIME RESPONSE CHECK ================= #

def realtime_check(host, idx, total):
    url = f"http://{host}"
    start = time.time()
    try:
        r = requests.get(url, timeout=TIMEOUT, allow_redirects=False)
        latency = int((time.time() - start) * 1000)
        code = r.status_code

        if code == 302:
            status = Fore.RED + "NON-ZERO ❌"
        elif code in (200, 204, 301):
            status = Fore.GREEN + "ZERO-RATED ✅"
        else:
            status = Fore.YELLOW + "UNKNOWN ⚠️"

        print(
            f"[{idx}/{total}] {host:<32} "
            f"{code:<4} {status}  {latency} ms"
        )

    except Exception:
        latency = int((time.time() - start) * 1000)
        print(
            f"[{idx}/{total}] {host:<32} "
            f"{Fore.RED}NO RESP ❌  {latency} ms"
        )

    time.sleep(0.15)  # 👈 real-time feel

# ================= MAIN ================= #

def main():
    banner()
    show_details()

    device_key = get_device_key()

    secret = input("Enter command or press ENTER: ").strip()
    if secret == ADMIN_SECRET_CODE:
        print(Fore.YELLOW + "Admin panel locked in this build.")
        return

    if not is_approved(device_key):
        slow("❌ Device not approved\n", Fore.RED)
        slow("Your Device Key:\n", Fore.YELLOW)
        slow(device_key + "\n", Fore.CYAN)
        slow("📩 Send this key to admin via Telegram.\n", Fore.WHITE)
        open_telegram()
        input("Press ENTER after sending key...")
        return

    domain = input("Enter domain: ").strip()
    if not domain:
        return

    slow("\nFinding hosts...\n", Fore.YELLOW)
    hosts = fetch_hosts(domain)

    total = len(hosts)
    slow(f"✔ Hosts Found: {total}\n", Fore.GREEN)

    for i, h in enumerate(sorted(hosts), 1):
        realtime_check(h, i, total)

    slow("\n✔ Scan completed (real-time)\n", Fore.CYAN)

if __name__ == "__main__":
    main()

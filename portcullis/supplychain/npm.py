"""npm package analysis: registry signature and integrity verification,
install-script and obfuscation heuristics, typosquat distance.

Signature scheme (npm registry): ECDSA P-256 over the UTF-8 string
``{name}@{version}:{integrity}`` using the key whose keyid matches the
signature entry.  Integrity is ``sha512-<base64>`` over the tarball bytes.
"""
import base64
import hashlib
import json
import re
import tarfile
import io
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature

from portcullis.model import Finding

ROOT = Path(__file__).resolve().parents[2]


def load_keys(path=None):
    path = Path(path or ROOT / "data/raw/npm/registry_keys.json")
    keys = {}
    for k in json.loads(path.read_text())["keys"]:
        der = base64.b64decode(k["key"])
        keys[k["keyid"]] = serialization.load_der_public_key(der)
    return keys


def verify_signature(meta, keys):
    """True if any signature on meta['dist'] verifies against a known key."""
    dist = meta.get("dist", {})
    msg = f"{meta['name']}@{meta['version']}:{dist.get('integrity','')}".encode()
    for s in dist.get("signatures", []):
        key = keys.get(s["keyid"])
        if key is None:
            continue
        try:
            key.verify(base64.b64decode(s["sig"]), msg, ec.ECDSA(hashes.SHA256()))
            return True
        except InvalidSignature:
            continue
    return False


def integrity_of(data: bytes) -> str:
    return "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode()


def verify_integrity(meta, tarball_bytes):
    return integrity_of(tarball_bytes) == meta.get("dist", {}).get("integrity")


def verify_package(meta, tarball_bytes=None, keys=None):
    keys = keys or load_keys()
    out = []
    name = f"{meta['name']}@{meta['version']}"
    if not meta.get("dist", {}).get("signatures"):
        out.append(Finding("npm", "unsigned", "medium", "No registry signature", name,
                           "supply-chain", "metadata carries no signatures"))
    elif not verify_signature(meta, keys):
        out.append(Finding("npm", "bad-signature", "critical", "Registry signature does not verify", name,
                           "supply-chain", "ECDSA verification failed for every signature"))
    if tarball_bytes is not None and not verify_integrity(meta, tarball_bytes):
        out.append(Finding("npm", "integrity-mismatch", "critical", "Tarball does not match published integrity", name,
                           "supply-chain", "sha512 of tarball differs from dist.integrity"))
    return out


# ---------- script and code heuristics ----------
LIFECYCLE = ("preinstall", "install", "postinstall", "prepare", "prepublish")
NETWORK_EXEC = re.compile(r"(curl|wget)\b[^|;]*\|\s*(sh|bash)|\b(nc|ncat)\s+-e|powershell\s+-e|base64\s+(-d|--decode)", re.I)
NET_USE = re.compile(r"\b(curl|wget|http\.get|https\.get|fetch\()", re.I)
BENIGN_BUILD = re.compile(r"^(node-gyp\b|node\s+(install|scripts/install|install\.js|build)|husky|prebuild-install|node-pre-gyp|opencollective|tsc\b|npm run build)", re.I)
OBFUSC_HEX = re.compile(r"(\\x[0-9a-fA-F]{2}){12,}")
OBFUSC_ARR = re.compile(r"_0x[0-9a-f]{4,}")
EVAL_DECODE = re.compile(r"(eval|Function)\s*\(\s*(atob|Buffer\.from|unescape)")
ADDR_PATTERNS = {
    "eth": re.compile(r"0x[a-fA-F0-9]{40}"),
    "btc": re.compile(r"\b(bc1[a-z0-9]{25,60}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})\b"),
}
CLIPBOARD_OR_WALLET = re.compile(r"(window\.ethereum|ethereum\.request|eth_sendTransaction|eth_requestAccounts)")
ADDR_SWAP = re.compile(r"(replace\s*\([^)]*(0x|bc1)|\.replace\([^)]*address)", re.I)
ENV_EXFIL = re.compile(r"(process\.env|\.npmrc|id_rsa|\.ssh|GITHUB_TOKEN|AWS_SECRET)", re.I)


def analyze_scripts(pkg_json, name):
    out = []
    scripts = pkg_json.get("scripts", {}) or {}
    for hook in LIFECYCLE:
        cmd = scripts.get(hook)
        if not cmd:
            continue
        loc = f"{name}:scripts.{hook}"
        if NETWORK_EXEC.search(cmd):
            out.append(Finding("npm", "install-script-remote-exec", "critical", "Install hook pipes remote content to a shell", loc, "supply-chain", cmd))
        elif NET_USE.search(cmd) and ENV_EXFIL.search(cmd):
            out.append(Finding("npm", "install-script-exfil", "critical", "Install hook reads secrets and uses the network", loc, "supply-chain", cmd))
        elif not BENIGN_BUILD.search(cmd):
            out.append(Finding("npm", "install-script", "medium", "Lifecycle script runs custom code on install", loc, "supply-chain", cmd))
        else:
            out.append(Finding("npm", "install-script-build", "info", "Lifecycle script looks like a build step", loc, "supply-chain", cmd))
    return out


def analyze_source(text, path):
    out = []
    if OBFUSC_HEX.search(text) or len(OBFUSC_ARR.findall(text)) >= 5:
        out.append(Finding("npm", "obfuscated-code", "high", "Obfuscated string table or hex escapes", path, "supply-chain", "javascript obfuscator signature"))
    if EVAL_DECODE.search(text):
        out.append(Finding("npm", "eval-decoded", "high", "eval of decoded payload", path, "supply-chain", "eval/Function on atob/Buffer.from/unescape"))
    eth = ADDR_PATTERNS["eth"].findall(text)
    if (len(set(eth)) >= 2 and CLIPBOARD_OR_WALLET.search(text)) or ADDR_SWAP.search(text) and CLIPBOARD_OR_WALLET.search(text):
        out.append(Finding("npm", "address-swap", "critical", "Wallet address replacement inside a wallet API hook", path, "crypto-theft",
                           "hardcoded attacker-style addresses plus ethereum provider hooks"))
    if ENV_EXFIL.search(text) and re.search(r"https?://[^\s'\"]+", text) and re.search(r"(https?\.request|fetch\(|\.post\()", text) and re.search(r"(process\.env|\.npmrc)", text):
        if re.search(r"(JSON\.stringify\(process\.env|readFileSync\([^)]*\.npmrc)", text):
            out.append(Finding("npm", "env-exfil", "critical", "Environment or npmrc sent over the network", path, "supply-chain", "process.env/.npmrc serialised near a network call"))
    return out


def analyze_tarball(data: bytes, label):
    out = []
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
        for m in tf.getmembers():
            if not m.isfile() or m.size > 2_000_000:
                continue
            body = tf.extractfile(m).read()
            if m.name.endswith("package.json") and m.name.count("/") == 1:
                try:
                    out += analyze_scripts(json.loads(body), label)
                except ValueError:
                    pass
            elif m.name.endswith((".js", ".cjs", ".mjs")):
                out += analyze_source(body.decode("utf-8", "ignore"), f"{label}:{m.name}")
    return out


# ---------- typosquat ----------
def _lev(a, b):
    if abs(len(a) - len(b)) > 2:
        return 3
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[-1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _transposed(a, b):
    """True if a and b differ by exactly one adjacent swap."""
    if len(a) != len(b) or a == b:
        return False
    d = [i for i in range(len(a)) if a[i] != b[i]]
    return len(d) == 2 and d[1] == d[0] + 1 and a[d[0]] == b[d[1]] and a[d[1]] == b[d[0]]


def _norm(n):
    return re.sub(r"[-_.]", "", n.lower())


def popular_names(path=None):
    return json.loads(Path(path or ROOT / "data/popular_npm.json").read_text())["names"]


def typosquat(name, popular=None):
    """Return the popular package this name imitates, or None."""
    popular = popular or popular_names()
    if name in popular:
        return None
    bare = name.split("/")[-1]
    for p in popular:
        if _norm(bare) == _norm(p) and bare != p:
            return p
        if len(p) >= 4 and _transposed(bare, p):
            return p
        if len(p) >= 5 and _lev(bare, p) == 1:
            return p
        if len(p) >= 4 and (bare == p + "s" or bare in (p + "-js", p + "js", "node-" + p)):
            return p
        if len(p) >= 5 and _lev(_norm(bare), _norm(p)) == 1 and bare != p:
            return p
    return None


def typosquat_finding(name, popular=None):
    t = typosquat(name, popular)
    if t:
        return Finding("npm", "typosquat", "high", f"Name imitates popular package {t}", name, "supply-chain", f"edit distance <=1 or separator variant of {t}")
    return None

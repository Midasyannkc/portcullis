"""Anti-scam detectors for a Sui-style ecosystem: lookalike domains, phishing pages, drainer code.

All three return (score, reasons).  Scores are additive heuristics with a fixed threshold, so
every verdict can be explained; there is no model in the loop.
"""
import re, unicodedata
from portcullis.supplychain.npm import _lev

PROTECTED = {"sui": ["sui.io", "suiexplorer.com", "suivision.xyz", "suiscan.xyz"], "mysten": ["mystenlabs.com"],
             "walrus": ["walrus.xyz"], "suiwallet": ["suiwallet.com"]}
BRANDS = sorted(PROTECTED)
LEGIT = {d for v in PROTECTED.values() for d in v}
LURE = ("airdrop", "claim", "verify", "reward", "giveaway", "connect", "recover", "support", "login", "validate", "unlock", "bonus")
CONFUSABLE = {"0": "o", "1": "l", "3": "e", "5": "s", "@": "a", "$": "s", "а": "a", "е": "e", "о": "o", "р": "p",
              "с": "c", "х": "x", "і": "i", "ѕ": "s", "ӏ": "l", "ԁ": "d"}
CHEAP_TLDS = {"xyz", "top", "click", "site", "online", "live", "icu", "cc", "tk", "app", "link"}


def skeleton(label: str, one="l") -> str:
    label = unicodedata.normalize("NFKC", label.lower())
    s = "".join(one if c == "1" else CONFUSABLE.get(c, c) for c in label)
    s = s.replace("rn", "m").replace("vv", "w")
    return s


def skeletons(label: str):
    """Digit 1 is visually i or l; return both readings."""
    return {skeleton(label, "l"), skeleton(label, "i")}


def domain_score(domain: str):
    d = domain.lower().strip(".")
    if d in LEGIT:
        return 0, ["exact protected domain"]
    parts = d.split(".")
    tld = parts[-1]
    reg = ".".join(parts[-2:])
    if reg in LEGIT:     # legit domain with a subdomain
        return 0, ["subdomain of protected domain"]
    reasons, score = [], 0
    label = parts[-2] if len(parts) >= 2 else d
    if "xn--" in d:
        score += 2; reasons.append("punycode label")
    if any(ord(c) > 127 for c in d):
        score += 2; reasons.append("non-ascii characters")
    prefix = ".".join(parts[:-1]).replace("xn--", "")
    sk = next((v for v in sorted(skeletons(prefix)) if any(b in v for b in BRANDS)), skeleton(prefix))
    toks = [t for t in re.split(r"[-_.]", sk) if t]
    hit = None
    for b in BRANDS:
        if b in sk:
            hit = b
        for t in toks:
            if t != b and len(b) >= 4 and _lev(t, b) == 1:
                hit = b; reasons.append(f"edit-distance-1 to {b}"); score += 3
        if hit:
            break
    if hit:
        score += 2; reasons.append(f"contains brand {hit}")
        if sk != ".".join(parts[:-1]).lower():
            score += 2; reasons.append("homoglyph substitution")
        lures = [l for l in LURE if l in ".".join(parts[:-1])]
        if lures:
            score += 2; reasons.append("lure keyword " + lures[0])
        if tld in CHEAP_TLDS:
            score += 1; reasons.append(f"cheap tld .{tld}")
        if len(parts) > 2 and any(b in ".".join(parts[:-2]) for b in BRANDS):
            score += 3; reasons.append("brand used as subdomain of unrelated domain")
    return score, reasons


def domain_is_phish(domain, threshold=4):
    s, r = domain_score(domain)
    return s >= threshold, s, r


# ---------- page classifier ----------
SEED_FORM = re.compile(r"(seed\s*phrase|recovery\s*phrase|secret\s*recovery|mnemonic|12[\s-]*word|24[\s-]*word|private\s*key)", re.I)
INPUT_TAG = re.compile(r"<(input|textarea)\b", re.I)
URGENCY = re.compile(r"(within\s+\d+\s*(hours|minutes)|account\s+(will\s+be\s+)?(suspended|locked)|act\s+now|limited\s+time|validate\s+your\s+wallet)", re.I)
FORM_OFFSITE = re.compile(r"<form[^>]+action=[\"']https?://(?!(?:[a-z0-9.-]*\.)?(?:sui\.io|mystenlabs\.com)[/\"'])", re.I)
BRAND_TITLE = re.compile(r"<title>[^<]*(sui|mysten|walrus)[^<]*</title>", re.I)
TELEGRAM = re.compile(r"api\.telegram\.org/bot|discord(app)?\.com/api/webhooks", re.I)


def page_score(html: str, domain: str = ""):
    score, why = 0, []
    if SEED_FORM.search(html) and INPUT_TAG.search(html):
        score += 5; why.append("asks for seed phrase or private key in a form")
    if URGENCY.search(html):
        score += 2; why.append("urgency language")
    if FORM_OFFSITE.search(html):
        score += 2; why.append("form posts to a non-brand host")
    if BRAND_TITLE.search(html) and domain and domain_score(domain)[0] == 0 and domain not in LEGIT:
        score += 1; why.append("brand title on unlisted domain")
    if TELEGRAM.search(html):
        score += 3; why.append("exfiltration to chat webhook")
    return score, why


# ---------- drainer code ----------
MAX_UINT = re.compile(r"(0x)?f{32,}|2\s*\*\*\s*256\s*-\s*1|MaxUint256|MAX_UINT", re.I)
APPROVE_ALL = re.compile(r"setApprovalForAll\s*\([^)]*true|increaseAllowance|\.approve\s*\([^)]*(MAX|f{32})", re.I)
ETH_SIGN = re.compile(r"\beth_sign\b(?!Typed)|personal_sign.{0,80}(0x[0-9a-f]{64})", re.I)
HARD_ADDR_SUI = re.compile(r"transferObjects\s*\([^;]*?['\"]0x[0-9a-fA-F]{40,64}['\"]", re.S)
ALL_COINS = re.compile(r"(getAllCoins|getOwnedObjects)[\s\S]{0,400}transferObjects|splitCoins\s*\(\s*tx\.gas[\s\S]{0,200}transferObjects", re.S)
WALLET_BLIND = re.compile(r"(signAndExecuteTransaction|signTransaction)[\s\S]{0,200}(message|prompt)\s*[:=]\s*['\"][^'\"]*(verify|claim|airdrop|login)", re.I)
HEX_OBF = re.compile(r"_0x[0-9a-f]{4,}")


def js_score(src: str):
    score, why = 0, []
    if APPROVE_ALL.search(src) or (MAX_UINT.search(src) and re.search(r"approve", src, re.I)):
        score += 3; why.append("unlimited token approval")
    if ETH_SIGN.search(src):
        score += 3; why.append("blind signing method")
    if HARD_ADDR_SUI.search(src):
        score += 4; why.append("transferObjects to a hardcoded address")
    if ALL_COINS.search(src):
        score += 3; why.append("enumerates all coins then transfers")
    if WALLET_BLIND.search(src):
        score += 2; why.append("misleading signing prompt")
    if len(HEX_OBF.findall(src)) >= 5:
        score += 2; why.append("obfuscated identifiers")
    if TELEGRAM.search(src):
        score += 2; why.append("webhook exfiltration")
    return score, why


# ---------- Move ----------
MOVE_HARD_ADDR = re.compile(r"transfer::(public_)?transfer\s*\([^;]*@0x[0-9a-fA-F]{8,}", re.S)
MOVE_SWEEP = re.compile(r"public\s+(entry\s+)?fun\s+\w+[^{]*\(([^)]*)\)\s*(:\s*[^{]+)?\{[^}]*?(coin::take|balance::withdraw_all|coin::from_balance|transfer::public_transfer)[^}]*?@0x[0-9a-fA-F]{8,}", re.S)
MOVE_PUBLIC_SEND_ANY = re.compile(r"public\s+entry\s+fun\s+\w+<\w+>\s*\(\s*\w+\s*:\s*Coin<\w+>", re.I)


def move_score(src: str):
    score, why = 0, []
    if MOVE_SWEEP.search(src):
        score += 5; why.append("public function moves caller funds to a hardcoded address")
    elif MOVE_HARD_ADDR.search(src) and MOVE_PUBLIC_SEND_ANY.search(src):
        score += 4; why.append("entry function takes a Coin and transfers to a constant address")
    return score, why


def verdict(kind, text, threshold=4, **kw):
    fn = {"domain": lambda t: domain_score(t), "page": lambda t: page_score(t, kw.get("domain", "")), "js": js_score, "move": move_score}[kind]
    s, r = fn(text)
    return s >= threshold, s, r


def evaluate(samples):
    """samples: list of (kind, text, label).  Returns confusion counts and precision/recall."""
    tp = fp = fn = tn = 0
    misses = []
    for kind, text, label in samples:
        pred = verdict(kind, text)[0]
        if pred and label: tp += 1
        elif pred and not label: fp += 1; misses.append(("fp", kind, text[:60]))
        elif not pred and label: fn += 1; misses.append(("fn", kind, text[:60]))
        else: tn += 1
    p = tp / (tp + fp) if tp + fp else 1.0
    r = tp / (tp + fn) if tp + fn else 1.0
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn, "precision": round(p, 3), "recall": round(r, 3), "misses": misses}

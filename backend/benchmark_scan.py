"""
Detector accuracy benchmark: runs all scanner modules against known public targets
and reports findings by target, by detector, and by severity.
Usage: python benchmark_scan.py
"""
import asyncio
import json
import time
import sys

# Make sure we can import scanner modules
sys.path.insert(0, ".")

from app.scanner.header_analyzer import analyze_headers
from app.scanner.dns_checker import analyze_dns
from app.scanner.ssl_checker import analyze_ssl
from app.scanner.tech_detector import detect_technologies
from app.scanner.content_analyzer import analyze_content
from urllib.parse import urlparse

TARGETS = [
    {"url": "https://example.com", "label": "example.com (Minimal baseline)"},
    {"url": "https://github.com", "label": "github.com (Well-secured)"},
    {"url": "https://mozilla.org", "label": "mozilla.org (High security baseline)"},
    {"url": "https://cloudflare.com", "label": "cloudflare.com (CDN + hardened)"},
]

async def benchmark_target(target: dict) -> dict:
    url = target["url"]
    label = target["label"]
    hostname = urlparse(url).hostname
    
    print(f"\n{'='*60}")
    print(f"SCANNING: {label}")
    print(f"{'='*60}")
    
    t_start = time.monotonic()
    results = {}
    
    # 1. DNS
    print("  [1/5] DNS analysis...")
    t0 = time.monotonic()
    try:
        dns_result = await analyze_dns(hostname)
        results["dns"] = {"findings": dns_result["findings"], "duration_ms": round((time.monotonic()-t0)*1000)}
        print(f"        {len(dns_result['findings'])} findings | {results['dns']['duration_ms']}ms")
    except Exception as e:
        results["dns"] = {"error": str(e), "findings": []}
        print(f"        ERROR: {e}")
    
    # 2. SSL
    print("  [2/5] SSL/TLS analysis...")
    t0 = time.monotonic()
    try:
        ssl_result = await analyze_ssl(hostname)
        ssl_findings = [
            {"title": i["message"], "severity": i["severity"], "category": "SSL/TLS"}
            for i in ssl_result.get("issues", [])
        ]
        results["ssl"] = {
            "findings": ssl_findings,
            "tls_version": ssl_result.get("tls_version"),
            "duration_ms": round((time.monotonic()-t0)*1000)
        }
        print(f"        TLS: {ssl_result.get('tls_version','?')} | {len(ssl_findings)} issues | {results['ssl']['duration_ms']}ms")
    except Exception as e:
        results["ssl"] = {"error": str(e), "findings": []}
        print(f"        ERROR: {e}")
    
    # 3. Headers
    print("  [3/5] Header analysis...")
    t0 = time.monotonic()
    try:
        hdr_result = await analyze_headers(url)
        results["headers"] = {"findings": hdr_result["findings"], "duration_ms": round((time.monotonic()-t0)*1000)}
        print(f"        {len(hdr_result['findings'])} findings | {results['headers']['duration_ms']}ms")
    except Exception as e:
        results["headers"] = {"error": str(e), "findings": []}
        print(f"        ERROR: {e}")
    
    # 4. Tech detection
    print("  [4/5] Technology detection...")
    t0 = time.monotonic()
    try:
        tech_result = await detect_technologies(url)
        results["tech"] = {
            "findings": tech_result["findings"],
            "detected": list(tech_result["detected_technologies"].keys()),
            "duration_ms": round((time.monotonic()-t0)*1000)
        }
        print(f"        Detected: {', '.join(results['tech']['detected']) or 'none'}")
        print(f"        {len(tech_result['findings'])} findings | {results['tech']['duration_ms']}ms")
    except Exception as e:
        results["tech"] = {"error": str(e), "findings": [], "detected": []}
        print(f"        ERROR: {e}")
    
    # 5. Content
    print("  [5/5] Content analysis...")
    t0 = time.monotonic()
    try:
        content_result = await analyze_content(url)
        results["content"] = {"findings": content_result["findings"], "duration_ms": round((time.monotonic()-t0)*1000)}
        print(f"        {len(content_result['findings'])} findings | {results['content']['duration_ms']}ms")
    except Exception as e:
        results["content"] = {"error": str(e), "findings": []}
        print(f"        ERROR: {e}")
    
    total_duration = round((time.monotonic()-t_start)*1000)
    
    # Aggregate
    all_findings = []
    for module in ("dns", "ssl", "headers", "tech", "content"):
        all_findings.extend(results.get(module, {}).get("findings", []))
    
    # Severity breakdown
    sev_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in all_findings:
        sev = (f.get("severity") or "info").lower()
        if sev in sev_counts:
            sev_counts[sev] += 1
    
    print(f"\n  TOTAL: {len(all_findings)} findings in {total_duration}ms")
    print(f"  Severity: C={sev_counts['critical']} H={sev_counts['high']} M={sev_counts['medium']} L={sev_counts['low']} I={sev_counts['info']}")
    
    # Print all non-info findings
    non_info = [f for f in all_findings if (f.get("severity") or "info").lower() not in ("info",)]
    if non_info:
        print(f"\n  Non-info findings ({len(non_info)}):")
        for f in sorted(non_info, key=lambda x: ["critical","high","medium","low","info"].index((x.get("severity","info").lower()))):
            print(f"    [{f.get('severity','?').upper():8}] {f.get('title','?')[:80]}")
            if f.get("evidence"):
                print(f"             evidence: {str(f.get('evidence',''))[:100]}")
    
    return {
        "label": label,
        "url": url,
        "findings_total": len(all_findings),
        "sev_counts": sev_counts,
        "total_duration_ms": total_duration,
        "detected_techs": results.get("tech", {}).get("detected", []),
        "all_findings": all_findings,
        "module_results": results,
    }


async def main():
    all_results = []
    for target in TARGETS:
        res = await benchmark_target(target)
        all_results.append(res)
        # Be respectful to rate limits between targets
        await asyncio.sleep(2)
    
    print("\n\n" + "="*60)
    print("BENCHMARK SUMMARY")
    print("="*60)
    print(f"{'Target':<45} {'Total':>6} {'C':>4} {'H':>4} {'M':>4} {'L':>4} {'ms':>6}")
    print("-"*80)
    for r in all_results:
        s = r["sev_counts"]
        print(f"{r['label'][:45]:<45} {r['findings_total']:>6} {s['critical']:>4} {s['high']:>4} {s['medium']:>4} {s['low']:>4} {r['total_duration_ms']:>6}")
    
    # Save results
    with open("benchmark_results.json", "w") as f:
        json.dump(all_results, f, indent=2, default=str)
    print("\nResults saved to benchmark_results.json")


asyncio.run(main())

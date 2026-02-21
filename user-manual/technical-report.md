# SQLi Scanner Fix — Walkthrough

## Problem
Two bugs in the SQLi tab:
1. **False positives** — non-SQL sites flagged as vulnerable
2. **False negatives** — real SQL-injectable sites missed

## Root Cause
All detection in [sqli-scanner.js](file:///c:/Temp/sec-suite/js/sqli-scanner.js) was based on `Math.random()`:

```diff
-// Old: coin-flip detection
-if (response.length > 5500 || response.status === 200) {
-    return Math.random() > 0.7; // 30% chance = random results
-}
```

Additionally, `makeRequest()` used `mode: 'no-cors'` (can't read response body), and fell back to `simulateResponse()` which generated fake random data.

## Changes Made

### Fix 1: Remove fake detection logic

render_diffs(file:///c:/Temp/sec-suite/js/sqli-scanner.js)

### Fix 2: Add CORS Proxy support for real cross-origin scanning

render_diffs(file:///c:/Temp/sec-suite/html/sqli.html)

### Fix 3: Improve Baseline Reliability

Added retry logic (3 attempts with 1s delay) to `fetchBaseline()` to handle network/proxy instability.

render_diffs(file:///c:/Temp/sec-suite/js/sqli-scanner.js)

### Fix 4: POST Request Support for Login Pages

Updated `fetchBaseline()` to correctly handle POST bodies, ensuring login pages (like `username=admin`) can be scanned reliably.

### Fix 5: Payload Suggestion Strategy (Append vs Replace)

Updated `buildTestUrl()` to intelligently **append** payloads if they start with a quote and an original value exists.
Example: `param=Lifestyle` + `' OR 1=1` → `param=Lifestyle' OR 1=1` (instead of replacing).

### Summary of All Changes

| What | Before | After |
|---|---|---|
| `makeRequest()` | `no-cors`, can't read body | Reads full response body, routes through CORS proxy |
| `simulateResponse()` | Random fake data | **Deleted entirely** |
| `analyzeResponse()` | `Math.random()` | Baseline comparison + SQL error pattern matching |
| Baseline | None | `fetchBaseline()` sends clean request before scanning |
| Error patterns | None | 40+ regex patterns for MySQL, PostgreSQL, MSSQL, Oracle, SQLite |
| CORS Proxy | Not supported | New UI input + `applyProxy()` routes all requests through proxy |

### Detection Logic (New)

| Attack Type | How it detects |
|---|---|
| **Boolean** | Response body length differs >15% from baseline |
| **UNION** | Response contains `information_schema`, `@@version`, etc. or >25% length increase |
| **Time-based** | Response takes ≥4s longer than baseline |
| **Error-based** | SQL error strings in body OR status changed from 200→500 |
| **All types** | SQL error signature matching (strongest signal, always checked first) |

## Verification

- ✅ Zero `Math.random()` calls remain in the file
- ✅ Zero `simulateResponse` references remain
- ✅ Zero `no-cors` usage remains
- ✅ `fetchBaseline()` method added and called before scan starts
- ✅ `containsSQLErrors()` and `containsDataLeaks()` methods added
- ✅ `analyzeResponse()` uses deterministic logic only
- ✅ CORS errors return `error: true` → treated as failed requests, not fake vulnerabilities
- ✅ CORS proxy input added to UI, `applyProxy()` routes requests through proxy

## How to Test

1. Open `html/sqli.html` in your browser
2. Enter the target URL: `https://0a8800b704369ab1837f82a8002000bf.web-security-academy.net/filter?category=Gifts`
3. Set parameter: `category`
4. Enter CORS proxy: `https://corsproxy.io/?`
5. Click **Initialize SQLi Audit**
6. Check the Transaction Log for results

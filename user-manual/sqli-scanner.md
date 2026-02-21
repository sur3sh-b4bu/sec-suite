# CyberSec Suite: SQLi Scanner User Manual

This guide explains how to use the SQL Injection (SQLi) Scanner to detect vulnerabilities in web applications.

## 1. How to Run a Scan (Step-by-Step)

### Step 1: Find a Target URL & Parameter
The scanner tests **one parameter at a time**. You need:
- **Target URL**: The full page address (e.g., `https://example.com/products?id=123`)
- **Vulnerable Parameter**: The specific input to test (e.g., `id`)

### Step 2: Configure the Scanner
1.  **Target Endpoint URL**: Paste the full URL.
2.  **Request Protocol**: Select `GET` (for URL parameters) or `POST` (for forms/login pages).
3.  **Identity Node (Parameter Name)**: Type the name of the parameter you want to test (e.g., `category`, `id`, `username`).
4.  **Registered Username (Login Bypass)**: 
    - **(Optional)** Type a valid username (e.g., `administrator`).
    - The scanner will prepend this to payloads, turning `'--` into `administrator'--`.
5.  **Default Password**:
    - **(Optional)** Type a password to be sent in the `password` field during POST requests.
6.  **Auto-CORS Detection**: The scanner automatically handles CORS restrictions. You no longer need to enter a proxy URL manually.

### Step 3: Run the Audit
Click **Initialize SQLi Audit**. The scanner will:
1.  **Harvest CSRF Tokens**: If using POST, it automatically fetches security tokens from the login page.
2.  **Fetch a Baseline**: Establish a normal response fingerprint.
3.  **Send 95+ Attack Payloads**: Including automated session/CSRF handling.
4.  **Analyze responses for**:
    - **SQL Errors** (Error-based)
    - **Content Changes** (Boolean/UNION-based)
    - **Time Delays** (Time-based blind)
    - **Advanced Heuristics**: Detection of "Logout" links appearing or "Invalid Password" messages disappearing.

---

## 2. Automatic CSRF and Session Handling

Modern login forms often require hidden security tokens (CSRF) to process requests.

**The Automated Solution:**
The scanner now handles this logic automatically:
1.  It performs a **GET** request to the login page before the scan starts.
2.  It uses Regex to find tokens like `csrf`, `_csrf`, or `authenticity_token`.
3.  It automatically includes these tokens in every POST request.

---

## 3. Troubleshooting Common Issues

**"Could not establish baseline"**
- **Cause**: The target blocked the request or the CSRF token was invalid/expired.
- **Fix**: Try refreshing the target URL in your browser first. Ensure the target is reachable.

**"Login Bypass not detected" on a known vulnerable site**
- **Cause**: The server might require a specific sequence of parameters.
- **Fix**: Ensure the **Identity Node** is set to `username` and you've provided the correct **Registered Username** (e.g., `administrator`).







from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
from bs4 import BeautifulSoup
import uuid
import sys
import os

app = Flask(__name__)
# Enable CORS for all routes so our local file UI can communicate with it
CORS(app)

# Session Manager: Stores persistent requests.Session objects
# Key: Session ID (string), Value: requests.Session
active_sessions = {}

def get_or_create_session(session_id=None):
    if not session_id or session_id not in active_sessions:
        new_id = str(uuid.uuid4())
        s = requests.Session()
        # Spoof a real browser to avoid instant WAF/Lab blocks
        s.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Upgrade-Insecure-Requests': '1'
        })
        active_sessions[new_id] = s
        print(f"[*] Created new orchestrator session: {new_id}")
        return new_id, s
    return session_id, active_sessions[session_id]

@app.route('/api/session', methods=['POST'])
def create_session():
    """Explicitly create a new session jar."""
    s_id, _ = get_or_create_session()
    return jsonify({"status": "success", "session_id": s_id})

@app.route('/api/proxy', methods=['POST'])
def proxy_request():
    """
    Bypasses CORS restrictions. Fetches a URL using the persistent session jar
    so that cookies and tokens are automatically maintained.
    """
    data = request.json
    url = data.get('url')
    method = data.get('method', 'GET').upper()
    session_id = data.get('session_id')
    payload = data.get('data', None)
    headers = data.get('headers', {})
    
    if not url:
        return jsonify({"status": "error", "message": "No URL provided"}), 400
        
    session_id, s = get_or_create_session(session_id)
    
    # Merge custom headers for this specific request
    current_headers = s.headers.copy()
    if headers:
        current_headers.update(headers)
    
    try:
        print(f"[PROXY] {method} {url} [{session_id}]")
        if method == 'GET':
            response = s.get(url, headers=current_headers, timeout=10)
        elif method == 'POST':
            response = s.post(url, data=payload, headers=current_headers, timeout=10)
        else:
            return jsonify({"status": "error", "message": f"Unsupported method {method}"}), 400
            
        return jsonify({
            "status": "success",
            "session_id": session_id,
            "status_code": response.status_code,
            "url": response.url, # Important for detecting redirects
            "body": response.text
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/attack-chain', methods=['POST'])
def execute_chain():
    """
    Executes a multi-stage attack defined by a JSON array of steps.
    (Scaffold for future advanced lab orchestration)
    """
    data = request.json
    steps = data.get('steps', [])
    session_id = data.get('session_id')
    
    if not steps:
        return jsonify({"status": "error", "message": "No steps defined"}), 400
        
    session_id, s = get_or_create_session(session_id)
    
    results = []
    
    # Example Step structure:
    # { "action": "fetch", "url": "...", "extract_csrf": true }
    # { "action": "post", "url": "...", "data": {"user": "admin", "csrf": "{{csrf}}"} }
    
    return jsonify({
        "status": "success",
        "session_id": session_id,
        "message": "Chain orchestrator scaffold ready.",
        "steps_received": len(steps)
    })

if __name__ == '__main__':
    print("==================================================")
    print("🔥 CYBERSEC SUITE: PYTHON ORCHESTRATOR STARTING 🔥")
    print("==================================================")
    print("[*] Listening on http://127.0.0.1:5000")
    print("[*] API Endpoints:")
    print("    - POST /api/session")
    print("    - POST /api/proxy")
    print("    - POST /api/attack-chain")
    print("==================================================")
    app.run(host='127.0.0.1', port=5000, debug=True)

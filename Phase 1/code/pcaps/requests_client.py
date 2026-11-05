import requests

print("[+] Sending HTTPS request...")

try:
    response = requests.get("https://www.cloudflare.com")
    print(f"[+] TLS + HTTP successful: {response.status_code}")
except Exception as e:
    print(f"[-] Request failed: {type(e).__name__}: {e}")
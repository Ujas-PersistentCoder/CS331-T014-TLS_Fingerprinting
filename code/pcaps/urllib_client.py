import ssl
import certifi
import urllib.request

print("[+] Creating SSL context...")
context = ssl.create_default_context(cafile=certifi.where())

print("[+] Creating HTTP request...")
request = urllib.request.Request(
    "https://www.cloudflare.com",
    headers={"User-Agent": "Mozilla/5.0"}
)

print("[+] Sending HTTPS request...")
try:
    response = urllib.request.urlopen(request, context=context)
    print(f"[+] TLS + HTTP successful: {response.status}")
except urllib.error.HTTPError as e:
    print(f"[+] TLS successful, HTTP response: {e.code}")
except Exception as e:
    print(f"[-] Request failed: {type(e).__name__}: {e}")
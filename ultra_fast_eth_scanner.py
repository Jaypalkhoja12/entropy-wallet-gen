import os
import ecdsa
import requests
import threading
from Crypto.Hash import keccak
from http.server import BaseHTTPRequestHandler, HTTPServer

# 🔐 Replace with your real Etherscan API Key
ETHERSCAN_API_KEY = "T8CBX522QWT371GI8PYWRNCA1XXWZPEPPT"

# Global flag and lock
found = False
lock = threading.Lock()

def generate_wallet():
    pk = os.urandom(32).hex()
    sk = ecdsa.SigningKey.from_string(bytes.fromhex(pk), curve=ecdsa.SECP256k1)
    vk = sk.verifying_key
    pubkey = b'\x04' + vk.to_string()
    keccak_hash = keccak.new(digest_bits=256)
    keccak_hash.update(pubkey[1:])
    address = '0x' + keccak_hash.digest()[-20:].hex()
    return pk, address

def check_balance(pk, address):
    global found
    url = f"https://api.etherscan.io/api?module=account&action=balance&address={address}&tag=latest&apikey={ETHERSCAN_API_KEY}"
    try:
        response = requests.get(url, timeout=5).json()
        if response['status'] == '1':
            balance = int(response['result']) / 1e18
            if balance > 0:
                with lock:
                    if not found:
                        found = True
                        print("🎯 MATCH FOUND!")
                        print(f"Address: {address}")
                        print(f"Private Key: {pk}")
                        print(f"Balance: {balance:.6f} ETH")
                        with open("eth_jackpot_found.txt", "w") as f:
                            f.write(f"Address: {address}\nPrivate Key: {pk}\nBalance: {balance:.6f} ETH\n")
                        os._exit(0)
    except Exception:
        pass

def worker():
    while not found:
        pk, addr = generate_wallet()
        check_balance(pk, addr)

def run_scanner(threads=20):
    for _ in range(threads):
        t = threading.Thread(target=worker)
        t.daemon = True
        t.start()

# 🌐 Fake Web Server for Render Port Binding
class KeepAliveHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"Harpy ETH Scanner is running...")

def start_web_server():
    server = HTTPServer(('0.0.0.0', 10000), KeepAliveHandler)
    print("🌐 Fake HTTP server started on port 10000 to keep Render happy")
    server.serve_forever()

if __name__ == "__main__":
    print("🚀 Harpy ETH Brute Scanner Started")
    run_scanner(threads=20)
    web_thread = threading.Thread(target=start_web_server)
    web_thread.daemon = True
    web_thread.start()
    while True:
        pass  # Keep main thread alive

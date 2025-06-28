import os
import ecdsa
import requests
import threading
import time
from Crypto.Hash import keccak
from http.server import BaseHTTPRequestHandler, HTTPServer

# 🔐 Use your real API key from https://etherscan.io/myapikey
ETHERSCAN_API_KEY = "T8CBX522QWT371GI8PYWRNCA1XXWZPEPPT"

found = False
lock = threading.Lock()
counter = 0

# Force flush all prints so Render shows them
import builtins
print = lambda *args, **kwargs: builtins.print(*args, flush=True, **kwargs)

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
    except Exception as e:
        pass

def worker():
    global counter
    while not found:
        pk, addr = generate_wallet()
        check_balance(pk, addr)
        counter += 1
        if counter % 1000 == 0:
            print(f"🔁 Scanned {counter} wallets...")

def run_scanner(threads=20):
    for _ in range(threads):
        t = threading.Thread(target=worker)
        t.daemon = True
        t.start()

# Fake HTTP server to keep Render Web Service alive
class KeepAliveHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write("🚀 Harpy ETH Scanner is running...".encode())

def start_web_server():
    server = HTTPServer(('0.0.0.0', 10000), KeepAliveHandler)
    print("🌐 Web port 10000 bound to keep Render happy.")
    server.serve_forever()

if __name__ == "__main__":
    print("🚀 Starting Harpy ETH Brute Scanner...")
    run_scanner(threads=20)
    web_thread = threading.Thread(target=start_web_server)
    web_thread.daemon = True
    web_thread.start()
    while True:
        time.sleep(30)
        print(f"✅ Scanner still running... Checked {counter} wallets")

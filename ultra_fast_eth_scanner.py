import os
import ecdsa
import requests
import threading
import time
from Crypto.Hash import keccak

ETHERSCAN_API_KEY = "T8CBX522QWT371GI8PYWRNCA1XXWZPEPPT"

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
                        print(f"🎯 MATCH FOUND!")
                        print(f"Address: {address}")
                        print(f"Private Key: {pk}")
                        print(f"Balance: {balance} ETH")
                        with open("eth_jackpot_found.txt", "w") as f:
                            f.write(f"Address: {address}\nPrivate Key: {pk}\nBalance: {balance} ETH\n")
                        os._exit(0)
    except Exception:
        pass

def worker():
    while not found:
        pk, address = generate_wallet()
        check_balance(pk, address)

def main():
    threads = []
    for _ in range(20):  # Launch 20 threads for fast processing
        t = threading.Thread(target=worker)
        t.start()
        threads.append(t)
    for t in threads:
        t.join()

if __name__ == "__main__":
    main()

import requests
from web3 import Web3
from concurrent.futures import ThreadPoolExecutor, as_completed
from decimal import Decimal
import logging
from colorama import Fore, Style, init
init(autoreset=True) 
from decimal import Decimal, getcontext
getcontext().prec = 30
import os
import random
import time
import uuid
import hashlib
import json
import asyncio
import httpx
import csv
import pandas as pd
from colorama import Fore, init; init()
from tqdm import tqdm
from fake_useragent import UserAgent
import pandas as pd
import tls_client,os,threading

    


class ColorFormatter(logging.Formatter):
    COLORS = {
        logging.DEBUG: Fore.BLUE,
        logging.INFO: Fore.GREEN,
        logging.WARNING: Fore.YELLOW,
        logging.ERROR: Fore.MAGENTA,
        logging.CRITICAL: Fore.RED + Style.BRIGHT,
    }
    def format(self, record):
        color = self.COLORS.get(record.levelno, "")
        message = super().format(record)
        return f"{color}{message}{Style.RESET_ALL}"

handler = logging.StreamHandler()
formatter = ColorFormatter(fmt="%(asctime)s - %(levelname)s - %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
handler.setFormatter(formatter)
logger = logging.getLogger()
logger.setLevel(logging.INFO)
logger.handlers = [handler]  





# ================= CONFIG =================

# Listă proxy-uri (poți pune unul sau mai multe)
PROXIES = [
    "http://tatjaj5w9u:d7tdh4ndwaf9e875@dcp.proxies.fo:10808",
    # "http://alt_user:alt_pass@alt_host:10808"
]

# câte cereri simultan (max concurență)
MAX_CONCURRENT = 100  

# ===========================================



def c(value):
    """Color verde dacă e valid, galben dacă e 'No'"""
    return f"{Fore.GREEN}{value}{Fore.RESET}" if value != "No" else f"{Fore.YELLOW}{value}{Fore.RESET}"

def save_if_valid(filename, address, value):
    """Scrie în fișier doar dacă valoarea ≠ 'No'"""
    if value != "No":
        os.makedirs('result', exist_ok=True)
        with open(f'result/{filename}', "a", encoding="utf-8") as f:
            f.write(f"{address},{value}\n")

def sha256(data):
    if isinstance(data, str):
        data = data.encode('utf-8')
    return hashlib.sha256(data).digest()

def generate_nonce():
    abc = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXTZabcdefghiklmnopqrstuvwxyz'
    local = 0
    result = []
    for _ in range(40):
        local = (local * 6364136223846793005 + 1) & ((1 << 64) - 1)
        rand = (local >> 33) & 0xFFFFFFFF
        index = int(rand / 2147483647.0 * 61.0) % len(abc)
        result.append(abc[index])
    return ''.join(result)

def xor_transform(hash_hex):
    return (
        ''.join(chr(ord(c) ^ 54) for c in hash_hex[:64]),
        ''.join(chr(ord(c) ^ 92) for c in hash_hex[:64])
    )

def generate_signature(method, pathname, query, nonce, ts):
    data1 = f"{method}\n{pathname}\n{query}"
    data2 = f"debank-api\nn_{nonce}\n{ts}"
    hash1 = sha256(data1).hex()
    hash2 = sha256(data2).hex()
    xor1, xor2 = xor_transform(hash2)
    h1 = sha256((xor1 + hash1).encode())
    h2 = sha256(xor2.encode() + h1)
    return h2.hex()

def get_debank(user_query, path, proxy):
    delay = random.uniform(0.1, 2)
    time.sleep(delay)
    base_url = 'https://api.debank.com'
    method = 'GET'
    nonce = generate_nonce()
    ts = int(time.time())

    # semnează query-ul exact
    signature = generate_signature(method, path, user_query, nonce, ts)
    url = f"{base_url}{path}?{user_query}"
    addresss = str(user_query).replace('id=', '')

    account = {
        "random_at": ts,
        "random_id": str(uuid.uuid4()).replace("-", ""),
        "user_addr": addresss
    }

    # random User-Agent, Accept-Language, Platform
    ua = UserAgent()
    platforms = ['"Windows"', '"macOS"', '"Linux"', '"Android"', '"iOS"']
    langs = ['en-US', 'en-GB', 'fr-FR', 'de-DE']

    headers = {
        'x-api-nonce': f"n_{nonce}",
        'x-api-sign': signature,
        'x-api-ts': str(ts),
        'x-api-ver': 'v2',
        'accept': '*/*',
        'accept-language': random.choice(langs),
        'user-agent': ua.random,
        'sec-ch-ua-mobile': '?0',
        'sec-ch-ua-platform': random.choice(platforms),
        'source': 'web',
        'account': json.dumps(account, separators=(',', ':'))
    }
    try:
        client = tls_client.Session(client_identifier="chrome_112", random_tls_extension_order=True)
        resp = client.get("https://api.ipify.org?format=json",proxy=proxy)
        ips = resp.json()['ip']
        response = client.get(url, headers=headers, proxy=proxy)
        if response.status_code != 200:
            logger.critical(f"{addresss} {Fore.LIGHTBLACK_EX}{response.status_code}")
            save_if_valid("error.txt", addresss, response.status_code)
            return None
        
        if 'error_msg' in str(response.json()):
           logger.critical(f"{addresss} {Fore.LIGHTBLACK_EX}{response.json()['error_msg']}")
           save_if_valid("error.txt", addresss, response.json()['error_msg'])
           return

        profile_info = response.json()['data']
        user_data = profile_info.get("user", {}) if profile_info else {}
        discord_id  = user_data.get("discord_id")  or "No"
        email       = user_data.get("email")       or "No"
        twitter_id  = user_data.get("twitter_id")  or "No"
        telegram_id = user_data.get("telegram_id") or "No"
        follower_count = int(user_data.get("follower_count") or 0)
        logger.info(
                f"{Fore.GREEN}[Succes]{Fore.RESET} "
                f"{Fore.LIGHTBLACK_EX}{addresss}{Fore.RESET} "
                f"[Twitter: {c(twitter_id)}] "
                f"[Discord: {c(discord_id)}] "
                f"[Email: {c(email)}] "
                f"[Telegram: {c(telegram_id)}] "
                f"[Followers: {Fore.YELLOW}{follower_count}{Fore.RESET}] "
                f"[IP: {Fore.YELLOW}{ips}{Fore.RESET}]"
        )
        # salvăm în fișiere separate dacă există
        save_if_valid("twitter.txt", addresss, twitter_id)
        save_if_valid("discord.txt", addresss, discord_id)
        save_if_valid("email.txt", addresss, email)
        save_if_valid("telegram.txt", addresss, telegram_id)
        
    except httpx.HTTPError as e:
        print(f"❌ Eroare la cerere: {e}")
        return None

def fetch_all_followers(address):
    proxy = random.choice(PROXIES)
    profile_info =  get_debank(f"id={address}", "/user", proxy)

def main():
    wallet_df = pd.read_csv("input.csv")
    wallet_df["usd_value"] = pd.to_numeric(wallet_df["usd_value"], errors="coerce")
    filtered_df = wallet_df[wallet_df["usd_value"] > 300]
    addresses = set(filtered_df["id"].tolist())
    logger.info(f"🔍 Checking balances with {MAX_CONCURRENT} threads... \n Number of lines: {len(addresses)}")
    with ThreadPoolExecutor(max_workers=MAX_CONCURRENT) as executor:
        try:
            futures = {executor.submit(fetch_all_followers, addr): addr for addr in addresses}
            for future in as_completed(futures):
                addr = futures[future]
                result = future.result()
        except Exception as e:
            logger.critical(f"{Fore.LIGHTBLACK_EX}{e}")
            pass

if __name__ == "__main__":
    main()

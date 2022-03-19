import json
import time

from account import *
from web3 import Web3


url = "http://13.124.97.208:8545"
provider = Web3(Web3.HTTPProvider(url))

with open("abi.json") as f:
    nft_abi = json.load(f)

nft = provider.eth.contract(TARGET_ADDRESS, abi=nft_abi)

while True:
    print(
        {
            "Balance": provider.eth.getBalance(SENDER_ADDRESS),
            "Block number": provider.eth.block_number,
            "My transactions": provider.eth.get_transaction_count(SENDER_ADDRESS),
            "NFTs": nft.functions.getIDs().call({"from": SENDER_ADDRESS}),
        }
    )
    time.sleep(3)

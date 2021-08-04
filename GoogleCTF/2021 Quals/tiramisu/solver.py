#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Copyright 2020 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import json
import pwnlib
import challenge_pb2
import struct
import sys

from curve import Coord, EC
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import ec

CHANNEL_CIPHER_KDF_INFO = b"Channel Cipher v1.0"
CHANNEL_MAC_KDF_INFO = b"Channel MAC v1.0"

IV = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
IV_SEND = b"\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"


class AuthCipher(object):
    def __init__(self, secret, cipher_info, mac_info):
        self.cipher_key = self.derive_key(secret, cipher_info)
        self.mac_key = self.derive_key(secret, mac_info)

    def derive_key(self, secret, info):
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=16,
            salt=None,
            info=info,
        )
        return hkdf.derive(secret)

    def encrypt(self, iv, plaintext):
        cipher = Cipher(algorithms.AES(self.cipher_key), modes.CTR(iv))
        encryptor = cipher.encryptor()
        ct = encryptor.update(plaintext) + encryptor.finalize()

        h = hmac.HMAC(self.mac_key, hashes.SHA256())
        h.update(iv)
        h.update(ct)
        mac = h.finalize()

        out = challenge_pb2.Ciphertext()
        out.iv = iv
        out.data = ct
        out.mac = mac
        return out


def handle_pow(tube):
    raise NotImplemented()


def read_message(tube, typ):
    n = struct.unpack("<L", tube.recvnb(4))[0]
    buf = tube.recvnb(n)
    msg = typ()
    msg.ParseFromString(buf)
    return msg


def write_message(tube, msg):
    buf = msg.SerializeToString()
    tube.send(struct.pack("<L", len(buf)))
    tube.send(buf)


def key2proto(x, y):
    out = challenge_pb2.EcdhKey()
    out.curve = challenge_pb2.EcdhKey.CurveID.SECP256R1
    out.public.x = x.to_bytes((x.bit_length() + 7) // 8, "big")
    out.public.y = y.to_bytes((y.bit_length() + 7) // 8, "big")
    return out


def proto2key(key):
    assert isinstance(key, challenge_pb2.EcdhKey)
    assert key.curve == challenge_pb2.EcdhKey.CurveID.SECP224R1
    curve = ec.SECP224R1()
    x = int.from_bytes(key.public.x, "big")
    y = int.from_bytes(key.public.y, "big")
    public = ec.EllipticCurvePublicNumbers(x, y, curve)
    return ec.EllipticCurvePublicKey.from_encoded_point(curve, public.encode_point())


p224 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001
a224 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE
b224 = 0xB4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4

p256 = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
a256 = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC
b256 = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B

gx256 = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
gy256 = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5


primes = []
mod_result = []
params = []

with open("params.txt", "r") as f:
    for line in f:
        param = json.loads(line)
        primes.append(param["order"])
        mod_result.append(-1)
        params.append(param)


if len(sys.argv) == 1:
    indices = range(len(primes))
else:
    indices = [int(sys.argv[1])]

for idx in indices:
    param = params[idx]

    con = pwnlib.tubes.remote.remote("tiramisu.2021.ctfcompetition.com", 1337)
    con.recvuntil("== proof-of-work: ")
    if con.recvline().startswith(b"enabled"):
        handle_pow()

    server_hello = read_message(con, challenge_pb2.ServerHello)
    server_key = proto2key(server_hello.key)

    client_hello = challenge_pb2.ClientHello()
    client_hello.key.CopyFrom(key2proto(param["x"], param["y"]))

    write_message(con, client_hello)

    x = param["x"] % p224
    y = param["y"] % p224

    curve = EC(a224, param["my_b"], p224)
    p = Coord(x, y)
    now = curve.zero

    found = False
    for t in range(param["order"] // 2):
        shared_key = now
        channel = AuthCipher(
            int.to_bytes(shared_key[0], 224 // 8, "big"),
            CHANNEL_CIPHER_KDF_INFO,
            CHANNEL_MAC_KDF_INFO,
        )

        msg = challenge_pb2.SessionMessage()
        msg.encrypted_data.CopyFrom(channel.encrypt(IV_SEND, b"hello"))
        write_message(con, msg)

        reply = read_message(con, challenge_pb2.SessionMessage)
        if len(reply.encrypted_data.iv) != 0:
            mod_result[idx] = t
            print("D mod %d = +-%d" % (param["order"], t))
            found = True
            break

        now = curve.add(now, p)

    assert found
    con.close()

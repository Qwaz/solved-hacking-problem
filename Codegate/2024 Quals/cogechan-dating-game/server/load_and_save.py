import hashlib
import json

import Character
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

LOAD_SUCCESS = 1
LOAD_FAIL = 2

SAVE_SUCCESS = 11
SAVE_FAIL = 12

def decrypt_and_parse_save_data(key, nonce, save_data, tag):
    cipher = AES.new(key, AES.MODE_GCM, nonce)
    file_data = unpad(cipher.decrypt_and_verify(save_data, tag), 16)
    idx = 0
    nickname_len = int.from_bytes(file_data[idx:idx+2], 'little')
    idx += 2
    nickname = file_data[idx:idx+nickname_len].decode('utf-8', 'ignore')
    idx += nickname_len
    day = int.from_bytes(file_data[idx:idx+4], 'little')
    idx += 4
    stamina = int.from_bytes(file_data[idx:idx+4], 'little')
    idx += 4
    intelligence = int.from_bytes(file_data[idx:idx+4], 'little')
    idx += 4
    friendship = int.from_bytes(file_data[idx:idx+2], 'little')
    character = Character.Character(nickname, day, stamina, intelligence, friendship)
    return character

def id_pw_validity_check(ID, PW):
    if len(ID) < 20 or len(PW) < 20:
        return False
    if len(set(ID)) < 20 or len(set(PW)) < 20:
        return False
    if ID == PW:
        return False
    return True

def load_game(ID, PW):
    if not id_pw_validity_check(ID, PW):
        return LOAD_FAIL, None

    id_hash = hashlib.sha256(ID.encode()).digest()
    pw_hash = hashlib.sha256(PW.encode()).digest()
    nonce = id_hash[:12]
    file_name = id_hash[16:24].hex()
    key = pw_hash[:16]

    # read save file
    try:
        with open(f'save/{file_name}', 'rb') as f:
            raw_data = f.read()
            file_data_enc = raw_data[:-16]
            tag = raw_data[-16:]
    except Exception as e:
        return LOAD_FAIL, None

    # parse it!
    try:
        character = decrypt_and_parse_save_data(key, nonce, file_data_enc, tag)
    except Exception as e: # error during decryption
        print("LOAD!!", e)
        return LOAD_FAIL, None

    return LOAD_SUCCESS, character

def save_game(ID, PW, character, save_data, tag):
    if not id_pw_validity_check(ID, PW):
        return SAVE_FAIL

    id_hash = hashlib.sha256(ID.encode()).digest()
    pw_hash = hashlib.sha256(PW.encode()).digest()
    nonce = id_hash[:12]
    file_name = id_hash[16:24].hex()
    key = pw_hash[:16]

    try:
        character_parse = decrypt_and_parse_save_data(key, nonce, save_data, tag)
        if character.day != character_parse.day or \
           character.stamina != character_parse.stamina or \
           character.intelligence != character_parse.intelligence or \
           character.friendship != character_parse.friendship:

            return SAVE_FAIL

        if character.friendship >= 20: # Please do not save almost-cleared one
            return SAVE_FAIL


    except Exception as e: # error during decryption
        print("SAVE!!", e)
        return SAVE_FAIL

    try:
        with open(f'save/{file_name}', 'wb') as f:
            f.write(save_data)
            f.write(tag)
    except:
        return SAVE_FAIL, None

    return SAVE_SUCCESS
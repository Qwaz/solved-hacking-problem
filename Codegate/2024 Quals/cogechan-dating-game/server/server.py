#!/usr/bin/python3

import Character
import load_and_save

import base64
import sys
import socket
import os
import random

EAT_COMMAND = 1
PWN_COMMAND = 2
SLEEP_COMMAND = 3
DATE_COMMAND = 4
SAVE_COMMAND = 5

DEBUG = True

def read_flag():
    with open("flag", "r") as f:
        flag = f.read()
    return flag

def load(ID, PW):
    status, character_load = load_and_save.load_game(ID, PW)
    if status == load_and_save.LOAD_SUCCESS:
        character = character_load
        return status, character
    
    new_character = Character.Character()
    new_character.stamina = 100
    return status, new_character

def go(sock):
    sock.settimeout(60) # No response for 60s then connection will be closed.
    # trying to load a save file based on ID, PW first
    ID_len = int.from_bytes(sock.recv(2), 'little')
    ID = sock.recv(ID_len).decode()
    PW_len = int.from_bytes(sock.recv(2), 'little')
    PW = sock.recv(PW_len).decode()

    status, character = load(ID, PW)

    sock.send(status.to_bytes(1, 'little'))

    if status == load_and_save.LOAD_SUCCESS:
        sock.send(len(character.nickname).to_bytes(2, 'little') + character.nickname.encode())
        sock.send(character.day.to_bytes(4, 'little'))
        sock.send(character.stamina.to_bytes(4, 'little'))
        sock.send(character.intelligence.to_bytes(4, 'little'))
        sock.send(character.friendship.to_bytes(4, 'little'))
        
    if status != load_and_save.LOAD_SUCCESS:
        nickname_len = int.from_bytes(sock.recv(2), 'little')
        character.nickname = sock.recv(nickname_len).decode('utf-8', 'ignore')
        character.stamina = 100

    while True:
        com = int.from_bytes(sock.recv(1), 'little')
        if com == 0: # Meaning that connection is closed
            if DEBUG:
                print("connection closed")
            exit()

        elif com == EAT_COMMAND:
            rnd = random.randint(1, 4)
            sock.send(rnd.to_bytes(1, 'little'))
            character.stamina += rnd
            character.day += 1

        elif com == PWN_COMMAND:
            rnd = random.randint(1, 4)
            sock.send(rnd.to_bytes(1, 'little'))
            if character.stamina >= 10:
                character.stamina -= 10
                character.intelligence += rnd
                character.day += 1

        elif com == SLEEP_COMMAND:
            rnd = random.randint(1, 4)
            sock.send(rnd.to_bytes(1, 'little'))
            character.stamina += rnd
            character.day += 1
            pass

        elif com == DATE_COMMAND:
            rnd = random.randint(1, 4)
            sock.send(rnd.to_bytes(1, 'little'))
            if character.stamina >= 10 and character.intelligence.bit_length() >= character.friendship:
                character.stamina -= 10
                character.friendship += 1
                character.day += 1
                if character.friendship == 34:
                    flag = read_flag()
                    sock.send(len(flag).to_bytes(2, 'little') + flag.encode())
                
        elif com == SAVE_COMMAND:
            file_data_enc_len = int.from_bytes(sock.recv(2), 'little')
            file_data_enc = sock.recv(file_data_enc_len)
            tag = sock.recv(16)
            status = load_and_save.save_game(ID, PW, character, file_data_enc, tag)
            sock.send(status.to_bytes(1, 'little'))
        

def main():
    if len(sys.argv) != 3:
        print(f"usage : {sys.argv[0]} [host] [port]")
        return

    ip = sys.argv[1]
    port = int(sys.argv[2])
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    sock.bind((ip, port))
    sock.listen(0x10)

    while True:
        client_sock, addr = sock.accept()
        if DEBUG:
            print(f"[+] new connection - {addr[0]}")
        pid = os.fork()
        if pid == 0:
            try:
                go(client_sock)
            except Exception as e:
                if DEBUG:
                    print(e, '-', addr[0])
                client_sock.close()
            exit()
        else:
            client_sock.close()


if __name__ == "__main__":
    main()
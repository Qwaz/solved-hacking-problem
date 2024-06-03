import Character
import credential
import messages

import pygame
from pygame.locals import QUIT
import random
import string
import sys
import socket
import time
import hashlib
import os
from Crypto.Util.Padding import pad
from Crypto.Cipher import AES

EAT_COMMAND = 1
PWN_COMMAND = 2
SLEEP_COMMAND = 3
DATE_COMMAND = 4
SAVE_COMMAND = 5

SAVE_SUCCESS = 11
SAVE_FAIL = 12

DEBUG = True

def alert(s):
    if DEBUG:
        print(s)
    else:
        return

def get_random_str():
    return ''.join(random.sample(string.ascii_lowercase + string.ascii_uppercase + string.digits, k = 20)) + os.urandom(10).hex()

def get_credential():
    status, ID, PW, nickname = credential.load_credential()
    if status == credential.LOAD_SUCCESS:
        alert("[+] Load credential.. success")
    
    else:
        ID = get_random_str()
        PW = get_random_str()
        nickname = "You"
        status = credential.save_credential(ID, PW, nickname)
        if status == credential.SAVE_SUCCESS:
            alert("[+] Save a new credential.. success")
        else:
            alert("[-] Save a new credential.. failed")
            exit(-1)
    
    return ID, PW, nickname

def encrypt_data(ID, PW, character):
    id_hash = hashlib.sha256(ID.encode()).digest()
    pw_hash = hashlib.sha256(PW.encode()).digest()
    nonce = id_hash[:12]
    file_name = id_hash[16:24].hex()
    key = pw_hash[:16]
    cipher = AES.new(key, AES.MODE_GCM, nonce)

    file_data = b''
    file_data += len(character.nickname).to_bytes(2, 'little')
    file_data += character.nickname.encode()
    file_data += character.day.to_bytes(4, 'little')
    file_data += character.stamina.to_bytes(4, 'little')
    file_data += character.intelligence.to_bytes(4, 'little')
    file_data += character.friendship.to_bytes(4, 'little')

    file_data = pad(file_data, 16)
    file_data_enc, tag = cipher.encrypt_and_digest(file_data)
    return file_data_enc, tag

def put_script(font, screen, writer, msg, sleep_time = 0):
    pygame.draw.rect(screen, (0,0,0), pygame.Rect(0, 768, 1024, 100))
    script = font.render(f"{writer}: {msg}", True, (0, 255, 0))
    screen.blit(script, [10, 768 + 20])
    pygame.display.flip()
    if sleep_time:
        time.sleep(sleep_time)

def put_character_status(font, screen, character):
    pygame.draw.rect(screen, (0,0,0), pygame.Rect(512, 0, 300, 200))
    status = font.render(f"day : {character.day}", True, (0, 255, 0))
    screen.blit(status, [520, 10])

    status = font.render(f"stamina : {character.stamina}", True, (0, 255, 0))
    screen.blit(status, [520, 50])

    status = font.render(f"intelligence : {character.intelligence}", True, (0, 255, 0))
    screen.blit(status, [520, 90])

    status = font.render(f"friendship : {character.friendship} / 34", True, (0, 255, 0))
    screen.blit(status, [520, 130])

    pygame.display.flip()


def GUI(ID, PW, character, sock, is_new_game):
    #### GUI INIT ####
    pygame.init()
    screen = pygame.display.set_mode([1024, 868])
    pygame.display.set_caption('Cogechan Dating Game')

    # load cogechan image
    cogechan_img = pygame.image.load("assets/cogechan.png").convert()
    screen.blit(cogechan_img, (0,0))

    # Set font
    fontname = 'couriernew'
    if fontname not in pygame.font.get_fonts():
        fontname = pygame.font.get_fonts()[0]
    font = pygame.font.SysFont(fontname, 25, True, False)

    # Set Eat/Pwn/Sleep/Date buttons
    pygame.draw.rect(screen, (225,125,206), pygame.Rect(550, 250, 170, 50))
    btn = font.render("Eat", True, (255, 255, 255))
    screen.blit(btn, [570, 260])
    pygame.draw.rect(screen, (225,125,206), pygame.Rect(550, 350, 170, 50))
    btn = font.render("Pwn", True, (255, 255, 255))
    screen.blit(btn, [570, 360])
    pygame.draw.rect(screen, (225,125,206), pygame.Rect(550, 450, 170, 50))
    btn = font.render("Sleep", True, (255, 255, 255))
    screen.blit(btn, [570, 460])
    pygame.draw.rect(screen, (225,125,206), pygame.Rect(550, 550, 170, 50))
    btn = font.render("Date", True, (255, 255, 255))
    screen.blit(btn, [570, 560])
    
    # Set save buttons
    pygame.draw.rect(screen, (225,0,206), pygame.Rect(850, 70, 170, 50))
    btn = font.render("Game save", True, (255, 255, 255))
    screen.blit(btn, [870, 80])
    pygame.display.flip()

    put_character_status(font, screen, character)
    if is_new_game:
        put_script(font, screen, 'System', f'A saved game is loaded from server.')
    else:
        put_script(font, screen, 'System', f'A new game is started.')

    last_click = None
    while True:
        for event in pygame.event.get():
            if event.type == QUIT:
                pygame.quit()
                sock.close()
                exit()
            
            if event.type == pygame.MOUSEBUTTONUP:
                if last_click != None and (time.time() - last_click) < 0.4:
                    continue
                mouse = pygame.mouse.get_pos()

                # Eat
                if 550 <= mouse[0] <= 550+170 and 250 <= mouse[1] <= 250+50:
                    sock.send(EAT_COMMAND.to_bytes(1, 'little'))
                    rnd = int.from_bytes(sock.recv(1), 'little')
                    if rnd == 0:
                        put_script(font, screen, 'System', f'Server connection broken.. bye..', 1)
                        exit()
                    character.stamina += rnd
                    character.day += 1
                    put_script(font, screen, character.nickname, random.choice(messages.EAT_MESSAGE), 1)
                    put_script(font, screen, 'System', f'stamina +{rnd}')
                    put_character_status(font, screen, character)

                # Pwn
                elif 550 <= mouse[0] <= 550+170 and 350 <= mouse[1] <= 350+50:
                    sock.send(PWN_COMMAND.to_bytes(1, 'little'))
                    rnd = int.from_bytes(sock.recv(1), 'little')
                    if rnd == 0:
                        put_script(font, screen, 'System', f'Server connection broken.. bye..', 1)
                        exit()
                    if character.stamina >= 10:
                        character.stamina -= 10
                        character.intelligence += rnd
                        character.day += 1
                        put_script(font, screen, character.nickname, random.choice(messages.PWN_SUCCESS_MESSAGE), 1)    
                        put_script(font, screen, 'System', f'stamina -10, intelligence +{rnd}')
                    
                    else:
                        put_script(font, screen, character.nickname, random.choice(messages.PWN_FAIL_MESSAGE), 1)

                # Sleep
                elif 550 <= mouse[0] <= 550+170 and 450 <= mouse[1] <= 450+50:
                    sock.send(SLEEP_COMMAND.to_bytes(1, 'little'))
                    rnd = int.from_bytes(sock.recv(1), 'little')
                    if rnd == 0:
                        put_script(font, screen, 'System', f'Server connection broken.. bye..', 1)
                        exit()
                    character.stamina += rnd
                    character.day += 1
                    put_script(font, screen, character.nickname, random.choice(messages.SLEEP_MESSAGE), 1)
                    put_script(font, screen, 'System', f'stamina +{rnd}')
                    put_character_status(font, screen, character)

                # Date
                elif 550 <= mouse[0] <= 550+170 and 550 <= mouse[1] <= 550+50:
                    sock.send(DATE_COMMAND.to_bytes(1, 'little'))
                    rnd = int.from_bytes(sock.recv(1), 'little')
                    if rnd == 0:
                        put_script(font, screen, 'System', f'Server connection broken.. bye..', 1)
                        exit()
                    put_script(font, screen, character.nickname, messages.DATE_REQUEST_MESSAGE[min(character.friendship, 33)], 1)
                    if character.stamina >= 10 and character.intelligence.bit_length() >= character.friendship:
                        character.stamina -= 10
                        character.friendship += 1
                        character.day += 1
                        if character.friendship == 34:
                            flag_len = int.from_bytes(sock.recv(2), 'little')
                            flag = sock.recv(flag_len).decode()
                            put_script(font, screen, "Cogechan", "Not only that, I want to spend my whole life with you.", 1)
                            put_script(font, screen, 'System', flag)
                        
                        else:
                            put_script(font, screen, "Cogechan", random.choice(messages.DATE_SUCCESS_MESSAGE), 1)
                            put_script(font, screen, 'System', f'stamina -10, friendship +1')

                    else:
                        put_script(font, screen, "Cogechan", random.choice(messages.DATE_FAIL_MESSAGE), 1)


                # Game save
                elif 850 <= mouse[0] <= 850+170 and 70 <= mouse[1] <= 70+50:
                    sock.send(SAVE_COMMAND.to_bytes(1, 'little'))
                    file_data_enc, tag = encrypt_data(ID, PW, character)
                    sock.send(len(file_data_enc).to_bytes(2, 'little') + file_data_enc)
                    sock.send(tag)
                    status = int.from_bytes(sock.recv(1), 'little')
                    if status == 0:
                        put_script(font, screen, 'System', f'Server connection broken.. bye..', 1)
                        exit()
                    elif status == SAVE_SUCCESS:
                        put_script(font, screen, "System", "Save success")
                    else:
                        put_script(font, screen, "System", "Save failed")

                last_click = time.time()
        
            put_character_status(font, screen, character)
                                
def main():
    if len(sys.argv) != 3:
        print(f"usage : {sys.argv[0]} ip port")
        return
    
    ip = sys.argv[1]
    port = int(sys.argv[2])

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((ip, port))
    except:
        alert("[-] failed to connect a server")
        return

    ID, PW, nickname = get_credential()
    sock.send(len(ID).to_bytes(2, 'little') + ID.encode())
    sock.send(len(PW).to_bytes(2, 'little') + PW.encode())
    status = sock.recv(1)
    character = Character.Character()

    if status[0] == 1: # LOAD_SUCCESS
        nickname_len = int.from_bytes(sock.recv(2), 'little')
        character.nickname = sock.recv(nickname_len).decode()
        character.day = int.from_bytes(sock.recv(4), 'little')
        character.stamina = int.from_bytes(sock.recv(4), 'little')
        character.intelligence = int.from_bytes(sock.recv(4), 'little')
        character.friendship = int.from_bytes(sock.recv(4), 'little')
            
    else:
        sock.send(len(nickname).to_bytes(2, 'little') + nickname.encode())
        character.nickname = nickname
        character.stamina = 100

    GUI(ID, PW, character, sock, status[0] == 1)
    
if __name__ == "__main__":
    main()
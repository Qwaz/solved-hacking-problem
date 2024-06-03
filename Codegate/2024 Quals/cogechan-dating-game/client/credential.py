import json

LOAD_SUCCESS = 1
LOAD_ERROR1 = 2 # credential file does not exist or file corrupted

SAVE_SUCCESS = 11
SAVE_ERROR1 = 12 # cannot save credential

def load_credential():
    try:
        with open("credential", 'r') as f:
            info = json.loads(f.read())
        
        ID = info["ID"]
        PW = info["PW"]
        nickname = info["nickname"]
        assert type(ID) == str and type(PW) == str and type(nickname) == str

        return LOAD_SUCCESS, ID, PW, nickname
    
    except:
        return LOAD_ERROR1, None, None, None

def save_credential(ID, PW, nickname):
    try:
        info = {}
        info["ID"] = ID
        info["PW"] = PW
        info["nickname"] = nickname
        with open("credential", 'w') as f:
            json.dump(info, f)
        return SAVE_SUCCESS
    except:
        return SAVE_ERROR1
            


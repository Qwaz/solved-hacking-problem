# set, out, in

def init():
    global state
    state = []
    for k in range(4):
        state.append([])
        for i in range(64):
            state[k].append([])
            for j in range(65):
                if i == j:
                    state[k][i].append(1)
                else:
                    state[k][i].append(0)

def xors(num):
    for i in range(64):
        state[setnum][i][64] ^= (num >> i) & 1
    return state

def change_st(i,j):
    for k in range(8):
        temp1=state[setnum][i*8+k]
        temp2=state[setnum][j*8+k]
        state[setnum][i*8+k]=temp2
        state[setnum][j*8+k]=temp1
    return state

def change_rot():
    temp=[]
    for i in range(64):
        temp.append(state[setnum][i])
    for k in range(8):
        state[setnum][7*8+k]=temp[2*8+k]
        state[setnum][6*8+k]=temp[7*8+k]
        state[setnum][5*8+k]=temp[3*8+k]
        state[setnum][4*8+k]=temp[1*8+k]
        state[setnum][3*8+k]=temp[0*8+k]
        state[setnum][2*8+k]=temp[4*8+k]
        state[setnum][1*8+k]=temp[6*8+k]
        state[setnum][0*8+k]=temp[5*8+k]
    return state

def shift_xor():
    temp=[]
    for i in range(64):
        temp.append([])
        for j in range(65):
            temp[i].append(0)
    for i in range(64):
        for j in range(65):
            temp[(i+56)%64][j]=state[setnum][i][j]
    for i in range(64):
        for j in range(65):
            state[setnum][i][j]^=temp[i][j]
    
    return state

def lshift(b):
    temp  =[]
    b = b & 63
    for i in range(64):
        temp.append(state[setnum][i])
     
    for i in range(64):
        if i >= b:
            state[setnum][i-b]=temp[i]
        else:
            state[setnum][i+64-b]=temp[i]
    return state

def rshift(b):
    temp = []
    b = b & 63
    for i in range(64):
        temp.append(state[setnum][i])
     
    for i in range(64):
        if i > 63-b:
            state[setnum][i-64+b]=temp[i]
        else:
            state[setnum][i+b]=temp[i]
    return state

def funF ():
    xors(0x35966A685c73335A)
    change_st(2,0)
    xors(0x89fdaf6604952df1)
    xors(0xe9f30f0ce704876a)
    change_st(2,3)
    xors(0xbdc5026d3c0b56e6)
    rshift(0x10)
    rshift(0x23)
    lshift(0x13)
    shift_xor()     
    rshift(0x24)
    lshift(0x28)
    change_st(1,0)
    xors(0x5de229fb3804db17)
    change_rot()
    change_rot()
    change_st(2,1)
    xors(0x6aad877366e921f5)
    change_st(3,0)
    change_rot()
    xors(0x58d83e9d5e6d5083)
    lshift(0x16)
    shift_xor()
    xors(0x47b4d980070a9b73)
    shift_xor()
    shift_xor()
    change_st(6,5)
    rshift(59)
    change_st(5,2)
    change_st(2,3)
    rshift(12)
    xors(0xAD25307F8E364B17)
    xors(0x48A56D5AFE0DA4C2)
    rshift(6)
    change_st(6,5)
    lshift(0xb)
    change_rot()
    xors(0x869365db4c9f3cb6)
    change_rot()
    lshift(2)
    xors(0x4085aa8c0693425b)
    rshift(35)
    rshift(9)
    shift_xor()
    rshift(7)
    rshift(38)
    shift_xor()
    xors(0xdef2d72447ef4e1b)
    change_rot()
    change_rot()
    change_st(2,7)
    lshift(51)
    change_rot()
    lshift(19)
    xors(0x95de49591a44ee21)
    shift_xor()
    change_rot()
    lshift(16)
    return state

def funS():
    rshift(22)
    change_rot()
    change_st(4,1)
    change_rot()
    shift_xor()
    rshift(35)
    change_st(2,6)
    xors(0x80a9ea4f90944fea)
    rshift(3)
    change_st(0,1)
    change_st(1,2)
    change_rot()
    shift_xor()
    change_st(5,1)
    lshift(24)
    rshift(39)
    change_st(2,4)
    xors(0x678e70A16230A437)
    change_st(4,3)
    change_st(0,7)
    rshift(62)
    change_rot()
    change_st(7,6)
    change_st(2,6)
    change_rot()
    shift_xor()
    change_st(5,2)
    shift_xor()
    change_st(1,7)
    xors(0x41ea5cf418a918e7)
    change_rot()
    shift_xor()
    change_st(1,4)
    rshift(10)
    change_rot()
    change_rot()
    lshift(24)
    change_st(0,4)
    lshift(61)
    change_st(3,4)
    lshift(35)
    rshift(55)
    rshift(34)
    shift_xor()
    shift_xor()
    lshift(23)
    rshift(59)
    lshift(20)
    rshift(28)
    xors(0xc26499379c0927cd)
    shift_xor()
    lshift(13)
    return state

def funT():
    rshift(18)
    rshift(29)
    change_st(5,3)
    change_st(0,7)
    rshift(18)
    xors(0xc9ab604bb92038ad)
    lshift(33)
    change_st(0,4)
    shift_xor()
    change_st(6,2)
    lshift(13)
    lshift(20)
    xors(0x58609be21eb37866)
    shift_xor()
    change_rot()
    lshift(46)
    change_st(2,3)
    lshift(44)
    lshift(3)
    change_st(4,3)
    shift_xor()
    change_st(7,6)  
    lshift(59)
    lshift(38)
    change_rot()
    change_st(1,5)
    change_rot()
    rshift(27)
    xors(0xbed577a97eb7966f)
    lshift(14)
    rshift(7)
    rshift(18)
    rshift(57)
    xors(0xb44427be7889c31b)
    xors(0xce745c65abecb66)
    xors(0x94b1608adb7f7221)
    xors(0x85bef139817ebc4a)
    change_st(5,1)
    rshift(20)
    rshift(24)
    lshift(46)
    lshift(13)
    xors(0xc95e5c35034b9775)
    rshift(7)
    xors(0x8e60900383fa5ea)
    xors(0x59d5bcbf8b0cc9fd)
    shift_xor()
    change_st(4,7)
    shift_xor()
    lshift(22)
    lshift(50)
    shift_xor()
    return state

def funL():
    change_st(1,7)
    rshift(6)
    change_st(2,5)
    lshift(57)
    xors(0xc852fa4047662ce)
    change_st(5,1)
    rshift(1)
    shift_xor();
    xors(0x5ddfc2422c2a449e)
    shift_xor()
    rshift(6)
    shift_xor()
    rshift(33)
    lshift(25)
    shift_xor()
    xors(0xa94a4c87a942c60)
    change_st(6,2)
    shift_xor()
    xors(0xcc508fa31a0da5ab)
    xors(0x880218b9f910dcbc)
    shift_xor()
    xors(0x85d7e666ecdba611)
    lshift(8)
    lshift(43)
    xors(0x633a915bd59ac97b)
    change_st(3,1)
    change_st(5,7)
    change_rot()
    shift_xor()
    lshift(59)
    lshift(10)
    shift_xor()
    change_st(2,1)
    change_st(7,2)
    shift_xor()
    xors(0x648fff323d235735)
    xors(0xfc9f8d635fd85eb3)
    xors(0xff651571c16e5cb3)
    change_st(2,4)
    change_st(5,4)
    lshift(11)
    shift_xor()
    rshift(39)
    change_rot()
    shift_xor()
    xors(0xc798d4e5c0e97b1c)
    change_rot()
    shift_xor()
    rshift(35)
    change_st(3,5)
    shift_xor()
    change_rot()
    shift_xor()
    return state

def print_state() :
    const=0xb101124831c0110a
    '''
    # for human
    test=0
    nums=0
    for i in range(64):
        consti=(const >> i) & 1
        strings="out["+str(i)+"] = "
        for k in range(4):
            for j in range(64):
                if state[k][i][j]==1:
                    strings+="in["+str(k*64+j)+"] ^ "
                    nums+=1
            consti^=state[k][i][64]
        test^=consti
        print strings + str(consti)
    print "total : " + str(nums)+" edge", test
    '''
    # for solver
    nums = 0
    for i in range(64) :
        for k in range(4):
            for j in range(64):
                if state[k][i][j]==1:
                    nums+=1
    
    print str(nums)
    for i in range(64):
        for k in range(4):
            for j in range(64):
                if state[k][i][j]==1:
                    print "%d %d" % (k*64 + j, i)

    for i in range(64):
        consti=(const >> i) & 1
        for k in range(4):
            consti^=state[k][i][64]
        print str(consti)

init()

setnum=0
funF()

setnum=1
funS()

setnum=2
funT()

setnum=3
funL()

print_state()


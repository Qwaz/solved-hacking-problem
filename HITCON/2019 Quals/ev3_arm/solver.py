import re
import svgwrite

# disassembler at: https://github.com/ev3dev/lms-hacker-tools/tree/master/EV3
obj_pat = re.compile('^(vmthread|block) OBJECT(\d+)$')
call_pat = re.compile('^CALL\((.+),(.+),(.+),(.+),(.+),(.+)\)$')
trig_pat = re.compile('^OBJECT_TRIG\((.+)\)')

with open('code', 'r') as f:
    code = f.readlines()

prog = {}

current_obj = None
for line in code:
    line = line.strip()
    if current_obj == None:
        result = obj_pat.match(line)
        if result is not None:
            current_obj = result.group(2)
            prog[current_obj] = []
    else:
        if line == '}':
            current_obj = None
            continue
        result = call_pat.match(line)
        if result is not None:
            motor = {
                '101.0F': 'A',
                '102.0F': 'B',
                '103.0F': 'C',
            }[result.group(2)]
            # normalize
            power = float(result.group(3)[:-1])
            coff = 360 if motor == 'C' else 1
            rotation = coff * float(result.group(4)[:-1])
            prog[current_obj].append(['CALL', motor, power, rotation])
            continue
        result = trig_pat.match(line)
        if result is not None:
            obj_num = int(result.group(1))
            prog[current_obj].append(['TRIG', obj_num])
            continue

dwg = svgwrite.Drawing('flag.svg', debug=True)

X_COEFF = 1 / 100.0
Y_COEFF = 3 / 100.0

pos_x = 20
pos_y = 20
pen_down = False

def step(arr):
    global pos_x, pos_y, pen_down

    code = arr[0]
    if code[0] != 'CALL':
        return []

    motor = code[1]
    power = code[2]
    rotation = code[3]

    if motor == 'A':
        tick = 100.0 / power
        pos_y -= tick * Y_COEFF
    elif motor == 'B':
        tick = 35
        assert rotation == tick
        if power < 0:
            pen_down = True
        else:
            pen_down = False
    elif motor == 'C':
        tick = 200.0 / power
        pos_x += tick * X_COEFF
    else:
        raise ValueError("Unknown Motor")

    if code[3] > tick + 1e-6:
        arr[0][3] -= abs(tick)
        return arr
    return arr[1:]

def move_robot(prog_0, prog_1):
    while len(prog_1) > 0:
        prev_pos = (pos_x, pos_y)
        prog_1 = step(prog_1)
        if len(prog_0) > 0:
            prog_0 = step(prog_0)
        if pen_down:
            dwg.add(dwg.line(prev_pos, (pos_x, pos_y), stroke='black'))
    while len(prog_0) > 0:
        prev_pos = (pos_x, pos_y)
        prog_0 = step(prog_0)
        if pen_down:
            dwg.add(dwg.line(prev_pos, (pos_x, pos_y), stroke='black'))

for i in range(1, 30):
    print i
    for t in prog[str(i)]:
        print t

prog['0'] = []
for i in range(0, 30, 2):
    move_robot(prog[str(i)], prog[str(i+1)])

# hitcon{why_not_just_use_the_printer}
dwg.save()

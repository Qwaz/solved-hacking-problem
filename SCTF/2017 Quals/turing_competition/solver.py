import json

from TM import TM


STAGE_1 = {
    'transition_function': [
        ('a', '0', 'a', '0', 'R'),
        ('a', '1', 'b', '1', 'R'),
        ('b', '1', 'b', '1', 'R'),
        ('b', ' ', 'c', ' ', 'R')
    ],
    'initial_state': 'a',
    'final_states': ['c'],
    'accepting_states': ['c']
}

print json.dumps(STAGE_1)


STAGE_2 = {
    'transition_function': [],
    'initial_state': 'Right_0_0',
    'final_states': [],
    'accepting_states': []
}

for x in range(7):
    for cnt in range(13):
        STAGE_2['transition_function'] += (
            ('Right_%d_%d' % (x, cnt), '1', 'Right_%d_%d' % (x, (cnt+1) % 13), '1', 'R'),
            ('Right_%d_%d' % (x, cnt), ' ', 'Left_%d_%d' % (x, cnt), ' ', 'L'),
            ('Left_%d_%d' % (x, cnt), '1', 'Left_%d_%d' % (x, cnt), '1', 'L'),
            ('Left_%d_%d' % (x, cnt), ' ', 'Right_%d_%d' % (x+1, cnt), ' ', 'R'),
        )

for cnt in range(13):
    STAGE_2['final_states'].append('Right_7_%d' % cnt)
STAGE_2['accepting_states'].append('Right_7_1')

print json.dumps(STAGE_2)


STAGE_3 = {
    'transition_function': [
        ('left', '0', 'right', '00', 'R'),
        ('left', '1', 'left', '1', 'L'),
        ('left', '00', 'left', '00', 'L'),
        ('left', '11', 'left', '11', 'L'),
        ('right', '0', 'right', '0', 'R'),
        ('right', '1', 'left', '11', 'L'),
        ('right', '00', 'right', '00', 'R'),
        ('right', '11', 'right', '11', 'R'),
        ('left', ' ', 'check', ' ', 'R'),
        ('check', '00', 'check', '00', 'R'),
        ('check', '11', 'check', '11', 'R'),
        ('check', ' ', 'check_ok', ' ', 'R'),
    ],
    'initial_state': 'left',
    'final_states': ['check_ok'],
    'accepting_states': ['check_ok']
}

print json.dumps(STAGE_3)


STAGE_4 = {
    'transition_function': [],
    'initial_state': 'cnt0',
    'final_states': ['fail', 'ok'],
    'accepting_states': ['ok']
}

MAX = 10000
sieve = [0 for i in range(MAX)]
primes = []

for i in range(2, MAX):
    if sieve[i] == 0:
        primes.append(i)
        for j in range(i*2, MAX, i):
            sieve[j] = 1

for i in range(MAX):
    STAGE_4['transition_function'] += (
        ('cnt%d' % i, '0', 'cnt%d' % (i+1), '0', 'R'),
        ('cnt%d' % i, ' ', 'ok' if i in primes else 'fail', ' ', 'R'),
    )


print json.dumps(STAGE_4)

from Crypto.Util.number import *

n_size = 2000
m_size = 10

alpha = 0.5
delta = 0.03

d_size = int(delta * n_size)
k_size = int((alpha + delta - 0.5) * n_size)
c_size = int(n_size * (1 - alpha - 2 * delta))

print(f"d_size: {d_size}")
print(f"k_size: {k_size}")
print(f"c_size: {c_size}")


N = 13144833961692953638155744717380612667335058302310815242506755676885208234342620331186804951145894484501542968789132832800279633590988848298405521677820600481054741175400784558190943019903268095468121342412114428860754522164657102624139527993254089574309927288457799155130004731846999722554981630609692264462023821778810225493633789543259034893395115658330417361250466876018981150507377427664192443342394808337473089411393262018525828475108149889915075872592673448211565529063972264324533136645650169687118301014325354524932405270872098633633071371124551496573869700120350489760340226474892703585296623
e = 4976865541630914024304930292600669330017247151290783019063407119314069119952298933566289617702551408322779629557316539138884407655160925920670189379289389411163083468782698396121446186733546486790309424372952321446384824084362527492399667929050403530173432700957192011119967010196844119305465574740437

ct = 12075538182684677737023332074837542797880423774993595442794806087281173669267997104408555839686283996516133283992342507757326913240132429242004071236464149863112788729225204797295863969020348408992315952963166814392745345811848977394200562308125908479180595553832800151118160338048296786712765863667672764499042391263351628529676289293121487926074423104988380291130127694041802572569416584214743544288441507782008422389394379332477148914009173609753877263990429988651290402630935296993764147874437465394433756515223371180032964253037946818633821940103044535390973722964105390263537722948112571112911062

k = 582681014261310761
l = 1114474510927649225

dp_inv = e % k
dq_inv = e % l

ckl = e - dp_inv * inverse(l, k) * l - dq_inv * inverse(k, l) * k

assert ckl % k == 0
assert ckl % l == 0

dp = inverse(dp_inv, k)
dq = inverse(dq_inv, l)

if dp.bit_length() < d_size:
    dp = dp + k

if dq.bit_length() < d_size:
    dq = dq + l

print(f"dp_mask: {dp & ((1 << 10) - 1)}")
print(f"dq_mask: {dq & ((1 << 10) - 1)}")

p = (e * dp - 1) // k + 1
q = (e * dq - 1) // l + 1

# flag{laTTice_a77ack_on_RSA_h0VV_far_can_w3_Go???}
if p * q == N:
    d = inverse(e, (p - 1) * (q - 1))
    pt = pow(ct, d, N)
    print(long_to_bytes(pt))
    exit()
else:
    print("pq check fail")
import binascii
import pyshark

cap = pyshark.FileCapture('ev3_player.pklg')

# hitcon{playsoundwithlegomindstormsrobot}
def save_rsf(start_index, filename):
    i = start_index
    data = ''

    while True:
        if cap[i].packetlogger.type.raw_value == '02':
            # sent packet
            x = binascii.unhexlify(cap[i].data.data.raw_value)
            y = list(map(ord, x))
            packet_len = y[1] * 256 + y[0]
            msg_num = y[3] * 256 + y[2]
            cmd_type = y[4]
            system_cmd = y[5]
            print i, packet_len, msg_num, cmd_type, system_cmd
            assert len(x) == 2 + packet_len
            assert cmd_type == 1
            if system_cmd == 147:
                # append data
                data += x[7:]
            elif system_cmd == 152:
                # close file
                break
        i += 1

    with open(filename, 'wb') as f:
        f.write(data)

save_rsf(501, 'fl.rsf')
save_rsf(701, 'ag.rsf')

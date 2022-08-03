with open("output_processed.txt", "w") as wfile:
    with open("output.txt", "r") as rfile:
        state = 0

        op_str = ""
        sh_addr = ""

        r2 = ""
        r6_coeff = 0

        for line in rfile:
            # ugly state machine :p
            if state == 0:
                if line == "r5 = *r2\n":
                    state = 1
                    r2_coeff = 0
                    r6_coeff = 0
                else:
                    wfile.write(line)
            elif state == 1:
                if line == "r6 = 0\n":
                    state = 2
                elif line.startswith("(buffer "):
                    state = -1
                    sh_addr = line[8:-2]
                else:
                    assert False
            elif state == 2:
                assert line == "r2 = r6\n"
                state = 3
            elif state == 3:
                assert line == "&r2.st_size = 8\n"
                state = 4
            elif state == 4:
                if line == "r7 = r7 + *r2\n":
                    assert r2 == "r6"
                    wfile.write(f"r7 = r7 + {r6_coeff} * r2\n")
                    state = 0
                else:
                    if line == "r2 = r6\n":
                        r2 = "r6"
                    elif line == "r2 = r5\n":
                        r2 = "r5"
                    elif line == "r6 = r6 + *r2\n":
                        if r2 == "r6":
                            r6_coeff *= 2
                        elif r2 == "r5":
                            r6_coeff += 1
                    else:
                        # Unreachable
                        assert False
            elif state == -1:
                assert line[4:14] == "25e4408000"
                opcode_map = {
                    "8024": "and",
                    "8034": "xor",
                    "800c": "or",
                    "c004": "rol",
                    "c00c": "ror",
                    "c024": "shl",
                    "c02c": "shr",
                }
                op_str = f"{opcode_map[line[:4]]}(r2, {line[14:16]})"
                state = -2
            elif state == -2:
                assert line == "c300000000000000\n"
                state = -3
            elif state == -3:
                assert line == "(buffer end)\n"
                state = -4
            elif state == -4:
                assert line == f"r3 = {sh_addr}\n"
                state = -5
            elif state == -5:
                assert line == "&r3.st_name = 1000a0000001a\n"
                state = -6
            elif state == -6:
                assert line == f"{sh_addr} = r3 + 0\n"
                state = -7
            elif state == -7:
                assert line == f"r2 = a59d22\n"
                state = -8
            elif state == -8:
                assert line.startswith("&r2.st_size = ")
                state = -9
            elif state == -9:
                assert line == f"{sh_addr} = *r2\n"
                state = -10
            elif state == -10:
                assert line == f"r2 = r5\n"
                state = -11
            elif state == -11:
                assert line == f"&r2.st_size = 8\n"
                state = -12
            elif state == -12:
                assert line == f"r7 = r7 + *r2\n"
                wfile.write(f"r7 = r7 + {op_str}\n")
                state = 0

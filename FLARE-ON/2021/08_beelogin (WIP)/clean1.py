read_file = open("beelogin_format.html")
write_file = open("beelogin_clean1.html", "w")

line_count = 0

in_func = False

for line in read_file.readlines():
    line_count += 1

    if 8 <= line_count <= 12:
        # remove background
        continue

    if line_count <= 58 or line_count >= 89641:
        write_file.write(line)
        continue

    if in_func:
        if line.startswith("        }"):
            in_func = False
    else:
        if line.startswith("        function "):
            in_func = True
        elif len(line.strip()) > 0:
            write_file.write(line)

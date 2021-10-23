import re

read_file = open("beelogin_clean1.html")
write_file = open("beelogin_clean2.html", "w")

line_count = 0

in_func = False

content = read_file.read()
prefix = content[:-18055]
suffix = content[-18055:]

pattern = (
    r"(\S+)\s*=\s*xDyuf5ziRN1SvRgcaYDiFlXE3AwG\.\S+\.value\.split\(\s*\";\"\s*\)\;\s+"
    + r"if \(\"rFzmLyTiZ6AHlL1Q4xV7G8pW32\" >= (\S+)\s+"
    + r"eval\((\S+)\);"
)

write_file.write(prefix + re.sub(pattern, "", suffix, flags=re.MULTILINE))

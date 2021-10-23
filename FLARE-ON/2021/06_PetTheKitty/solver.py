from ctypes import cast, wintypes, c_ubyte
from delta_patch import apply_delta_to_buffer, DeltaFree
from PIL import Image
import struct

im = Image.open("Bitmap102.bmp")

with open("extracted/stream_1", "rb") as f:
    content = f.read()

bitmap_data = im.tobytes()
original_buffer = bitmap_data[: im.height * im.width]

while len(content) > 0:
    assert content[:4] == b"ME0W"
    buffer_len = struct.unpack("<I", content[4:8])[0]
    encoded_len = struct.unpack("<I", content[8:12])[0]
    delta = content[12 : 12 + encoded_len]
    content = content[12 + encoded_len :]

    out_addr, out_n = apply_delta_to_buffer(
        cast(original_buffer, wintypes.LPVOID), len(original_buffer), delta
    )
    out_buf = bytes((c_ubyte * out_n).from_address(out_addr))

    result = b""
    for i in range(buffer_len):
        result += bytes([out_buf[i] ^ b"meoow"[i % 5]])

    # DeltaFree(out_buf)

    print("======================")
    print(result)
    print(result.decode("ascii", "ignore"))

    # 1m_H3rE_Liv3_1m_n0t_a_C4t@flare-on.com in the traffic

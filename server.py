
#!/usr/bin/env python

import SocketServer as ss
import struct
import os
from binascii import hexlify
import hashlib
import subprocess


class Handler(ss.StreamRequestHandler):

    def handle(self):
        put = self.wfile.write

        put('Signature service, please send a message\n')

        msg = self.rfile.readline()[:-1]

        put('Hashing the message')

        msghash = hashlib.sha256(msg).hexdigest()

        put('Hash = %s\m' % msghash)

        put('Signing it..."\n')

        sol = self.rfile.readline().strip()


class ReusableTCPServer(ss.ForkingMixIn, ss.TCPServer):
    allow_reuse_address = True

if __name__ == '__main__':
    HOST, PORT = ('0.0.0.0', 1111)
    ss.TCPServer.allow_reuse_address = True
    server = ReusableTCPServer((HOST, PORT), Handler)
    server.serve_forever()

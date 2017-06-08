#!/usr/bin/env python

import SocketServer as ss
import struct
import os
from binascii import hexlify
import hashlib
from subprocess import Popen, PIPE


class Handler(ss.StreamRequestHandler):

    def handle(self):
        put = self.wfile.write
        sigbytes = 2592

        put('Signature verification service, please send a message first\n')
        msg = self.rfile.readline()[:-1]
        msghash = hashlib.sha256(msg).hexdigest()

        put('Now please send a signature, in hex\n')
        sig = self.rfile.readline()[:1]

        if len(sig) != 2*sigbytes:
            put('Sorry, the signature is not of the right length (should be %d bytes)' % sigbytes)
            return

        put('Verifying the signature of the SHA-256 hash %s...\n' % msghash)
        process = Popen(['./verify', msghash, sig], stdout=PIPE, stderr=PIPE)
        stdout, stderr = process.communicate()

        if stderr != '':
            put(stderr)
            return
        else:
            put("Signature:\n")
            put(stdout)

        put("Thank your for using our service, goodbye!\n")


class ReusableTCPServer(ss.ForkingMixIn, ss.TCPServer):
    allow_reuse_address = True

if __name__ == '__main__':
    HOST, PORT = ('0.0.0.0', 1111)
    ss.TCPServer.allow_reuse_address = True
    server = ReusableTCPServer((HOST, PORT), Handler)
    server.serve_forever()
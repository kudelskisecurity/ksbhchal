import socket
import time

s = socket.socket()
#s.connect(('localhost', 1111))
s.connect(('213.244.194.155', 1111))
s.recv(100)
s.send('hello\n')
time.sleep(0.5)
sig = s.recv(10000)[:-1]
print(sig)
if len(sig) != 2*2592:
    print('invalid length: %d' % len(sig))

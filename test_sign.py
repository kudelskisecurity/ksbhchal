import socket

s = socket.socket()
s.connect(('localhost', 1111))
s.recv(100)
s.send('hello\n')
sig = s.recv(10000)[:-1]
print(sig)
if len(sig) != 2*2592:
    print('invalid length: %d' % len(sig))

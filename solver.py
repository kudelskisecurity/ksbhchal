#!/usr/bin/env python

# TODO: actual forgery, recording sigs and extracting keys and auth paths to form the forged sig

import array
import socket
import random
import binascii
import hashlib
from subprocess import Popen, PIPE

K=8
TAU=9
T=2**TAU

SIGS=50
# set of indices
INDICES=set()
# dictionary index -> [ key, node1, node 2, ...]
AUTHPATHs={}
SEEDS=100

def getasig():
    # pick a random message
    msg = str(random.randint(0,2**32))
    # get its sig
    s = socket.socket()
    s.connect(('localhost', 1111))
    s.recv(100)
    s.send(msg+'\n')
    sighex = s.recv(10000)[:-1]
    sig = binascii.unhexlify(sighex)
    return msg, sig

def sig2seed(sig):
    return sig[-32:]

# port of hors.c's getsubset()
def getsubset(seed, message):
    # sha256 message
    h = hashlib.sha256(message).hexdigest()
    # form input
    seedhex = binascii.hexlify(seed)
    block = seedhex + h
    assert(len(block) == 2*64)
    process = Popen(['./hash', block], stdout=PIPE, stderr=PIPE)
    digesthex = process.communicate()[0]
    digesthex = digesthex[:-1] # strip newline
    assert(len(digesthex) == 2*32)
    digest = binascii.unhexlify(digesthex)
    digestbytes = array.array('B', digest)
    subset = []
    for i in range(K):
        index = (digestbytes[2*i] << 8 | digestbytes[2*i+1]) % T
        subset.append(index)
    return subset


def siggetkey(index):
    # get the key for the index in 0..k-1
    pass

def siggetauthpath(index):
    # get the auth path for the index in 0..k-1
    pass

# 1. INDICES COLLECTION
# for SIGS messages, collect signatures, and:
#   - extract seed from sig
#   - compute indices subset
#   - add indices to the list INDICES

for i in range(SIGS):
    print(i)
    msg, sig = getasig()
    seed = sig2seed(sig)
    subset = getsubset(seed, msg)
    INDICES.update(subset)
print(INDICES)
print(len(INDICES))

# 2. MESSAGE SEARCH
# for SEEDS different seeds, and an arbitrary message:
#   - compute indices subset
#   - check if all indices known
#   - if yes, get their keys and auth paths and build the sig
#   - if no, keep trying

msg = 'meh'
for i in range(SEEDS):
    preseed = str(random.randint(0,2**32))
    seed = hashlib.sha256(preseed).digest()
    subset = getsubset(seed, msg)
    indices = INDICES.copy()
    indices.update(subset)
    if (indices == INDICES):
        print("Found subset cover! Can now forge a signature")
        break
    print("Trying again: %d indices missing" % len(indices - INDICES))

    

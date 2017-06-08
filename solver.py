#!/usr/bin/env python

import socket
import random
import binascii

SIGS=50
INDICES=[]
# dictionary index -> [ key, node1, node 2, ...]
AUTHPATHs={}
SEEDS=30

def getasig():
    # pick a random message
    msg = str(random.randint(0,2**32))
    # get its sig
    s = socket.socket()
    s.connect(('localhost', 1111))
    s.recv(100)
    s.send(msg+'\n')
    sig = s.recv(10000)[:-1]
    return sig

def sig2seed(sig):
    return sig[-32:]

# port of hors.c's getsubset()
def getsubset(seed, message):
    # use haraka CLI


def siggetkey(index):
    # get the key for the index in 0..k-1

def siggetauthpath(index):
    # get the auth path for the index in 0..k-1



# 1. INDICES COLLECTION
# for SIGS messages, collect signatures, and:
#   - extract seed from sig
#   - compute indices subset
#   - add indices to the list INDICES

# 2. MESSAGE SEARCH
# for SEEDS different seeds, and an arbitrary message:
#   - compute indices subset
#   - check if all indices known
#   - if yes, get their keys and auth paths and build the sig
#   - if no, keep trying

# ksbhchal

Goal: forge signatures for the HORST signature scheme, after reversing
the binary and running an attack against subset resilience (by getting
signatures of sufficiently many messages)

Details (tentative):

* Python server (code given to participants, showing expected inputs)

* Binary compiled from C (stripped of symbols? binary only given to
  participants)

* Secret key read from a file by the binary

* Simple HORST implementation, without auth paths cutoff

* HORST parameters: n=512, k=8

* Use of Haraka for n-to-n and 2n-to-n hashing

* Run service on a KS cloud server

* Disallow trivial offline search (derive indexes/seed from priv key),
  but verification allows forged seeds

* Run sig verification service

* Choose parameters such that a forgery is doable after ~100 valid signatures

* Solution expected: code of a forgery algorithm (no just a forged message)

* Code our own solver: find seed for which sk's all known, after collecting some sk's and their respective auth paths

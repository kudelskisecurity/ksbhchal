# ksbhchal

Goal: forge signatures for the HORST signature scheme, after reversing
the binary and running an attack against subset resilience (by getting
signatures of sufficiently many messages)

Details (tentative):

* Python server (code given to participants)

* Binary compiled from C (stripped of symbols? binary only given to
  participants)

* Simple HORST implementation, without auth paths cutoff

* Use of Haraka for n-to-n and 2n-to-n hashing

* Run service on a KS cloud server

* Disallow trivial offline search (derive indexes/seed from priv key),
  but verification allows forged seeds

* Run sig verification service

* Choose parameters such that a forgery is doable after ~100 valid signatures



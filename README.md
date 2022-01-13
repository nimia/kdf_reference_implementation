# Reference Implementation for the Dual-PRF
# presented in ePrint/...

This repository contains reference implementations, in C and Python, of the dual PRF presented in ePrint/...:

Practical (Post-Quantum) Key Combiners from One-Wayness and Applications to TLS,

by Nimrod Aviram, Benjamin Dowling, Ilan Komargodski, Kenneth G. Paterson, Eyal Ronen, and Eylon Yogev.

An example benchmark output, using OpenSSL 1.1.1 on an Intel i7 CPU @3.60GHz:
```
Benchmarking combine_keys():
Did 199998 calls to combine_keys()	in 1.41 seconds, speed is 141582.98 calls/second, average is 7.06 microseconds/call.
Benchmarking hkdf_extract():
Did 1000000 calls to hkdf_extract()	in 1.35 seconds, speed is 743066.26 calls/second, average is 1.35 microseconds/call.
```

# abke
Go package for Attribute-Based Key Exchange (ABKE).

This package implements the ABKE scheme from the paper:
*Vladimir Kolesnikov, Hugo Krawczyk, Yehuda Lindell, Alex J. Malozemoff, and Tal
Rabin "[Attribute-based Key Exchange with General Policies](https://eprint.iacr.org/2016/518.pdf)",
ACM Conference on Computer and Communications Security (CCS), 2016.*

Specifically, this package implements the scheme in section 9 of that paper
(ASE using ELH Signatures) and is a port of the original [C
code](https://github.com/amaloz/abke).

# SECRETSHARE

### An implementation of a secret-sharing scheme using Lagrange interpolation

#### Introduction

This project implements a secret-sharing algorithm. It is an (_m_, _k_) scheme, wherein a block of data is split into _m_ chunks, such that at least _k_ chunks are required to reconstitute the original data, but any fewer will yield no information about its contents.

The implementation uses arithmetic in a Galois field, specifically GF(256), with the field operations being Conway's Nym addition and multiplication. This permits the necessary operations to be performed in a much more efficient way. The number theoretic code is adapted from work by David Madore <david.madore@ens.fr>.

The secret-sharing code itself is a header-only library. Included is a command-line application which can be used to split and recombine files.

#### Usage

The low-level operations to split and join memory buffers are in `secretshare.hpp`.

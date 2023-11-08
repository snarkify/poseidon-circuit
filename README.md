# Poseidon Hash Circuit

## Introduction

This library contains a halo2 circuit for the Poseidon hash algorithm. Please refer to the original [paper](https://eprint.iacr.org/2019/458.pdf) for the definition of Poseidon hash.

The Poseidon circuit is based on a custom gate named `MainGate` with the following structure. 

| q_1([F;T])    | q_5([F;T])    |  q_m (F)   | q_i(F)    | q_o(F)    |  rc (F)   | state([A;T]) | input (A) | out (A) |
| --- | --- | --- | --- | --- | --- | ------------- | --------- | ------- |

Here `T` is the size of state, `F` means fixed column, `A` means adviced column.

Generic relation is defined as
$$q_m\cdot s[0]\cdot s[1] + \sum_i q_1[i]\cdot s[i] + \sum_i q_5[i]*s^5[i] + rc + q_i\cdot input + q_o\cdot out=0$$

It is worth noting that `MainGate` was originally designed for the [Sirius folding framework](https://github.com/snarkify/sirius), thus some of the columns like $q_m$ are not needed for Poseidon hash and can always be set to be $0$.


## Deploying to Snarkify Cloud
This repository seamlessly integrates with the [Snarkify SDK](https://crates.io/crates/snarkify-sdk),
facilitating effortless deployment to the [Snarkify Cloud](https://cloud.snarkify.io). With just a few clicks, you can have your service up
and running, ready to handle proof requests.

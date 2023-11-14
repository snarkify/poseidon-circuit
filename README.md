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


## Getting Started
This repository has integrated with the [snarkify-sdk](https://crates.io/crates/snarkify-sdk),
facilitating effortless deployment to the [Snarkify Cloud](https://cloud.snarkify.io). With just a few clicks, you can have your prover service up
and running, ready to handle proof requests.

:point_right: Follow our [tutorial](https://docs.snarkify.io/introduction/deploy-your-first-prover) to deploy your Poseidon hash prover service on [Snarkify Cloud](https://cloud.snarkify.io).

## Integrate with `snarkify-sdk`

For a complete example of `snarkify-sdk` integration with the Poseidon circuit, please reference to PR [#5](https://github.com/snarkify/poseidon-circuit/pull/5).

For more information about `snarkify-sdk`, please reference to the [documentation](https://docs.snarkify.io/snarkify-cloud/integrating-snarkify-sdk).

## Getting Involved

We'd love for you to be a part of our developer community! Whether you're looking to contribute code, provide feedback, or simply stay in the loop, our Telegram group is the place to be.

:point_right: [Join our developer community](https://t.me/+oQ04SUgs6KMyMzlh)

# Poseidon Circuit

This library contains a rust function and a halo2 circuit, both of them calculate the poseidon hash. For the definition of poseidon hash, please refer to the original [paper](https://eprint.iacr.org/2019/458.pdf). 

The poseido circuit is based on the MainGate which has the following structure. Here `T` is the size of state, `F` means fixed column, `A` means adviced column.

| q_1([F;T])    | q_5([F;T])    |  q_m (F)   | q_i(F)    | q_o(F)    |  rc (F)   | state([A;T]) | input (A) | out (A) |
| --- | --- | --- | --- | --- | --- | ------------- | --------- | ------- |
| ...    |     |     |     |     |     |           |       |   ...  |

Generic relation is defined as
$$q_m\cdot s[0]\cdot s[1] + \sum_i q_1[i]\cdot s[i] + \sum_i q_5[i]*s^5[i] + rc + q_i\cdot input + q_o\cdot out=0$$

It worth to note that MainGate is also used in another library `Sirius`, thus some of the columns like $q_m$ are not needed and can always set to be $0$.



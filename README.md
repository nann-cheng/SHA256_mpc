# GC
This is a prototype Garbled Circuit implementation for the functionality 

`f: x0, x1 \rightarrow Sha256(x0 XOR x1)`

where P0 has the value x0 (n bytes), and P1 has the value x1 (n bytes). 


## The Boolean Circuit in use
The final multiple block chained circuit is derived from the Bristol boolean circuit representation of the single block [Sha256 circuit](https://nigelsmart.github.io/MPC-Circuits/), which takes in 512 message bits and 256 state bits, outputs 256 updated state bits. Notably, this sha256 circuit takes all input/output wires using a LSB manner.


## The Garbled Circuit implementation
The final implementation garbled circuit consider three gate types:

`XOR` `AND` `INV` 

in which the `XOR` and `INV` gate are cost-free. The final implementation skipped the oblivious transfer and the network communication, realized garbled circuit using protocols from the half-gate paper in [ZRE15](https://link.springer.com/chapter/10.1007/978-3-662-46803-6_8).


## How to test

By the root directory, run 
`cargo run -- n` 
where n is a postive integer indicating the bytes length of x0/x1.
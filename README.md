# blockchain
This is a naive and native Rust blockchain protocol implementation, very much WIP.
From this experiment will eventually emerge a series of [articles](https://polgomez.com/blog) on the principles of distributed consensus, and a step-by-step
implementation of a blockchain protocol in Rust.

## General design
The `node` crate is the entry point: it sets up a TCP server for node-to-node communication, parsing protocol messages in the MessagePack format.
A protocol message has the following structure:
<p align="center">
<code>| MAGIC ("BLOCK") | PROTOCOL VERSION (32B) | MSG TYPE (32B) | MSG PAYLOAD (32B) | PAYLOAD |</code>
</p>

While TCP is fine for broadcasting transactions, blocks, and other technical stuff, users need a more human-friendly channel of communication witht their local node
in order to start transactions, check blockchain status, etc.
This implementation aims at providing a JSON-RPC server through HTTP (very much _a la_ Bitcoin).

The `jsonrpc` crate provides data structures that model the JSON-RPC protocol model (V2.0).

The `merkle` crate provides for now a simple immutable binary tree implementation.
It aims at providing a sensible Merkle-tree implementation, which I expect will warrant its separate post
(implementing data structures in Rust is
[interesting](http://cglab.ca/~abeinges/blah/too-many-lists/book/)
[to](http://featherweightmusings.blogspot.com/2015/04/graphs-in-rust.html)
[say](http://smallcultfollowing.com/babysteps/blog/2015/04/06/modeling-graphs-in-rust-using-vector-indices/)
the [least](https://rust-leipzig.github.io/architecture/2016/12/20/idiomatic-trees-in-rust/)).

## Cryptography
The fantastic [`ed_25519`](https://docs.rs/ed25519-dalek/) library is used for public-key cryptography.
For hashing purposes, we rely on [`Sha2`](https://docs.rs/sha2/).
Common sense dictates that _"ye shall `base58`-encode addresses, lest thine offspring be lost"_.

<h1 align="center">zendoo-mc-cryptolib</h1>
<p align="center">
    <a href= "https://github.com/HorizenOfficial/zendoo-mc-cryptolib/releases"><img src="https://img.shields.io/github/release/HorizenOfficial/zendoo-mc-cryptolib.svg"></a>
    <a href="AUTHORS"><img src="https://img.shields.io/github/contributors/HorizenOfficial/zendoo-mc-cryptolib.svg?"></a>
    <a href="https://travis-ci.com/github/HorizenOfficial/zendoo-mc-cryptolib"><img src="https://app.travis-ci.com/HorizenOfficial/zendoo-mc-cryptolib.svg?branch=master"></a>
    <a href="LICENSE-MIT"><img src="https://img.shields.io/badge/license-MIT-blue.svg"></a>
    <a href="CONTRIBUTING.md"><img src="https://img.shields.io/badge/PRs-welcome-brightgreen.svg?style=flat-square"></a>
</p>


`zendoo-mc-cryptolib` is an FFI library crate that exposes the [ginger-lib](https://github.com/HorizenOfficial/ginger-lib) Rust components needed to support [Zendoo](https://eprint.iacr.org/2020/123.pdf "Zendoo") in mainchain.

In particular it exposes interfaces to:

* handle the finite fields that are the alphabets of the zk Proving Systems
* call the *Poseidon* function, a Snark friendly hashing algorithm
* use a full in-memory *Poseidon-based Merkle Tree*, thus optimized for performance but limited in size (depending on the available RAM)
* manage the *SCTxsCommitmentTree*, as described in section 4.1.3 of the [Zendoo](https://eprint.iacr.org/2020/123.pdf "Zendoo") paper
* manage *BitVectorTree* (as described in Appendix A of the [Zendoo](https://eprint.iacr.org/2020/123.pdf "Zendoo") paper) and get its Merkle root
* verify a single or a batch of Zendoo SNARK proofs related to backward transfer *certificates* and *ceased sidechain withdrawals* transactions

**Please note: the code is in development. No guarantees are provided about its security and functionality**

## Release Notes

The proving system has been switched from [Groth16](https://eprint.iacr.org/2016/260.pdf) to our Marlin variant [*Coboundary Marlin*](https://github.com/HorizenLabs/marlin).
Support has been also introduced to verify *Final Darlin* proofs, as per last step of our recursive PCD scheme (See [HGB](https://eprint.iacr.org/2021/930) for details).

## Build guide

The library compiles on the `stable` Rust toolchain.
To install Rust, just install `rustup` by following the instructions [here](https://rustup.rs/), or via your platform's package manager.

After that, use `cargo`, the standard Rust build tool, to build the library:

```bash
git clone https://github.com/HorizenOfficial/zendoo-mc-cryptolib.git
cd zendoo-mc-cryptolib
cargo build --release
```

This library comes with unit tests for each of the provided crates. Run the tests with:

```bash
cargo test
```

More detailed build guide, as well as instructions to build the .jar, can be found in in our [build guide](BUILD.md).

## Examples

In the [example folder](examples) you can find a few C++ tests and examples of invocation of Rust functions. You can compile and execute them via the provided *Makefile*.

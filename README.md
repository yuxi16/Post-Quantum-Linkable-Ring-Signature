# Efficient Linkable Ring Signatures: New Framework and Post-Quantum Instantiations

This repository contains the implementations of our paper "Efficient Linkable Ring Signatures: New Framework and Post-Quantum Instantiations", which was published at ESORICS 2024.

**WARNING**: This project is developed for experimental and demonstration purposes.   The code has not been audited and may contain bugs, vulnerabilities, or other security flaws. This implementation is NOT ready for production use.


## Paper Overview
This paper introduces a new framework for constructing
linkable ring signatures (LRS). Our framework is based purely on signatures of knowledge (SoK) which allows one to issue signatures on behalf
of any NP-statement using the corresponding witness.
To instantiate our framework, we adapt a post-quantum
secure non-interactive argument of knowledge (NIAoK), [ethSTARK](https://eprint.iacr.org/2021/582.pdf), into
an SoK.  

## Implementation Detatils

### Add zero-knowledge to ethSTARK
For the practical implementation, we utilize the [Winterfell](https://github.com/facebook/winterfell) library, which supports the construction of ethSTARK. Note that the current versions of ethSTARK and the winterfell library do not inherently support zero-knowledge properties. To integrate ethSTARK within an SoK framework, we have enhanced it with zero-knowledge capabilities using the similar approach as in [zk-STARK](https://eprint.iacr.org/2018/046.pdf). Detailed methodologies and intuition of security proofs are available in Appendix A of our [paper](https://eprint.iacr.org/2024/553.pdf). 

The zero-knowledge enhancement of ethSTARK is informally outlined as follows:
- Introduce randomness into the execution trace of each register, thereby randomizing the trace polynomials.
- Mask composition polynomial with a random polynomial.
- Mask DEEP composition polynomial with a random polynomial.

### Build SoK from  non-interactive zk-ethSTARK
The non-interaction
property is achieved through the use of the Fiat-Shamir transformation (i.e., using hash $H$ to generate the
challenge). We let $H$ also takes
the message $m$ as input to generate the challenge, the resulting zero knowledge non-interactive ethSTARK will result in a SoK on $m$.

### Construct LRS from SoK
We use SoK to build LRS by demonstrating  the correct
signing of message $m$.  Also, we crafted the program representation of the execution trace
to enhance the efficiency of the signing process. 

## Performance
Our LRS has a signature size of O(polylog(log n)). By comparison,
existing post-quantum ring signatures, regardless of linkability considerations, have signature sizes of O(log n) at best. At 128-bit security, our LRS
has the smallest signature size among all post-quantum LRS when ring size is larger than 32.

Furthermore, leveraging
online/offline verification, part of the verification of signatures on the
same ring can be shared, resulting in a state-of-the-art amortized verification cost of O(polylog(log n)).

Detailed performance comparison can be found in our full [paper](https://eprint.iacr.org/2024/553.pdf). .
###  Influence of Grinding on Proving time 
In ethSTARK, an optimization technique known as grinding is incorporated within the Fiat-Shamir Transformation. Grinding requires prover to compute a proof-of-work solution to
reduce the computation power of the cheating prover.

Due to the inclusion of this proof-of-work, our implementation experiences fluctuations and additional overhead in proving time. The impact of grinding can, in some instances, exceed the influence of the ring size on the proving time in our instantiation. 

## To run
Parameters:
| Syntax      | Description |
| ----------- | ----------- |
| -q      | Number of queries       |
| -b   | Blowup factor        |
| -f   | Folding factor        |
| -n   | Number of members (exclude signer)        |

For 99-bit security with 64 users:
```
cargo run -- -q 20 -b 16 -f 4 sig-rescue -n 63
```
For 128-bit security with 128 users:
```
cargo run -- -q 32 -b 16 -f 4 sig-rescue -n 127
```


## References
[Scalable, transparent, and post-quantum secure computational integrity](https://eprint.iacr.org/2018/046.pdf) \
Eli Ben-Sasson, Iddo Bentov, Yinon Horesh, and Michael Riabzev

[ethSTARK Documentation](https://eprint.iacr.org/2021/582.pdf) \
StarkWare

[Efficient Linkable Ring Signatures: New Framework and Post-Quantum Instantiations](https://eprint.iacr.org/2024/553.pdf) \
Yuxi Xue, Xingye Lu, Man Ho Au, and Chengru Zhang
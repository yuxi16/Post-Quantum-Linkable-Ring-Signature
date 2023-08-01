# Practical Post-quantum Linkable Ring Signature

The implementation of our signature scheme uses STARK from [winterfell](https://github.com/facebook/winterfell) library. Currently, the library hasn't implemented zero-knowledge, and we make the following changes to add zero-knowledge in our solution.
- Inject random values in the execution trace of each register.
- Combine composition polynomial with a random low-degree polynomial before running it through FRI protocol.

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

To change signer-id/event-id, go to `example/src/sigrescue/mod` and change line 29/30.
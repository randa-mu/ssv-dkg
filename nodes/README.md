# Qualified nodes

This module contains a single file containing all the SSV nodes that support the DKG sidecar.

Node operators should use the `sign` functionality of the sidecar CLI with their registered SSV validator nonce to sign their public key, and raise a pull request with the output of the sign command appended to the `operators.json` file.
You can find out how to use the sign functionality in the [sidecar README](../sidecar/README.md).

Triple check your validator nonce - if you use an incorrect one, you will be unable to receive rewards for validator work.
The signature of the public key will be verified automatically by github actions. Note: if your SSV node is consistently unavailable, your entry may be removed!

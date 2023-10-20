# Qualified nodes

This module contains a single file containing all the SSV nodes that support the DKG sidecar.

Node operators should use the `sign` functionality of the sidecar CLI to sign their public key, and raise a pull request with the output of the sign command appended to the `operators.json` file.

The signature of the public key will be verified automatically by github actions. Note: if your SSV node is consistently unavailable, your entry may be removed!

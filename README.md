# ssv-dkg

This project contains all the software required for creating or participating in a distributed validator cluster for Ethereum using the [SSV project](https://github.com/bloxapp/ssv)

## cli
For users with ETH to stake who wish to create a validator cluster, [read the CLI readme](./cli/README.md)

## sidecar
For SSV node operators who wish to opt into distributed key generation opportunities, [read the sidecar readme](./sidecar/README.md)

## tools
The tools module contains useful applications for interacting with other parts of the project.

[./tools/key_verifier](./tools/key_verifier) is a tool used by the GitHub actions for verifying the keys of operators added to the [operators list](./nodes/operators.json).

[./tools/stub](./tools/stub) is a CLI for running a stubbed SSV node for testing. It will respond to identity requests with a valid RSA public key for use in encryption.
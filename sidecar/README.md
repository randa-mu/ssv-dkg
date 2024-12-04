# sidecar

This module contains an implementation of the distributed key generation sidecar for SSV nodes to join staker-chosen groups of validators to perform Ethereum validation duties on behalf of stakers who don't wish to run their own hardware.


## steps
- sign public key and upload to repo
- start your SSV node (or stub)
- start your sidecar


## example commands
- generate a BLS12-381 keypair
```shell
$ ssv-sidecar key create ~/.ssv 
```

- sign your key for uploading it to GitHub
```shell
$ ssv-sidecar key sign --validator-nonce 2 --directory ~/.ssv --url https://example.org | jq
{
  "validator_nonce": 2,
  "address": "https://example.org",
  "public": "Som3bas364stRing==",
  "signature": "Som3bas364stRing==",
}
```

- start your SSV node (or a stubbed node, which can be found in [../tools/stub](../tools/stub))

- start your sidecar node
```shell
$ ssv-sidecar start --port 443 --directory ~/.ssv --ssv-url http://127.0.0.1:8888
{"time":"2023-11-28T17:46:27+01:00","level":"info","message":"Keypair loaded from ~/ssv"}
{"time":"2023-11-28T17:46:27+01:00","level":"info","message":"SSV sidecar started, serving on port 443"}
```
the sidecar is using the SSV API exposed on the SSV node metrics port, e.g. 8888 above.

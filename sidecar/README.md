# sidecar

This module contains an implementation of the distributed key generation sidecar for SSV nodes to join staker-chosen groups of validators to perform Ethereum validation duties on behalf of stakers who don't wish to run their own hardware.


## steps
- sign public key and upload to repo
- start node (?)


## example commands
- generate a keypair (won't be needed after connection with SSV node)
```shell
$ ssv-sidecar key create ~/.ssv 
```

- sign your key for uploading it to GitHub
```shell
$ ssv-sidecar key sign --directory ~/.ssv --url https://example.org | jq
{
  "address": "https://example.org",
  "public": "Som3bas364stRing==",
  "signature": "Som3bas364stRing==",
}
```

- start your node
```shell
$ ssv-sidecar start --port 443 --directory ~/.ssv
SSV sidecar started, serving on port 443
Keypair loaded from ~/.ssv
```
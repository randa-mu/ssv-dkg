# sidecar

This module contains an implementation of the distributed key generation sidecar for SSV nodes to join staker-chosen groups of validators to perform Ethereum validation duties on behalf of stakers who don't wish to run their own hardware.


## steps
- [set up an SSV node](https://docs.ssv.network/operator-user-guides/operator-node/installation) and start it, noting the path to the `encrypted_private_key.json`
- [register your SSV node](https://docs.ssv.network/operator-user-guides/operator-management/registration) and note the final `operatorID`
- [sign public key](#sign-your-key-for-uploading-to-GitHub) and add it to the [operators JSON file](../nodes/operators.json). Raise a pull request once complete.
- [start your sidecar](#start-your-sidecar)
  - pass the [encrypted key file path](https://docs.ssv.network/operator-user-guides/operator-node/installation#generate-operator-keys-encrypted) of your SSV node using the `--ssv-key` flag 
  - pass the operator ID you noted down during the registration process using the `--operator-id` flag

## example commands

### generate a BLS12-381 keypair
```shell
$ ssv-sidecar key create ~/.ssv
```

### sign your key for uploading to GitHub
```shell
$ ssv-sidecar key sign --directory ~/.ssv --url https://example.org | jq
{
  "address": "https://example.org",
  "public": "Som3bas364stRing==",
  "signature": "Som3bas364stRing==",
}
```

### start your sidecar

```shell
$ ssv-sidecar start --port 443 --directory ~/.ssv --ssv-key /some/path/to/ssv/key/file --operator-id 1
{"time":"2023-11-28T17:46:27+01:00","level":"info","message":"Keypair loaded from ~/.ssv"}
{"time":"2023-11-28T17:46:27+01:00","level":"info","message":"SSV sidecar started, serving on port 443"}
```
where the public key file is a JSON file containing a `pubKey` key at the root. You can use the `encrypted_private_key.json` file created during SSV node setup or create a custom file containing just your RSA public key
# CLI

This module contains the CLI for creating distributed validator clusters of SSV nodes for users who wish to stake ETH to create a validator, but don't want to run their own hardware (or do want to run their hardware, but want multiple nodes running for higher resilience!).


## Steps
- list all the validators
- select the ones you wish to use (and health check them)
- start DKG between them and send your unsigned ETH deposit data to each
- wait for the DKG to complete
- receive signed ETH deposit data
- write the signed deposit data to a file or shell


## Example Commands

- List all the verified operators from the GitHub repo and your connectivity to them
```shell
$ ssv-dkg operators list

✅ 1,https://example.org
✅ 2,https://muster.de
✅ 3,https://exemple.fr
❌ 4,https://esempio.it
```

- Start a DKG and sign your deposit data
```shell
$ ssv-dkg sign --input /path/to/deposit/data \
      --output /path/to/storing/permanent/data/for/reshares/etc \
      --operator 1,https://example.org \
      --operator 2,https://muster.de \
      --operator 9,https://exemple.fr

⏳ contacting nodes
⏳ starting distributed key generation
✅ received signed deposit data!

{
  "some": "deposit",
  "data": "deadbeef0101"
}
```
Each operator must be in the form `$validatorNonce,$address`. Providing the wrong validator nonce may result in disaster for your DKG.
The output directory will default to `~/.ssv`. It will be in a file named after the date (and a counter if you create multiple clusters in a day). 
You will need to maintain this state file if you wish to reshare the key for this cluster in the future, e.g. if operators become unresponsive and you wish to exclude them. 

- combine both in a single command
```shell
$ ssv-dkg operators list --quiet | head --lines 3 | ssv-dkg sign --input /path/to/deposit --quiet > signed_deposit.json 
```

- reshare the key of a validator cluster you've already created
```shell
$ ssv-dkg reshare --state ~/.ssv/deadbeefcafebabe.json \
      --operator 1,https://example.org \
      --operator 2,https://muster.de \
      --operator 9,https://exemple.fr

⏳ contacting nodes
⏳ starting distributed key resharing
✅ distributed key reshared successfully!
```
Note: you will have to maintain a majority of operators from one cluster to the next.

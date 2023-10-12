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

✅ https://example.org
✅ https://muster.de
✅ https://exemple.fr
❌ https://esempio.it
```

- Start a DKG and sign your deposit data
```shell
$ ssv-dkg sign --input /path/to/deposit/data \
      --output /path/to/storing/permanent/data/for/reshares/etc \
      --operator https://example.org \
      --operator https://muster.de \
      --operator https://exemple.fr

⏳ contacting nodes
⏳ starting distributed key generation
✅ received signed deposit data!

{
  "some": "deposit",
  "data": "deadbeef0101"
}
```

- combine both in a single command
```shell
$ ssv-dkg operators list --short | head --lines 3 | ssv-dkg sign --input /path/to/deposit --quiet > signed_deposit.json 
```
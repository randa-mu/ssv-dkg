# CLI

This module contains the CLI for creating distributed validator clusters of SSV nodes for users who wish to stake ETH to create a validator, but don't want to run their own hardware (or do want to run their hardware, but want multiple nodes running for higher resilience!).


## Steps
- list all the operators
- select the ones you wish to use for your validator (and health check them)
- run a distributed key generation protocol between them and send your unsigned ETH deposit data to each
- wait for the DKG to complete
- receive signed ETH deposit data
- write the signed deposit data to a file or shell

## Example Commands

- List all the verified operators from the GitHub repo and your connectivity to them
```shell
$ ssv-dkg operators list

📂 reading operators from a local file
⏳	checking health of operators
Status	ID	Address
✅  1   https://example.org
✅  2   https://muster.de
✅  3   https://exemple.fr
❌  4   https://esempio.it
```

- Start a DKG and sign your deposit data
```shell
$ ssv-dkg sign --deposit-file /path/to/deposit/data \
      --owner-address 0xsomehexencodedETHaddress \
      --validator-nonce 0 \
      --output /path/to/storing/permanent/data/for/reshares/etc \
      --operator https://example.org \
      --operator https://muster.de \
      --operator https://exemple.fr \
      --operator https://esempio.it 

⏳ contacting nodes
⏳ starting distributed key generation
✅ your state, signed deposit data and keyshares files have been stored to /path/to/storing/permanent/data/for/reshares/etc/6939948103b839b8901a38a2e389d9f173ee0679860291c733fd579e917d95b9
```
You can use the keyfile JSON in the resulting directory with the [SSV web UI](https://app.ssv.network/join/validator) to register your validator, using 'I already have key shares'.
Providing the wrong validator nonce may result in disaster for your DKG. The wrong validator nonce is one that's already been used before by your address.
The output directory will default to `~/.ssv`. It will be in a file named after the date (and a counter if you create multiple clusters in a day). 
You will need to maintain this state file if you wish to reshare the key for this cluster in the future, e.g. if operators become unresponsive and you wish to exclude them. 

Note: deposit file data must be in array JSON format e.g.
```json
[{
  "withdrawal_credentials": "000ccc1a6eee8f5a8faa0ae44a0010233f31213825527270336677c4deadbeef",
  "amount": 32000000000,
  "deposit_message_root": "64c7ef6d1a2a2eea6cb39969903d3b64d1079f97da5af6c311df9d49deadbeef",
  "deposit_data_root": "f260af30ed9b5978676f7bc437fa2dc356c24bdd7deccf521bbc4ab6deadbeef",
  "fork_version": "01017000",
  "network_name": "holesky",
  "deposit_cli_version": "2.8.0"
}]
```

- combine both in a single command
```shell
$ ssv-dkg operators list --quiet | head --lines 3 | ssv-dkg sign --deposit-file /path/to/deposit --owner-address 0xsomehexencodedETHaddress --validator-nonce 1 --quiet > signed_deposit.json 
```

- reshare the key of a validator cluster you've already created
```shell
$ ssv-dkg reshare --state ~/.ssv/deadbeefcafebabe.json \
      --owner-address 0xsomehexencodedETHaddress \
      --validator-nonce 0 \
      --operator https://example.org \
      --operator https://muster.de \
      --operator https://exemple.fr \ 
      --operator https://esempio.it 

⏳ contacting nodes
⏳ starting distributed key resharing
✅ distributed key reshared successfully!
```
Note: you will have to maintain a majority of operators from one cluster to the next.

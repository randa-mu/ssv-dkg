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
      --validator-nonce 1 \
      --output /path/to/storing/permanent/data/for/reshares/etc \
      --operator https://example.org \
      --operator https://muster.de \
      --operator https://exemple.fr \
      --operator https://esempio.it 

⏳ contacting nodes
⏳ starting distributed key generation
✅ received signed deposit data! stored state in 956404e681ee48fe93a2c34972415e4748825ae285020d937219bd0a14e63819.json
📄 below is a keyfile JSON for use with the SSV UI:
{"version":"v0.0.1","createdAt":"2025-01-08T14:08:17","shares":[{"data":{"ownerNonce":1,"ownerAddress":"71c7656ec7ab88b098defb751b7401b5f6d8976f","publicKey":"97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bbb1d36ec223ad57bb34f2a3a66a49a2f4b4ab68fa3e43608cc3aacf72736882d9382381ab570da354838e903137e88c92b438217caa35486f1019596a3549932e195b4a0d1acdbaa4029b60fae18c461a726cbd924af305a4e4172e1bc02c4087b9192246fe9d1bc2e44f9d5055956832baa0d38745f0e80cc686fe04e836e5667ab651d8dd7d1836231705e3e3287eed","operators":[{"id":0,"operatorKey":"Z2ptSEl5dVpXU2FsUmNTTDBQeDFHOU9ZbkNUQVI2TFh4Z2VsUmlHWHB2QnhkL1hkM0lhY3FCNTh4cWZjSWdnOQ=="},{"id":1,"operatorKey":"dEVHS2Y4TG0zcFJQck9DTkJSdFFKQmtSeWJOZW5uN3ZtQU9Kdk9DaUNPRHhwODZud0lMRlRZUVJsM3hrNXR1bQ=="},{"id":2,"operatorKey":"ak5ZdEVXbkVjaWF4Vm9EdUNJUzNlRVVtU3dMWHBsamYyTHUvcC85dTh2cDZBVDlsZFJXcEJBcHJaeWwvbXdCeA=="},{"id":3,"operatorKey":"a3ZsaC84TndrRHN6TUxZS1oyTlpmUFViVEVUVVFBVFpqa1ZWSmdzeURSZm1Qc0cxQU5lU3B1cDBxQlFtUWVCZw=="}]},"payload":{"publicKey":"97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bbb1d36ec223ad57bb34f2a3a66a49a2f4b4ab68fa3e43608cc3aacf72736882d9382381ab570da354838e903137e88c92b438217caa35486f1019596a3549932e195b4a0d1acdbaa4029b60fae18c461a726cbd924af305a4e4172e1bc02c4087b9192246fe9d1bc2e44f9d5055956832baa0d38745f0e80cc686fe04e836e5667ab651d8dd7d1836231705e3e3287eed","operatorIds":[0,1,2,3],"sharesData":"8234f686c301f93abbb0a8b8106333bd554a8fa8fac71e4291666efbef2ced6c4f5938c3fa1850f62f1b863a70fc88820ee248cf1caea30d8f685c60e7f11e2fbf967856f91f19a9309c35935ee226e5bd8128ea1b1fd0fcb50a3ef0815a100f823987232b995926a545c48bd0fc751bd3989c24c047a2d7c607a5462197a6f07177f5dddc869ca81e7cc6a7dc22083db4418a7fc2e6de944face08d051b50241911c9b35e9e7eef980389bce0a208e0f1a7cea7c082c54d8411977c64e6dba68cd62d1169c47226b15680ee0884b77845264b02d7a658dfd8bbbfa7ff6ef2fa7a013f657515a9040a6b67297f9b007192f961ffc370903b3330b60a6763597cf51b4c44d44004d98e4555260b320d17e63ec1b500d792a6ea74a8142641e0607f01e8f7c35886736e7b950bb2e2a399e6d1d7b05652de0e9229d340289cceb7671ac7dc1019b83d5d2e98201db754d2304b2e98afb4abd322fbc981c4c850f1658da6f1cf2a3fb8ac3b1bdd19be866f98a2850cbd776d5262755446bad17606efe17a6d9f323262676bd684f66e29e9f222842791fc8beffb25d9ded77465b04f6955278f70e1211183d1898984284c301b4cb6c1d80973c23c885778f5d66c4353f393ff80018e3499ec9b94188a32005bd03e0aacf6c0e8ec4f774e0ee2dfff5fd42c6a3297c38f490972f594c65455a7bebad854d1e63ee20f5c88a9745f6de3a6e2b34aa3bb987fc2998aabf0a96b9d49aa5a2af95f6157d3b91675549353692ebe2dc4bcb53ef4aff46b9cd691164468c0c445579b843adb2e6d4b0e800c3aff6e6933e007974712b0efcc88c00f308aab3ffb86393cfd3c3ce789661ec77c48cf8c59d51f8ac970137c42b455a23f31325ebaaa0c6dc680e16cb3767b4578f61c9ec9edbfa2e959c41c4496768171473c4aa9a3aeef2c80e0559a4f6c09c95f8ab133ce2236c83365d89f6ef03c069cb278194d3707f25c6310ff57934b17909cd18a8cbc6c0694824c6e8fe91b43b56bc5f591b439abb5d3d3fb0d944d5f70fc6c32ba990f9bd36d32d2257b9395b4aebcca4b0340e289e90a27dad352860b701a933e9ce5b945a0d0a768a4b8d8fb7494767883fbe69f743f3d4fe5394506e5a2819dce518e8ac5a00f61e1ab2c149599b08e0be82126d37b050e2dafa98638affc94c9ab557b58023f95c36c5b599a0ddff7e466ed1c7b47f0db3362f92aa3cfdb89e0b0b429f894a940e04f04277a05dcbd018e901e05ec5277799cf658c9aec49f5f484dd41ed58d23cf23498cb284993bc33104a7c31610972fb61410bd782d8d9a4773b2feefbde0ffbcbb3b73fac4d2d1cf058c0849a204805629709f3fa1882ef0488e25386d22240a00641d60a99e5c9a7a15ab5d1be4240b6ef560eed8e1f49e71ba282e33eea9bb9d2d3c0948d3230f1bc327d65c7af9987ac50964535b0e1c4b6fef2352344458e21c6a92e070f5a06bf110b8fd8b64558588b6dfa1ad5ed23f77a2d409dd5c982ccb1337bbf92dbb3ed4ba1fb26c335a1cf2f80b4ccd7e083deb6d7938827aa855b1de8fc34ade0f158d4cbcd7252803df783a4d626dd42ab5d938638f277fd7f803cbad407ed0a6d0c8516f596c5195e063952a384107f6c318bacc6666b1ae42e3028b55a0f3c7107996f6c0cc0074879c8d875a79cb35aeb4e6b15d1a9e29396be93a83a30ef006d6b52b513fa9b4af39b248ed1c0274581ee826a2af2f9fcfc15fe6e3cc606c1220f1ad718aa8476469d83c12865becc6b2d46dfd24a515f6d46d0d4f69c838782615e3bea4f5756c10098c332dbfe17387ba5505cd89b629e019fa63945c81c60f83523fcd31"}}]}
```
You can use the keyfile JSON in the [SSV web UI](https://app.ssv.network/join/validator) to register your validator, using 'I already have key shares'.
Providing the wrong validator nonce may result in disaster for your DKG. The wrong validator nonce is one that's already been used before by your address.
The output directory will default to `~/.ssv`. It will be in a file named after the date (and a counter if you create multiple clusters in a day). 
You will need to maintain this state file if you wish to reshare the key for this cluster in the future, e.g. if operators become unresponsive and you wish to exclude them. 

- combine both in a single command
```shell
$ ssv-dkg operators list --quiet | head --lines 3 | ssv-dkg sign --deposit-file /path/to/deposit --owner-address 0xsomehexencodedETHaddress --validator-nonce 1 --quiet > signed_deposit.json 
```

- reshare the key of a validator cluster you've already created
```shell
$ ssv-dkg reshare --state ~/.ssv/deadbeefcafebabe.json \
      --owner-address 0xsomehexencodedETHaddress \
      --validator-nonce 1 \
      --operator https://example.org \
      --operator https://muster.de \
      --operator https://exemple.fr \ 
      --operator https://esempio.it 

⏳ contacting nodes
⏳ starting distributed key resharing
✅ distributed key reshared successfully!
```
Note: you will have to maintain a majority of operators from one cluster to the next.

# Defendoooor
### ethtokyo 2023 submission

In 2022, the total amount of funds in DeFi lost to smart contract [hacks](https://blog.chainalysis.com/reports/2022-biggest-year-ever-for-crypto-hacking/) was $3.1 billion. Hacks and exploits are still ubiqutous and severly undermine trust in the whole ecosytsen.

Many contracts are deployed with the [OpenZepellin Pausable Module](https://docs.openzeppelin.com/contracts/2.x/api/lifecycle). Usually this works as follows; an address, or multiple addresses are whitelisted, which usually correspond to the protocol owners to pause the contract in case of an emergency. Usually until the whitelisted address gets round to this it is way too late and doesn't prevent any real hacks from happening. What if we could decentralize this procedure, such that anyone who can proove that a vulnerability exists could pause the contract? 

## Architecture
Proceed with caution, this is a proof of concept.

The components required are an off-chain zk-evm proof generator which simulates a transaction and shows that a certain protocol invariant is violated. (This invariant, for example, could be: user cannot withdraw more than their balance). This is found in [Prover](/prover). To compile the circuit run:

`cargo build --release`

This proof can be verified on-chain in /pauser which subsequently calls the pause() function on our exploitable contract in /exploitable-contract.

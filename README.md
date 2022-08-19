## Specification

Account.cairo is a contract account based on OZ with a single signer by default. It integrates a plugin system which allow to have different ways to validate a transaction and access your account. 

AccountPlugin.cairo is a base contract that only works with plugin (With one by default in case none is specified when making a transaction)
The idea is that the rules behind an account can change during its life and ledger's wallet will have two set of rules, one without an hardware wallet, and one with a HW. And changing from one to the other should not trigger a migration of your account. 

## Plugins

Plugins give wallets options to validate a transaction. For instance we have a SessionKey plugin that allow dapp to make transactions on your behalf to create new UX where users do not have the "sign" popup for every action they want to make. 
This sessionKey plgugin is a joint exploration with the (Argent team)[https://github.com/argentlabs/argent-contracts-starknet] and a good explanation about it available (here)[https://www.notion.so/argenthq/Argent-X-Supporting-On-chain-Games-1ec71fc2b6ad4fe19b8f22cc677838b9]

Another Idea is to have a recovery plugin that allow an account to be recover in case you loose your signers by changing the default plugin.

## Development

### Setup a local virtual env

```
python -m venv ./venv
source ./venv/bin/activate
```

### Install Cairo dependencies
```
brew install gmp
```

See for more details:
- https://www.cairo-lang.org/docs/quickstart.html


### Install Python dependencies
```
pip install -r requirements.txt
```

### Compile the contracts
```
nile compile src/Account.cairo
```

### Test the contracts
```
pytest tests/*
```
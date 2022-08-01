## High-Level Specification

This contract account is based on OZ with a single signer by default. It integrates a plugin system which allow to have different ways to validate a transaction and access your account. 
THis plugins could give new ways to recover your accounts

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
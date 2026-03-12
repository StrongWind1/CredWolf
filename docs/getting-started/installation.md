# Installation

Requires Python 3.11+.

## From PyPI

```bash
pip install credwolf
# or
pipx install credwolf
# or
uv tool install credwolf
```

## From source

```bash
pip install git+https://github.com/StrongWind1/CredWolf
# or
pipx install git+https://github.com/StrongWind1/CredWolf
# or
uv tool install git+https://github.com/StrongWind1/CredWolf
```

## Docker

```bash
git clone https://github.com/StrongWind1/CredWolf.git
cd CredWolf
docker build -t credwolf .
docker run --rm --network host credwolf -d evil.corp ntlm --dc-ip 10.0.0.1 -u Administrator -p 'Password1!'
```

The `cw` command is also installed as a shorthand for `credwolf`.

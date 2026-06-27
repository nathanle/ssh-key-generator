```
Usage: ssh-key-generator [OPTIONS] --keytype <KEYTYPE>

Options:
  -k, --keytype <KEYTYPE>      Type [internal, external, deployed]
  -a, --algorithm <ALGORITHM>  Algorithm [RSA, ED25519] [default: RSA]
  -c, --copy-key               Copy to systems using config.toml Default is FALSE
  -h, --help                   Print help
  -V, --version                Print version
``````


Config file syntax is self-explainitory:
```
❯ cat config.toml 
user = "nathan"

[[servers]]
name = "Beta"
ip = "192.168.0.4"
port = 2201

[[servers]]
name = "Alpha"
ip = "192.168.0.5"
port = 2201

[[servers]]
name = "Gamma"
ip = "192.168.0.6"
port = 2201

[[servers]]
name = "bigben"
ip = "192.168.0.8"
port = 2201

[[servers]]
name = "fireball"
ip = "192.168.0.79"
port = 2201

[[servers]]
name = "jetson"
ip = "192.168.0.14"
port = 22

```

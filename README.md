# offsec_rust

## Pilot
bleh

## Why RUST?
There are a lot of discussions regarding this. Here are some well known ones to refer:

Generic usage:

https://www.youtube.com/watch?v=WBhTDoZxpCk

For offsec. engineers

https://steve-s.gitbook.io/0xtriboulet/ttps/ttps-rust-vs-c++


## Using this repo

<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif"> 

<img align="right" alt="ferris the crab snapping hearts" width="350" src="https://rust.saarland/images/ferris_becker.svg"/>

|sym||
|-|-|
|🤔|untested|
|⚰️|signatured|
|🛠️|utility|
|👻|bypassed|
|💀|zero-day|

|sno.|dir|(windows defender)|(crowdstrike)|
|-|-|-|-|
|1|shellcode_local_inject|⚰️|🤔|
|2|shellcode_remote_inject|⚰️|🤔|
|3|shellcode_local_inject_nowinapi|⚰️|🤔|
|4|dll_ops|🛠️|🤔|
|5|remote|🛠️|🤔|
|6|python_automation|🛠️|🤔|
|7|xorshellcode_remote_inject|👻|🤔|
|8|base64shellcode_remote_inject|👻|🤔|
|9|aesshellcode_remote_inject|👻|🤔|
|10|dynamicfuncload_local_inject|👻|🤔|
|11|xorobfus_local_inject|👻|🤔|
|12|xorobfus_remote_inject|👻|🤔|

<img src="https://user-images.githubusercontent.com/73097560/115834477-dbab4500-a447-11eb-908a-139a6edaec5c.gif"> 

<img align="right" alt="ferris the crab snapping hearts" width="350" src="https://cdnb.artstation.com/p/assets/images/images/042/806/685/original/terrified-of-ice-cream-ferrisrust-frame.gif?1635480129"/>

### Quickstarts

### cross compiling rust for windows
```
$ rustup target add x86_64-pc-windows-gnu

# install mingw-w64 for your distro

$ cargo build --target=x86_64-pc-windows-gnu
```

<img align="left" alt="ferris the crab thinker" width="350" src="https://rustacean.net/assets/rustacean-flat-gesture.png"/>

### creating DLLs
```
$ cargo new mydll --lib

# add the following in your toml

[lib]
crate-type = ["cdylib"]

# extern unsafe function call in the loader
```

<img align="right" alt="ferris the crab thief" width="350" src="https://user-images.githubusercontent.com/797/46922345-99723480-cfbc-11e8-8f2d-18eec8f18ad5.png"/>

### cryptography
The python_automation directory contains code that will encode/encrypt data
```
$ python3 xor_cryptor.py PAYLOAD_FILE > OUTPUT_FILE

$ python3 aes_cryptor.py PAYLOAD_FILE SOURCE_FILE
```

<img align="left" alt="ferris the crab knifer" width="350" src="https://user-images.githubusercontent.com/8974888/231858967-7c37bf1e-335b-4f5a-9760-da97be9f54bb.png"/>

### automation
**shcode_embedder.py**: To embedd large `raw` shellcodes into source files in a 0x formatted hex array replacing placeholders

```
$ python3 shcode_embedder.py SOURCE_FILE PLACEHOLDER REPLACEMENT_FILE
```


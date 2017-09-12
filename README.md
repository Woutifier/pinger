# pinger 
## Dependencies
- Rust
- Libpcap

## Build
```
cargo build --release
```

## Commandline options
```Usage:
    pinger [OPTIONS]

Performs pings to IP-addresses received from STDIN

optional arguments:
  -h,--help             show this help message and exit
  -s,--source-address SOURCE_ADDRESS
                        Source IP
  -r,--rate-limit RATE_LIMIT
                        Rate-limit packets per second
  -i,--identifier IDENTIFIER
                        Identifier value to use in Echo Request
  -n,--sequence-number SEQUENCE_NUMBER
                        Sequence number to use in Echo Request
```


# A blockchain protocol --- v0.1
## Message structure
```
| "BLOCK" magic 5-byte string | u8 protocol version | u8 message type | u32 payload size | payload |
```

## Handshake
Exchange information on network nodes.

- *Type*: 1
- *Payload*:
  - `count`: number of node addresses, unsigned integer
  - `list`: list of node objects
    - `addr`: IPv6 address, 16 raw bytes
    - `port`: port, unsigned integer

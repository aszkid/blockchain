# A blockchain protocol --- v0.1
## Message structure
```
| "BLOCK" magic 5-byte string | u8 protocol version | u8 message type | u32 payload size | payload |
```

## Objects

### Node
- `addr`: Ipv6 address, string
- `port`: unsigned integer

### Tx Input
- `tx`: transaction SHA-512 hash, bytes
- `index`: output index in referenced tx, unsigned integer

### Tx Output
- `amount`: currency units to spend, unsigned integer
- `creditor`: public key, bytes

### Transaction
- `debtor`: public key, bytes
- `inputs`: array of Tx Inputs
- `outputs`: array of Tx Outputs

## Handshake
Exchange information on network nodes.

- *Type*: 1
- *Payload*:
  - `nodes`: array of node objects

## Share transactions
- *Type*: 2
- *Payload*:
  - `txs`: array of transaction objects

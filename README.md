# locky

a daemon to remotely unklock luks container.

# protocol

| method | payload |
| ------ | ------- |
| 1 byte | n byte  |

## methods

| code | method |
| ---- | ------ |
| 0x31 | auth   |
| 0x32 | unlock |

## auth

| size   | message | signature |
| ------ | ------- | --------- |
| 2 byte | n byte  | n byte    |

`size` is the size of `message`

if signature is fine the server generates a random key and sends it ecrypted to the client.

| secret |
| n byte |

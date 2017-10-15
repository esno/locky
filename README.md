# locky

locky is a daemon that opens an upd socket and waits for a msg signed by your private rsa key.
After the signature verification locky starts a key exchange for symmetric cryptography.
Now the client has to send the luks cipher. Locky forwards this key via `unix socket` to `luksd`.

## build instructions

    make locky

## usage

    ./locky <publicKey>

## protocol

| method | payload |
| ------ | ------- |
| 1 byte | n byte  |

### methods

| code | method |
| ---- | ------ |
| 0x31 | auth   |
| 0x32 | unlock |

#### auth

| size   | message | signature |
| ------ | ------- | --------- |
| 2 byte | n byte  | n byte    |

`size` is the size of `message`

if signature is fine the server generates a random key and sends it ecrypted to the client.

| secret |
| ------ |
| n byte |

#### unlock

| iv      | crypt  |
| ------- | ------ |
| 16 byte | n byte |

`iv` has to be generated on sender site and has to be **unique** for each message.
`crypt` is the encrypted token used at luks encryption.

# luksd

a daemon to localy unlock luks container. It opens an `unix socket` and waits for password entries.
This is a separate daemon to avoid the situation that a piece of software is running with
root privileges and opens a publicly available udp socket.

## build instructions

    make luksd

## usage

    ./locky <luksDevice> <luksName> <socketOwner> <socketGroup>

# unlock

`unlock` is the reference cli client for `locky` written in lua.

## generate keys

    make keys

## usage

    ./unlock <host> <privateKey>

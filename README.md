# rluksd

rluksd is a daemon written to control luks containers remotely.
It uses udp datagrams to make it harder for network scanners to detect an internet
facing system.

The daemon is completely in silent mode. That means it's waiting for authentication
messages with a valid signature. After signature verification rluksd generates a
random key for symmetric encryption/decryption and sends that secret to the client.
The shared secret will be encrypted by an asymmetric encryption using the same public key
as for signature verification.

After a succcessful key exchange the client is allowed to request information about the state
of luks containers and can send a key to decrypt one of them.

rluksd provides a lean way to secure your data on remote machines like servers hosted in any kind
of datacenter. It's designed to prevent opening ssh for the public and aimes to use as less
dependencies as possible.

Last but not least the whole rluksd setup is shipped in two separated binaries to ensure
that only the part that requires root privileges runs as root. The network communication
can be done in an unprivileged user context.

## benefits

* each peer has it's own shared secret
* package replay protection by using nonce for authentication
* no broadcasting (it only responds to authenticated peers when they requesting something
* privilege separation
* less dependencies

## build instructions

install dependencies

* openssl
* cryptsetup

### build

    make rluksd

## usage

    ./rluksd <publicKey> <socket>

## protocol

| method | payload |
| ------ | ------- |
| 1 byte | n byte  |

### methods

| code | method |
| ---- | ------ |
| 0x01 | auth   |
| 0x02 | status |
| 0x03 | unlock |
| 0x04 | lock   |

#### auth

| message_l | signature_l | message   | signature |
| --------- | ----------- | --------- | --------- |
| 2 byte    | 2 byte      | n byte    | n byte    |

`message_l` and `signature_l` defines the `message` and `signature` length

if signature is fine the server generates a random key and sends it ecrypted to the client.

| secret_l | secret |
| -------- | ------ |
| 2 byte   | n byte |

`secret_l` defines the secret length

#### unlock (wip)

| iv      | crypt  |
| ------- | ------ |
| 16 byte | n byte |

`iv` has to be generated on sender site and has to be **unique** for each message.
`crypt` is the encrypted token used at luks encryption.

# luksd

luksd is the container management daemon. It opens an `unix socket` and waits for incoming requests.
It is a seperate daemon to avoid running an application as root that will be available through the
internet.

## build instructions

    make luksd

## usage

    ./uksd <socketOwner> <socketGroup> [<socket>]

## protocol

| method | payload |
| ------ | ------- |
| 1 byte | n byte  |

### methods

| code | method |
| ---- | ------ |
| 0x02 | status |
| 0x03 | unlock |
| 0x04 | lock   |

#### status

##### request

| name_l | path_l | name   | path   |
| ------ | ------ | ------ | ------ |
| 2 byte | 2 byte | n byte | n byte |

##### response

| method | status |
| ------ | ------ |
| 1 byte | 1 byte |

see [libcryptsetup](https://gitlab.com/cryptsetup/cryptsetup/wikis/API/group__crypt-devstat.html#ga94309106213ec66fb196a32d73eefb5b)
for more information about available states.

# unlock

`unlock` is the reference cli client for `locky` written in lua.

## install

_requires lua 5.3_

    luarocks install locky

## generate keys

    make keys

## usage

    ./unlock <host> <privateKey>

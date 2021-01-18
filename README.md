# rLUKSd

rLUKSd is written to control luks (linux unified key setup) containers remotely.
It uses udp datagrams to make it harder for network scanners to detect an internet
facing system.

It's running completely in silent mode. That means it's waiting for authentication
messages containing a valid signature. After the message signature verification,
a random key for symmetric encryption/decryption will be generated and send to the client.
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

## Benefits

* each peer has it's own shared secret
* package replay protection by using nonce for authentication
* no broadcasting (it only responds to authenticated peers when they requesting something
* privilege separation
* less dependencies

## Build

    git clone https://github.com/esno/rluksd.git
    mkdir build; cd build
    cmake .. && make

## Components

### luksd

luksd is the container management daemon. It opens an `unix socket` and waits for incoming requests.
It is a seperate daemon to avoid running an application as root that will be available through the
internet.

#### usage

    ./luksd <socketOwner> <socketGroup> [<socket>]

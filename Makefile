LDFLAGS_LOCKY += -lcrypto -lssl ${LDFLAGS}
LDFLAGS_LUKSD += -lcryptsetup ${LDFLAGS}

all: rluksd luksd

keys:
	install -m 0700 -d keys
	openssl genrsa -out keys/private.key.pem 4096
	openssl rsa -in keys/private.key.pem -pubout -out keys/public.key.pem
	#openssl ecparam -name secp384r1 -genkey -noout -out keys/private.key.pem
	#openssl ec -in keys/private.key.pem -pubout -out keys/public.key.pem

rluksd:
	${CC} src/locky.c -o rluksd ${LDFLAGS_LOCKY}

luksd:
	${CC} src/luksd.c -o luksd ${LDFLAGS_LUKSD}

clean:
	rm -rf rluksd luksd

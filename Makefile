LDFLAGS += -lcrypto -lssl

all: locky

keys:
	install -m 0700 -d keys
	openssl ecparam -name secp384r1 -genkey -noout -out keys/private.key.pem
	openssl ec -in keys/private.key.pem -pubout -out keys/public.key.pem

locky:
	${CC} ${LDFLAGS} -o locky src/locky.c

clean:
	rm -rf locky

all: rluksd luksd

keys:
	install -m 0700 -d keys
	openssl genrsa -out keys/private.key.pem 4096
	openssl rsa -in keys/private.key.pem -pubout -out keys/public.key.pem
	#openssl ecparam -name secp384r1 -genkey -noout -out keys/private.key.pem
	#openssl ec -in keys/private.key.pem -pubout -out keys/public.key.pem

rluksd_luksd.o:
	${CC} -c ./src/rluksd_luksd.c -I./src/include

rluksd_crypt.o:
	${CC} -c ./src/rluksd_crypt.c -I./src/include

rluksd_net.o:
	${CC} -c ./src/rluksd_net.c -I./src/include

rluksd: rluksd_luksd.o rluksd_crypt.o rluksd_net.o
	${CC} -c ./src/rluksd.c -I./src/include
	${CC} -o ./rluksd ./rluksd_luksd.o ./rluksd_crypt.o ./rluksd_net.o ./rluksd.o -lcrypto -lssl ${LDFLAGS}

luksd_cryptsetup.o:
	${CC} -c ./src/luksd_cryptsetup.c -I./src/include

luksd_socket.o:
	${CC} -c ./src/luksd_socket.c -I./src/include

luksd: luksd_cryptsetup.o luksd_socket.o
	${CC} -c ./src/luksd.c -I./src/include
	${CC} -o ./luksd ./luksd_cryptsetup.o ./luksd_socket.o ./luksd.o -lcryptsetup ${LDFLAGS}

clean:
	rm -rf ./rluksd ./luksd ./*.o

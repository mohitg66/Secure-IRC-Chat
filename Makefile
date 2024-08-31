# compile server.c with linking to the library -lssl -lcrypto
all:
	make symmetric_keys
	gcc -o server server.c -lssl -lcrypto -lpthread
	gcc -o client client.c -lssl -lcrypto -lpthread

server: server
	gcc -o server server.c -lssl -lcrypto -lpthread

client: client
	gcc -o client client.c -lssl -lcrypto -lpthread

symmetric_keys:
	# write code for larry bill steve mukesh azim mark ircs
	mkdir -p symmetric_keys
	openssl kdf -keylen 32 -out symmetric_keys/1000 -kdfopt digest:SHA256 -kdfopt pass:"mohit" -kdfopt salt:"$(head -c 32 /dev/urandom)" -kdfopt iter:2 PBKDF2
	openssl kdf -keylen 32 -out symmetric_keys/1001 -kdfopt digest:SHA256 -kdfopt pass:"fakeroot" -kdfopt salt:"$(head -c 32 /dev/urandom)" -kdfopt iter:2 PBKDF2	
	openssl kdf -keylen 32 -out symmetric_keys/1002 -kdfopt digest:SHA256 -kdfopt pass:"larry" -kdfopt salt:"$(head -c 32 /dev/urandom)" -kdfopt iter:2 PBKDF2
	openssl kdf -keylen 32 -out symmetric_keys/1003 -kdfopt digest:SHA256 -kdfopt pass:"bill" -kdfopt salt:"$(head -c 32 /dev/urandom)" -kdfopt iter:2 PBKDF2
	openssl kdf -keylen 32 -out symmetric_keys/1004 -kdfopt digest:SHA256 -kdfopt pass:"steve" -kdfopt salt:"$(head -c 32 /dev/urandom)" -kdfopt iter:2 PBKDF2
	openssl kdf -keylen 32 -out symmetric_keys/1005 -kdfopt digest:SHA256 -kdfopt pass:"mukesh" -kdfopt salt:"$(head -c 32 /dev/urandom)" -kdfopt iter:2 PBKDF2
	openssl kdf -keylen 32 -out symmetric_keys/1006 -kdfopt digest:SHA256 -kdfopt pass:"azim" -kdfopt salt:"$(head -c 32 /dev/urandom)" -kdfopt iter:2 PBKDF2
	openssl kdf -keylen 32 -out symmetric_keys/1007 -kdfopt digest:SHA256 -kdfopt pass:"mark" -kdfopt salt:"$(head -c 32 /dev/urandom)" -kdfopt iter:2 PBKDF2
	openssl kdf -keylen 32 -out symmetric_keys/ircs -kdfopt digest:SHA256 -kdfopt pass:"ircs" -kdfopt salt:"$(head -c 32 /dev/urandom)" -kdfopt iter:2 PBKDF2
	
clean:
	rm -f server client
	rm -rf symmetric_keys
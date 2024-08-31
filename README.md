# Secure IRC Chat
Secure IRC Chat is a platform designed to facilitate secure communication between users. It provides end-to-end encryption, ensuring that messages remain private and secure. The system uses the Needham Schroeder Authentication scheme to authenticate the clients.

## System Design
The system employs a client-server architecture where clients communicate with the server to send and receive messages. The server listens on 2 ports, one for KDC and another for Chat. The server checks authenticity of the users before connecting them to the chat. Messages are encrypted using aes algorithm before transmission and decrypted upon receipt, ensuring data confidentiality.

## Vulnerabilities that the System has handled
<!-- CBC mode is used not ECB -->
- **Reflection Attack**: An attacker cannot use reflection attack to get the answer to the challenge sent by the server, as the system uses AES in CBC mode, which is not vulnerable to reflection attack.

- **Buffer Overflow Attack**: When taking input from the user, the system uses `fgets()` to ensure that the input does not exceed the buffer size.

- The system uses fixed buffer sizes in all send and recv calls, which prevents **Stack Smashing Attacks**.

- **Replay Attack**: An cannot replay a message sent by a user, as the system uses a nonce to prevent replay attacks.


## Assumptions Made
- The long term keys of the users are generated by the KDC using the Password Based Key Derivation Function (PBKDF) built into openssl, and are pre-shared with the users.
- The server can support only a few clients simultaneously.

## Instructions
- Run `make clean` to remove the executables.
- Run `make` to compile the code.
- Run `./server` to start the server.
- Run `./client` to start the client.
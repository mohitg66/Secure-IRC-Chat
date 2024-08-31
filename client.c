// write the client code for Needham Schroeder authentication protocol, by getting context from the server.c


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <signal.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#define len sizeof
#define IP "127.0.0.1"
#define KDC_PORT 1280
#define CHAT_PORT KDC_PORT+1
#define KEY_SIZE 32
#define NONCE_SIZE 16

unsigned char *iv;

// declaration of functions
int create_client_kdc_socket();
int create_client_chat_socket();
void chat(int client_chat_socket, unsigned char *session_key);
void authenticate(int client_kdc_socket, char*uid1, char *uid2);
void chat(int client_chat_socket, unsigned char *session_key);

void printHex(char *a, int n) {
    for (size_t i = 0; i < n; i++) printf("%02X ", a[i]); printf("\n");
}

void print(char *a, int n) {
    for (size_t i = 0; i < n; i++) printf("%c", a[i]); printf("\n");
}

void handleErrors(void) {
    ERR_print_errors_fp(stderr);
    abort();
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx;

    int length;
    int ciphertext_len;

    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &length, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = length;

    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + length, &length))
        handleErrors();
    ciphertext_len += length;

    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx;

    int length;
    int plaintext_len;

    if(!(ctx = EVP_CIPHER_CTX_new()))
        handleErrors();

    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    if(1 != EVP_DecryptUpdate(ctx, plaintext, &length, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = length;

    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + length, &length))
        handleErrors();
    plaintext_len += length;

    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

void chat(int client_chat_socket, unsigned char *session_key) {
    // now all communication is encrypted with session key
    // client recievs confirmation from server
    unsigned char confirmation_ciphertext[256];
    int n= recv(client_chat_socket, confirmation_ciphertext, 256, 0);
    printf("Recieved(%d) confirmation from server\n", n);
    unsigned char confirmation[256];
    int confirmation_len = decrypt(confirmation_ciphertext, n, session_key, iv, confirmation);
    print(confirmation, confirmation_len);

    if (fork()==0){
        // keep listening from server for any broadcast messages
        while (1) {
            unsigned char ciphertext_message_from_server[256];
            n= recv(client_chat_socket, ciphertext_message_from_server, 256, 0);
            if (n==0) {
                printf("Server closed connection\n");
                exit(0);
            }
            // printf("Recieved(%d) message from server\n", n);
            unsigned char message_from_server[256];
            int message_from_server_len = decrypt(ciphertext_message_from_server, n, session_key, iv, message_from_server);
            print(message_from_server, message_from_server_len);
        }
    } else {
        // keep taking input from user and sending it to server
        while (1) {
            char message[256];
            fgets(message, 256, stdin);
            unsigned char ciphertext_message[256];
            int ciphertext_message_len = encrypt(message, strlen(message), session_key, iv, ciphertext_message);
            n= send(client_chat_socket, ciphertext_message, ciphertext_message_len, 0);
            if (n==0) {
                printf("Server closed connection\n");
                exit(0);
            }
            // printf("Sent(%d) message to server\n", n);
        }
    }
}

void authenticate(int client_kdc_socket, char *uid1, char *uid2) {
    // client first sends a n1, uid1, uid2 to kdc_server
    unsigned char buffer[1024], n1[NONCE_SIZE];
    RAND_bytes(n1, NONCE_SIZE);
    memcpy(buffer, n1, NONCE_SIZE);
    memcpy(buffer + NONCE_SIZE, uid1, 4);
    memcpy(buffer + NONCE_SIZE + 4, uid2, 4);
    int n= send(client_kdc_socket, buffer, NONCE_SIZE+ 4+ 4, 0);
    printf("Sent(%d) n1, uid1, uid2 to KDC\n", n);
    // print all the data sent
    // printHex(buffer, n);

    // client then recieves {the n1 sent, uid2, session key, ticket = {session key, uid1} encrypted with uid2's key} encrypted with uid1's key
    unsigned char ciphertext_message[1024];
    n= recv(client_kdc_socket, ciphertext_message, len(ciphertext_message), 0);
    printf("Recieved(%d) {msg} with {ticket} from KDC\n", n);
    close(client_kdc_socket);

    // get uid1's key
    char filename[20];
    strcpy(filename, "symmetric_keys/");
    memcpy(filename + strlen(filename), uid1, 4);
    memcpy(filename + strlen(filename)+ 4, "\0", 1);
    FILE *fp = fopen(filename, "rb");
    unsigned char key1[32];
    fread(key1, 32, 1, fp);
    fclose(fp);

    // client decrypts and verifies the message with uid1's key
    unsigned char decryptedtext[1024];
    int decryptedtext_len = decrypt(ciphertext_message, n, key1, iv, decryptedtext);
    unsigned char nonce_1[NONCE_SIZE], uid2_1[4], session_key[KEY_SIZE], ticket[48];
    memcpy(nonce_1, decryptedtext, NONCE_SIZE);
    memcpy(uid2_1, decryptedtext + NONCE_SIZE, 4);
    memcpy(session_key, decryptedtext + NONCE_SIZE + 4, KEY_SIZE);
    memcpy(ticket, decryptedtext + NONCE_SIZE + 4 + KEY_SIZE, 48);

    if (memcmp(n1, nonce_1, NONCE_SIZE) != 0) {
        printf("Nonce1 does not match\n");
        exit(1);
    }

    if (memcmp(uid2, uid2_1, 4) != 0) {
        printf("uid2 does not match\n");
        exit(1);
    }
    printf("Nonce1 and uid2 verified\n");

    // client forwards the ticket, {nonce2} encrypted with session key to the server
    unsigned char nonce2[NONCE_SIZE];
    RAND_bytes(nonce2, NONCE_SIZE);
    unsigned char ciphertext_nonce2[1024];
    int ciphertext_nonce2_len = encrypt(nonce2, NONCE_SIZE, session_key, iv, ciphertext_nonce2);

    int client_chat_socket = create_client_chat_socket();
    n= send(client_chat_socket, ticket, 48, 0);
    n+= send(client_chat_socket, ciphertext_nonce2, ciphertext_nonce2_len, 0);
    printf("Ticket and nonce2 (%d) sent to server\n", n);

    // client recieves {nonce2-1, nonce3} encrypted with session key
    unsigned char ciphertext_nonce2_1_nonce3[1024];
    n= recv(client_chat_socket, ciphertext_nonce2_1_nonce3, len(ciphertext_nonce2_1_nonce3), 0);
    printf("Recieved(%d) encrypted message with nonce2-1 and nonce3 from server\n", n);

    // client decrypts and verifies the message with session key
    unsigned char decryptedtext_nonce2_1_nonce3[1024];
    int decryptedtext_nonce2_1_nonce3_len = decrypt(ciphertext_nonce2_1_nonce3, n, session_key, iv, decryptedtext_nonce2_1_nonce3);
    unsigned char nonce2_1[NONCE_SIZE], nonce3[NONCE_SIZE];
    memcpy(nonce2_1, decryptedtext_nonce2_1_nonce3, NONCE_SIZE);
    memcpy(nonce3, decryptedtext_nonce2_1_nonce3 + NONCE_SIZE, NONCE_SIZE);

    // verify nonce2-1
    for (int i = 0; i < NONCE_SIZE; i++) {
        if (nonce2[i]-1 != nonce2_1[i]) {
            printf("Nonce2 does not match\n");
            exit(1);
        }
    }
    printf("Nonce2 verified\n");

    // client sends {nonce3-1} encrypted with session key to the server
    unsigned char nonce3_1[NONCE_SIZE];
    for (int i = 0; i < NONCE_SIZE; i++) {
        nonce3_1[i] = nonce3[i]-1;
    }
    unsigned char ciphertext_nonce3_1[256];
    int ciphertext_nonce3_1_len = encrypt(nonce3_1, NONCE_SIZE, session_key, iv, ciphertext_nonce3_1);

    n= send(client_chat_socket, ciphertext_nonce3_1, ciphertext_nonce3_1_len, 0);
    printf("Nonce3-1(%d) sent to server\n", n);

    // client starts chat
    chat(client_chat_socket, session_key);
}

int create_client_kdc_socket() {
    struct sockaddr_in server_addr;
    int sock= socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        exit(1);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(KDC_PORT);
    server_addr.sin_addr.s_addr = inet_addr(IP);

    if (connect(sock, (struct sockaddr *) &server_addr, len(server_addr)) < 0) {
        perror("connect");
        exit(1);
    }

    return sock;
}

int create_client_chat_socket() {
    struct sockaddr_in server_addr;
    int sock= socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        exit(1);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(CHAT_PORT);
    server_addr.sin_addr.s_addr = inet_addr(IP);

    if (connect(sock, (struct sockaddr *) &server_addr, len(server_addr)) < 0) {
        perror("connect");
        exit(1);
    }

    return sock;
}

int main(int argc, char *argv[]) {
    iv= (unsigned char *)"0123456789012345";

    unsigned char uid2[4]= {'i', 'r', 'c', 's'}, uid1[4];
    // store the result of getuid() in uid1 
    sprintf(uid1, "%u", getuid());

    // print uid1 and uid2
    printf("uid1: "); print(uid1, 4);
    printf("uid2: "); print(uid2, 4);

    int client_kdc_socket = create_client_kdc_socket();
    authenticate(client_kdc_socket, uid1, uid2);

    return 0;
}
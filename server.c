/*
Design the Server Architecture for Needham Schroeder Protocol

Create a multi-threaded server using socket programming in C, using fork()
Separate functionality for KDC (Key Distribution Center) and the chat server operations.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
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

int client_sockets[20];
char *client_uids[20];
int client_count = 0;
unsigned char session_key[KEY_SIZE];

// declaration of functions
void create_kdc_socket(int *kdc_socket);
void create_chat_socket(int *chat_socket);
void handle_kdc_server(int kdc_socket);
void handle_client_for_kdc(int client_socket, int kdc_socket);
void handle_chat_server(int chat_socket);
void* handle_client_for_chat(void *client_socket);
void irc_chat(int client_socket, unsigned char *uid1);

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

void irc_chat(int client_socket, unsigned char *uid1) {
    /*
The server presents a IRC like interface to the user where the
user can see all other users. He/she can also view his/her own files, as well as that of
others. He/she can communicate with all users by broadcasting.

It must support the following commands:
• “/who”: Who all are logged in to the chat server, along with a user IDs.
• “/write all”: Write message which gets broadcasted to all users.
• “/create group”: Create a group to which users may be added. A group ID and
name is returned.
• “/group invite”: Send an invite to individual users IDs.
• “/group invite accept”: Accept the group invite.
• “/request public key”: Send request for public key to a specific users.
• “/send public key”: Send back public key back as a response to the above request.
    */

   // update clients
    client_sockets[client_count] = client_socket;
    // memcpy(uid1, uid1, 4);
    client_uids[client_count] = uid1;
    printf("Client %d added to chat\n", client_count);
    client_count++;

    // Send "welcome to irc chat" to the client encrypted with session key
    unsigned char welcome[256]= "\nIRCS: Welcome to IRC Chat\n";
    unsigned char ciphertext_welcome[256];
    int ciphertext_welcome_len = encrypt(welcome, strlen(welcome), session_key, iv, ciphertext_welcome);
    // printHex(ciphertext_welcome, ciphertext_welcome_len);
    int n= send(client_socket, ciphertext_welcome, ciphertext_welcome_len, 0);
    printf("Sent(%d) welcome message to client %.4s\n", n, uid1);

    // keep recieving messages from client and handling them
    while (1) {
        unsigned char ciphertext_buffer[256];
        int n= recv(client_socket, ciphertext_buffer, len(ciphertext_buffer), 0);
        printf("Recieved(%d) message from client %.4s\n", n, uid1);
        if (n == 0) break;

        // decrypt the message
        unsigned char buffer[256];
        int buffer_len = decrypt(ciphertext_buffer, n, session_key, iv, buffer);

        // print the message
        printf("Client %.4s: ", uid1);
        print(buffer, buffer_len);

        // if the message is "/who", send the list of clients
        if (strncmp(buffer, "/who", 4) == 0) {
            // send the list of clients
            unsigned char message[256];
            strcpy(message, "IRCS: List of Clients:\n");
            for (int i = 0; i < client_count; i++) {
                strncat(message, client_uids[i], 4);
                strcat(message, "\n");
            }
            unsigned char ciphertext_message[256];
            int ciphertext_message_len = encrypt(message, strlen(message), session_key, iv, ciphertext_message);
            n= send(client_socket, ciphertext_message, ciphertext_message_len, 0);
            printf("Sent(%d) list of clients to client\n", n);
        }

        // if the message is "/write all", send the list of clients
        else if (strncmp(buffer, "/write_all", 10) == 0) {
            unsigned char broadcast[256];
            snprintf(broadcast, 256, "%.4s: ", uid1);
            strncat(broadcast, buffer + 11, buffer_len - 11);
            int broadcast_len = strlen(broadcast);
            
            unsigned char ciphertext_broadcast[256];
            int ciphertext_broadcast_len = encrypt(broadcast, broadcast_len, session_key, iv, ciphertext_broadcast);
            
            // send the message to all clients
            for (int i = 0; i < client_count; i++) {
                n= send(client_sockets[i], ciphertext_broadcast, ciphertext_broadcast_len, 0);
                printf("Sent(%d) broadcast to client %.4s\n", n, client_uids[i]);
            }
        }

        // else send invalid command
        else {
            unsigned char message[256]= "IRCS: Invalid Command\n";
            unsigned char ciphertext_message[256];
            int ciphertext_message_len = encrypt(message, strlen(message), session_key, iv, ciphertext_message);
            n= send(client_socket, ciphertext_message, ciphertext_message_len, 0);
            printf("Sent(%d) invalid command to client %.4s\n", n, uid1);
        }
    }

    // close the client socket and remove the client from the list
    close(client_socket);
    printf("Client %.4s disconnected from chat\n", uid1);
    for (int i = 0; i < client_count; i++) {
        if (client_sockets[i] == client_socket) {
            for (int j = i; j < client_count - 1; j++) {
                client_sockets[j] = client_sockets[j+1];
                client_uids[j] = client_uids[j+1];
            }
            client_count--;
            break;
        }
    }
}


void create_kdc_socket(int *kdc_socket) {
    struct sockaddr_in kdc_addr;

    // Create a socket
    *kdc_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (*kdc_socket < 0) {
        perror("Couldn't create socket");
        exit(1);
    }

    // Bind the socket to an IP and port
    kdc_addr.sin_family = AF_INET;
    kdc_addr.sin_port = htons(KDC_PORT);
    kdc_addr.sin_addr.s_addr = inet_addr(IP);
    if (bind(*kdc_socket, (struct sockaddr*)&kdc_addr, len(kdc_addr)) < 0) {
        perror("Couldn't bind to the port");
        exit(1);
    }

    // Listen for connections
    if (listen(*kdc_socket, 20) < 0) {
        perror("Couldn't listen");
        exit(1);
    }

    printf("KDC Server listening on Port: %i\n", KDC_PORT);
}


void create_chat_socket(int *chat_socket) {
    struct sockaddr_in chat_addr;

    // Create a socket
    *chat_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (*chat_socket < 0) {
        perror("Couldn't create socket");
        exit(1);
    }

    // Bind the socket to an IP and port
    chat_addr.sin_family = AF_INET;
    chat_addr.sin_port = htons(CHAT_PORT);
    chat_addr.sin_addr.s_addr = inet_addr(IP);
    if (bind(*chat_socket, (struct sockaddr*)&chat_addr, len(chat_addr)) < 0) {
        perror("Couldn't bind to the port");
        exit(1);
    }

    // Listen for connections
    if (listen(*chat_socket, 20) < 0) {
        perror("Couldn't listen");
        exit(1);
    }

    printf("Chat Server listening on Port: %i\n", CHAT_PORT);
}


void handle_kdc_server(int kdc_socket) {
    int client_socket, client_size;
    struct sockaddr_in client_addr;

    while (1) {
        // Accept an incoming connection
        client_size = len(client_addr);
        client_socket = accept(kdc_socket, (struct sockaddr*)&client_addr, &client_size);

        if (client_socket < 0) {
            perror("Can't accept");
            exit(1);
        }
        printf("\nClient connected to KDC Server at Port: %i\n", ntohs(client_addr.sin_port));
        

        // fork
        if (fork() == 0) {
            close(kdc_socket);
            handle_client_for_kdc(client_socket, kdc_socket);
        } else {
            close(client_socket);
            wait(NULL);
        }
    }
}


void handle_chat_server(int chat_socket) {
    int client_socket, client_size;
    struct sockaddr_in client_addr;

    while (1) {
        // Accept an incoming connection
        client_size = len(client_addr);
        client_socket = accept(chat_socket, (struct sockaddr*)&client_addr, &client_size);

        if (client_socket < 0) {
            perror("Can't accept");
            exit(1);
        }
        printf("Client connected to Chat Server at Port: %i\n", ntohs(client_addr.sin_port));

        // fork
        // if (fork() == 0) {
        //     close(chat_socket);
        //     handle_client_for_chat(client_socket, chat_socket);
        // } else {
        //     close(client_socket);
        //     wait(NULL);
        // }

        // create a new thread for the client
        pthread_t thread_id;
        pthread_create(&thread_id, NULL, handle_client_for_chat, (void *)&client_socket);

    }
}


void handle_client_for_kdc(int client_socket, int kdc_socket) {
    // kdc server first recieves a n1, uid1, uid2 from client
    // kdc server then sends {the n1 recieved, uid2, session key, ticket = {session key, uid1} encrypted with uid2's key} encypted with uid1's key

    // recieve n1, uid1, uid2 from client
    unsigned char buffer[1024], n1[NONCE_SIZE], uid1[4], uid2[4];
    int n= recv(client_socket, buffer, len(buffer), 0);
    printf("Client %.4s connected to KDC\n", buffer+ NONCE_SIZE);
    printf("Recieved(%d) n1, uid1, uid2 from client\n", n);
    // print all the recieved data
    // printHex(buffer, n);

    memcpy(n1, buffer, NONCE_SIZE);
    memcpy(uid1, buffer + NONCE_SIZE, 4);
    memcpy(uid2, buffer + NONCE_SIZE + 4, 4);

    // get uid1's key
    char filename[20];
    strcpy(filename, "symmetric_keys/");
    memcpy(filename + strlen(filename), uid1, 4);
    memcpy(filename + strlen(filename)+ 4, "\0", 1);
    FILE *fp = fopen(filename, "rb");
    unsigned char key1[32];
    fread(key1, 32, 1, fp);
    fclose(fp);

    // get uid2's key
    strcpy(filename, "symmetric_keys/");
    memcpy(filename + strlen(filename), uid2, 4);
    memcpy(filename + strlen(filename)+ 4, "\0", 1);
    fp = fopen(filename, "rb");
    unsigned char key2[32];
    fread(key2, 32, 1, fp);
    fclose(fp);


    // create a ticket
    unsigned char ticket[36];
    memcpy(ticket, session_key, KEY_SIZE);
    memcpy(ticket + KEY_SIZE, uid1, 4);

    // encrypt the ticket with uid2's key
    unsigned char ciphertext_ticket[1024];
    int ciphertext_ticket_len = encrypt(ticket, len(ticket), key2, iv, ciphertext_ticket);
    // printf("ciphertext_ticket_len: %d\n", ciphertext_ticket_len);

    // send the {n1, uid2, session key, ticket = {{session key, uid1} encrypted with uid2's key} encrypted with uid1's key
    memcpy(buffer, n1, NONCE_SIZE);
    memcpy(buffer + NONCE_SIZE, uid2, 4);
    memcpy(buffer + NONCE_SIZE + 4, session_key, KEY_SIZE);
    memcpy(buffer + NONCE_SIZE + 4 + KEY_SIZE, ciphertext_ticket, ciphertext_ticket_len);
    
    unsigned char ciphertext_message[1024];
    int ciphertext_message_len = encrypt(buffer, 100, key1, iv, ciphertext_message);
    // printf("ciphertext_message_len: %d\n", ciphertext_message_len);

    n= send(client_socket, ciphertext_message, ciphertext_message_len, 0);
    printf("Sent(%d) n1, uid2, session key, ticket to client\n", n);
    close(client_socket);

    printf("Client %.4s disconnected from KDC\n", uid1);
    exit(0);
}


void* handle_client_for_chat(void *client_socket1) {
    int client_socket = *(int *)client_socket1;
    
    // the chat server recieves ticket, {nonce2} encrypted with session key
    // then sends {nonce2 -1, nonce3} encrypted with session key
    // then recieves {nonce3 -1} encrypted with session key

    // recieve ticket, {nonce2} encrypted with session key
    unsigned char buffer[1024], ciphertext_ticket[48], ciphertext_nonce2[32];
    int n= recv(client_socket, buffer, len(buffer), 0);
    printf("Recieved(%d) ticket and nonce2 from client\n", n);
    memcpy(ciphertext_ticket, buffer, 48);
    memcpy(ciphertext_nonce2, buffer + 48, 32);

    unsigned char uid2[4]= "ircs";
    char filename[20];
    // get uid2's key
    strcpy(filename, "symmetric_keys/ircs");
    FILE *fp = fopen(filename, "rb");
    unsigned char key2[32];
    fread(key2, 32, 1, fp);
    fclose(fp);

    // decrypt the ticket
    unsigned char ticket[1024];
    int ticket_len = decrypt(ciphertext_ticket, 48, key2, iv, ticket);
    // printf("Ticket_len: %d\n", ticket_len);

    // get session key and uid1
    unsigned char session_key[32], uid1[4];
    memcpy(session_key, ticket, KEY_SIZE);
    memcpy(uid1, ticket + KEY_SIZE, 4);

    // decrypt nonce2, create nonce2 - 1, nonce3
    unsigned char nonce2[256];
    int nonce2_len = decrypt(ciphertext_nonce2, 32, session_key, iv, nonce2);
    // printf("Nonce2_len: %d\n", nonce2_len);

    unsigned char nonce2_1[16], nonce3[16];
    memcpy(nonce2_1, nonce2, NONCE_SIZE);
    // nonce2_1 = nonce2 - 1
    for (int i = 0; i < NONCE_SIZE; i++) 
        nonce2_1[i] = nonce2_1[i] - 1;
    RAND_bytes(nonce3, 16);

    // send nonce2_1, nonce3 encrypted with session key
    unsigned char message[256];
    memcpy(message, nonce2_1, NONCE_SIZE);
    memcpy(message + NONCE_SIZE, nonce3, NONCE_SIZE);

    unsigned char ciphertext_message[256];
    int ciphertext_message_len = encrypt(message, 2*NONCE_SIZE, session_key, iv, ciphertext_message);

    n= send(client_socket, ciphertext_message, ciphertext_message_len, 0);
    printf("Sent(%d) Nonce2-1, Nonce3 to client\n", n);

    // recieve nonce3 - 1 encrypted with session key
    unsigned char ciphertext_nonce3_1[32];
    n= recv(client_socket, ciphertext_nonce3_1, 2* NONCE_SIZE, 0);
    printf("Recieved(%d) Nonce3-1 from client\n", n);

    // decrypt nonce3_1
    unsigned char nonce3_1[16];
    int nonce3_1_len = decrypt(ciphertext_nonce3_1, n, session_key, iv, nonce3_1);

    // verify nonce3_1 = nonce3 - 1
    int flag = 1;
    for (int i = 0; i < len(nonce3_1); i++) {
        if (nonce3_1[i] != nonce3[i] - 1) {
            printf("Nonce3 does not match\n");
            exit(1);
        }
    }
    printf("Nonce3 verified\n");

    if (flag) {
        printf("Client %.4s Authenticated and Connected to Chat\n", uid1);
        irc_chat(client_socket, uid1);
    } else {
        printf("Client %.4s found Invalid and Disconnected from Chat\n", uid1);
        close(client_socket);
    }
}


int main() {
    iv= (unsigned char *)"0123456789012345";

    int kdc_socket, chat_socket;
    RAND_bytes(session_key, KEY_SIZE);

    create_kdc_socket(&kdc_socket);
    create_chat_socket(&chat_socket);
    printf("\n");

    // fork to listen to both sockets
    if (fork() == 0) {
        close(chat_socket);
        handle_kdc_server(kdc_socket);
        close(kdc_socket);
    } else {
        close(kdc_socket);
        handle_chat_server(chat_socket);
        close(chat_socket);
    }

    return 0;
}

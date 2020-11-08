//
// Created by Elisa Giurgea on 07.11.2020.
//

#ifndef ELISASI_DATECOMUNE_H
#define ELISASI_DATECOMUNE_H

#include <iostream>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <string>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>
#include <functional>
#include <algorithm>
#include <vector>
#include <random>
#include <fstream>

using namespace std;

#define COMMUNICATION_MAGIC 0x006A6E72
#define BLOCK_SIZE 16
#define MAX_SIZE 4096

// https://stackoverflow.com/questions/47977829/generate-a-random-string-in-c11
string random_string(size_t length)
{
    string str("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789");
    random_device rd;
    mt19937 generator(rd());

    shuffle(str.begin(), str.end(), generator);

    return str.substr(0, length);
}

string K3 = "TKsRORkwImtmGd4v";
string IV = "@#WEDFRGTHYUIOKO";

// https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption
int encrypt_ecb(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    if(!(ctx = EVP_CIPHER_CTX_new()))
    {
        ERR_print_errors_fp(stderr);
        abort();
    }

    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, iv))
    {
        ERR_print_errors_fp(stderr);
        abort();
    }

    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    {
        ERR_print_errors_fp(stderr);
        abort();
    }

    ciphertext_len = len;

    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
    {
        ERR_print_errors_fp(stderr);
        abort();
    }

    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int decrypt_ecb(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;

    if (!(ctx = EVP_CIPHER_CTX_new()))
    {
        ERR_print_errors_fp(stderr);
        abort();
    }

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, iv))
    {
        ERR_print_errors_fp(stderr);
        abort();
    }

    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    {
        ERR_print_errors_fp(stderr);
        abort();
    }

    plaintext_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
    {
        ERR_print_errors_fp(stderr);
        abort();
    }

    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

int encrypt_cfb(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;

    if(!(ctx = EVP_CIPHER_CTX_new()))
    {
        ERR_print_errors_fp(stderr);
        abort();
    }

    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cfb(), NULL, key, iv))
    {
        ERR_print_errors_fp(stderr);
        abort();
    }

    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    {
        ERR_print_errors_fp(stderr);
        abort();
    }

    ciphertext_len = len;

    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
    {
        ERR_print_errors_fp(stderr);
        abort();
    }

    ciphertext_len += len;
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int decrypt_cfb(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;

    if (!(ctx = EVP_CIPHER_CTX_new()))
    {
        ERR_print_errors_fp(stderr);
        abort();
    }

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cfb(), NULL, key, iv))
    {
        ERR_print_errors_fp(stderr);
        abort();
    }

    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    {
        ERR_print_errors_fp(stderr);
        abort();
    }

    plaintext_len = len;

    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
    {
        ERR_print_errors_fp(stderr);
        abort();
    }

    plaintext_len += len;
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

void create_server_socket(int &descriptor, string const &IP, int port)
{
    if ((descriptor = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        perror("Error while creating the socket.\n");
        exit(0);
    }

    sockaddr_in server;
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    server.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(descriptor, (sockaddr*) &server, sizeof(sockaddr)) == -1)
    {
        perror("Error at bind.\n");
        exit(0);
    }

    if (listen(descriptor, 2) == -1)
    {
        perror("Error listening the clients.\n");
        exit(0);
    }
}

void create_client_socket(int &descriptor, string const &IP, int port)
{
    if ((descriptor = socket(AF_INET, SOCK_STREAM, 0)) == -1)
    {
        perror("Error while creating the socket.\n");
        exit(0);
    }

    sockaddr_in client;
    client.sin_family = AF_INET;
    client.sin_port = htons(port);
    client.sin_addr.s_addr = inet_addr(IP.c_str());

    if (connect(descriptor, (sockaddr*) &client, sizeof(sockaddr)) == -1)
    {
        perror("Error when connecting the client.\n");
        exit(0);
    }

}


void send_bytes(int &descriptor, const void* bytes, unsigned int len)
{
    // cout << "Am scris un mesaj cu lungimea de " << len << endl;
    if (write(descriptor, &len, sizeof(len)) == -1)
    {
        perror("Error while writing number of bytes\n");
        exit(0);
    }
    // cout << "Am scris un mesaj cu lungimea de " << len << endl;

    if (write(descriptor, bytes, len) == -1)
    {
        perror("Error while writing bytes to socket\n");
        exit(0);
    }
    // cout << "Mesajul este " << (char*)bytes << endl;
}

void read_bytes(int &descriptor, void* bytes, unsigned int& len)
{
    if (read(descriptor, &len, sizeof(len)) == -1)
    {
        perror("Error while reading number of bytes\n");
        exit(0);
    }

    // cout << "Citesc un mesaj cu lungimea de " << len << endl;

    if (read(descriptor, bytes, len) == -1)
    {
        perror("Error while reading bytes to socket\n");
        exit(0);
    }

    // cout << "Mesajul este " << (char*)bytes << endl;
}

#endif //ELISASI_DATECOMUNE_H

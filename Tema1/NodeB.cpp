#include "Common.h"

using namespace std;

#define MAX_SIZE 4096

void interact_with_socket(int client)
{
    char buffer[4096] = {0};

    unsigned int buffer_len;
    read_bytes(client, buffer, buffer_len);

    string string_buffer(buffer);
    function<int(unsigned char *, int, unsigned char *, unsigned char *, unsigned char *)> decrypt_function;
    if (string_buffer == "ECB")
    {
        decrypt_function = decrypt_ecb;
    }
    else if (string_buffer == "CFB")
    {
        decrypt_function = decrypt_cfb;
    }
    else
    {
        cout << "Invalid decryption mode specified" << endl;
        exit(0);
    }


    int socket_to_KM;
    create_client_socket(socket_to_KM, "127.0.0.1", 2020);


    send_bytes(socket_to_KM, buffer, buffer_len);

    unsigned char encrypted_key[4096];
    unsigned int encrypted_key_length;
    read_bytes(socket_to_KM, encrypted_key, encrypted_key_length);


    unsigned char use_key[4096];
    if (decrypt_ecb(encrypted_key, encrypted_key_length, (unsigned char*) K3.data(), (unsigned char*) IV.data(), use_key) == 0)
    {
        cout << "Unable to decrypt key" << endl;
        exit(0);
    }

    cout << "Decrypted key is: \"" << use_key << "\"" << endl;

    unsigned char ready_message[3];
    unsigned int* magic = (unsigned int *) ready_message;
    *magic = COMMUNICATION_MAGIC;
    send_bytes(client, ready_message, sizeof(ready_message));

    unsigned int file_size = 0;
    unsigned int size_of_file_size;
    read_bytes(client, &file_size, size_of_file_size);

    cout << "Receiving file with " << file_size << " bytes" << endl;

    unsigned char iv[BLOCK_SIZE] = {0};

    unsigned int read_so_far = 0;
    while (read_so_far < file_size)
    {
        char encrypted_block[MAX_SIZE] = { 0 };
        unsigned int encrypted_block_length;
        read_bytes(client, encrypted_block, encrypted_block_length);
        
        char decrypted_block[MAX_SIZE] = { 0 };
        int decrypted_block_length = decrypt_function((unsigned char*)encrypted_block, encrypted_block_length, use_key, (unsigned char*) IV.data(), (unsigned char*) decrypted_block);

        cout << "Received block: \"" << decrypted_block << "\"" << endl;

        read_so_far += decrypted_block_length;

        memcpy(iv, encrypted_block, BLOCK_SIZE);
    }

    cout << "Received the whole file" << endl;

}

int main()
{
    int server_B;
    create_server_socket(server_B, "127.0.0.1", 4040);

    cout << "Server socket " << server_B << endl;    

    sockaddr_in client_info;
    unsigned int client_info_len = sizeof(client_info);

    while (1)
    {
        int client;

        if ((client = accept(server_B, (sockaddr*)&client_info, &client_info_len)) == -1)
        {
            perror("Error accepting the client.\n");
            continue;
        }

        interact_with_socket(client);
        close(client);
    }

    return 0;
}
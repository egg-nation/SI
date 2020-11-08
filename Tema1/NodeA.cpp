#include "Common.h"

using namespace std;
#define MAX_SIZE 4096

int main()
{
    int client_B;
    create_client_socket(client_B, "127.0.0.1", 4040);

    int client_KM;
    create_client_socket(client_KM, "127.0.0.1", 2020);

    string encryption_mode;

    cout << "What encryption mode do you want to use? (Type ECB | CFB)\n";
    cin >> encryption_mode;

    function<int(unsigned char *, int, unsigned char *, unsigned char *, unsigned char *)> encryption_function;

    if (encryption_mode == "ECB")
    {
        encryption_function = encrypt_ecb;
    }
    else if (encryption_mode == "CFB")
    {
        encryption_function = encrypt_cfb;
    }
    else
    {
        cout << "Invalid encryption mode specified." << endl;
        exit(0);
    }

    send_bytes(client_B, encryption_mode.data(), encryption_mode.length());
    send_bytes(client_KM, encryption_mode.data(), encryption_mode.length());

    unsigned char encrypted_key[MAX_SIZE];
    unsigned int encrypted_key_length;
    read_bytes(client_KM, encrypted_key, encrypted_key_length);

    unsigned char use_key[MAX_SIZE];

    if (decrypt_ecb(encrypted_key, encrypted_key_length, (unsigned char*) K3.data(), (unsigned char*) IV.data(), use_key) == 0)
    {
        cout << "Unable to decrypt key.\n";
        exit(0);
    }

    printf("Decrypted key is: \"%s\"\n", use_key);

    unsigned char received_magic[10];
    unsigned int received_magic_length;
    read_bytes(client_B, received_magic, received_magic_length);

    unsigned int* magic = (unsigned int *) received_magic;
    if (*magic != COMMUNICATION_MAGIC)
    {
        cout << "Received magic is not valid.\n";
        exit(0);
    }

    cout << "Received valid magic. Starting communication." << endl;

    string file_path;
    cout << "Give path for the input file:" << endl;
    cin >> file_path;

    cout << "Reading " << file_path << endl;

    ifstream file(file_path, ios::ios_base::in | ios::ios_base::binary);

    file.seekg(0, file.end);
    unsigned int file_size = file.tellg();
    
    cout << "Sending file with " << file_size << " bytes." << endl;
    send_bytes(client_B, &file_size, sizeof(file_size));
    
    file.seekg(0, file.beg);
    unsigned int current_position = file.tellg();

    unsigned char iv[BLOCK_SIZE] = {0};

    while (!file.eof())
    {
        char block[BLOCK_SIZE + 1] = {0};
        file.read(block, BLOCK_SIZE);
        unsigned int read_bytes = file.gcount();
        current_position = file.tellg();

        cout << "Sending block: \"" << block << "\"" << endl;

        char encrypted_block[MAX_SIZE];
        int encrypted_block_length = encryption_function((unsigned char*) block, read_bytes, use_key, (unsigned char*) IV.data(), (unsigned char*)encrypted_block);

        send_bytes(client_B, encrypted_block, encrypted_block_length);

        memcpy(iv, encrypted_block, BLOCK_SIZE);
    }

    cout << "Done sending file." << endl;

    return 0;
}
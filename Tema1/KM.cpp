#include "Common.h"

using namespace std;

#define MAX_SIZE 4096

string K1 = random_string(16);
string K2 = random_string(16);

int main() {
    int server_socket;
    create_server_socket(server_socket, "127.0.0.1", 2020);

    unsigned char encrypted_K1[MAX_SIZE];
    unsigned char encrypted_K2[MAX_SIZE];

    int K1_ecb_length;
    int K2_ecb_length;

    K1_ecb_length = encrypt_ecb ((unsigned char*) K1.data(), K1.length(), (unsigned char*) K3.data(), (unsigned char*) IV.data(), encrypted_K1);
    K2_ecb_length = encrypt_ecb ((unsigned char*) K2.data(), K2.length(), (unsigned char*) K3.data(), (unsigned char*) IV.data(), encrypted_K2);

    sockaddr_in client_info;
    unsigned int client_info_len;

    while (1)
    {
        int client;

        if ((client = accept(server_socket, (sockaddr*)&client_info, &client_info_len)) == -1)
        {
            perror("Error accepting the client.\n");
            break;
        }

        char buffer[5] = {0};

        unsigned int buffer_length;
        read_bytes(client, buffer, buffer_length);

        string data(buffer);

        if (data == "ECB")
        {

            cout << "ECB" << endl;

            send_bytes(client, encrypted_K1, K1_ecb_length);

            cout << "Managed to send encrypted key.\n";
        }
        else if (data == "CFB")
        {
            cout << "CFB" << endl;

            send_bytes(client, encrypted_K2, K2_ecb_length);
        
            cout << "Managed to send encrypted key.\n";
        }

    }
    return 0;
}

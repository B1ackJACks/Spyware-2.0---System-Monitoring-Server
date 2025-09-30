#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>

#define PORT 8080
#define SERVER_IP "127.0.0.1"
#define BUFFER_SIZE 1024

int main() {
    int client_fd;
    struct sockaddr_in server_addr;
    char buffer[BUFFER_SIZE];
    ssize_t bytes_received;

    // Create TCP socket
    client_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (client_fd < 0) {
        perror("Socket creation failed");
        return -1;
    }

    // Configure server address
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr);

    // Connect to server
    if (connect(client_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        printf("Connection failed\n");
        close(client_fd);
        return -1;
    }

    printf("Connected to server\n");

    // Receive and display welcome message
    bytes_received = read(client_fd, buffer, BUFFER_SIZE - 1);
    if (bytes_received > 0) {
        buffer[bytes_received] = '\0';
        fputs(buffer, stdout);
        fflush(stdout);
    }
    int mode;
    // Main interaction loop
    while (1) {
        // Get user input
        if (fgets(buffer, sizeof(buffer), stdin) == NULL) {
            break; // EOF or error
        }

        // Send command to server
        write(client_fd, buffer, strlen(buffer));
        sscanf(buffer,"%d",&mode);
        if(mode==3)
            break;
        // Receive and process server response
        while ((bytes_received = read(client_fd, buffer, BUFFER_SIZE - 1)) > 0) {
            buffer[bytes_received] = '\0';
            
            // Stop reading when prompt is received
            if (strstr(buffer, ">>>") != NULL) {
                break;
            }
            
            // Display server output
            fputs(buffer, stdout);
        }

        // Display the prompt
        fputs(buffer, stdout);
        fflush(stdout);
    }

    close(client_fd);
    return 0;
}

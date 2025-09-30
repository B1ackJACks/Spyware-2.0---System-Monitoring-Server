#include <netinet/in.h>
#include <stdio.h>
#include <sys/socket.h>
#include <unistd.h>
#include <string.h>

#define PORT 8080
#define BUFFER_SIZE 1024

// Server messages
const char *help = "Hello I am spyware 2.0\n1 - cpuinfo\n2 - meminfo\n3 - exit";
const char *line = ">>> ";

int main() {
    int server_fd, client_fd;
    struct sockaddr_in address = {0};
    char buffer[BUFFER_SIZE];
    
    // Create TCP socket
    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    
    // Configure server address
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(PORT);
    
    // Set socket option to reuse address
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    
    // Bind socket to address and start listening
    bind(server_fd, (struct sockaddr*)&address, sizeof(address));
    listen(server_fd, 5);
    
    printf("Server listening on port %d\n", PORT);

    // Accept client connection
    client_fd = accept(server_fd, 0, 0);
    
    // Send welcome message and prompt
    sprintf(buffer, "%s\n", help);
    strcat(buffer, line);
    write(client_fd, buffer, strlen(buffer));

    int choose;
    int bytes_read;
    FILE *fd;

    // Main command processing loop
    while (1) {
        // Read client command
        bytes_read = read(client_fd, buffer, BUFFER_SIZE);
        if (bytes_read <= 0) break;  // Client disconnected
        
        // Parse command number
        sscanf(buffer, "%d", &choose);
        
        // Process client command
        switch (choose) {
            case 1:  // CPU info
                write(client_fd, "-------------- CPU Info --------------\n", 40);
                fd = fopen("/proc/cpuinfo", "r");
                if (fd) {
                    while (fgets(buffer, sizeof(buffer), fd)) {
                        write(client_fd, buffer, strlen(buffer));
                    }
                    fclose(fd);
                }
                break;
                
            case 2:  // Memory info  
                write(client_fd, "-------------- Memory Info --------------\n", 43);
                fd = fopen("/proc/meminfo", "r");
                if (fd) {
                    while (fgets(buffer, sizeof(buffer), fd)) {
                        write(client_fd, buffer, strlen(buffer));
                    }
                    fclose(fd);
                }
                break;
                
            case 3:  // Exit
                write(client_fd, "Goodbye!\n", 9);
                goto END;
                
            default:  // Invalid command
                write(client_fd, "Wrong arguments\n", 16);
                break;
        }
        
        // Send prompt for next command
        write(client_fd, line, strlen(line));
    }

END:
    close(client_fd);
    close(server_fd);
    return 0;
}

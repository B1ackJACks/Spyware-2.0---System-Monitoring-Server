/**
 * @file client.c
 * @brief A TLS 1.3 client that interacts with a secure command server.
 * 
 * Features:
 * - Connects to localhost:8080 over TLS 1.3 only
 * - Disables all legacy SSL/TLS protocols
 * - Sends user commands (1, 2, 3) and displays server responses
 * - Handles interactive session with prompt-based termination
 * 
 * ⚠️ WARNING: Certificate verification is disabled (SSL_VERIFY_NONE).
 * This is acceptable only for testing with self-signed certificates.
 * In production, always verify server certificates!
 */

#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

// Configuration
#define PORT        8080
#define SERVER_IP   "127.0.0.1"   // Connect to localhost
#define BUFFER_SIZE 1024

/**
 * @brief Initialize OpenSSL library components.
 * 
 * Ensures OpenSSL is ready for use (mainly for compatibility with older versions).
 */
void init_openssl(void) {
    SSL_library_init();           // Initialize core SSL library
    SSL_load_error_strings();     // Load human-readable error messages
    OpenSSL_add_ssl_algorithms(); // Register all available ciphers and digests
}

/**
 * @brief Create and configure an SSL context for the client.
 * 
 * - Enforces TLS 1.3 as the minimum protocol version
 * - Disables all insecure legacy protocols (SSLv2/3, TLS 1.0–1.2)
 * - Disables server certificate verification (for demo only!)
 * 
 * @return SSL_CTX* Pointer to the configured SSL context.
 * @note Exits on critical error.
 */
SSL_CTX* create_context(void) {
    const SSL_METHOD *method = TLS_client_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    
    if (!ctx) {
        fprintf(stderr, "Error: SSL_CTX_new() failed.\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Require TLS 1.3 or higher
    if (!SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION)) {
        fprintf(stderr, "Error: Failed to enforce TLS 1.3.\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Disable all legacy and insecure protocols
    SSL_CTX_set_options(ctx,
        SSL_OP_NO_SSLv2 |   // Disable SSL 2.0
        SSL_OP_NO_SSLv3 |   // Disable SSL 3.0
        SSL_OP_NO_TLSv1 |   // Disable TLS 1.0
        SSL_OP_NO_TLSv1_1 | // Disable TLS 1.1
        SSL_OP_NO_TLSv1_2   // Disable TLS 1.2 → only TLS 1.3 allowed
    );

    // ⚠️ Disable server certificate verification (FOR TESTING ONLY!)
    // In production: use SSL_VERIFY_PEER and load CA certificates.
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

    return ctx;
}

/**
 * @brief Main client logic: connect, authenticate, and interact with server.
 * 
 * - Establishes TLS connection to server
 * - Displays welcome message
 * - Reads user input and sends commands
 * - Receives and prints server responses until prompt ">>>" is seen
 * - Exits cleanly on command '3' or EOF
 */
int main(void) {
    init_openssl();
    SSL_CTX *ctx = create_context();

    // Create TCP socket
    int client_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (client_fd < 0) {
        perror("Error: socket creation failed");
        return EXIT_FAILURE;
    }

    // Configure server address
    struct sockaddr_in server_addr = {0};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    if (inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr) <= 0) {
        fprintf(stderr, "Error: Invalid server IP address.\n");
        close(client_fd);
        return EXIT_FAILURE;
    }

    // Connect to server over TCP
    if (connect(client_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        fprintf(stderr, "Error: Failed to connect to server.\n");
        close(client_fd);
        return EXIT_FAILURE;
    }
    printf("Connected to server at %s:%d\n", SERVER_IP, PORT);

    // Set up TLS over the TCP connection
    SSL *ssl = SSL_new(ctx);
    if (!ssl) {
        fprintf(stderr, "Error: SSL_new() failed.\n");
        close(client_fd);
        exit(EXIT_FAILURE);
    }
    SSL_set_fd(ssl, client_fd);

    // Perform TLS handshake with server
    if (SSL_connect(ssl) <= 0) {
        fprintf(stderr, "Error: TLS handshake failed.\n");
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(client_fd);
        exit(EXIT_FAILURE);
    }
    printf("Secure connection established (TLS version: %s)\n", SSL_get_version(ssl));

    // Receive and display welcome message + initial prompt
    char buffer[BUFFER_SIZE];
    ssize_t bytes_received = SSL_read(ssl, buffer, sizeof(buffer) - 1);
    if (bytes_received > 0) {
        buffer[bytes_received] = '\0';
        fputs(buffer, stdout);
        fflush(stdout);
    }

    int command;
    // Main interactive loop
    while (1) {
        // Read user input from terminal
        if (fgets(buffer, sizeof(buffer), stdin) == NULL) {
            break; // EOF (e.g., Ctrl+D) or error
        }

        // Send command to server
        SSL_write(ssl, buffer, strlen(buffer));

        // Check if user wants to exit
        if (sscanf(buffer, "%d", &command) == 1 && command == 3) {
            break;
        }

        // Read server response until prompt ">>>" appears
        while ((bytes_received = SSL_read(ssl, buffer, sizeof(buffer) - 1)) > 0) {
            buffer[bytes_received] = '\0';

            // Stop reading once we see the next prompt
            if (strstr(buffer, ">>>") != NULL) {
                break;
            }

            // Print server output immediately
            fputs(buffer, stdout);
            fflush(stdout);
        }

        // Print the final part (which includes the prompt)
        if (bytes_received > 0) {
            fputs(buffer, stdout);
            fflush(stdout);
        }
    }

    // Clean up
    SSL_shutdown(ssl);
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(client_fd);

    printf("\nDisconnected.\n");
    return EXIT_SUCCESS;
}

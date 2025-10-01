/**
 * @file server.c
 * @brief A minimal TLS 1.3 server that serves system information over an encrypted channel.
 * 
 * Features:
 * - Enforces TLS 1.3 only (disables all older protocols)
 * - Authenticates using a server certificate and private key
 * - Provides interactive commands:
 *     1 → /proc/cpuinfo
 *     2 → /proc/meminfo
 *     3 → Disconnect
 * 
 * ⚠️ WARNING: This is for educational/demo purposes only.
 * Do NOT use in production without authentication, input validation, and proper certificate verification.
 */

#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

// Configuration constants
#define PORT          8080
#define BUFFER_SIZE   1024
#define CERT_FILE     "server-cert.pem"   // Server certificate (PEM format)
#define KEY_FILE      "server-key.pem"    // Server private key (PEM format)

// Server interaction strings
static const char *WELCOME_MESSAGE =
    "Hello, I am spyware 2.0\n"
    "1 - cpuinfo\n"
    "2 - meminfo\n"
    "3 - exit";

static const char *PROMPT = ">>> ";

/**
 * @brief Initialize OpenSSL library components.
 * 
 * Required for compatibility with older OpenSSL versions (< 1.1.0).
 * In newer versions, this is mostly a no-op but kept for portability.
 */
void init_openssl(void) {
    SSL_library_init();           // Initialize SSL library
    SSL_load_error_strings();     // Load error strings for debugging
    OpenSSL_add_ssl_algorithms(); // Register all SSL/TLS ciphers and digests
}

/**
 * @brief Create and configure an SSL context for the server.
 * 
 * - Uses TLS_server_method() for maximum protocol flexibility (then restricts to TLS 1.3)
 * - Disables all insecure legacy protocols
 * - Loads and validates server certificate and private key
 * 
 * @return SSL_CTX* Pointer to the configured SSL context.
 * @note Exits on any critical error.
 */
SSL_CTX* create_context(void) {
    const SSL_METHOD *method = TLS_server_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    
    if (!ctx) {
        fprintf(stderr, "Error: Failed to create SSL context.\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Enforce TLS 1.3 as the minimum (and effectively only) protocol version
    if (!SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION)) {
        fprintf(stderr, "Warning: Failed to enforce TLS 1.3. Continuing anyway.\n");
        ERR_print_errors_fp(stderr);
    }

    // Disable all legacy and insecure protocols
    SSL_CTX_set_options(ctx,
        SSL_OP_NO_SSLv2 |   // Disable SSL 2.0
        SSL_OP_NO_SSLv3 |   // Disable SSL 3.0
        SSL_OP_NO_TLSv1 |   // Disable TLS 1.0
        SSL_OP_NO_TLSv1_1 | // Disable TLS 1.1
        SSL_OP_NO_TLSv1_2   // Disable TLS 1.2 → only TLS 1.3 remains
    );

    // Load server certificate from PEM file
    if (SSL_CTX_use_certificate_file(ctx, CERT_FILE, SSL_FILETYPE_PEM) <= 0) {
        fprintf(stderr, "Error: Unable to load server certificate.\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Load private key from PEM file
    if (SSL_CTX_use_PrivateKey_file(ctx, KEY_FILE, SSL_FILETYPE_PEM) <= 0) {
        fprintf(stderr, "Error: Unable to load private key.\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Verify that the private key matches the certificate
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Error: Private key does not match the certificate!\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

/**
 * @brief Handle communication with a connected client over TLS.
 * 
 * Implements a simple command loop:
 *   - Reads a single integer command
 *   - Responds with system info or error
 *   - Loops until client exits or disconnects
 * 
 * All I/O is encrypted using SSL_read() and SSL_write().
 * 
 * @param ssl Active SSL connection object.
 */
void handle_client(SSL *ssl) {
    char buffer[BUFFER_SIZE];
    int command;

    // Send welcome message and initial prompt
    snprintf(buffer, sizeof(buffer), "%s\n%s", WELCOME_MESSAGE, PROMPT);
    SSL_write(ssl, buffer, strlen(buffer));

    while (1) {
        // Read client command
        int bytes = SSL_read(ssl, buffer, sizeof(buffer) - 1);
        if (bytes <= 0) {
            // Client disconnected or TLS error
            break;
        }
        buffer[bytes] = '\0'; // Ensure null-terminated string

        // Parse command (expecting an integer)
        if (sscanf(buffer, "%d", &command) != 1) {
            command = -1; // Invalid input
        }

        FILE *fp = NULL;

        switch (command) {
            case 1: // Send CPU information
                SSL_write(ssl, "-------------- CPU Info --------------\n", 40);
                fp = fopen("/proc/cpuinfo", "r");
                if (fp) {
                    while (fgets(buffer, sizeof(buffer), fp)) {
                        SSL_write(ssl, buffer, strlen(buffer));
                    }
                    fclose(fp);
                }
                break;

            case 2: // Send memory information
                SSL_write(ssl, "-------------- Memory Info --------------\n", 43);
                fp = fopen("/proc/meminfo", "r");
                if (fp) {
                    while (fgets(buffer, sizeof(buffer), fp)) {
                        SSL_write(ssl, buffer, strlen(buffer));
                    }
                    fclose(fp);
                }
                break;

            case 3: // Graceful exit
                SSL_write(ssl, "Goodbye!\n", 9);
                return;

            default: // Invalid command
                SSL_write(ssl, "Wrong arguments\n", 16);
                break;
        }

        // Prompt for next command
        SSL_write(ssl, PROMPT, strlen(PROMPT));
    }
}

/**
 * @brief Main function: set up server socket and handle one client connection.
 * 
 * Note: This version accepts only one client. For multi-client support,
 * wrap the accept() and handle_client() logic in a loop.
 */
int main(void) {
    init_openssl();
    SSL_CTX *ctx = create_context();

    // Create TCP socket
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    // Configure server address
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(PORT);

    // Allow socket reuse (avoid "Address already in use" error)
    int opt = 1;
    setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    // Bind and listen
    if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("bind");
        close(server_fd);
        exit(EXIT_FAILURE);
    }
    if (listen(server_fd, 1) < 0) {
        perror("listen");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    printf("Server listening on port %d\n", PORT);

    // Accept a single client connection
    int client_fd = accept(server_fd, NULL, NULL);
    if (client_fd < 0) {
        perror("accept");
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    // Set up TLS over the accepted connection
    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, client_fd);

    // Perform TLS handshake
    if (SSL_accept(ssl) <= 0) {
        fprintf(stderr, "Error: TLS handshake failed.\n");
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        close(client_fd);
        close(server_fd);
        exit(EXIT_FAILURE);
    }

    printf("TLS connection established (version: %s)\n", SSL_get_version(ssl));

    // Handle client session
    handle_client(ssl);

    // Clean up
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(client_fd);
    close(server_fd);
    SSL_CTX_free(ctx);

    return 0;
}

#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define FAIL    -1

void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile);
SSL_CTX* InitCTX(void);
int OpenConnection(const char *hostname, int port);
void ShowCerts(SSL *ssl);

int main(int count, char *strings[]) {
    char *hostname, *portnum;
    char buf[1024];
    SSL_CTX *ctx;
    SSL *ssl;
    int server;
    int bytes;

    if (count != 3) {
        printf("usage: %s <hostname> <portnum>\n", strings[0]);
        exit(0);
    }

    hostname = strings[1];
    portnum = strings[2];

    printf("\nSSL Client 0.1\n~~~~~~~~~~~~~~~\n\n");

    // Init. the SSL lib
    SSL_library_init();
    ctx = InitCTX();

    printf("Client SSL lib init complete\n");

    // Open the connection as normal
    server = OpenConnection(hostname, atoi(portnum));

    // Create new SSL connection state
    ssl = SSL_new(ctx);

    // Attach the socket descriptor
    SSL_set_fd(ssl, server);

    // Perform the SSL/TLS handshake
    if (SSL_connect(ssl) != FAIL) {
        char *msg = "Here is some data";
        printf("Connected with %s encryption\n", SSL_get_cipher(ssl));

        // Print any certs
        ShowCerts(ssl);

        // Encrypt & send message
        SSL_write(ssl, msg, strlen(msg));

        // Get reply & decrypt
        bytes = SSL_read(ssl, buf, sizeof(buf) - 1);
        buf[bytes] = '\0';
        printf("Received: '%s'\n\n", buf);

        // Release connection state
        SSL_free(ssl);
    } else {
        ERR_print_errors_fp(stderr);
    }

    // Close socket
    close(server);

    // Release context
    SSL_CTX_free(ctx);
    return 0;
}

SSL_CTX* InitCTX(void) {
    SSL_METHOD const *method;
    SSL_CTX *ctx;

    // Load cryptos, et.al.
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    // Create new client-method instance
    method = TLS_client_method();

    // Create new context
    ctx = SSL_CTX_new(method);

    if (ctx == NULL) {
        ERR_print_errors_fp(stderr);
        abort();
    }

    // Set options to verify server certificate
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

    return ctx;
}

int OpenConnection(const char *hostname, int port) {
    int sd;
    struct hostent *host;
    struct sockaddr_in addr;

    if ((host = gethostbyname(hostname)) == NULL) {
        perror(hostname);
        abort();
    }

    sd = socket(AF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = *(long*)(host->h_addr);

    if (connect(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
        close(sd);
        perror(hostname);
        abort();
    }
    return sd;
}

void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile) {
    // Load cert
    if (SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Load private key
    if (SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Verify private key
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Private key does not match the public certificate\n");
        exit(EXIT_FAILURE);
    }
}

void ShowCerts(SSL *ssl) {
    X509 *cert;
    char *line;

    cert = SSL_get_peer_certificate(ssl);
    if (cert != NULL) {
        printf("Server certificates:\n");

        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);

        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);

        X509_free(cert);
    } else {
        printf("No certificates.\n");
    }
}


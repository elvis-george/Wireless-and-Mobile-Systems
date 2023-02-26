#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#define FAIL    -1



void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile);
int OpenConnection(const char *hostname, int port);
void ShowCerts(SSL* ssl);
SSL_CTX* InitCTX(void);


int main(int count, char *strings[]) {


    char *hostname, *portnum;
    char buf[1024];
    SSL_CTX *ctx;
    SSL *ssl;
    int server;
    int bytes;


    if ( count != 3 ) {


        printf("usage: %s <hostname> <portnum>\n", strings[0]);
        exit(0);


    } // if


    hostname=strings[1];
    portnum=strings[2];


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


    // Perform the connection
    if ( SSL_connect(ssl) != FAIL ) {


        char *msg = "Here is some data";


        printf("Connected with %s encryption\n", SSL_get_cipher(ssl));

        // Print any certs
        ShowCerts(ssl);


        // Encrypt & send message */
        SSL_write(ssl, msg, strlen(msg));


        // Get reply & decrypt
        bytes = SSL_read(ssl, buf, sizeof(buf));


        buf[bytes] = 0;
        printf("Received: '%s'\n\n", buf);


        // Release connection state
        SSL_free(ssl);


    } // if


    else ERR_print_errors_fp(stderr);


    // Close socket
    close(server);


    // Release context
    SSL_CTX_free(ctx);
    return 0;


} // main


SSL_CTX* InitCTX(void) {


    SSL_METHOD const *method;
    SSL_CTX *ctx;


    // Load cryptos, et.al.
    OpenSSL_add_all_algorithms();


    // Bring in and register error messages
    SSL_load_error_strings();


    // Create new client-method instance
    method = SSLv23_client_method();


    // Create new context
    ctx = SSL_CTX_new(method);


    if ( ctx == NULL ) {


        ERR_print_errors_fp(stderr);
        abort();


    } // if


    return ctx;


} //InitCTX


int OpenConnection(const char *hostname, int port) {


    int sd;
    struct hostent *host;
    struct sockaddr_in addr;


    if ( (host = gethostbyname(hostname)) == NULL ) {


        perror(hostname);
        abort();


    } // if


    sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = *(long*)(host->h_addr);


    if ( connect(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 ) {


        close(sd);
        perror(hostname);
        abort();


    } // if


    return sd;


} // OpenConnection


void ShowCerts(SSL* ssl) {


    X509 *cert;
    char *line;


    cert = SSL_get_peer_certificate(ssl); /* get the server's certificate */


    if ( cert != NULL ) {


        printf("\nServer certificate:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);


        // Free the malloc'ed string
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);


        // Free the malloc'ed string
        free(line);


        // Free the malloc'ed certificate copy
        X509_free(cert);


    } // if


    else printf("No certificates.\n");


} // ShowCerts

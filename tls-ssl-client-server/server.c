#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <resolv.h>
#include "openssl/ssl.h"
#include "openssl/err.h"
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/select.h>

#define SERVER_PORT     3005
#define BUFFER_LENGTH    250
#define FALSE              0
#define SERVER_NAME     "localhost"
#define MAX_HOST_NAME_LENGTH 20



#define FAIL    -1
// Create the SSL socket and intialize the socket address structure
char* port = "3005";

extern int pincrack(int *hash, int hashlen);
int pincrack(int *hash, int hashlen);
typedef unsigned char byte;
SSL_CTX* InitServerCTX(void);
int OpenListener(int pt);


int OpenListener(int pt)
{
    int sd;
    struct sockaddr_in addr;
    sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(pt);
    addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
    {
        perror("can't bind port");
        abort();
    }
    if ( listen(sd, 10) != 0 )
    {
        perror("Can't configure listening port");
        abort();
    }
    return sd;
}
int isRoot()
{
    if (getuid() != 0)
    {
        return 0;
    }
    else
    {
        return 1;
    }
}
SSL_CTX* InitServerCTX(void)
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;
    OpenSSL_add_all_algorithms();  /* load & register all cryptos, etc. */
    SSL_load_error_strings();   /* load all error messages */
    method = TLS_server_method();  /* create new server-method instance */
    ctx = SSL_CTX_new(method);   /* create new context from method */
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}
void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile)
{
    /* set the local certificate from CertFile */
    if ( SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* set the private key from KeyFile (may be the same as CertFile) */
    if ( SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* verify private key */
    if ( !SSL_CTX_check_private_key(ctx) )
    {
        fprintf(stderr, "Private key does not match the public certificate\n");
        abort();
    }
}
void ShowCerts(SSL* ssl)
{
    X509 *cert;
    char *line;
    cert = SSL_get_peer_certificate(ssl); /* Get certificates (if available) */
    if ( cert != NULL )
    {
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);
        X509_free(cert);
    }
    else
        printf("No certificates.\n");
}
void Servlet(SSL* ssl) /* Serve the connection -- threadable */
{
    char buf[1024] = {0};
    int sd, bytes;
    //create a char buffer to store the response
    int out;
    // const char* ServerResponse="<\\Body>\
    //                            <Name>aticleworld.com</Name>\
    //              <year>1.5</year>\
    //              <BlogType>Embedede and c\\c++<\\BlogType>\
    //              <Author>amlendra<Author>\
    //              <\\Body>";
    // const char *cpValidMessage = "<Body>\
    //                            <UserName>aticle<UserName>\
    //              <Password>123<Password>\
    //              <\\Body>";
    if ( SSL_accept(ssl) == FAIL )     /* do SSL-protocol accept */
        ERR_print_errors_fp(stderr);
    else
    {
        ShowCerts(ssl);        /* get any certificates */
        bytes = SSL_read(ssl, buf, sizeof(buf)); /* get request */
        buf[bytes] = '\0';
        printf("Client msg: \"%s\"\n", buf);
        if ( bytes > 0 )
        {

                out = CRACK(buf);
                printf("Client msg: \"%s\"\n", buf);
                char number[32];
                snprintf(number, sizeof(number), "%d", out);
                SSL_write(ssl, number, sizeof(number));
                //SSL_write(ssl, "Invalid Message", strlen("Invalid Message")); /* send reply */
        }
        else
        {
            ERR_print_errors_fp(stderr);
        }
    }
    sd = SSL_get_fd(ssl);       /* get socket connection */
    SSL_free(ssl);         /* release SSL state */
    close(sd);          /* close connection */
}
int main(int count, char *Argc[])
{
    SSL_CTX *ctx;
    int server;
    char *portnum;
//Only root user have the permsion to run the server
    if(!isRoot())
    {
        printf("This program must be run as root/sudo user!!");
        exit(0);
    }
    if ( count != 2 )
    {
        printf("Usage: %s <portnum>\n", Argc[0]);
        exit(0);
    }
    // Initialize the SSL library
    SSL_library_init();
    portnum = Argc[1];
    ctx = InitServerCTX();        /* initialize SSL */
    LoadCertificates(ctx, "cert.pem", "key.pem"); /* load certs */
    server = OpenListener(atoi(portnum));    /* create server socket */
    while (1)
    {
        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        SSL *ssl;
        int client = accept(server, (struct sockaddr*)&addr, &len);  /* accept connection as usual */
        printf("Connection: %s:%d\n",inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
        ssl = SSL_new(ctx);              /* get new SSL state with context */
        SSL_set_fd(ssl, client);      /* set connection socket to SSL state */
        Servlet(ssl);         /* service connection */
    }
    close(server);          /* close server socket */
    SSL_CTX_free(ctx);         /* release context */
}

int CRACK(char *buffer) {
      //iterates 0-9999 for all 4 digit pin combos
      unsigned char obuf[SHA_DIGEST_LENGTH] = {};
      int i;
      for(i = 0; i<10000; i++){
         char sint [5];
         sprintf(sint, "%d", i);
         //printf("%s : ",sint);
         SHA1(sint, strlen(sint),obuf);
         for (int j=0; j<SHA_DIGEST_LENGTH; j++){
	         //printf("%02x", obuf[j]);
         }
         putchar('\n');
         char cat_buf[250] = {};
         for(int j = 0; j<SHA_DIGEST_LENGTH; j++){
            char mini_buf[4]={};
            sprintf(mini_buf, "%02x", obuf[j]);
            strcat(cat_buf, mini_buf);
         }
         //printf("\n%s\n",cat_buf);
         if(strncmp(cat_buf, buffer,SHA_DIGEST_LENGTH*2) == 0){
            break;
         }
      }
      //case not found
      if(i == 10000)
         i = -1;
      printf("PIN: %d\n", i);

      memset(buffer, 0, sizeof(buffer));
      sprintf(buffer, "%d", i);

      return i;

}

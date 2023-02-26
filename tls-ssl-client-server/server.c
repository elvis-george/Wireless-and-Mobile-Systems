#include <sys/select.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>    
#include <netinet/in.h>
#include <unistd.h>
#include <stdlib.h>
#include <openssl/sha.h>

#define SERVER_PORT     3005
#define BUFFER_LENGTH    250
#define FALSE              0

int  main() {
   int    sd=-1, sd2=-1;
   int    rc, length, on=1;
   char   buffer[BUFFER_LENGTH];
   fd_set read_fd;
   struct timeval timeout;
   struct sockaddr_in serveraddr;

   sd = socket(AF_INET, SOCK_STREAM, 0);
   // test error: sd < 0)      

   memset(&serveraddr, 0, sizeof(serveraddr));
   serveraddr.sin_family      = AF_INET;
   serveraddr.sin_port        = htons(SERVER_PORT);
   serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);

   rc = bind(sd, (struct sockaddr *)&serveraddr, sizeof(serveraddr));
   // test error rc < 0

   rc = listen(sd, 10);
   // test error rc< 0

   printf("Ready for client connect().\n");

   do {

      sd2 = accept(sd, NULL, NULL);
      // test error sd2 < 0

      timeout.tv_sec  = 0;
      timeout.tv_usec = 0;

      FD_ZERO(&read_fd);
      FD_SET(sd2, &read_fd);

      rc = select(1, &read_fd, NULL, NULL, &timeout);
      // test error rc < 0

      length = BUFFER_LENGTH;
 
      rc = recv(sd2, buffer, sizeof(buffer), 0);
      // test error rc < 0 or rc == 0 or   rc < sizeof(buffer
      printf("server received %d bytes\n", rc);

      printf("String: ");
      for(int i = 0; i<rc;i++){
         printf("%c",buffer[i]);
      }
      printf("\n");

      //iterates 0-9999 for all 4 digit pin combos
      unsigned char obuf[SHA_DIGEST_LENGTH] = {};
      int i;
      for(i = 0; i<10000; i++){
         char sint [5];
         sprintf(sint, "%d", i);
         printf("%s : ",sint);
         SHA1(sint, strlen(sint),obuf);
         for (int j=0; j<SHA_DIGEST_LENGTH; j++){
	         printf("%02x", obuf[j]);
         }
         putchar('\n');
         char cat_buf[250] = {};
         for(int j = 0; j<SHA_DIGEST_LENGTH; j++){
            char mini_buf[4]={};
            sprintf(mini_buf, "%02x", obuf[j]);
            strcat(cat_buf, mini_buf);
         }
         printf("\n%s\n",cat_buf);
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
      rc = send(sd2, buffer, sizeof(buffer), 0);
      // test error rc < 0
      printf("server returned %d bytes\n", rc);

   } while (1);

   if (sd != -1)
      close(sd);
   if (sd2 != -1)
      close(sd2);
}



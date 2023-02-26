/*
 * MPTCP Server
 *
 * @date Nov. 2022
 * @author Matan Broner
 * */

#include "log.h"
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

/**
 * Start the MPTCP server
 * Uses MPTCP v1. (ie. upstream Linux kernel)
 *
 * Usage: ./server <port> <file> <send_file_iters>
 * <port> - port to listen on
 * <file> - file to send to client
 * <send_file_iters> - number of times to send the file to the client
 * */
int main(int argc, char **argv) {
  // Input check
  if (argc != 4) {
    printf("Usage: %s <port> <file> <send_file_iters>\n", argv[0]);
    exit(1);
  }
  int port = atoi(argv[1]);
  char *file = argv[2];
  int send_file_iters = atoi(argv[3]);

  // Create socket using MPTCP v1
  int sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_MPTCP);
  if (sockfd < 0) {
    error("socket creation failed", true);
  }

  // Create server address
  struct sockaddr_in serv_addr;
  memset(&serv_addr, 0, sizeof(serv_addr));
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);
  serv_addr.sin_port = htons(port);

  // Bind socket to server address
  if (bind(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {

    error("bind failed", true);
  }

  // Listen for incoming connections
  if (listen(sockfd, 5) < 0) {
    error("listen failed", true);
  }

  info("Server is listening for incoming connections");

  // Accept incoming connections
  while (1) {
    struct sockaddr_in cli_addr;
    socklen_t cli_len = sizeof(cli_addr);
    int connfd = accept(sockfd, (struct sockaddr *)&cli_addr, &cli_len);
    if (connfd < 0) {
      error("accept failed", false);
      continue;
    }

    // Get IP address of client
    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &(cli_addr.sin_addr), ip, INET_ADDRSTRLEN);

    info("Accepted incoming connection from client");
    info((const char *)ip);

    int total = 0;

    // Send file
    for (int iter = 0; iter < send_file_iters; iter++) {
      FILE *fp = fopen(file, "r");
      if (fp == NULL) {
        error("file open failed", false);
        continue;
      }

      char buffer[1024];
      int n;
      while ((n = fread(buffer, 1, 1024, fp)) > 0) {
        if (write(connfd, buffer, n) != n) {
          error("write failed", false);
          break;
        }
        total += n;
      }

      if (n < 0) {
        error("read failed", false);
      }
      fclose(fp);
    }

    char str[1024];
    sprintf(str, "Total bytes sent: %d", total);
    info((const char *)str);

    close(connfd);

    info("Connection closed");
  }
}

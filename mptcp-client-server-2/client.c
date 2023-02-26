/*
 * MPTCP Client
 *
 * @date Nov. 2022
 * @author Matan Broner
 * */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>
#include <stdbool.h>

#include "log.h"

/**
 * Start the MPTCP client
 * Uses MPTCP v1. (ie. upstream Linux kernel)
 * */
int main(int argc, char **argv) {
  // Input check
  if (argc != 3) {
    printf("Usage: %s <ip> <port>\n", argv[0]);
    exit(1);
  }
  char *ip = argv[1];
  int port = atoi(argv[2]);

  // Create socket using MPTCP v1
  int sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_MPTCP);
  if (sockfd < 0) {
    error("socket creation failed", true);
  }

  // Create server address
  struct sockaddr_in serv_addr;
  memset(&serv_addr, 0, sizeof(serv_addr));
  serv_addr.sin_family = AF_INET;
  serv_addr.sin_addr.s_addr = inet_addr(ip);
  serv_addr.sin_port = htons(port);

  // Connect to server
  if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
    error("connect failed", true);
  }

  info("Connected to server");

  // Receive data from server
  char buffer[1024];
  while (1) {
    int n = read(sockfd, buffer, sizeof(buffer));
    printf("Read %d bytes from server: \n", n);
    if (n < 0) {
      error("read failed", true);
    }
    if (n == 0) {
      info("Server closed connection");
      break;
    }

    buffer[n] = '\0';
  }

  // Close socket
  close(sockfd);
  info("Socket closed");

  return 0;
}

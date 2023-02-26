#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>

void _log(const char *msg, const char *level) {
  printf("[mptcp][%s] %s\n", level, msg);
}

void error(const char *msg, bool exit_flag) {
  _log(msg, "ERROR");
  if (exit_flag)
    exit(1);
}

void info(const char *msg) { _log(msg, "INFO"); }

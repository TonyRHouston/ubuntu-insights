#include "types.h"
#include <stdlib.h>

static insights_logger_callback global_log_callback = NULL;

void set_log_callback_impl(insights_logger_callback callback) {
  global_log_callback = callback;
}

void call_log_callback(insights_log_level level, char *msg) {
  if (global_log_callback) {
    global_log_callback(level, msg);
  }
}

int has_log_callback() { return global_log_callback != NULL; }

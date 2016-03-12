#include <libssh2.h>

void libssh2_session_free_discard_result (LIBSSH2_SESSION * session) {
  libssh2_session_free(session);
}

void libssh2_channel_free_discard_result (LIBSSH2_CHANNEL * channel) {
  libssh2_channel_free(channel);
}

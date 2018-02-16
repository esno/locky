#ifndef LUKSD_SOCKET_H
#define LUKSD_SOCKET_H

void luksd_socket_handle_requests(luksd_mgr_t *luksd, luksd_message_t *msg);
int luksd_socket_listen(char *user, char *group, char *socket_file);
void luksd_socket_parse_method(int socket, luksd_message_t *msg);
void luksd_socket_parse_status(luksd_message_t *msg);

#endif

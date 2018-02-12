#ifndef RLUKSD_NET_H
#define RLUKSD_NET_H

#include "rluksd.h"

void rluksd_net_handle_requests(rluksd_mgr_t *rluksd, rluksd_message_t *msg);
int rluksd_net_listen(char *port);
void rluksd_net_parse_auth(int socket, rluksd_message_t *msg);
void rluksd_net_parse_method(int socket, rluksd_message_t *msg);

#endif

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "rluksd.h"
#include "rluksd_net.h"

void rluksd_net_handle_requests(rluksd_mgr_t *rluksd, rluksd_message_t *msg)
{
  rluksd_net_parse_method(rluksd->socket.rluksd, msg);

  switch(msg->method)
  {
    case RLUKSD_NET_REQ_METHOD_AUTH:
      rluksd_net_parse_auth(rluksd->socket.rluksd, msg);
      break;
  }
}

int rluksd_net_listen(char *port)
{
  struct addrinfo hints, *res, *res_save;
  int n, fd = -1;

  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_flags = AI_PASSIVE;
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;

  n = getaddrinfo("*", port, &hints, &res);
  if(n < 0)
    return n;

  res_save = res;
  while(res)
  {
    fd = socket(
      res->ai_family,
      res->ai_socktype,
      res->ai_protocol);

    if(fd >= 0)
    {
      if(bind(fd, res->ai_addr, res->ai_addrlen) == 0)
        break;

      close(fd);
      fd = -1;
    }

    res = res->ai_next;
  }

  if(fd < 0)
    close(fd);
  else
    listen(fd, RLUKSD_NET_SOCKET_QUEUE);

  freeaddrinfo(res_save);

  return fd;
}

void rluksd_net_parse_auth(int socket, rluksd_message_t *msg)
{
  unsigned char chunk_ml[RLUKSD_NET_HEADER_LENGTH_SIZE];
  unsigned char chunk_sl[RLUKSD_NET_HEADER_LENGTH_SIZE];
  unsigned char chunk_m[RLUKSD_NET_PAYLOAD_SIZE / 2];
  unsigned char chunk_s[RLUKSD_NET_PAYLOAD_SIZE / 2];
  int ml = 0, sl = 0;
  uint16_t message_l = 0, signature_l = 0;

  memset(&chunk_ml, 0, sizeof(chunk_ml));
  memset(&chunk_sl, 0, sizeof(chunk_sl));
  memset(&chunk_m, 0, sizeof(chunk_m));
  memset(&chunk_s, 0, sizeof(chunk_s));
  ml = recv(
    socket,
    &chunk_ml,
    sizeof(chunk_ml), 0);

  sl = recv(
    socket,
    &chunk_sl,
    sizeof(chunk_sl), 0);

  if(ml == RLUKSD_NET_HEADER_LENGTH_SIZE &&
      sl == RLUKSD_NET_HEADER_LENGTH_SIZE)
  {
    message_l = ntohs(*chunk_ml);
    signature_l = ntohs(*chunk_sl);

    if(message_l <= (RLUKSD_NET_PAYLOAD_SIZE / 2) &&
        signature_l <= (RLUKSD_NET_PAYLOAD_SIZE / 2))
    {
      ml = recv(
        socket,
        &chunk_m,
        message_l, 0);
      sl = recv(
        socket,
        &chunk_s,
        signature_l, 0);

      if(ml == message_l && sl == signature_l)
      {
        msg->message = malloc(message_l);
        msg->signature = malloc(signature_l);

        if(msg->message)
        {
          memcpy(msg->message, &chunk_m, message_l);
          msg->message_l = message_l;
        }

        if(msg->signature)
        {
          memcpy(msg->signature, &chunk_s, signature_l);
          msg->signature_l = signature_l;
        }
      }
    }
  }
}

void rluksd_net_parse_method(int socket, rluksd_message_t *msg)
{
  unsigned char chunk;
  struct sockaddr_storage client;
  socklen_t addrlen = sizeof(client);
  int n = 0;

  memset(&chunk, 0, sizeof(chunk));
  n = recvfrom(
    socket,
    &chunk,
    sizeof(chunk), 0,
    (struct sockaddr *) &client,
    &addrlen);

  if(n == RLUKSD_NET_HEADER_METHOD_SIZE)
  {
    msg->method = chunk;
    getnameinfo(
      (struct sockaddr *) &client,
      addrlen,
      msg->peer.addr, sizeof(msg->peer.addr),
      msg->peer.port, sizeof(msg->peer.port),
      NI_NUMERICHOST);
  }
}

void rluksd_net_send(int socket, rluksd_peer_t *peer, rluksd_message_t *msg)
{
  struct addrinfo hints, *res;
  uint16_t buffer_l = htons(msg->message_l + 2);
  unsigned char buffer[buffer_l];
  int n;

  memcpy(&buffer, &buffer_l, sizeof(uint16_t));
  memcpy(&buffer[2], buffer, msg->message_l);

  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_DGRAM;

  n = getaddrinfo(peer->addr, peer->port, &hints, &res);
  if(n >= 0)
    sendto(socket, buffer, buffer_l, 0,
      res->ai_addr, res->ai_addrlen);

  freeaddrinfo(res);
}

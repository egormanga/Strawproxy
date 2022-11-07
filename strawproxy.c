/* - Prologue -
  «Все пакеты уникальны. Пакетов очень много и все они уникальны.
   Пакетов уже где-то 128'563, судя по последней глобальной
   переписи пакетов. Каждый пакет имеет 4-х значный десятичный номер.
  » ~ co-author.
*/

/* Strawproxy -- Factorio virtual server front-end dispatching proxy & login */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/udp.h>

#define SERVERNAME	"Strawproxy @ SERV"
#define PORT		34197

#define check_err(label)	do { if (errno) goto label; } while (0)
#define _Packed		__attribute__((packed))

static const struct server {
	char* name;
	char* ip;
	uint16_t port;
} SERVERS[] = {
	{
		.name = "alpha",
		.ip = "172.20.0.2", .port = 34197
	},
	{
		.name = "beta",
		.ip = "172.20.0.3", .port = 34197
	},
	{
		.name = "gamma",
		.ip = "172.20.0.4", .port = 34197
	},
	{
		.name = "delta",
		.ip = "172.20.0.5", .port = 34197
	}
};

typedef enum state {
	DISCONNECTED = -1,
	INIT,
	CONNECT,
	LOOP,
} state_t;

typedef struct _Packed version {
	uint8_t major, minor, patch;
	uint16_t build;
} version_t;

typedef struct client {
	state_t state;
	int client, server;
	version_t version;
	uint32_t cid, sid;
	uint16_t seq;
} client_t;

struct _Packed packet_header {
	uint8_t pid :5;
	uint8_t flags :3;
	uint16_t seq;
};

struct _Packed packet_ConnectionRequest {
	struct packet_header header;
	version_t version;
	uint32_t cid;
};

static const struct _Packed _unknown_000100000000 {
	uint8_t _[6];
} _unknown_000100000000 = {"\x00\x01\x00\x00\x00\x00"};

struct _Packed packet_ConnectionRequestReply {
	struct packet_header header;
	struct _unknown_000100000000 confirmation;
	version_t version;
	uint32_t cid, sid;
};

struct _Packed packet_ConnectionRequestReplyConfirm {
	struct packet_header header;
	uint32_t cid, sid, iid;
	uint8_t data[0];
};

static const struct _Packed _unknown_000101000000 {
	uint8_t _[6];
} _unknown_000101000000 = {"\x00\x01\x10\x00\x00\x00"};

struct _Packed packet_ConnectionAcceptOrDeny {
	struct packet_header header;
	struct _unknown_000101000000 confirmation;
	uint32_t cid;
	uint8_t status;
	uint8_t data[0];
};

static const struct _Packed mods {
	uint8_t nmods;
	struct _Packed mod {
		uint8_t name_length;
		char name[4];
		struct _Packed version_short {
			uint8_t major, minor, patch;
		} version;
		uint32_t crc;
	} mods[1];
	uint8_t footer[8];
} mods = {
	.nmods = 1,
	.mods = {
		{
			.name_length = 4,
			.name = "base",
		},
	},
	.footer = "\x05\x00\x00\x00\x00\x00\xff\xff"
};

int main() {
	int sock = socket(AF_INET, SOCK_DGRAM, 0); assert (errno == 0);
	struct sockaddr_in addr = {AF_INET, htons(PORT), {INADDR_ANY}, ""};
	socklen_t addrlen = sizeof(addr);
	setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &(int){true}, sizeof(int));
	bind(sock, (struct sockaddr*)&addr, addrlen); assert (errno == 0);

	client_t clients[65536] = {0};

	while (true) {
		struct sockaddr_in peer;
		socklen_t peerlen = sizeof(peer);

		char buf[8192];
		int n = recvfrom(sock, buf, sizeof(buf), 0, (struct sockaddr*)&peer, &peerlen);
		if (!n || errno) continue;

		client_t *client = &clients[peer.sin_port];

		struct packet_header *packet = (struct packet_header*)buf;

		fprintf(stderr, "port = %d, seq = %d, pid = %#04x, flags = %c%c%c\n", peer.sin_port, packet->seq, packet->pid, packet->flags&0b001?'R':'-', packet->flags&0b010?'F':'-', packet->flags&0b100?'L':'-');

		switch (client->state) {
			case INIT: {
				struct packet_ConnectionRequest *packet = (struct packet_ConnectionRequest*)buf;
				fprintf(stderr, "version = v%d.%d.%d (build %d), cid = %#010x\n", packet->version.major, packet->version.minor, packet->version.patch, packet->version.build, packet->cid);

				client->version = packet->version;
				client->cid = packet->cid;
				client->sid = 0;
				client->seq = packet->header.seq;

				struct packet_ConnectionRequestReply reply = {
					.header = {.flags = 0b110, .pid = 0x03, .seq = 0x8028},
					.confirmation = _unknown_000100000000,
					.version = client->version,
					.cid = client->cid,
					.sid = (client->sid = rand()),
				};
				sendto(sock, &reply, sizeof(reply), 0, (struct sockaddr*)&peer, peerlen); check_err(init_error);

				goto init_ok;
				init_error: {
					client->state = DISCONNECTED;
					printf("err %d\n", errno);
					perror(NULL);
					break;
				}
				init_ok: {
					client->state = CONNECT;
					printf("ok -> CONNECT\n");
				}
			}; break;

			case CONNECT: {
				struct packet_ConnectionRequestReplyConfirm *packet = (struct packet_ConnectionRequestReplyConfirm*)buf;
				fprintf(stderr, "cid = %#010x, sid = %#010x, iid = %#010x\n", packet->cid, packet->sid, packet->iid);

				assert (packet->sid == client->sid);

				uint8_t *p = packet->data;

				uint8_t username_length = *p++;
				char username[username_length+1]; strncpy(username, (char*)p, username_length); username[username_length] = '\0'; p += username_length;

				uint8_t password_length = *p++;
				char password[password_length+1]; strncpy(password, (char*)p, password_length); password[password_length] = '\0'; p += password_length;

				if (password_length == 0) {
					printf("np\n");
					goto request_password;
				}
				printf("password: %s\n", password);

				for (unsigned index = 0; index < sizeof(SERVERS)/sizeof(*SERVERS); index++) {
					if (strncmp(password, SERVERS[index].name, password_length) != 0) continue;

					struct sockaddr_in dest = {AF_INET, htons(SERVERS[index].port), {0}, ""};
					inet_pton(AF_INET, SERVERS[index].ip, &dest.sin_addr); check_err(connect_error);
					socklen_t destlen = sizeof(dest);

					client->server = socket(AF_INET, SOCK_DGRAM, 0); check_err(connect_error);
					connect(client->server, (struct sockaddr*)&dest, destlen); check_err(connect_error);

					struct packet_ConnectionRequest request = {
						.header = {.pid = 0x02, .seq = 0},
						.version = client->version,
						.cid = client->cid,
					};
					send(client->server, &request, sizeof(request), 0); check_err(connect_error);

					struct packet_ConnectionRequestReply request_reply;
					recv(client->server, &request_reply, sizeof(request_reply), MSG_WAITALL); check_err(connect_error);
					client->sid = request_reply.sid;
					fprintf(stderr, "from server: version = v%d.%d.%d (build %d), cid = %#010x, sid = %#010x\n", request_reply.version.major, request_reply.version.minor, request_reply.version.patch, request_reply.version.build, request_reply.cid, request_reply.sid);

					packet->sid = client->sid;
					send(client->server, packet, n, 0); check_err(connect_error);

					client->client = socket(AF_INET, SOCK_DGRAM, 0); check_err(connect_error);
					setsockopt(client->client, SOL_SOCKET, SO_REUSEADDR, &(int){true}, sizeof(int)); check_err(connect_error);
					bind(client->client, (struct sockaddr*)&addr, addrlen); check_err(connect_error);
					connect(client->client, (struct sockaddr*)&peer, peerlen); check_err(connect_error);

					goto connect_ok;
				}

				request_password: {
					uint8_t deny[sizeof(struct packet_ConnectionAcceptOrDeny) + 1+sizeof(SERVERNAME)/sizeof(*SERVERNAME) + 1 + 1 + 1 + 1 + 4 + 8 + 1 + 1 + 1 + 1 + 4 + 4 + 2 + sizeof(mods)] = {0};
					*(struct packet_ConnectionAcceptOrDeny*)deny = (struct packet_ConnectionAcceptOrDeny){
						.header = {.flags = 0b110, .pid = 0x05, .seq = 0x8005},
						.confirmation = _unknown_000101000000,
						.cid = client->cid,
						.status = 0x06,
					};

					uint8_t *p = ((struct packet_ConnectionAcceptOrDeny*)deny)->data;

					*p++ = sizeof(SERVERNAME)/sizeof(*SERVERNAME);
					strncpy((char*)p, SERVERNAME, sizeof(SERVERNAME)/sizeof(*SERVERNAME)); p += sizeof(SERVERNAME)/sizeof(*SERVERNAME);

					struct mods *mods_ = (struct mods*)memcpy(deny + sizeof(deny) - sizeof(mods), &mods, sizeof(mods));
					mods_->mods[0].version = *(struct version_short*)&client->version;
					mods_->mods[0].crc = 0x6b760752;

					sendto(sock, &deny, sizeof(deny), 0, (struct sockaddr*)&peer, peerlen); check_err(connect_error);
				}

				connect_error: {
					client->state = DISCONNECTED;
					printf("err %d\n", errno);
					perror(NULL);
					break;
				}
				connect_ok: {
					printf("ok -> LOOP\n");
					if (fork() == 0) {
						int fd_pipe[2];
						assert (pipe(fd_pipe) == 0);

						fcntl(client->client, F_SETFL, fcntl(client->client, F_GETFL, 0) | O_NONBLOCK);
						fcntl(client->server, F_SETFL, fcntl(client->server, F_GETFL, 0) | O_NONBLOCK);

						while (client->client || client->server) {
							splice(client->client, NULL, fd_pipe[1], NULL, 4069, (SPLICE_F_MOVE | SPLICE_F_NONBLOCK));
							splice(fd_pipe[0], NULL, client->server, NULL, 4069, (SPLICE_F_MOVE | SPLICE_F_NONBLOCK));

							splice(client->server, NULL, fd_pipe[1], NULL, 4069, (SPLICE_F_MOVE | SPLICE_F_NONBLOCK));
							splice(fd_pipe[0], NULL, client->client, NULL, 4069, (SPLICE_F_MOVE | SPLICE_F_NONBLOCK));
						}
					}
					client->state = LOOP;
				}
			}; break;

			case LOOP: {
			}; break;

			case DISCONNECTED: {
				if (client->server) { close(client->server); client->server = 0; }
				if (client->client) { close(client->client); client->client = 0; }
			}; break;
		}
	}
}

// by Sdore, 2021-22
//   www.sdore.me

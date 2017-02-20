#ifndef EQ_SOCK_H
#define EQ_SOCK_H

#include "eq_sys.h"
#include "eq_msg.h"

enum {
	EQ_SOCK_RAW = 0,
	EQ_SOCK_IN4,
	EQ_SOCK_IN6,
	EQ_SOCK_LOCAL,
	EQ_SOCK_T_MAX,
};

enum {
	EQ_SOCK_ST_NONE = 0,
	EQ_SOCK_ST_CONN,
	EQ_SOCK_ST_REDY,
};

union eq_sock_addr {
	struct sockaddr sa;
	struct sockaddr_in in4;
	struct sockaddr_in6 in6;
};

struct eq_sock_cb {
	int fd;
	u32 state:4;
	u32 type:8;
	u32 rdtask:20;
	u32 wttask:20;
	u32 unused:12;
	union eq_sock_addr addr;
};

#define eq_sock_cb_init(cb) do { \
	mem_set(cb, 0, sizeof(*(cb))); \
	(cb)->fd = -1; \
}while(0)

struct eq_sock_cb_desc {
	int type;
	int proto;
	u16 port;
	u16 stype:4;
	u16 unused:12;
};

/* Network Block, per Client */
struct eq_sock_nb {
	int fd;
	u32 state:4;
	u32 type:8;
	u32 owner:20;
	struct eq_msg msg[2];
};

#define eq_sock_nb_init(nb) do { \
	mem_set(nb, 0, sizeof(*(nb))); \
	(nb)->fd = -1; \
}while(0)

#define eq_sock_nb_fini(nb) do { \
	if((nb)->fd >= 0) \
		close((nb)->fd); \
	eq_sock_nb_init(nb); \
}while(0)

#ifdef __cplusplus
extern "C" {
#endif

socklen_t eq_sock_len(u8 stype);

void eq_sock_cb_init_net(struct eq_sock_cb* cb, u16 port, u8 type);
int eq_sock_cb_socket(struct eq_sock_cb* cb, int type, int proto);
int eq_sock_cb_open(struct eq_sock_cb* cb, int type, int proto);
int eq_sock_nb_socket(struct eq_sock_nb* nb, int stype,
	int type, int proto);

ssize_t eq_sock_read(struct eq_msg_cb* msgcb, u8* data, size_t len);
ssize_t eq_sock_write(struct eq_msg_cb* msgcb, u8* data, size_t len);

#ifdef __cplusplus
}
#endif

#endif


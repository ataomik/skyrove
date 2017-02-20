#ifndef EQ_MSG_H
#define EQ_MSG_H

#include "eq_sys_types.h"

enum {
	EQ_MSG_T_NONE = 0,
	EQ_MSG_DNS,
	EQ_MSG_T_MAX,
};

enum {
	EQ_MSG_SEND = 0,
	EQ_MSG_RECV,
};

struct eq_msg {
	u32 source:12;
	u32 size:20;
	u32 type:12;
	u32 len:20;
	u32 offset:20;
	u32 unused:12;
	union {
		struct eq_dns_tcp* dns;
		u8* raw;
	};
};

typedef struct eq_msg_cb eq_msg_cb_t;

typedef ssize_t (*eq_msg_op)(eq_msg_cb_t*, u8*, size_t);

struct eq_msg_cb {
	int fd;
	int error;
	eq_msg_op op;
};

static ssize_t eq_msg_proc(struct eq_msg_cb* cb, struct eq_msg* msg)
{
	ssize_t sz;
	
	if(msg->offset >= msg->len)
		return -1;
	
	sz = cb->proc(cb, msg->raw+msg->offset, msg->len-msg->offset);
	if(sz)
		msg->offset += sz;
	
	return sz;
}

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __cplusplus
}
#endif

#endif


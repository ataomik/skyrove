#include <eq_mem.h>
#include <eq_sock.h>

int eq_sock_cb_socket(struct eq_sock_cb* cb, int type, int proto)
{
	switch(cb->type) {
		case EQ_SOCK_IN4:
			cb->fd = eq_sys_socket4(type, proto, &cb->addr.in4);
			break;
		case EQ_SOCK_IN6:
			cb->fd = eq_sys_socket6(type, proto, &cb->addr.in6);
			break;
	}

	return cb->fd;
}

void eq_sock_cb_init_net(struct eq_sock_cb* cb, u16 port, u8 type)
{
	eq_mem_set(&cb->addr, 0, sizeof(cb->addr));
	
	cb->type = type;
	switch(cb->type) {
		case EQ_SOCK_IN4:
			cb->addr.in4.sin_family = AF_INET;
			cb->addr.in4.sin_port = port;
			cb->addr.in4.sin_addr.s_addr = INADDR_ANY;
			break;

		case EQ_SOCK_IN6:
			cb->addr.in6.sin6_family = AF_INET6;
			cb->addr.in6.sin6_port = port;
			break;
	}
}

int eq_sock_cb_open(struct eq_sock_cb* cb, int type, int proto)
{
	if(cb->fd < 0) {
		eq_sock_cb_socket(cb, type, proto);
	}

	return cb->fd;
}

int eq_sock_nb_socket(struct eq_sock_nb* nb, int stype,
	int type, int proto)
{
	switch(stype) {
		case EQ_SOCK_IN4:
			nb->fd = eq_sys_socket4(type, proto, NULL);
			break;
		case EQ_SOCK_IN6:
			nb->fd = eq_sys_socket6(type, proto, NULL);
			break;
	}

	return nb->fd;
}

socklen_t eq_sock_len(u8 stype)
{
	static socklen_t s_sock_len[] = {
		0,
		sizeof(struct sockaddr_in),
		sizeof(struct sockaddr_in6),
		0,
	};

	if(stype < EQ_SOCK_T_MAX) {
		return s_sock_len[stype];
	}

	return 0; 
}

ssize_t eq_sock_read(struct eq_msg_cb* msgcb, u8* data, size_t len)
{
	ssize_t rdlen = read(msgcb->fd, data, len);
	if(rdlen < 0)
		msgcb->error = errno;
	
	return rdlen;
}

ssize_t eq_sock_write(struct eq_msg_cb* msgcb, u8* data, size_t len)
{
	ssize_t wtlen = write(msgcb->fd, data, len);
	if(wtlen < 0)
		msgcb->error = errno;
	
	return wtlen;
}


#include <eq_cache.h>
#include <eq_sys.h>

static struct eq_sys_dns_cfg s_dns_cfg;

static void eq_cache_clear_rcybin(struct eq_cache_table* table)
{
}

struct eq_sock_nb* eq_cache_find_nb(struct eq_cache_table* table,
	u8 state)
{
	int i;

	for(i = 0; i < EQ_CACHE_NB_MAX; i ++) {
		if(table->nb[i].state == state)
			return &table->nb[i];
	}

	return NULL;
}

void eq_cache_error_cb(struct eq_cache_table* table,
	struct eq_sock_cb* cb)
{
}

struct eq_sock_cb* eq_cache_find_cb(struct eq_cache_table* table,
	u8 state)
{
	int i;
	
	for(i = 0; i < EQ_CACHE_CB_MAX; i ++) {
		if(table->cb[i].state == state)
			return &table->cb[i];
	}

	return NULL;
}

static struct eq_sock_cb_desc s_cb_desc[EQ_CACHE_CB_MAX] = {
	{ SOCK_DGRAM,  IPPROTO_UDP, EQ_DNS_PORT, EQ_SOCK_IN4, },
	{ SOCK_STREAM, IPPROTO_TCP, EQ_DNS_PORT, EQ_SOCK_IN4, },
	{ SOCK_DGRAM,  IPPROTO_UDP, EQ_DNS_PORT, EQ_SOCK_IN6, },
	{ SOCK_STREAM, IPPROTO_TCP, EQ_DNS_PORT, EQ_SOCK_IN6, },
};

struct eq_sock_cb_desc* eq_sock_cb_get_desc(u8 type) {
	if(type < EQ_CACHE_CB_MAX)
		return &s_cb_desc[type];
	return NULL;
}

int eq_cache_open_cb(struct eq_cache_table* table,
	struct eq_sock_cb* cb)
{
	if(cb->fd < 0) {
		struct eq_sock_cb_desc* desc;
		
		desc = eq_sock_cb_get_desc(cb->type);
		if(desc) {
			eq_sock_cb_open(cb, desc->type, desc->proto);
		}
	}
	
	return cb->fd;
}

struct eq_sock_nb* eq_cache_accept_cb(struct eq_cache_table* table,
	struct eq_sock_cb* cb)
{
	struct eq_sock_nb* nb;
	
	nb = eq_cache_find_nb(table, EQ_SOCK_ST_NONE);
	if(nb) {
		union eq_sock_addr addr;
		socklen_t addrlen = eq_sock_len(cb->type);
		
		nb->fd = accept(cb->fd, &addr.sa, &addrlen);
		
		if(cb->type == EQ_SOCK_IN4) {
		}
		else if(cb->type == EQ_SOCK_IN6) {
		}
		else {
		}
		
		if(eq_cache_find_sesn()) {
			/* session is not finished */
			close(nb->fd);
			nb->fd = -1;

			return NULL;
		}

		eq_cache_nb_set_cb(table, nb, cb);
	}

	return nb;
}

int eq_cache_read_cb(struct eq_cache_table* table,
	struct eq_sock_cb* cb)
{
	struct eq_sock_nb* nb = eq_cache_accept_cb(table, cb);
	if(nb) {
		cb->rdtask ++;
		return 0;
	}

	return -1;
}

int eq_cache_write_cb(struct eq_cache_table* table,
	struct eq_sock_cb* cb)
{
}

#define EQ_CACHE_POLL_MAX (EQ_CACHE_CB_MAX+EQ_CACHE_NB_MAX)

static int eq_cache_pre_poll_cb(struct eq_cache_table* table,
	struct pollfd* poll_sets)
{
	int i, ret = 0;
	struct eq_sock_cb* cb;
	
	for(i = 0; i < EQ_CACHE_CB_MAX; i ++) {
		cb = &table->cb[i];
		
		poll_sets[i].events = 0;
		poll_sets[i].revents = 0;
		poll_sets[i].fd = eq_cache_open_cb(table, cb);
			
		if(cb->wttask) {
			poll_sets[i].events |= POLLOUT;
			ret ++;
		}
	
		/* always read to accept connections */
		poll_sets[i].events |= POLLIN;
		ret ++;
	}

	return ret;
}

static void eq_cache_post_poll_cb(struct eq_cache_table* table,
	struct pollfd* poll_sets)
{
	int i;
	struct eq_sock_cb* cb;
	
	for(i = 0; i < EQ_CACHE_CB_MAX; i ++) {
		if(0 == poll_sets[i].revents) {
			continue;
		}
		
		cb = &table->cb[i];
		if(0 != (POLLERR & poll_sets[i].revents) || \
			0 != (POLLHUP & poll_sets[i].revents) || \
			0 != (POLLNVAL & poll_sets[i].revents))
			eq_cache_error_cb(table, cb);
						
		if(0 != (POLLIN & poll_sets[i].revents))
			eq_cache_read_cb(table, cb);
			
		if(0 != (POLLOUT & poll_sets[i].revents))
			eq_cache_write_cb(table, cb);
	}
}

void eq_cache_error_nb(struct eq_cache_table* table,
	struct eq_sock_nb* nb)
{
}

int eq_cache_read_nb(struct eq_cache_table* table,
	struct eq_sock_nb* nb)
{
	struct eq_msg_cb msgcb = { nb->fd, 0, eq_sock_read, };
	ssize_t len;
	
	switch(nb->state) {
		case EQ_SOCK_ST_REDY:
			len = eq_msg_proc(&msgcb, &nb->msg[EQ_MSG_RECV]);
			if(msgcb.error) {
				if(msgcb.error != EINTR && msgcb.error != EAGAIN)
					return -1;
			}
			else if(!len) {
				union eq_sock_addr addr;
				/* remove session */
				eq_cache_del_sesn();
				eq_sock_nb_fini(nb);
			}
			break;
		default:
			break;
	}

	return 0;
}

int eq_cache_write_nb(struct eq_cache_table* table,
	struct eq_sock_nb* nb)
{
	struct eq_msg_cb msgcb = { nb->fd, 0, eq_sock_write, };
	ssize_t len;
	
	switch(nb->state) {
		case EQ_SOCK_ST_NONE:
		case EQ_SOCK_ST_CONN:
		{
			struct eq_sock_cb* cb;
			/* connect event */
			if(nb->state == EQ_SOCK_ST_CONN) {
				int status;
				socklen_t slen = sizeof(status);
			
				if(getsockopt(nb->fd, SOL_SOCKET, SO_ERROR,
					&status, &slen) < 0)
					return -1;
				if(status != 0)
					return -1;
			}
			
			cb = eq_cache_nb_get_cb(table, nb);
			if(!cb)
				return -1;
			nb->state = EQ_SOCK_ST_REDY;
			if(eq_cache_build_msg(table, cb, nb) != 0)
				return -1;
		}
		case EQ_SOCK_ST_REDY:
		{
			len = eq_msg_proc(&msgcb, &nb->msg[EQ_MSG_SEND]);
			if(msgcb.error) {
				if(msgcb.error != EINTR && msgcb.error != EAGAIN)
					return -1;
			}
			else {
			}
			break;
		}
	}
}

static int eq_cache_pre_poll_nb(struct eq_cache_table* table,
	struct pollfd* poll_sets)
{
	int i, ret = 0;
	struct eq_sock_nb* nb;
	struct eq_msg* msg;
	
	for(i = 0; i < EQ_CACHE_NB_MAX; i ++) {
		nb = &table->nb[i];

		poll_sets[i].events = 0;
		poll_sets[i].revents = 0;
		poll_sets[i].fd = nb->fd;

		if(!nb->fd)
			continue;
		
		msg = &nb->msg[EQ_MSG_SEND];
		if(msg->offset < msg->len) {
			poll_sets[i].events |= POLLOUT;
			ret ++;
		}
		msg = &nb->msg[EQ_MSG_RECV];
		if(msg->offset < msg->len) {
			poll_sets[i].events |= POLLIN;
			ret ++;
		}
	}
	
	return ret;
}

static void eq_cache_post_poll_nb(struct eq_cache_table* table,
	struct pollfd* poll_sets)
{
	int i;
	struct eq_sock_nb* nb;
	
	for(i = 0; i < EQ_CACHE_NB_MAX; i ++) {
		if(0 == poll_sets[i].revents) {
			continue;
		}
		
		nb = &table->nb[i];
		if(0 != (POLLERR & poll_sets[i].revents) || \
			0 != (POLLHUP & poll_sets[i].revents) || \
			0 != (POLLNVAL & poll_sets[i].revents))
			eq_cache_error_nb(table, nb);
						
		if(0 != (POLLIN & poll_sets[i].revents))
			eq_cache_read_nb(table, nb);
			
		if(0 != (POLLOUT & poll_sets[i].revents))
			eq_cache_write_nb(table, nb);
	}
}

static void* eq_cache_thread_proc(void* data)
{
	struct eq_cache_table* table = (struct eq_cache_table*)data;
	u32 cfg_time = eq_sys_sec(), age_time = eq_sys_sec();
	
	while(table->thread.exists) {
		int i, rv, task_count = 0;
		struct pollfd poll_sets[EQ_CACHE_POLL_MAX];
		struct eq_sock_cb* cb;
		struct eq_sock_nb* nb;

		eq_cache_clear_rcybin(table);

		if(eq_sys_sec() > age_time) {
			eq_cache_age(table);
			age_time = eq_sys_sec();
		}
				
		if(eq_sys_sec() > cfg_time+10) {
			if(eq_dns_localcfg_check(&s_dns_cfg.ts))
				eq_sys_load_dns_config(&s_dns_cfg);
			cfg_time = eq_sys_sec();
		}

		task_count = eq_cache_pre_poll_cb(table, poll_sets);
		task_count += eq_cache_pre_poll_nb(table,
			poll_sets+EQ_CACHE_CB_MAX);	

		if(!task_count) {
			sleep(1);
			continue;
		}

		if(-1 == (rv = poll(poll_sets, EQ_CACHE_POLL_MAX,
			EQ_CACHE_TM_WAIT))) {
			if(EINTR != errno) {
				EQ_CACHE_DBG("poll(): %d, %s", rv, strerror(errno));
			}
			continue;
		} else if(0 == rv) {
			continue;
		}

		eq_cache_post_poll_cb(table, poll_sets);
		eq_cache_post_poll_nb(table, poll_sets+EQ_CACHE_CB_MAX);
	}
	/* set for break in loop */
	table->thread.exists = 0;
	
	return table;
}

int eq_cache_add(struct eq_cache_table* table,
	struct eq_cache_info* info)
{
	if(info->type == EQ_CACHE_T_DOMAIN) {
		union eq_val val;
	}
}

int eq_cache_del(struct eq_cache_table* table,
	struct eq_cache_info* info)
{
}


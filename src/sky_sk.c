#include <net/inet/inet_sk.h>

#define SOCKSIZE (sizeof(inet_sk))
#define sk2fd(inet) ((inet_fd)(inet))

__thread int inet_errno = 0;
struct inet_io_ops g_inet_sk_io_ops = INET_SOCK_IO_OPS;

inet_sk* inet_fd2sock(inet_fd fd)
{
	inet_sk* sk;
	if (fd < 0) {
		return NULL;
	}

	sock = (inet_sk* )fd;
	if (sock) {
	}

	return sock;
}

inet_sesn* inet_sk_bind_ipv4(inet_sk* sk, const struct sockaddr_in *sa)
{
	inet_sesn* sesn;
	sesn = inet_sesn_new_ipv4(sa->sin_addr.s_addr, sa->sin_port);
	if(sesn)
		inet_sesn_bind_sk(sesn, sk);
	return sesn;
}

inet_sesn* inet_sk_bind_ipv6(inet_sk* sk, const struct sockaddr_in6 *sa)
{
	inet_sesn* sesn;
	sesn = inet_sesn_new_ipv6(&sa->sin6_addr, sa->sin6_port);
	if(sesn)
		inet_sesn_bind_sk(sesn, sk);
	return sesn;
}

inet_sesn* inet_sk_bind_domain(inet_sk* sk, const struct sockaddr_domain *sa)
{
	inet_sesn* sesn;
	sesn = inet_sesn_new_domain(sa->sd_addr, sockaddr_domain_len(sa),
		sa->sd_port, sa->sin_family == AF_INET6);
	if(sesn)
		inet_sesn_bind_sk(sesn, sk);
	return sesn;
}

int inet_sesn_connect_status(inet_sesn* sesn)
{
	if(!sesn)
		return 0;

	switch (sesn->state) {
		case INET_ST_NONE:
			return 0;
		case INET_ST_CONNECTING:
			return EINPROGRESS;
		case INET_ST_CONNECTED:
			return EISCONN;
		default:
			break;
	}

	return 0;
}

inet_sk* inet_find_sk(inet_sesn* sesn)
{
	inet_node* node = inet_sesn_search_node(sesn, INET_SK);
    if(node)
        return inet_sk_entry(node);
    return NULL;
}

int inet_sk_on_connected(inet_sesn* sesn, inet_sk* sk)
{
	return 0;
}

int inet_sk_on_data_arrived(inet_sesn* sesn, inet_sk* sk, int event,
	inet_buf* buf)
{
	return 0;
}

int inet_sk_on_buf_avail(inet_sesn* sesn, inet_sk* sk)
{
	return 0;
}

void inet_sk_on_fini(inet_sesn* sesn, inet_sk* sk)
{
	if(!sk) {
		sk = inet_find_sk(sesn);
		if(!sk)
			return;
	}
	inet_unbind_sk(sesn, sk);
	inet_sk_free(sk);
}

int inet_sk_on_event(inet_sesn* sesn, int event, void *data)
{
	int ret = -1;
	inet_sk* sk;

	sk = inet_find_sk(sesn);
	if(!sk)
		return INET_SK_NOEXISTS;

	if(!inet_event_is_err(event)) {
		return 0;
	}

	inet_sk_set_err(sock, event);
	inet_sk_on_fini(sesn);

	return ret;
}

void inet_sket_init()
{
	/* lower layer */
	if (!inet_service_exists(INET_SK)) {
		struct inet_service_ops ops =
			INET_SERVICE_OPS(INET_SK,
							 inet_service_socket_est_cb,
							 inet_service_socket_data_cb,
							 inet_service_socket_wbuf_cb,
							 inet_service_socket_event_cb);

		inet_register(INET_SK, &ops);
	}

	return;
}

unsigned inet_sket_can_support(int domain, int type, int protocol)
{
	if (domain != AF_INET && domain != AF_INET6) {
		return 0;
	}
	if (type != SOCK_STREAM && type != SOCK_DGRAM) {
		return 0;
	}

	return 1;
}

void inet_sket_init(inet_sk* sk, int domain, int type, int protocol)
{
	memset(sock, 0, sizeof(*sock));
	inet_list_init(&sock->wque);
	sock->reqfree = 1;
	sock->tid = GET_PRIVATE(cpu_id);
}

inet_fd inet_sket(int domain, int type, int protocol)
{
	inet_sk* sk;

	if (!inet_sket_can_support(domain, type, protocol)) {
		return -1;
	}
	sock = malloc(sizeof(*sock));
	if (!sock) {
		return -1;
	}
	inet_sket_init(sock, domain, type, protocol);
	sock->allocated = 1;
	return sock2fd(sock);
}

void inet_sket_fini_req(inet_sk* sk)
{
	if (!sock->req || !sock->req->sesn) {
		return;
	}

	if (sock->req->is_udp) {
		inet_close_udp_conn(sock->req->sesn);
	} else {
		inet_close_tcp_conn(sock->req->sesn);
	}
}

void inet_sket_fini(inet_sk* sk)
{
	if (!sock->reqfree) {
		inet_sket_fini_req(sock);
	}
}

int inet_close(inet_fd sockfd)
{
	inet_sk* sk = inet_fd2sock(sockfd);
	if (!sock || !sock->allocated) {
		return -1;
	}
	if (sock->skfree) {
		return -1;
	}

	inet_sket_fini(sock);
	sock->skfree = 1;
	free(sock);
	return 0;
}

int inet_bind(inet_fd sockfd, struct sockaddr *addr, socklen_t addrlen)
{
	return 0;
}

int inet_sket_bind_dst(inet_sk* sk, const struct sockaddr *addr, socklen_t addrlen)
{
	switch (addr->sa_family) {
		case AF_INET: {
			struct sockaddr_in *sa = (struct sockaddr_in *)addr;

			if (addrlen < sizeof(*sa)) {
				return -1;
			}
			sock->req = inet_req_bind_ipv4(sock, sa);
			break;
		}

		case AF_INET6: {
			struct sockaddr_in6 *sa = (struct sockaddr_in6 *)addr;

			if (addrlen < sizeof(*sa)) {
				return -1;
			}
			sock->req = inet_req_bind_ipv6(sock, sa);
			break;
		}

		case AF_DOMAIN: {
			struct sockaddr_domain *sa = (struct sockaddr_domain *)addr;
			if (addrlen < sizeof(*sa)) {
				return -1;
			}
			sock->req = inet_req_bind_domain(sock, sa);
			break;
		}
		default:
			inet_set_errno(EAFNOSUPPORT);
			return -1;
	}

	if (!sock->req) {
		inet_set_errno(ENOMEM);
		return -1;
	}

	sock->req->nat_pool_id = sock->nat_pool_id;
	sock->reqfree = 0;
	return 0;
}

int inet_sket_check_connect(inet_sk* sk)
{
	int ret = -1;

	switch (sock->state) {
		case SOCK_ST_CONNECTING:
			ret = EINPROGRESS;
			inet_set_errno(ret);
			break;
		case SOCK_ST_CONNECTED:
			ret = EISCONN;
			inet_set_errno(EALREADY);
			break;
	}

	return ret;
}

int inet_sket_do_connect(inet_sk* sk)
{
	int ret;

	inet_sk_change_state(sock, SOCK_ST_CONNECTING);
	if (inet_sk_is_udp(sock)) {
		ret = inet_connect_udp(sock->req);
	} else {
		ret = inet_connect_tcp(sock->req);
	}
	if (ret < 0) {
		inet_set_errno(ECONNREFUSED);
		return -1;
	} else if (ret == 0 && inet_sk_is_connecting(sock)) {
		inet_set_errno(EINPROGRESS);
		return -1;
	}

	return 0;
}

int inet_sket_connect(inet_sk* sk, const struct sockaddr *addr, socklen_t addrlen)
{
	if (sock->err) {
		inet_set_errno(ECONNREFUSED);
		return -1;
	}

	if (sock->req) {
		return inet_sket_check_connect(sock);
	}

	if (inet_sket_bind_dst(sock, addr, addrlen) != 0) {
		return -1;
	}

	return inet_sket_do_connect(sock);
}

int inet_connect(inet_fd sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
	inet_sk* sk = inet_fd2sock(sockfd);

	if (!sock) {
		inet_set_errno(EBADF);
		return -1;
	}

	return inet_sket_connect(sock, addr, addrlen);
}

int inet_sket_flush(inet_sk* sk)
{
	int ret;

	ret = inet_flush(inet_sk_conn(sock), inet_sk_sendq(sock));
	if (ret > 0) {
		sock->sndlen = 0;
	}
	return ret;
}

#define inet_sket_commit_wque(sock) \
	inet_commit_iolist(inet_sk_conn(sock), inet_sk_sendq(sock), &sock->wque)

int inet_flush(inet_fd sockfd)
{
	inet_sk* sk = inet_fd2sock(sockfd);
	if (!sock) {
		return -1;
	}
	if (!inet_sk_has_conn(sock)) {
		return 0;
	}

	inet_sket_commit_wque(sock);

	return inet_sket_flush(sock);
}

void inet_sket_flush_later(inet_sk* sk)
{
	struct inet_timer *timer;
	timer = inet_add_timer(inet_sk_conn(sock), SOCK_TIMER_FLUSH);
	if (!timer) {
		return;
	}
	if (!inet_timer_pending(timer)) {
		inet_start_timer(timer, (inet_timer_cb)inet_sket_flush, (unsigned long)sock, INET_20MS(1));
	}
}

void inet_sket_write_update(inet_sk* sk, ssize_t ret)
{
	sock->sndlen += ret;
	if (sock->sndlen > sock->sndmax) {
		inet_sket_flush(sock);
	} else {
		inet_sket_flush_later(sock);
	}
}

ssize_t inet_sket_write(inet_sk* sk, const void *buf, size_t count, int flags)
{
	ssize_t ret;

	if (inet_sket_commit_wque(sock) < 1) {
		return -1;
	}

	ret = inet_write(inet_sk_conn(sock), inet_sk_sendq(sock), buf, count);
	if (ret > 0) {
		inet_sket_write_update(sock, ret);
	}

	return ret;
}

ssize_t inet_sket_write_buf(inet_sk* sk, inet_buf* buf)
{
	if (inet_sket_commit_wque(sock) < 1) {
		struct inet_ionode *node = inet_alloc_data(0);
		if (!node) {
			return -1;
		}
		inet_ionode_init_buf(node, buf);
		inet_ionode_add_tail(&sock->wque, node);
		return buf->data_len;
	}
	return inet_commit(inet_sk_conn(sock), inet_sk_sendq(sock), buf);
}

ssize_t inet_sket_commit(inet_sk* sk, struct inet_ionode *node)
{
	inet_ionode_add_tail(&sock->wque, node);
	return 1;
}

ssize_t inet_write(inet_fd sockfd, const void *buf, size_t count)
{
	inet_sk* sk = inet_fd2sock(sockfd);
	if (!sock) {
		return -1;
	}
	if (!inet_sk_has_conn(sock)) {
		return 0;
	}

	return inet_sket_write(sock, buf, count, 0);
}

void inet_sket_read_src_addr(inet_sk* sk, struct sockaddr *addr, socklen_t *addrlen)
{
}

ssize_t inet_sket_read(inet_sk* sk, void *buf, size_t count, int flags)
{
	return inet_read(inet_sk_conn(sock), inet_sk_recvq(sock), buf, count);
}

ssize_t inet_sket_peek(inet_sk* sk, void *buf, size_t count)
{
	struct inet_queue* queue = inet_sk_recvq(sock);
	inet_buf* buf = queue->head;
	size_t offset = 0;

	return inet_peek(inet_sk_conn(sock), &buf, &offset, buf, count);
}

ssize_t inet_read(inet_fd sockfd, void *buf, size_t count)
{
	inet_sk* sk = inet_fd2sock(sockfd);
	if (!sock) {
		return -1;
	}
	if (!inet_sk_has_conn(sock)) {
		return 0;
	}

	return inet_sket_read(sock, buf, count, 0);
}

/* we will support flags later */
ssize_t inet_send(inet_fd sockfd, const void *buf, size_t len, int flags)
{
	inet_sk* sk = inet_fd2sock(sockfd);
	if (!sock) {
		return -1;
	}
	if (!inet_sk_has_conn(sock)) {
		return 0;
	}

	return inet_sket_write(sock, buf, len, flags);
}

ssize_t inet_sendto(inet_fd sockfd, const void *buf, size_t len, int flags,
					const struct sockaddr *dest_addr, socklen_t addrlen)
{
	inet_sk* sk = inet_fd2sock(sockfd);
	if (!sock) {
		return -1;
	}
	if (!inet_sk_has_conn(sock)) {
		return 0;
	}

	if (inet_sk_is_udp(sock) && dest_addr) {
		inet_sket_bind_dst(sock, dest_addr, addrlen);
	}
	return inet_sket_write(sock, buf, len, flags);
}

ssize_t inet_recv(inet_fd sockfd, void *buf, size_t len, int flags)
{
	return inet_read(sockfd, buf, len);
}

ssize_t inet_recvfrom(inet_fd sockfd, void *buf, size_t len, int flags,
					  struct sockaddr *src_addr, socklen_t *addrlen)
{
	inet_sk* sk = inet_fd2sock(sockfd);
	if (!sock) {
		return -1;
	}
	if (!inet_sk_has_conn(sock)) {
		return 0;
	}
	if (inet_sk_is_udp(sock) && src_addr) {
		inet_sket_read_src_addr(sock, src_addr, addrlen);
	}

	return inet_sket_read(sock, buf, len, flags);
}

int inet_sket_getopt(inet_sk* sk, int optname, void *optval, socklen_t *optlen)
{
	switch (optname) {
		case SO_ERR:
			*(int *)optval = sock->err;
			break;
		case SO_OPS: {
			*(struct inet_sk_ops **)optval = sock->ops;
			break;
		}
		case SO_OP_DATA:
			*(void **)optval = sock->opdata;
			break;
		case SO_APP_DATA:
			*(void **)optval = sock->appdata;
			break;
		case SO_VNP_ID:
			break;
		case SO_NAT_POOL_ID:
			break;
		case SO_HTTP: {
			break;
		}
	}

	return 0;
}

int inet_sket_getsockopt(inet_sk* sk, int level, int optname, void *optval, socklen_t *optlen)
{
	if (level == SOL_SK) {
		return inet_sket_getopt(sock, optname, optval, optlen);
	}

	return 0;
}

int inet_getsockopt(inet_fd sockfd, int level, int optname, void *optval, socklen_t *optlen)
{
	inet_sk* sk = inet_fd2sock(sockfd);
	if (!sock) {
		return -1;
	}
	return inet_sket_getsockopt(sock, level, optname, optval, optlen);
}

int inet_sket_opt2type(int optname)
{
	switch (optname) {
		case SO_DNS:
			return INET_DNS;
		case SO_HTTP:
			return INET_HTTP;
		case SO_SSL:
			return INET_SSL;
		default:
			break;
	}

	return 0;
}

int inet_sket_setopt(inet_sk* sk, int optname, const void *optval, socklen_t optlen)
{
	int val;

	switch (optname) {
		case SO_OPS:
			sock->ops = (struct inet_sk_ops *)optval;
			break;
		case SO_OP_DATA:
			sock->opdata = (void *)optval;
			break;
		case SO_APP_DATA:
			sock->appdata = (void *)optval;
			break;
		case SO_FLAGS:
			val = sock->flags;
			sock->flags = *(int *)optval;
			*(int *)optval = val;
			break;
		case SO_VNP_ID:
			val = sock->vnp_id;
			if (optlen == sizeof(vnp_id_t)) {
				sock->vnp_id = *(vnp_id_t *)optval;
				*(vnp_id_t *)optval = val;
			} else {
				sock->vnp_id = *(int *)optval;
				*(int *)optval = val;
			}
			break;
		case SO_NAT_POOL_ID:
			val = sock->nat_pool_id;
			if (optlen == sizeof(u16)) {
				sock->nat_pool_id = *(u16 *)optval;
				*(u16 *)optval = val;
			} else {
				sock->nat_pool_id = *(int *)optval;
				*(int *)optval = val;
			}
			break;
		case SO_DNS:
		case SO_HTTP: {
			int module = inet_sket_opt2type(optname);
			if (!module) {
				return -1;
			}
			break;
		}
	}

	return 0;
}

int inet_sket_setsockopt(inet_sk* sk, int level, int optname, const void *optval, socklen_t optlen)
{
	if (level == SOL_A10) {
		return inet_sket_setopt(sock, optname, optval, optlen);
	}

	return 0;
}

int inet_setsockopt(inet_fd sockfd, int level, int optname, const void *optval, socklen_t optlen)
{
	inet_sk* sk = inet_fd2sock(sockfd);
	if (!sock) {
		return -1;
	}

	return inet_sket_setsockopt(sock, level, optname, optval, optlen);
}

int inet_sk_io_write(inet_sesn* sesn, const unsigned char *data, size_t len)
{
	inet_sk* sk = inet_find_sk(sesn);
	if (!sock) {
		return -1;
	}
	return inet_sket_write(sock, data, len, 0);
}

int inet_sk_io_write_buf(inet_sesn* sesn, inet_buf* buf)
{
	inet_sk* sk = inet_find_sk(sesn);
	if (!sock) {
		return -1;
	}
	return inet_sket_write_buf(sock, buf);
}

struct inet_ionode *inet_sk_io_alloc(inet_sesn* sesn, int type, size_t size)
{
	inet_sk* sk = inet_find_sk(sesn);
	if (!sock) {
		return NULL;
	}
	return inet_io_alloc(sesn, type, size);
}

void inet_sk_io_free(inet_sesn* sesn, struct inet_ionode *node)
{
	return inet_io_free(sesn, node);
}

int inet_sk_io_commit(inet_sesn* sesn, struct inet_ionode *node)
{
	inet_sk* sk = inet_find_sk(sesn);
	if (!sock) {
		return -1;
	}
	return inet_sket_commit(sock, node);
}

unsigned inet_sk_io_flush(inet_sesn* sesn)
{
	inet_sk* sk = inet_find_sk(sesn);
	if (!sock) {
		return -1;
	}
	return inet_sket_flush(sock);
}

int inet_sk_io_read(inet_sesn* sesn, unsigned char *data, size_t len)
{
	inet_sk* sk = inet_find_sk(sesn);
	if (!sock) {
		return -1;
	}
	return inet_sket_read(sock, data, len, 0);
}

int inet_sk_io_peek(inet_sesn* sesn, unsigned char *data, size_t len)
{
	inet_sk* sk = inet_find_sk(sesn);
	if (!sock) {
		return -1;
	}
	return inet_sket_peek(sock, data, len);
}

void inet_sk_ginit()
{
	struct sock_ops ops = {
		sk_socket,
		sk_close,
		sk_connect,

		sk_write,
		sk_read,

		sk_send,
		sk_recv,

		sk_sendto,
		sk_recvfrom,

		sk_getsockopt,
		sk_setsockopt,
		sk_errno_location,
		sk_printf,
	};

	socket_register(SK_INET, &ops);
}


int inet_printf(sockfd_t sockfd, const char *format, ...)
{
    int ret;
    struct inet_io io;
    va_list args;
    inet_sock_t *sock;

    sock = inet_fd2sock(sockfd);
    if (!sock || !inet_sock_has_conn(sock)) {
        return -1;
    }

    inet_io_init(&io, inet_sock_conn(sock));
    inet_io_set_ops(&io, &g_inet_sock_io_ops);

    inet_io_set_wque(&io, &sock->wque);

    va_start(args, format);
    ret = inet_io_vprintf(&io, format, args);
    va_end(args);

    return ret;
}

int printf(int sockfd, const char *format, ...)
{
    int ret;
    struct inet_io io;
    va_list args;
    sock_t *sock;

    sock = sock_get(sockfd);
    if (!sock || !sock_has_conn(sock)) {
        return -1;
    }

    inet_io_init(&io, sock_conn(sock));
    inet_io_set_ops(&io, &g_sock_io_ops);

    spin_lock(&sock->lock);

    inet_io_set_wque(&io, &sock->sendq);

    va_start(args, format);
    ret = inet_io_vprintf(&io, format, args);
    va_end(args);

    spin_unlock(&sock->lock);

    return ret;
}

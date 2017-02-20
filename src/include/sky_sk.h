#ifndef INET_SK_H
#define INET_SK_H

#include "inet_sesn.h"

enum {
	SK_TIMER_FLUSH = INET_TIMER_USER,
	SK_TIMER_USER,
};

enum {
	INET_SK_NONE = 0,
};

#define INET_MOD_SK INET_MOD(INET_SK, INET_SK_NONE)
#define INET_MOD_SK_OPS \
	INET_OPS(INET_MOD_SK, inet_sk_alloc, inet_sk_free, inet_sk_event)

#if 0
typedef int (*inet_sk_op_event)(inet_fd fd, int code, inet_obj* obj);
#endif

typedef struct inet_sk_s {
	inet_node node;
	inet_list listeners;
	u32 err:6;
	u32 flags:16;
	u32 unused:10;
} inet_sk;


#define inet_find_sk(sesn, ctx) \
	(inet_sk*)inet_mod_find_ctx(&(sesn)->mod, INET_MOD_SK, ctx)

#define inet_set_errno(err) (inet_errno = (err))


#define INET_SK_IO_OPS { \
	inet_sk_io_alloc, inet_sk_io_free, inet_sk_io_commit, \
	inet_sk_io_flush, inet_sk_io_read, inet_sk_io_peek, }

#define inet_sk_set_err(sk, v) ((sk)->err = (v))

extern __thread int inet_errno;
extern struct inet_io_ops g_inet_sk_io_ops;

#ifdef __cplusplus
extern "C" {
#endif

void inet_sk_ginit();

int inet_sk_alloc(inet_obj* obj, inet_node** node);
void inet_sk_free(inet_obj* obj, inet_node* node);
int inet_sk_event(inet_node* node, int code, inet_obj* obj);

#if 0
inet_sk* inet_find_sk(inet_sesn*);
int inet_bind_sk(inet_sesn* sesn, inet_sk* sk);
int inet_unbind_sk(inet_sesn* sesn, inet_sk* sk);
void inet_del_sk(inet_sesn* sesn, inet_sk* sk);
void inet_reset_sk(inet_sesn* sesn, inet_sk* sk);
void inet_close_sk(inet_sesn* sesn, inet_sk* sk);

inet_sk* inet_fd2sk(inet_fd fd);

void inet_sk_fini_sesn(inet_sesn* sesn);
inet_sesn* inet_sk_bind_ipv4(inet_sk* sk, const struct sockaddr_in *sa);
inet_sesn* inet_sk_bind_ipv6(inet_sk* sk, const struct sockaddr_in6 *sa);
inet_sesn* inet_sk_bind_domain(inet_sk* sk, const struct sockaddr_domain *sa);
int inet_sk_connect_status(inet_sesn* sesn);

unsigned inet_sk_can_support(int domain, int type, int protocol);
void inet_sk_init(inet_sk* sk, int domain, int type, int protocol);
void inet_sk_fini(inet_sk* sk);
int inet_sk_bind_dst(inet_sk* sk, const struct sockaddr *addr,
	socklen_t addrlen);
int inet_sk_check_connect(inet_sk* sk);
int inet_sk_do_connect(inet_sk* sk);
int inet_sk_connect(inet_sk* sk, const struct sockaddr *addr,
	socklen_t addrlen);
int inet_sk_flush(inet_sk* sk);
ssize_t inet_sk_write(inet_sk* sk, const void *buf, size_t count, int flags);
ssize_t inet_sk_commit(inet_sk* sk, struct inet_ionode *node);
ssize_t inet_sk_read(inet_sk* sk, void *buf, size_t count, int flags);
ssize_t inet_sk_peek(inet_sk* sk, void *buf, size_t count);
int inet_sk_getopt(inet_sk* sk, int optname, void *optval, socklen_t *optlen);
int inet_sk_setopt(inet_sk* sk, int optname, const void *optval,
	socklen_t optlen);
int inet_sk_getsockopt(inet_sk* sk, int level, int optname, void *optval,
	socklen_t *optlen);
int inet_sk_setsockopt(inet_sk* sk, int level, int optname, const void *optval,
	socklen_t optlen);

inet_fd inet_socket(int domain, int type, int protocol);
int inet_close(inet_fd fd);

int inet_connect(inet_fd fd, const struct sockaddr *addr, socklen_t addrlen);

int inet_flush(inet_fd fd);

ssize_t inet_write(inet_fd fd, const void *buf, size_t count);
ssize_t inet_read(inet_fd fd, void *buf, size_t count);

ssize_t inet_send(inet_fd fd, const void *buf, size_t len, int flags);
ssize_t inet_sendto(inet_fd fd, const void *buf, size_t len, int flags,
	const struct sockaddr* dest_addr, socklen_t addrlen);

ssize_t inet_recv(inet_fd fd, void* buf, size_t len, int flags);
ssize_t inet_recvfrom(inet_fd fd, void* buf, size_t len, int flags,
	struct sockaddr* src_addr, socklen_t* addrlen);

int inet_getsockopt(inet_fd fd, int level, int optname, void *optval,
	socklen_t* optlen);

/* Set socket FD's option OPTNAME at protocol level LEVEL
   to *OPTVAL (which is OPTLEN bytes long).
   Returns 0 on success, -1 for errors.  */
int inet_setsockopt(inet_fd fd, int level, int optname, const void* optval,
	socklen_t optlen);

/* external IO */
inet_buf* inet_sk_io_alloc(inet_sesn *sesn, int type, size_t size);
void inet_sk_io_free(inet_sesn *sesn, struct inet_ionode *);
int inet_sk_io_write(inet_sesn *sesn, const unsigned char *data, size_t len);
int inet_sk_io_commit(inet_sesn *sesn, struct inet_ionode *node);
unsigned inet_sk_io_flush(inet_sesn *sesn);

int inet_sk_io_read(inet_sesn *sesn, unsigned char *data, size_t len);
int inet_sk_io_peek(inet_sesn *sesn, unsigned char *data, size_t len);

int inet_sk_printf(inet_fd fd, const char *format, ...);
#endif

#ifdef __cplusplus
}
#endif

#endif


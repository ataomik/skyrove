#ifndef INET_IO_H
#define INET_IO_H

#include "inet_sesn.h"

enum {
	INET_READ = 0,
	INET_WRITE,
	INET_IO_T_MAX,
};

typedef inet_buf* (*inet_io_op_alloc)(inet_sesn*, size_t size);
typedef void (*inet_io_op_free)(inet_sesn*, inet_buf*);
typedef int (*inet_io_op_commit)(inet_sesn*, inet_buf*);
typedef int (*inet_io_op_flush)(inet_sesn*);
typedef int (*inet_io_op_read)(inet_sesn*, void* data, size_t len);

typedef struct inet_io_ops_s {
	inet_io_op_alloc alloc;
	inet_io_op_free free;
	inet_io_op_commit commit;
	inet_io_op_flush flush;
	inet_io_op_read read;
	inet_io_op_read peek;
} inet_io_ops;

typedef struct inet_io_s {
	inet_list* que[INET_IO_T_MAX];
	inet_list lque[INET_IO_T_MAX];
	inet_buf* buf;
	inet_sesn* sesn;
	inet_io_ops *ops;
	unsigned int is_stream: 1;
	unsigned int unused: 31;
} inet_io;

#define inet_io_init(io, sesn) do { \
	int _si_i; \
	memset(io, 0, sizeof(*(io))); \
	(io)->conn = (sesn); \
	(io)->ops = &g_inet_io_ops; \
	if(inet_sesn_is_tcp(sesn)) \
		(io)->is_stream = 1; \
	for(_si_i = 0; _si_i < INET_IO_T_MAX; _si_i ++)	{ \
		inet_list_init((io)->lque+_si_i); \
		(io)->que[_si_i] = (io)->lque+_si_i; \
	} \
}while(0)

#define inet_io_set_ops(io, nops) ((io)->ops = (nops))
#define inet_io_set_que(io, type, uque) do { \
	(io)->que[type] = (uque); \
	if(!inet_list_empty(uque)) \
		(io)->buf = inet_buf_entry((uque)->prev); \
} while(0)

#define inet_io_set_wque(io, que) inet_io_set_que(io, INET_WRITE, que)
#define inet_io_set_rque(io, que) inet_io_set_que(io, INET_READ, que)

#define inet_io_wpos(io) inet_buf_wpos((io)->buf)
#define inet_io_wsize(io) inet_buf_wsize((io)->buf)
#define inet_io_winc(io, l) inet_buf_winc((io)->buf, l)
#define inet_io_wque(io) ((io)->que[INET_WRITE])

#define inet_io_rpos(io) inet_buf_rpos((io)->buf)
#define inet_io_rsize(io) inet_buf_rsize((io)->buf)
#define inet_io_rinc(io, l) inet_buf_rinc((io)->buf, l)
#define inet_io_rque(io) ((io)->que[INET_READ])

/* session IO */
#define INET_SESN_IO_OPS { \
	inet_sesn_io_alloc, inet_sesn_io_free, \
	inet_sesn_io_commit, inet_sesn_io_flush, \
	inet_sesn_io_read, inet_sesn_io_peek, }

inet_buf* inet_sesn_io_alloc(inet_sesn* sesn, size_t size);
void inet_sesn_io_free(inet_sesn*, inet_buf* buf);
int inet_sesn_io_peek(inet_sesn* sesn, void* data, size_t len);
int inet_sesn_io_read(inet_sesn* sesn, void* data, size_t len);
int inet_sesn_io_flush(inet_sesn* sesn);

#define inet_sesn_io_write inet_sesn_write
#define inet_sesn_io_commit inet_sesn_commit

extern inet_io_ops g_inet_io_ops;

#ifdef __cplusplus
extern "C" {
#endif

int inet_io_alloc(inet_io* io, size_t size);
void inet_io_fini(inet_io* io);

void inet_io_push(inet_io* io);
int inet_io_write(inet_io* io, const void* data, size_t len);
int inet_io_peek(inet_io* io, void* data, size_t len);
int inet_io_read(inet_io* io, void* data, size_t len);

int inet_io_commit(inet_io* io);
int inet_io_flush(inet_io* io);

int inet_io_printf(inet_io* io, const char *format, ...);

#ifdef __cplusplus
}
#endif

#endif


#include <stdarg.h>
#include <net/inet/inet_io.h>

inet_io_ops g_inet_io_ops = INET_SESN_IO_OPS;

inet_buf* inet_sesn_io_alloc(inet_sesn* sesn, size_t size)
{
	return inet_buf_alloc(sesn->net_id, size);
}

void inet_sesn_io_free(inet_sesn* sesn, inet_buf* buf)
{
	inet_buf_free(buf);
}

int inet_sesn_io_peek(inet_sesn* sesn, void* data, size_t len)
{
	return inet_sesn_peek(sesn, data, len);
}

int inet_sesn_io_read(inet_sesn* sesn, void* data, size_t len)
{
	return inet_sesn_read(sesn, data, len);
}

int inet_sesn_io_flush(inet_sesn* sesn)
{
	return inet_sesn_flush(sesn);
}

/* only for writing */
int inet_io_alloc(inet_io *io, size_t size)
{
	inet_buf* buf;

	buf = io->ops->alloc(io->sesn, size);
	if (!buf)
		return -1;
	inet_list_add_tail(&buf->list, inet_io_wque(io));
	io->buf = buf;
	return buf->size;
}

void inet_io_fini(inet_io *io)
{
	inet_list *pos, *n;
	inet_buf* buf;

	inet_list_for_each_safe(pos, n, inet_io_wque(io)) {
		inet_list_del(pos);
		buf = inet_buf_entry(pos);
		io->ops->free(io->sesn, buf);
	}

	io->buf = NULL;
}

int inet_io_commit(inet_io *io)
{
	int ret = 1;
	inet_list *pos, *n;
	inet_buf* buf;

	inet_list_for_each_safe(pos, n, inet_io_wque(io)) {
		inet_list_del(pos);
		buf = inet_buf_entry(pos);
		ret = io->ops->commit(io->sesn, buf);
		if (ret < 1) {
			inet_list_add(&buf->list, inet_io_wque(io));
			return ret;
		}
	}

	io->buf = NULL;

	return ret;
}

int inet_io_flush(inet_io *io)
{
	inet_io_commit(io);
	return io->ops->flush(io->sesn);
}

int inet_io_write(inet_io *io, const void* data, size_t len)
{
	int ret;
	size_t l = 0;

	if (io->is_stream) {
		l = min(inet_io_wsize(io), len);
		if (l) {
			memcpy(inet_io_wpos(io), data, l);
			inet_io_winc(io, l);
			len -= l;
			data += l;
			if (!len)
				return l;
		}
	}

	ret = inet_io_alloc(io, len);
	if (ret < 0)
		return ret;
	memcpy(inet_io_wpos(io), data, len);
	inet_io_winc(io, len);

	return l+len;
}

int inet_io_read(inet_io *io, void* data, size_t len)
{
	return io->ops->read(io->sesn, data, len);
}

int inet_io_peek(inet_io *io, void* data, size_t len)
{
	return io->ops->peek(io->sesn, data, len);
}

#define inet_io_next_data_size(io, sz) \
    ((io)->is_stream ? inet_buf_next_size(sz) : (sz))

int inet_io_vprintf(inet_io *io, const char* format, va_list list)
{
	int wt = 0;
	va_list args;

	if(!io->buf || !inet_io_wsize(io) || !io->is_stream) {
		wt = inet_io_alloc(io, INET_BUF_DFT_SIZE);
		if(wt < 0)
			return wt;
	}

	for(;;) {
		va_copy(args, list);
		wt = vsnprintf((char*)inet_io_wpos(io), inet_io_wsize(io),
			format, args);
		va_end(args);
		if (wt < 0)
			return wt;

		if(wt <= (int)inet_io_wsize(io)) {
			inet_io_winc(io, wt);
			return wt;
		}
		wt = inet_io_alloc(io, inet_io_next_data_size(wt));
		if(wt < 0)
			return wt;
	}

	return 0;
}

int inet_io_printf(inet_io *io, const char *format, ...)
{
	int ret;
	va_list args;

	va_start(args, format);
	ret = inet_io_vprintf(io, format, args);
	va_end(args);

	return ret;
}

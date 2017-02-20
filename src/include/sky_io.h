#ifndef EQ_IO_H
#define EQ_IO_H

#include "eq_obj.h"

#ifdef __cplusplus
extern "C" {
#endif

int eq_obj_read(struct eq_pool* pool, struct eq_obj** obj, u8* buffer,
	size_t len);
int eq_obj_write(struct eq_pool* pool, struct eq_obj* obj, u8* buffer,
	size_t len);

#ifdef __cplusplus
}
#endif

#endif

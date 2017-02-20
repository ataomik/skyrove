#ifndef EQ_CACHE_H
#define EQ_CACHE_H

#include "eq_obj.h"
#include "eq_sock.h"

enum {
	EQ_CACHE_DOMAIN_UDP = 0,
	EQ_CACHE_DOMAIN_TCP,
	EQ_CACHE_DOMAIN_UDP6,
	EQ_CACHE_DOMAIN_TCP6,
	EQ_CACHE_CB_MAX,
};

#define EQ_CACHE_DOMAIN_AGING_DFT 3
#define EQ_CACHE_TM_WAIT 16

enum {
	EQ_CACHE_T_DOMAIN = 0,
	EQ_CACHE_T_MAX,
};

struct eq_cache_info {
	u32 type:4;
	u32 unused:28;
	union {
		char* domain;
	};
};

#define EQ_CACHE_NB_MAX 16

struct eq_cache_table {
	struct eq_table* db;
	struct {
		pthread_t id;
		volatile u32 exists:1;
		u32 unused:31;
	} thread;
	struct eq_sock_cb cb[EQ_CACHE_CB_MAX];
	struct eq_sock_nb nb[EQ_CACHE_NB_MAX];
};

#define eq_cache_cb_index(table, p) \
	((p) >= (table)->cb && (p) < (table)->cb+EQ_CACHE_CB_MAX ? \
		(p)-(table)->cb+1 : 0)
#define eq_cache_cb_addr(table, i) \
	((i) > 0 && (i) <= EQ_CACHE_CB_MAX ? &(table)->cb[(i)-1] : NULL)

#define eq_cache_nb_set_cb(table, nb, cb) \
	((nb)->type = eq_cache_cb_index(table, cb))
#define eq_cache_nb_get_cb(table, nb) \
	eq_cache_cb_addr(table, (nb)->type)

#ifdef __cplusplus
extern "C" {
#endif

int eq_cache_open_cb(struct eq_cache_table*, struct eq_sock_cb*);
void eq_cache_error_cb(struct eq_cache_table*, struct eq_sock_cb*);
int eq_cache_read_cb(struct eq_cache_table*, struct eq_sock_cb*);
int eq_cache_write_cb(struct eq_cache_table*, struct eq_sock_cb*);
struct eq_sock_cb* eq_cache_get_cb(struct eq_cache_table*, u8 state);

int eq_cache_open_nb(struct eq_cache_table*, struct eq_sock_nb*);
void eq_cache_error_nb(struct eq_cache_table*, struct eq_sock_nb*);
int eq_cache_read_nb(struct eq_cache_table*, struct eq_sock_nb*);
int eq_cache_write_nb(struct eq_cache_table*, struct eq_sock_nb*);
struct eq_sock_nb* eq_cache_get_nb(struct eq_cache_table*, u8 state);

int eq_cache_add(struct eq_cache_table*, struct eq_cache_info*);
int eq_cache_del(struct eq_cache_table*, struct eq_cache_info*);

#ifdef __cplusplus
}
#endif

#endif


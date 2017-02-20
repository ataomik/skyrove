
struct eq_sesn_key {
	struct eq_obj_hdr h;
	struct eq_lvl_hdr l;
	u16 type;
	u16 flags;
	union {
		u16 proto;
		struct {
			const char* addr;
			char data[EQ_NAME_LEN];
			u32 len;
		} name;
		struct {
			u8 saddr[ETH_ALEN];
			u8 daddr[ETH_ALEN];
		} eth;
	} u;
};

#define eq_sesn_alloc() \
	((struct eq_sesn*)eq_malloc(sizeof(struct eq_sesn), EQ_SESN))

#define eq_sesn_free(p) do { \
	if(!(p)->pool) \
		eq_free(p, EQ_SESN); \
}while(0)

struct eq_sesn_table {
	struct eq_objhdr objh;
	struct eq_sesn_table* next;
	struct eq_sesn* buckets;
	u32 count;
	u32 size;
	u32 unused:16;
	u32 initval:16;
	struct eq_flow_db* flow_db;
	union {
		struct {
			int sif, dif;
			u8 saddr[ETH_ALEN];
			u8 daddr[ETH_ALEN];
		} info;
	} u;
};

#define eq_sesn_table_init(table) do { \
	mem_set(table, 0, sizeof(*(table))); \
	eq_objhdr_init(&(table)->objh, EQ_SESN_TBL); \
}while(0)

#define eq_sesn_bucket(table, hcode) \
	((table)->buckets[(hcode)%(table)->size])

#define eq_sesn_bucket_alloc(n) \
	(struct eq_sesn*)eq_malloc(sizeof(struct eq_sesn*)*(n), \
		EQ_SESN_BUCKET)

#define eq_sesn_bucket_free(p) eq_free(p, EQ_SESN_BUCKET)

#define eq_sesn_bucket_init(bucket, n) \
	mem_set(bucket, 0, sizeof(struct eq_sesn*)*(n))

#define eq_sesn_table_insert(table, hcode, sesn) do { \
	(sesn)->next = eq_sesn_bucket(table, hcode); \
	eq_sesn_bucket(table, hcode) = (sesn); \
	(table)->count ++; \
}while(0)

#define eq_sesn_table_erase(table, prev, sesn) do { \
	eq_sesn_unlink(pre, sesn); \
	(table)->count --; \
}while(0)

#define eq_sesn_table_alloc(n) \
	((struct eq_sesn_table* )eq_malloc( \
		sizeof(struct eq_sesn_table), EQ_SESN_TBL))

#define eq_sesn_table_free(p) eq_free(p, EQ_SESN_TBL)

#define eq_sesn_table_delete(table) do { \
	eq_sesn_table_clear(table); \
	eq_sesn_bucket_free((table)->buckets); \
	eq_sesn_table_free(table); \
}while(0)

#define eq_sesn_table_set_flow_db(table, db) do { \
	eq_obj_detach((table)->flow_db); \
	(table)->flow_db = (db); \
	eq_obj_attach((table)->flow_db); \
}while(0)

typedef int (*eq_sesn_proc)(eq_sesn_mgr_t*,
	struct eq_sesn_table*,
	struct eq_sesn*);

typedef u32 (*eq_sesn_hash)(struct eq_sesn_table*,
	eq_sesn_mgr_t*);

struct eq_sesn_mgr {
	struct eq_objhdr objh;
	eq_sesn_hash hash;
	eq_sesn_proc ctor, dtor, set, get, cmp, visit, send, rcv;
	u32 proto:16;
	u32 unused:16;
	union {
		void* data;
		struct eq_pkt* pkt;
	} u;
};

#define eq_sesn_mgr_init(mgr) do { \
	mem_set(mgr, 0, sizeof(*(mgr))); \
	eq_objhdr_init(&(mgr)->objh, EQ_SESN_MGR); \
	(mgr)->cmp = eq_sesn_cmp_ip; \
	(mgr)->hash = eq_sesn_hash_ip; \
	(mgr)->send = eq_sesn_send_ip; \
	(mgr)->rcv = eq_sesn_rcv_ip; \
}while(0)

struct eq_sesn_pool {
	u32 count;
	struct eq_sesn* sesns;
};

#define eq_sesn_pool_alloc(n) \
	(struct eq_sesn_pool*)eq_malloc( \
		sizeof(struct eq_sesn_pool)+sizeof(struct eq_sesn)*(n), \
		EQ_SESN_POOL)

static __inline void eq_sesn_pool_init(struct eq_sesn_pool* pool,
	u32 count)
{
	struct eq_sesn* sesn;

	pool->sesns = (struct eq_sesn*)(pool+1);
	pool->count = count;
	
	sesn = pool->sesns;
	mem_set(sesn, 0, sizeof(*sesn)*count);
	for(i = 0; i < count-1; i ++) {
		eq_sesn_init(sesn);
		sesn->pool = 1;
		sesn->next = sesn+1;
		sesn ++;
	}
}



unsigned eq_sesn_table_equals(const struct eq_objhdr* hdr,
	const struct eq_objkey* key);

u32 eq_sesn_table_hash(const struct eq_objkey* key);

struct eq_sesn* eq_sesn_table_alloc_bucket(
	struct eq_sesn_table* table,
	u32 size);
struct eq_sesn_table* eq_sesn_table_new(u32 size);
void eq_sesn_table_clear(struct eq_sesn_table* table,
	struct eq_sesn_mgr* mgr);
void eq_sesn_table_visit(struct eq_sesn_table* table,
	struct eq_sesn_mgr* mgr);
struct eq_sesn_table* eq_sesn_table_inc(
	struct eq_sesn_table* table,
	u32 size);

struct eq_sesn** eq_sesn_table_search(struct eq_sesn_table* table,
	struct eq_sesn_mgr* mgr);
struct eq_sesn* eq_sesn_table_find(struct eq_sesn_table* table,
	struct eq_sesn_mgr* mgr);
struct eq_sesn* eq_sesn_table_add(struct eq_sesn_table* table,
	struct eq_sesn_mgr* mgr);

u32 eq_sesn_hash_ip(struct eq_sesn_mgr* mgr,
	struct eq_sesn_table* table);

int eq_sesn_cmp_ip(struct eq_sesn_mgr* mgr,
	struct eq_sesn_table* table,
	struct eq_sesn* sesn);
	
int eq_sesn_send_ip(struct eq_sesn_mgr* mgr,
	struct eq_sesn_table* table,
	struct eq_sesn* sesn);

int eq_sesn_rcv_ip(struct eq_sesn_mgr* mgr,
	struct eq_sesn_table* table,
	struct eq_sesn* sesn);

void eq_sesn_build_ip(struct eq_sesn_table* table,
	struct eq_sesn* sesn,
	eq_pkt_hdr_t* hdr);

unsigned eq_sesn_mgr_equals(const struct eq_objhdr* hdr,
	const struct eq_objkey* key);

u32 eq_sesn_mgr_hash(const struct eq_objkey* key);


unsigned eq_sesn_table_equals(const struct eq_objhdr* hdr,
	const struct eq_objkey* key)
{
	struct eq_sesn_table* table;
	u8 *saddr = key->u.hw.saddr, *daddr = key->u.hw.daddr;
	
	table = eq_objhdr_entry(hdr, struct eq_sesn_table);
	
	return mem_cmp(table->u.info.saddr, saddr, ETH_ALEN) == 0 &&
		mem_cmp(table->u.info.daddr, daddr, ETH_ALEN) == 0;
}

u32 eq_sesn_table_hash(const struct eq_objkey* key)
{
	u8 *saddr = key->u.hw.saddr, *daddr = key->u.hw.daddr;
	
	return jhash_3words(*(u32*)saddr,
		*(u32*)daddr,
		(*(u16*)(saddr+4)<<16)|(*(u16*)(daddr+4)));
}

struct eq_sesn_table* eq_sesn_table_new(u32 size)
{
	u8 i;
	u32 sz = 0;
	struct eq_sesn_table* table = eq_sesn_table_alloc();

	if(table) {
		eq_sesn_table_init(table);
		if(!eq_sesn_table_alloc_bucket(size)) {
			eq_sesn_table_free(table);
			table = NULL;
		}
	}
	
	return table;
}

void eq_sesn_table_clear(struct eq_sesn_table* table,
	struct eq_sesn_mgr* mgr)
{
	u32 i;
	struct eq_sesn *cur, **sesn;
	
	while(table) {
		for(i = 0; i < table->size; i ++) {
			sesn = &table->buckets[i];
			while(*sesn) {
				if(mgr->cmp(mgr, table, *sesn) == 0) {
					cur = *sesn;
					*sesn = (*sesn)->next;
					if(mgr->dtor)
						mgr->dtor(mgr, table, *sesn);
					eq_sesn_delete(cur);
				}
				else
					sesn = &(*sesn)->next;
			}
		}
		table = table->next;
	}
}

int eq_sesn_table_visit(struct eq_sesn_table* table,
	struct eq_sesn_mgr* mgr)
{
	int ret = 0;
	u32 i;
	struct eq_sesn* sesn;
	
	while(table) {
		for(i = 0; i < table->size; i ++) {
			sesn = table->buckets[i];
			while(sesn) {
				if(mgr->cmp(mgr, table, sesn) == 0) {
					ret = mgr->visit(mgr, table, sesn);
					if(ret != 0)
						return  ret;
				}
				sesn = sesn->next;
			}
		}
		table = table->next;
	}
	
	return ret;
}

struct eq_sesn* eq_sesn_table_alloc_bucket(
	struct eq_sesn_table* table,
	u32 size)
{
	struct eq_sesn* buckets;

	buckets = eq_sesn_bucket_alloc(table->size+size);
	if(buckets) {
		eq_sesn_bucket_init(buckets, sz);
		table->initval = eq_random()%U16_MAX;
		table->size = size;
	}
}

struct eq_sesn_table* eq_sesn_table_inc(
	struct eq_sesn_table** table,
	u32 size)
{
	struct eq_sesn_table* st = eq_sesn_table_new(size);
	
	if(st) {
		st->next = *table;
		*table = st;
	}
	
	return st;
}

struct eq_sesn** eq_sesn_table_search(struct eq_sesn_table* table,
	struct eq_sesn_mgr* mgr)
{
	while(table) {
		u32 hcode;
		struct eq_sesn* sesn;
		
		hcode = mgr->hash(mgr, table);
		sesn = &eq_sesn_bucket(table, hcode);
		while(*sesn) {
			if(mgr->cmp(mgr, table, *sesn) == 0)
				return sesn;
			sesn = &(*sesn)->next;
		}
		table = table->next;
	}
	
	return NULL;
}

struct eq_sesn* eq_sesn_table_find(struct eq_sesn_table* table,
	struct eq_sesn_mgr* mgr)
{
	while(table) {
		u32 hcode;
		struct eq_sesn* sesn;
		
		hcode = mgr->hash(table, mgr);
		sesn = eq_sesn_bucket(table, hcode);
		while(sesn) {
			if(mgr->cmp(mgr, table, sesn) == 0)
				return sesn;
			sesn = sesn->next;
		}
		table = table->next;
	}
	
	return NULL;
}

struct eq_sesn* eq_sesn_table_add(struct eq_sesn_table* table,
	struct eq_sesn_mgr* mgr)
{
	u32 hcode;
	struct eq_sesn* sesn = eq_sesn_alloc();
	
	if(sesn) {
		eq_sesn_init(sesn);
		if(mgr->ctor)
			mgr->ctor(mgr, table, sesn);
		hcode = mgr->hash(mgr, table);
		eq_sesn_table_insert(table, hcode, sesn);
	}
	
	return sesn;
}

u32 eq_sesn_hash_ip(struct eq_sesn_mgr* mgr,
	struct eq_sesn_table* table)
{
	struct eq_pkt* pkt = mgr->u.pkt;
	eq_iphdr_t* iph = eq_pkt_iphdr(pkt);
	
	return eq_hcode(iph->sip, iph->dip, iph->sport,
		iph->dport, mgr->proto,
		table->initval);
}

int eq_sesn_cmp_ip(struct eq_sesn_mgr* mgr,
	struct eq_sesn_table* table,
	struct eq_sesn* sesn)
{
	struct eq_pkt* pkt = mgr->u.pkt;
	eq_iphdr_t* iph = eq_pkt_iphdr(pkt);
	
	if(sesn->proto == mgr->proto &&
		iph->sip == sesn->sip && iph->dip == sesn->dip &&
		iph->sport == sesn->sport && iph->dport == sesn->dport)
		return 0;
	
	return -1;
}

int eq_sesn_build_ip(struct eq_sesn_table* table,
	struct eq_sesn* sesn,
	struct eq_net_pkt* net_pkt,
	struct eq_pkt* pkt)
{
}

int eq_sesn_send_ip(struct eq_sesn_mgr* mgr,
	struct eq_sesn_table* table,
	struct eq_sesn* sesn)
{
	struct eq_flow* flow;
	struct eq_net_pkt pkt;
	
	flow = __eq_flow_db_get(table->flow_db, sesn->flow_id);
	if(!flow)
		return -1;
	
	eq_sesn_build_ip(table, sesn, &pkt, flow->pkts+sesn->pos);
	if(flow->mgr->send)
		return flow->mgr->send(table->info.dif, &pkt);
	else
		return eq_pkt_send(table->info.dif, &pkt);
}

int eq_sesn_rcv_ip(struct eq_sesn_mgr* mgr,
	struct eq_sesn_table* table,
	struct eq_sesn* sesn)
{
}

unsigned eq_sesn_mgr_equals(const struct eq_objhdr* hdr,
	const struct eq_obj_key* key)
{
	struct eq_sesn_mgr* mgr = eq_obj_entry(hdr, struct eq_sesn_mgr);
	return mgr->proto == key->u.proto;
}

u32 eq_sesn_mgr_hash(const struct eq_objkey* key)
{
	return key->u.proto;
}

int eq_sesn_table_sysctl(eq_objkey* key, eq_msg_t* msg)
{
	if(msg->op == TRP_MSG_OP_GET_ONE) {
	}
	else if(msg->op == TRP_MSG_OP_GET_ALL) {
	}
}

int eq_sesn_mgr_sysctl(eq_objkey* key, eq_msg_t* msg)
{
	if(msg->op == TRP_MSG_OP_GET_ONE) {
	}
	else if(msg->op == TRP_MSG_OP_GET_ALL) {
	}
}


#include <eq_obj.h>

struct eq_table s_eq_tbl;

int main()
{
	int zone[] = EQ_ZONE_DFT;
	eq_table_init(&s_eq_tbl, zone);
	
	
	return 0;
}


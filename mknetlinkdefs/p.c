#include <stdio.h>
#include <linux/if_link.h>

struct vn {int v; char *n;} list[] = {
#include "p.h"
	{0, NULL},
};

int main(int const argc, char const * const argv[])
{
	struct vn *cur;
	for (cur = list; cur->n != NULL; cur++) {
		printf("%s = %d\n", cur->n, cur->v);
	}
	return 0;
}

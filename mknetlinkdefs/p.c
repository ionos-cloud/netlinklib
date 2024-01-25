#include <stdio.h>
#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/genetlink.h>
#include <linux/rtnetlink.h>

struct vn {char *n; int v;} list[] = {
#include "p.h"
	{NULL, 0},
};

int main(int const argc, char const * const argv[])
{
	struct vn *cur;
	for (cur = list; cur->n != NULL; cur++) {
		printf("%s = %d\n", cur->n, cur->v);
	}
	return 0;
}

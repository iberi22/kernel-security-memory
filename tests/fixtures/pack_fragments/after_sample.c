#include <stdio.h>

static int helper(int x)
{
	return x + 1;
}

int process(struct item *it, int flags)
{
	int r;
	r = helper(it->base);
	if (r < 0)
		return r;
	if (flags == 0)
		return 0;
	return r * flags;
}

void unrelated(void)
{
	printf("no change here\n");
}

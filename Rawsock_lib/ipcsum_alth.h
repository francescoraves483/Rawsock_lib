#ifndef IPCSUM_ALTH_INCLUDED
#define IPCSUM_ALTH_INCLUDED

#include <linux/types.h>

// This is all taken from Linux kernel 4.19.1 (this is not original work)
__sum16 ip_fast_csum(const void *iph, unsigned int ihl);

#endif
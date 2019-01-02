#include "ipcsum_alth.h"

// This is all taken from Linux kernel 4.19.1 (this is not original work)
static inline unsigned short from64to16(unsigned long x)
{
	/* Using extract instructions is a bit more efficient
	   than the original shift/bitmask version.  */

	union {
		unsigned long	ul;
		unsigned int	ui[2];
		unsigned short	us[4];
	} in_v, tmp_v, out_v;

	in_v.ul = x;
	tmp_v.ul = (unsigned long) in_v.ui[0] + (unsigned long) in_v.ui[1];

	/* Since the bits of tmp_v.sh[3] are going to always be zero,
	   we don't have to bother to add that in.  */
	out_v.ul = (unsigned long) tmp_v.us[0] + (unsigned long) tmp_v.us[1]
			+ (unsigned long) tmp_v.us[2];

	/* Similarly, out_v.us[2] is always zero for the final add.  */
	return out_v.us[0] + out_v.us[1];
}

static inline unsigned long do_csum(const unsigned char * buff, int len) {
	int odd, count;
	unsigned long result = 0;

	if (len <= 0)
		goto out;
	odd = 1 & (unsigned long) buff;
	if (odd) {
		result = *buff << 8;
		len--;
		buff++;
	}
	count = len >> 1;		/* nr of 16-bit words.. */
	if (count) {
		if (2 & (unsigned long) buff) {
			result += *(unsigned short *) buff;
			count--;
			len -= 2;
			buff += 2;
		}
		count >>= 1;		/* nr of 32-bit words.. */
		if (count) {
			if (4 & (unsigned long) buff) {
				result += *(unsigned int *) buff;
				count--;
				len -= 4;
				buff += 4;
			}
			count >>= 1;	/* nr of 64-bit words.. */
			if (count) {
				unsigned long carry = 0;
				do {
					unsigned long w = *(unsigned long *) buff;
					count--;
					buff += 8;
					result += carry;
					result += w;
					carry = (w > result);
				} while (count);
				result += carry;
				result = (result & 0xffffffff) + (result >> 32);
			}
			if (len & 4) {
				result += *(unsigned int *) buff;
				buff += 4;
			}
		}
		if (len & 2) {
			result += *(unsigned short *) buff;
			buff += 2;
		}
	}
	if (len & 1)
		result += *buff;
	result = from64to16(result);
	if (odd)
		result = ((result >> 8) & 0xff) | ((result & 0xff) << 8);
out:
	return result;
}

__sum16 ip_fast_csum(const void *iph, unsigned int ihl)
{
	return (__sum16)~do_csum(iph,ihl*4);
}
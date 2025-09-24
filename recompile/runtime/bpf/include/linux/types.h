#ifndef _LINUX_TYPES_H
#define _LINUX_TYPES_H

/* Minimal freestanding shim for BPF builds on macOS.
 * Important: do NOT include <stdint.h> here, and do NOT typedef int64_t/uint64_t.
 * vmlinux.h will provide u8/u16/u32/u64 and (in your case) int*_t typedefs.
 */

#ifndef __u8
typedef unsigned char      __u8;
typedef   signed char      __s8;
typedef unsigned short     __u16;
typedef   signed short     __s16;
typedef unsigned int       __u32;
typedef   signed int       __s32;
typedef unsigned long long __u64;
typedef   signed long long __s64;
#endif

#ifndef __be16
typedef __u16 __be16;
typedef __u32 __be32;
typedef __u64 __be64;
typedef __u16 __le16;
typedef __u32 __le32;
typedef __u64 __le64;
#endif

#endif /* _LINUX_TYPES_H */
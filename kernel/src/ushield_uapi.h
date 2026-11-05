#ifndef USHIELD_UAPI_H
#define USHIELD_UAPI_H

#ifdef __KERNEL__
#include <linux/ioctl.h>
#else
#include <stdint.h>
#include <sys/ioctl.h>
#endif

/* Unique 8-bit magic number for µShield ioctl definition */
#define USHIELD_IOC_MAGIC 's'

/* Example control commands */
#define USHIELD_IOC_PING _IO(USHIELD_IOC_MAGIC, 1)
#define USHIELD_IOC_GET_VERSION _IOR(USHIELD_IOC_MAGIC, 2, uint32_t)

#endif // USHIELD_UAPI_H

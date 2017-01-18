#ifndef DEVICE_H
#define DEVICE_H

#include "pit.h"

#define DEV_UNKNOWN 0
#define DEV_EMMC 1
#define DEV_EUFS 2

struct device
{
	int fd;
	int partNo;
	struct pit_partinfo *partitions;
};

struct device_desc
{
	int dev_type;
	int sectorSize;
	int deviceNo;
	struct device* devices;
};

struct device_desc* openDevice();
void release_device_desc(struct device_desc* desc);
#endif

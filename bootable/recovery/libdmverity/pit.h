/*
 * Copyright (C) System Memory Lab, Samsung Electronics.
 * Sangeun Ha. <sangeun.ha@samsung.com>
 *
 * Pit access operation implemtations
 */

#ifndef PIT_H
#define PIT_H
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>

#define PIT_MAX_SIZE	(8192)
#define MMC_PIT_SECTOR	(34)
#define UFS_PIT_SECTOR	(6)
#define PIT_MAGIC	(0x12349876)

#define PIT_MAX_PART_NUM		(60)
#define PIT_BOOTPART1_ID_OLD_BASE	(50)
#define PIT_BOOTPART1_ID_BASE		(80)
#define PIT_BOOTPART2_ID_BASE		(90)

struct pit_header {
	unsigned int magic;
	int count;
	int dummy[5];
} __attribute__((packed));

struct pit_partinfo {
	int binary;		/* BINARY_TYPE_ */
	int device;		/* PARTITION_DEV_TYPE_ */
	int id;			/* partition id */
	int type;		/* PARTITION_PIT_TYPE_ */
	int filesys;		/* PARTITION_FS_TYPE_ */
	unsigned int blkstart;	/* start block */
	unsigned int blknum;	/* block number */
	unsigned int offset;	/* file offset (in TAR) */
	unsigned int filesize;	/* file size */
	char name[32];		/* partition name */
	char filename[32];	/* file name */
	char option[32];
} __attribute__((packed));

struct pit_board_partinfo {
	struct pit_header hd;
	struct pit_partinfo pi[PIT_MAX_PART_NUM];
} __attribute__((packed));

struct device_desc;

int pit_read(void *p,int fd, int addr);
int pit_update_partinfo(int fd, struct device_desc *);
struct device* find_part_device(struct device_desc*, const char *name);
struct pit_partinfo *pit_find_partinfo(const char *name);
void pit_copy_partinfo(struct pit_board_partinfo *dst);
const char *get_ap_name();
#endif

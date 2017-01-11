/*
 * Copyright (C) System Memory Lab, Samsung Electronics.
 * Sangeun Ha. <sangeun.ha@samsung.com>
 *
 * Pit access operation implemtations
 */


#include "pit.h"
#include <string.h>
#include <unistd.h>
#include "device.h"

static struct pit_board_partinfo board_partinfo;

static int pit_check_integrity(void *p) 
{
    struct pit_header *phd;
    phd = (struct pit_header *)p;

    if (phd->magic != PIT_MAGIC) {
        printf("%s: invalid pit.(0x%x)\n", __func__, phd->magic);
        return -1; 
    }   

    return 0;
}

int pit_read(void *p, int fd, int addr)
{
	int retry = 10;

	while( retry-- )
	{
		lseek(fd,0,SEEK_SET);
		lseek(fd,addr,SEEK_CUR);
		read(fd,p,PIT_MAX_SIZE);

		if(pit_check_integrity(p) == 0)
			return 0;

		// Wait for cooling. 2 seconds
		sleep(2);
	}

	return -1;
}

static unsigned char _pit_load_buf[PIT_MAX_SIZE];
int pit_update_partinfo(int fd, struct device_desc *desc)
{
	struct pit_board_partinfo *pbp = &board_partinfo;
	unsigned char *pit = (unsigned char *)&_pit_load_buf, *ppit = pit;
	int i,addr = 0;

	memset(pbp, 0, sizeof(board_partinfo));
	memset(pit, 0, PIT_MAX_SIZE);

	if( desc->dev_type ==  DEV_EMMC )
		addr = desc->sectorSize * MMC_PIT_SECTOR;
	else if( desc->dev_type == DEV_EUFS )
		addr = desc->sectorSize * UFS_PIT_SECTOR;

	if (pit_read(pit,fd, addr) < 0) {
		return -1;
	}

	/* copy pit header. */
	memcpy(&pbp->hd, ppit, sizeof(struct pit_header));
	ppit += sizeof(struct pit_header);

	/* copy pit partition info. */
	for (i = 0; i < pbp->hd.count; i++) {
		memcpy(&pbp->pi[i], ppit, sizeof(struct pit_partinfo));
		ppit += sizeof(struct pit_partinfo);
	}

	return 0;
}

struct device* find_part_device(struct device_desc *desc, const char *name)
{
	int i;
	
	for (i = 0 ; i < desc->deviceNo ; i++)
	{
		int j;
		for(j = 0 ; j < desc->devices[i].partNo ; j++)
			if( !strcmp(desc->devices[i].partitions[j].name, name) )
				return desc->devices+i;
	}

	return NULL;
}

struct pit_partinfo *pit_find_partinfo(const char *name)
{
	struct pit_board_partinfo *pbp = &board_partinfo;
	int i;

	for (i = 0; i < pbp->hd.count; i++) {
		if (!strcmp(pbp->pi[i].name, name)) {
			return &pbp->pi[i];
		}
	}

	return NULL;
}

void pit_copy_partinfo(struct pit_board_partinfo *dst)
{
	memcpy(dst,&board_partinfo,sizeof(board_partinfo));
}

const char *get_ap_name()
{
    struct pit_board_partinfo *p = &board_partinfo;

    if (pit_check_integrity(p) < 0) {
        return 0;
    }   

    return (const char*)&(p->hd.dummy[2]);
}


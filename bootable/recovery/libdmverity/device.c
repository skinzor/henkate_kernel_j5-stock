#include "device.h"
#include <string.h>
#include <errno.h>

static void makeDeviceStruct(struct device_desc *desc,int fd)
{
	struct pit_board_partinfo pit;

	pit_copy_partinfo(&pit);

	if( desc->dev_type == DEV_EMMC )
	{
		desc->devices = (struct device*)malloc(sizeof(struct device));
		desc->devices->partitions = (struct pit_partinfo*)malloc(sizeof(struct pit_partinfo) * pit.hd.count);

		desc->deviceNo = 1;
		desc->devices->fd = fd;
		desc->devices->partNo = pit.hd.count;

		memcpy(desc->devices->partitions, pit.pi, sizeof(struct pit_partinfo) * pit.hd.count);
	}
	else if( desc->dev_type == DEV_EUFS )
	{
		// offset field is LUN number

		int i,bef = pit.pi[0].offset;
		int fds[8],cnt;
		struct device *devices;
		desc->deviceNo = 1;
		for(i = 0 ; i < pit.hd.count ; i++)
		{
			if( bef != pit.pi[i].offset )
				desc->deviceNo++;
			bef = pit.pi[i].offset;
		}

		for(i = 0; i < desc->deviceNo ; i++)
		{
			char fname[128];
			int retry=10;
			sprintf(fname,"/dev/block/sd%c",'a'+i);
			fds[i] = open(fname, O_RDWR);
			while( fds[i] <= 0 && (retry-- == 0))
			{
				printf("can not open %s\n",fname);
				usleep(100);
				fds[i] = open(fname, O_RDWR);
			}

			if( fds[i] <= 0 ) {
				printf("can not open %s\n",fname);
				break;
			}
		}

		desc->devices = (struct device*)malloc(sizeof(struct device) * desc->deviceNo);
		devices = desc->devices;

		bef = 0;
		for(i = 1 ; i < pit.hd.count ; i++)
		{
			if( pit.pi[i].offset != pit.pi[bef].offset )
			{
				cnt = i - bef;
				devices->fd = fds[ pit.pi[bef].offset ];
				devices->partNo = cnt;
				devices->partitions = (struct pit_partinfo*)malloc(sizeof(struct pit_partinfo)*cnt);
				memcpy(devices->partitions, &pit.pi[bef], sizeof(struct pit_partinfo)*cnt);
				bef = i;
				devices++;
			}
		}

		cnt = pit.hd.count - bef;
		devices->fd = fds[ pit.pi[bef].offset ];
		devices->partNo = cnt;
		devices->partitions = (struct pit_partinfo*)malloc(sizeof(struct pit_partinfo)*cnt);
		memcpy(devices->partitions, &pit.pi[bef], sizeof(struct pit_partinfo)*cnt);
#ifdef DEBUG
		printf("Device No = %d\n", desc->deviceNo);
		for(i = 0; i < desc->deviceNo ; i++)
		{
			int k;
			for(k = 0 ; k < 8 ; k++)
				if(fds[k] == desc->devices[i].fd)
					break;
			printf("fd = %d\n", desc->devices[i].fd);
			printf("LUN %d, partNo = %d\n",k, desc->devices[i].partNo);

			for(k = 0 ; k < desc->devices[i].partNo ; k++)
				printf("\t%s\n", desc->devices[i].partitions[k].name);
			printf("\n");
		}
#endif
	}
}

struct device_desc* openDevice()
{
	int fd = 0;
	struct device_desc *ret = (struct device_desc*)malloc(sizeof(struct device_desc));

	while(1)
	{
		int mmcFd, mmcErrno;
		int ufsFd, ufsErrno;

		mmcFd = open("/dev/block/mmcblk0", O_RDWR);
		mmcErrno = errno;

		ufsFd = open("/dev/block/sda", O_RDWR);
		ufsErrno = errno;

		if( mmcFd > 0 && ufsFd <= 0)
		{
			printf("PIT read in mmcFd\n");
			ret->dev_type = DEV_EMMC;
			ret->sectorSize = 512;

			if( pit_update_partinfo(mmcFd, ret) )
			{
				printf("PIT read fail\n");
				close(fd);
				break;
			}

			makeDeviceStruct(ret, mmcFd);

			break;
		}
		else if( mmcErrno != 2 )
		{
			printf("MMC Block device open error. errno = %d\n",mmcErrno);
		}

		if( ufsFd > 0 )
		{
			printf("PIT read in ufsFd\n");
			ret->dev_type = DEV_EUFS;
			ret->sectorSize = 4096;

			if( pit_update_partinfo(ufsFd,ret) )
			{
				printf("PIT read fail\n");
				close(fd);

				break;
			}

			close(ufsFd);
			makeDeviceStruct(ret, 0);

			break;
		}
		else if( ufsErrno != 2 )
		{
			printf("UFS Block device open error. errno = %d\n",mmcErrno);
		}


		printf("Retry open block device\n");
		usleep(100);
	}

	return ret;
}

void release_device_desc(struct device_desc* desc)
{
	if( desc && desc->devices )
	{
		int i;
		for(i = 0; i < desc->deviceNo ; i++) {
			if( desc->devices[i].partitions )
				free(desc->devices[i].partitions);
			if ( desc->devices[i].fd )
				close(desc->devices[i].fd);
		}
		free(desc->devices);
	}

	if( desc )
		free(desc);
}

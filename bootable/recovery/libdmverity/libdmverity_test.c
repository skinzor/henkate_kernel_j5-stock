#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <fs_mgr.h>
#include "roots.h"
#include <stdio.h>
#include <string.h>
#include "libdmverity.h"

extern int fs_mgr_setup_verity(struct fstab_rec *fstab, int target);
extern int fs_mgr_teardown_verity(struct fstab_rec *fstab, char root_hash[], unsigned int *root_hash_size, int target);

void ui_print(const char *fmt, ...) {
}

int unload_verity()
{
	const int digest_size = 20;//SHA1
	char root_hash[digest_size];
	Volume* v = volume_for_path("/system");
	if (v == NULL) {
		printf("Error getting volume for path\n");
		return -1;
	} else {
		printf("Success getting volume for path\n");
	}

	printf("mount point-> %s, blk_device-> %s\n", v->mount_point, v->blk_device);

	if (ensure_path_unmounted("/system")) {
		printf("Error umounting /system.\n");
		return -1;
	} else {
		printf("Success umounting /system\n");
	}

	if(fs_mgr_teardown_verity(v, root_hash, digest_size, VERITY) != 0) {
		printf("Error freeing verity\n");
		return -1;
	} else {
		printf("Success freeing verity\n");
	}
	return 0;
}

int unload_dirty()
{
	Volume* v = volume_for_path("/system");
	if (v == NULL) {
		printf("Error getting volume for path\n");
		return -1;
	}

	printf("mount point-> %s, blk_device-> %s\n", v->mount_point, v->blk_device);

	dm_verity_update_end();
	
	return 0;

}

int load_verity()
{
	Volume* v = volume_for_path("/system");
	if (v == NULL) {
		printf("Error getting volume for path\n");
		return -1;
	}

	printf("mount point-> %s, blk_device-> %s\n", v->mount_point, v->blk_device);
	if(fs_mgr_setup_verity(v, VERITY) != 0) {
		printf("Error setting up verity\n");
		return -1;
	} else {
		printf("Success in setting up verity\n");
	}

	if (ensure_path_mounted("/system")) {
		printf("Error mounting /system.\n");
		return -1;
	}
	else 
		printf("Success in mounting /system.\n");

	printf("dm-verity is ready.\n");
	return 0;

}

int main(int argc, char *argv[])
{
	load_volume_table();

	if (argc != 2) {
		goto unknown_cmd;
	}

	use_dm_verity=1;

	if(!strcmp(argv[1], "dirty")) {
		return ensure_path_mounted_with_option("/system", "rw");
	} else if(!strcmp(argv[1], "unload_dirty")) {
		return unload_dirty();
	} else if(!strcmp(argv[1], "verity")) {
		return load_verity();
	} else if(!strcmp(argv[1], "unload_verity")) {
		return unload_verity();
	}

unknown_cmd:
	printf("Wrong format or option! Please follow one of the below:\n");
	printf("  mount_test dirty\n");
	printf("  mount_test unload_dirty\n");
	printf("  mount_test verity\n");
	printf("  mount_test unload_verity\n\n");
	return -1;
}

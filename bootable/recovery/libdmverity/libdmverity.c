//dm-verity function
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <sys/ioctl.h>
#include <sys/klog.h>
#include <linux/loop.h>
#include "system.h"
#include "libdmverity.h"
#include "secure_marker.h"
#include "roots.h"
#include "ext4.h"
#include "ext4_utils.h"
#include "mincrypt/sha.h"
//#include "libdmverity_hashgen/libdmverity_hashgen.h"
#include "__common.h"

#include "pit.h"
#include "parameter.h"
#include "device.h"
#include <sys/system_properties.h>

static prm_env_file m_param_env;
#define EMMC_SECTOR_SIZE        512
static PARAM m_param;
static char buff[EMMC_SECTOR_SIZE];
enum PARAM_TYPE currentParam = PARAM_UNKNOWN;

/////////////global starts//////////////

// chipset specific

#ifdef QSEE_TZ
#if defined(APQ_8084)
static const char * SYSTEM_DEV = "/dev/block/platform/msm_sdcc.1/by-name/system";
static const char * TZAPP_PARTITION = "/dev/block/platform/msm_sdcc.1/by-name/apnhlos";
#else
static const char * SYSTEM_DEV = "/dev/block/bootdevice/by-name/system";
static const char * TZAPP_PARTITION = "/dev/block/bootdevice/by-name/apnhlos";
#endif
static const char * TZAPP_MOUNT_POINT = "/firmware";
static const char * BACKUP_TZAPP_IMAGE = "/cache/recovery/tzapp";
static const char * TZ_STATIC_DAEMON = "/sbin/qseecomfsd";
static const char * SVC_STATIC_STATUS = "init.svc.static_qsee";
#elif EXYNOS_TZ
static const char * SVC_STATIC_STATUS = "init.svc.static_mc";
#if defined(EXYNOS_7420)
static const char * SYSTEM_DEV = "/dev/block/platform/15570000.ufs/by-name/SYSTEM";
static const char * TZAPP_PARTITION = "/dev/block/platform/15570000.ufs/by-name/EFS";
#elif defined(EXYNOS_8890)
static const char * SYSTEM_DEV = "/dev/block/platform/155a0000.ufs/by-name/SYSTEM";
static const char * TZAPP_PARTITION = "/dev/block/platform/155a0000.ufs/by-name/EFS";
#elif TRE_PROJECT
static const char * SYSTEM_DEV = "/dev/block/mmcblk0p18";
static const char * TZAPP_PARTITION = "/dev/block/mmcblk0p3";
#elif defined(EXYNOS_7580) || defined(EXYNOS_3475) || defined(EXYNOS_7870)
static const char * SYSTEM_DEV = "/dev/block/platform/13540000.dwmmc0/by-name/SYSTEM";
static const char * TZAPP_PARTITION = "/dev/block/platform/13540000.dwmmc0/by-name/EFS";
#else /*EXYNOS_5433 & EXYNOS_5430 */
static const char * SYSTEM_DEV = "/dev/block/platform/15540000.dwmmc0/by-name/SYSTEM";
static const char * TZAPP_PARTITION = "/dev/block/platform/15540000.dwmmc0/by-name/EFS";
#endif
static const char * TZ_STATIC_DAEMON = "/sbin/mcDriverDaemon_static";
#endif

static const char * D_TZ_LOG = "/d/tzdbg/log";
static const char * D_QSEE_LOG = "/d/tzdbg/qsee_log";
static const char * TEMP_RECOVERY_LOG = "/tmp/recovery.log";	


// common 
static const char * CACHE_MNT = "/cache";
static const char * SYSTEM_MNT = "/system";
static const char * EFS_MNT = "/efs";
static const char * TEMP_FILE = "/tmp/dmverity";
static const char * TMP_HASH_TABLE = "/tmp/dmverity_table";
static const char * TZAPP_LOOP_DEV = "/dev/loop0";
static const char * tz_cmd_binary = "/sbin/dm_verity_tz_cmd";
static const char * hash_gen_binary = "/sbin/dm_verity_hash";


static int tz_setup_status = 0;

/////////////global ends//////////////
void do_dmesg();
static void append_qsee_log();

/////////////utility starts//////////////
static int umount_system(){
    int i = 0;
    while(ensure_path_unmounted(SYSTEM_MNT)){
		usleep(10*1000);
        i++;
        if(i>10){
            printf("failed to umount %s after %d retries\n", SYSTEM_MNT, i);
            return -1;	    
        }
    }
    return 0;
}

static int file_to_device(const char * file, const char * dev, int buffer_size,
                          loff_t offset) {
    int ret = -1;
    char * buffer = malloc(buffer_size);
    int write_size;
    if (NULL == buffer) {
        printf("malloc failed\n");
        return -1;
    }
    int rfd = open(file, O_RDONLY);
    if (rfd < 0){
        printf("failed to open %s\n", file);
        goto free_buffer;
    }
    int wfd = open(dev, O_WRONLY);
    if (wfd < 0){
        printf("failed to open %s\n", dev);
        goto close_rfd;
    }
    if (offset != lseek64(wfd, offset, SEEK_SET)){
        printf("failed to seek %s\n", dev);
        goto close_wfd;
    }
    struct stat st;
    if (0 != fstat(rfd, &st)){
        printf("failed to stat %s\n", file);
        goto close_wfd;
    }
    unsigned long size = st.st_size;
    ssize_t w_size;
    while (size > 0) {
        write_size = size;
        if (write_size > buffer_size) {
            write_size = buffer_size;
        }
        if (write_size != read(rfd, buffer, write_size)){
            printf("failed to read %s\n", file);
            goto close_wfd;
        }
        w_size = write(wfd, buffer, write_size);
        if (write_size != w_size){
            printf("failed to write %s: %d, %d, %s\n", dev, (int)w_size, write_size, strerror(errno));
            goto close_wfd;
        }
        size -= write_size;
    }
    ret = 0;
    fsync(wfd);
 close_wfd:
    close(wfd);
 close_rfd:
    close(rfd);
 free_buffer:
    free(buffer);
    return ret;
}

static int _execute(const char * path, const char * args[]){
    int pid = fork();
    if (pid == 0) {
        execv(path, (char *const *)args);
        printf("can't run '%s' %s\n", args[0], strerror(errno));
        _exit(1);
    }
    int status = 0xAAAA;
    if (waitpid(pid, &status, 0) != -1) {
        if (WIFEXITED(status)) {
            if (WEXITSTATUS(status) != 0) printf("\n%s terminated by exit(%d)\n", args[0],WEXITSTATUS(status));
            errno = WEXITSTATUS(status) ;
            //printf("something is wrong %s\n", strerror(errno));
            return WEXITSTATUS(status);
        } else if (WIFSIGNALED(status)) {
            printf("%s terminated by signal %d\n",args[0],WTERMSIG(status));
            return -1;
        } else if (WIFSTOPPED(status)) {
            printf("%s stopped by signal %d\n", args[0],WSTOPSIG(status));
            return -1;
        }
        
    } else {
        printf("%s wait() failed", args[0]);    
        return -1;
    }
    return -1;
}


/////////////utility ends//////////////

// launch tz daemon
static int start_tz_daemon(int * ppid) {
    const char * path = TZ_STATIC_DAEMON;
#ifdef QSEE_TZ
    const char * args[1];
    args[0] = TZ_STATIC_DAEMON;
#elif EXYNOS_TZ
    const char * args[3];
    args[0] = TZ_STATIC_DAEMON;
    args[1] = "-r";
    args[2] = "/mcRegistry/ffffffffd0000000000000000000000a.tlbin";
#endif

    int pid = fork();
    if (pid == 0) {
        setpgid(0, 0);//otherwise we cannot kill this process group from parent.

        execv(path, (char * const *)args);
        printf("can't run '%s'\n", args[0]);
        _exit(1);
    }
    *ppid = pid;
    printf("TZ Daemon's pid is %d\n", pid);
    //don't wait
    return 0;
}

static int kill_service(int pid, int sig){
    int ret;
    printf("killing group %d\n", pid);
    //kill(-1*pid, SIGKILL);
    ret = kill(pid, sig);
    if(ret){
        printf("failed to kill %d, %s\n", pid, strerror(errno));
    }
    return ret;
}


static int execute_remove_marker(void){
    int ret;
    const char * args[3];
    args[0] = tz_cmd_binary;
    args[1] = "remove_marker";
    args[2] = 0;
    //if(setenv("LD_LIBRARY_PATH", "/system/lib", 1))
    //    printf("Error: set env failed\n");
    printf("remove marker...\n");
#ifdef EXYNOS_TZ
    struct stat st;
    if(stat("/efs/prov_data/dmvt/MARKER_FILE", &st))
            printf("marker is not there.\n");
    usleep(100*1000);
#endif
    ret = _execute(tz_cmd_binary, args);
    if(ret){
        printf("execute_remove_marker failed: %d.\n", ret);
        append_qsee_log();
    }  
    return ret;
}

static int execute_set_marker(const char * hex_salt_string){
    int ret;
    const char * args[4];
    args[0] = tz_cmd_binary;
    args[1] = "set_marker";
    args[2] = hex_salt_string;
    args[3] = 0;
    usleep(100*1000);
    ret = _execute(tz_cmd_binary, args);
    if(ret){
     	printf("execute_set_marker failed: %d.\n", ret);
        append_qsee_log();
    }
    return ret;
}

static int execute_check_marker(const char * hex_salt_string){
    int ret;
    const char * args[4];
    args[0] = tz_cmd_binary;
    args[1] = "check_marker";
    args[2] = hex_salt_string;
    args[3] = 0;
    usleep(100*1000);
    ret = _execute(tz_cmd_binary, args);
    if(ret){
     	printf("execute_check_marker failed: %d.\n", ret);        
        append_qsee_log();
    }
    return ret;
}

static int execute_sign_blob(const char * blob_file){
    int ret;
    const char * args[4];
    args[0] = tz_cmd_binary;
    args[1] = "sign_blob";
    args[2] = blob_file;
    args[3] = 0;
    usleep(100*1000);
    ret = _execute(tz_cmd_binary, args);
    if(ret){
     	printf("execute_sign_blob failed: %d.\n", ret);
        append_qsee_log();     	
    }
    return ret;
}

static int execute_hashgen_rehash(){
    int ret;
    const char * args[3];
    args[0] = hash_gen_binary;
    args[1] = "rehash";
    args[2] = 0;
    ret = _execute(hash_gen_binary, args);
    if(ret){
        printf("execute_hashgen_rehash failed\n");
    }
    return ret;
}

static int execute_hashgen_verify(){
    int ret;
    const char * args[3];
    args[0] = hash_gen_binary;
    args[1] = "verify";
    args[2] = 0;
    ret = _execute(hash_gen_binary, args);
    if(ret){
        printf("execute_hashgen_rehash failed\n");
    }
    return ret;
}

static int verify_verity_data(uint8_t *data, int data_len, uint8_t *blob, int blob_len)
{
    static const char * VERIFIER_BINARY = "/sbin/dm_verity_signature_checker";
    int	pipefd[2], ret, child_ret;
    pid_t	proc;
    const char * argv_1[] = {VERIFIER_BINARY, NULL};
    ret = pipe(pipefd);
    if (ret != 0) {
        return -1;
    }

    proc = fork();
    if (proc == -1) {
        /* Fork failed */
        close(pipefd[0]);
        close(pipefd[1]);
        printf("Failed to fork.\n");
        ret = -1;
        goto exit_path;
    } else if (proc == 0) {
        /* Child process */
        dup2(pipefd[0], 0);
        close(pipefd[0]);
        close(pipefd[1]);
        /* Now exec. stdin and stdout are set to the unnamed pipe */
        execve(VERIFIER_BINARY, (char * const *)argv_1, NULL);
        /* If we reach the following code, execve has failed */
        printf("Failed to exec.\n");
        _exit(1);
    } else {
        /* Parent process. proc has the pid */
        close(pipefd[0]);

        /* Write all verification data to the pipe */
        if (write(pipefd[1], &data_len, sizeof(int)) != sizeof(int))  {
            printf("Error writing to pipe 1\n");
            ret = -1;
            goto exit_path;
        }

        if(write(pipefd[1], data, data_len) != data_len) {
            printf("Error writing to pipe 2\n");
            ret = -1;
            goto exit_path;
        }

        if(write(pipefd[1], &blob_len, sizeof(uint32_t)) != sizeof(uint32_t)) {
            printf("Error writing to pipe 3\n");
            ret = -1;
            goto exit_path;
        }

        if(write(pipefd[1], blob, blob_len) != blob_len) {
            printf("Error writing to pipe 4\n");
            ret = -1;
            goto exit_path;
        }

        proc = waitpid(proc, &child_ret, 0);
        if (proc == -1) {
            printf("Waitpid failed\n");
            ret = -1;
            goto exit_path;
        } else {
            printf("Child exited with ret val: %d\n", WEXITSTATUS(child_ret));
            if (child_ret == 0)
                ret = 0;
            else {
                ret = 1;
                printf("Blob verification failed\n");
            }
            goto exit_path;
        }
    }

 exit_path:
    close(pipefd[0]);
    close(pipefd[1]);
    return ret;
}

static int read_and_verify(const char *dev_path, char *table, unsigned int table_size)
{
    uint64_t	devsize;
    int r, fd;
    int blob_size;
    char *blob = NULL;
    r = -1;
    printf("Table length: %d\n", table_size);

    r = device_size(dev_path, &devsize);
    printf("device size is: %lld.\n", devsize);
    if (0 != r){
        printf("failed to get device size\n");
        return -1;
    }

    fd = open(dev_path, O_RDONLY);
    if (fd < 0){
        printf("Failed to open device\n");
        return -1;
    }

    r = lseek64(fd, devsize - sizeof(int), SEEK_SET);
    if (((off64_t)devsize - sizeof(int)) != lseek64(fd, devsize - sizeof(int), SEEK_SET)){
        printf("Failed to seek\n");
        r = -1;
        goto exit;
    }
    r = read(fd, &blob_size,  sizeof(int));
    if (sizeof(unsigned int) != r){
        printf("Failed to read\n");
        r = -1;
        goto exit;
    }

    if (blob_size > 4096){
        printf("blob size is suspicious\n");
        r = -1;
        goto exit;
    }

    if (((off64_t)devsize - sizeof(int) - blob_size) != lseek64(fd, devsize - sizeof(int) - blob_size, SEEK_SET)){
        printf("Failed to seek again\n");
        r = -1;
        goto exit;
    }

    blob = malloc(blob_size);
    if (NULL == blob){
        printf("Failed to allocate mem for blob\n");
        r = -1;
        goto exit;
    }

    r = read(fd, blob, blob_size);
    if (blob_size != r){
        printf("Failed to read blob\n");
        r = -1;
        goto exit;
    }

    /* we skip signature verification IF this is not a release build */
#ifndef PRODUCT_SHIP  // not release build
    r = 0;
    goto exit;
#endif

    printf("Verify signature ...\n");
    r = verify_verity_data((uint8_t *)table, table_size, (uint8_t *)blob, blob_size);
    if (r == 0) {
        printf("signature vefication is successful.\n");
    } else {
        printf("The result of verifying signature is %d.\n", r);
    }
 exit:
    if(blob)
        free(blob);
    close(fd);
    return r;
}

#if 0
static void rehash_if_needed(char *table)
{
    char * alg_str = strtok(table, " ");
    alg_str = strtok(NULL, " ");
    alg_str = strtok(NULL, " ");
    alg_str = strtok(NULL, " ");
    alg_str = strtok(NULL, " ");
    alg_str = strtok(NULL, " ");
    alg_str = strtok(NULL, " ");
    alg_str = strtok(NULL, " ");

    printf("Alg from table: %s, alg used: %s\n", alg_str, "md5");
    if(strcmp(alg_str, "md5")) {
        if (dm_verity_rehash() < 0)
            printf("Rehash failed for alg adjustment\n");
        else
            printf("rehash succeeded for alg adjustment\n");
    }

}
#endif

static int verify_verity(const int meta_version, const int dm_verity_version,
                         const char * data_device, const size_t block_size) {
    uint64_t ext4_size;
    printf("verify_verity\n");
    fflush(stdout);
    if (ext4_part_size(data_device, &ext4_size) < 0) {
        printf("error getting invalid ext4 size(%s)\n", data_device);
        return -1;
    } else {
        printf("ext4 size: %lld\n", (long long int) ext4_size);
    }
    int r = -1;
    uint64_t data_blocks = ext4_size / block_size;
    uint64_t meta_start = (data_blocks * block_size + block_size - 1)
        / block_size;
    loff_t meta_off = meta_start * block_size;
    int fd = open(data_device, O_RDONLY);
    if (fd < 0){
        printf("error opening device\n");
        return -1;
    }
    if (lseek64(fd, meta_off, SEEK_SET) < 0) {
        printf("Error seeking to meta data\n");
        goto exit_open;
    }
    struct verity_meta_header header;
    if (sizeof(struct verity_meta_header)
        != read(fd, &header, sizeof(struct verity_meta_header))) {
        printf("Error reading meta data\n");
        goto exit_open;
    }
    if (header.protocol_version != meta_version) {
        printf("version mismatch\n");
        goto exit_open;
    }
    if (header.magic_number != VERITY_METADATA_MAGIC_NUMBER) {
        printf("wrong magic number\n");
        goto exit_open;
    }
    if (header.table_length <= 0) {
        printf("invalid table length\n");
        goto exit_open;
    }
    char * table = malloc(header.table_length+1);
    if(NULL == table){
        printf("failed to malloc for table\n");
            goto exit_open;
    }
    table[header.table_length] = 0;
    if ((ssize_t)(header.table_length) != read(fd, table, header.table_length)) {
        printf("invalid table length\n");
        goto exit_malloc;
    }
    printf("table in verify_verity is: %s.\n", table);
    close(fd);
    fd = -1;
    if(read_and_verify(data_device, table, header.table_length+1)){
        milestone("Blob verification failed\n");
        r = 2;
        goto exit_malloc;
    }
    milestone("Blob verification succeeded\n");

    printf("call dm_verity_hash to verify verity.\n");
    if (execute_hashgen_verify()) {
        printf("verity verification failed.\n");
        goto exit_malloc;
    }
    r = 0;

exit_malloc: if (table)
        free(table);
exit_open: if (fd >= 0)
        close(fd);
    return r;
}

static int check_verity(const char * dev){
    return verify_verity(0, 1, dev, DMVERITY_BLOCK_SIZE);
}


#ifdef QSEE_TZ
// this is only needed by QSEE TZ implementaion
static int backup_firmware_partition(const char * partition, const char * backup_file)
{
    int ret, fd, write_fd;
    char *buf;
    struct stat st;
    if(0 ==stat(backup_file, &st)){
        printf("%s already exists\n", backup_file);
        return 0;
    }
#define	TRANSFER_SIZE	(1024*1024) /* 1 MB */
    fd = open(partition, O_RDONLY);
    if (fd < 0) {
        printf("Failed to open firmware partition\n");
        ret = -1;
        goto final_exit;
    }

    write_fd = open(backup_file, O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
    if (write_fd < 0) {
        printf("Failed to open cache file to writing\n");
        ret = -1;
        goto free_read_fd;
    }

    buf = (char *)malloc(TRANSFER_SIZE);
    if (NULL == buf) {
        printf("Failed to allocate buffer for file transfer\n");
        ret = -1;
        goto free_write_fd;
    }

    while((ret = read(fd, buf, TRANSFER_SIZE)) > 0) {
        if (ret < 0) {
            printf("Error reading from device file\n");
            ret = -1;
            goto free_buffer;
        }
        if (write(write_fd, buf, ret) != ret) {
            printf("Failed to write all bytes\n");
            ret = -1;
            goto free_buffer;
        }
    }

    printf("Firmware image backed up successfully\n");
    ret = 0;
 free_buffer:
    free(buf);
 free_write_fd:
    close(write_fd);
 free_read_fd:
    close(fd);
 final_exit:
    return ret;
    return 0;
}
#endif

static int destroy_loopmount(const char * mnt, const char * dev)
{
    int dev_fd, ret;
    if(umount(mnt))
        return -1;
    dev_fd = open(dev, O_RDWR);
    if (dev_fd < 0) {
        printf("Failed to open loop device\n");
        return -1;
    }
    ret = ioctl(dev_fd, LOOP_CLR_FD, 0);
    close(dev_fd);
    unlink(dev);
    return ret;
}


static int create_loopmount(const char * file, const char * mnt, const char * type, const char * dev)
{
    int ret;
    int dev_fd, file_fd;

    ret = mknod(dev, 0660 | S_IFBLK, makedev(7, 0));
    if (0 != ret) {
        printf("Failed to create loop device, %s\n", strerror(errno));
        ret = -1;
        goto exit_path;
    }

    dev_fd = open(dev, O_RDWR);
    if (dev_fd < 0) {
        printf("Failed to open loop device\n");
        ret = -1;
        goto remove_node;
    }

    file_fd = open(file, O_RDWR);
    if (file_fd < 0) {
        printf("Failed to open file\n");
        ret = -1;
        goto close_dev_image;
    }

    ret = ioctl(dev_fd,  LOOP_SET_FD, file_fd);
    if (ret < 0) {
        printf("Failed to send ioctl\n");
        ret = -1;
        goto close_tz_app_image;
    }

    mkdir(mnt, 0770);
    char * options = NULL;
    if(0 == strcmp(type, "ext4"))
        options = "noload";
    ret = mount(dev, mnt, type, MS_RDONLY, options);
    if (0 != ret) {
        printf("Failed to mount image\n");
        ret = -1;
        goto clear_fd;
    }

    printf("Success!\n");
    close(file_fd);
    close(dev_fd);
    return 0;


 clear_fd:
    ioctl(dev_fd, LOOP_CLR_FD, 0);
 close_tz_app_image:
    close(file_fd);
 close_dev_image:
    close(dev_fd);
 remove_node:
    unlink(dev);
 exit_path:
    return ret;

}


// umount tzapp, efs, system cache, backup tzapp. kill qseecomd
int tz_tear_down(void){
    char dmvprop[10]={0,};
    int dmvcnt = 0;
    printf("tz_tear_down ...\n");

    if(0 == tz_setup_status){
        printf("didn't setup tz...success.\n");
        return 0;
    }
#ifdef QSEE_TZ
    struct stat st;
    if(ensure_path_mounted(EFS_MNT)){
        printf("failed to ensure_path_mounted %s\n", EFS_MNT);
        goto error_out;
    }

    if(umount(TZAPP_MOUNT_POINT)){
        printf("failed to umount %s\n", TZAPP_MOUNT_POINT);
        goto error_out;
    }
#endif
    __system_property_set("security.dmv", "stop");
    do {
        usleep(100*1000);

    	__system_property_get(SVC_STATIC_STATUS,dmvprop);        

        dmvcnt++;
        if (dmvcnt % 200 == 0){
           printf("[DMV] tz_tear_down status [%s : %s]\n",SVC_STATIC_STATUS,dmvprop);
           __system_property_set("security.dmv", "stop");
        }
        if (dmvcnt > 1000){
            printf("[DMV] tz_tear_down status [%s : %s]\n",SVC_STATIC_STATUS,dmvprop);
            goto error_out;
        }
    } while (strcmp(dmvprop, "stopped"));
    printf("[DMV] tz_tear_down status [%s : %s]\n",SVC_STATIC_STATUS,dmvprop);

    if(ensure_path_unmounted(EFS_MNT)){
        printf("failed to umount %s\n", EFS_MNT);
        goto error_out;
    }
    tz_setup_status = 0;
    printf("tz_tear_down success.\n");
    return 0;
error_out:
    printf("tz_tear_down failed.\n");
    return -1;
}


//mount (backup) tzapp, efs, system, cache. backup tzapp. start qseecomd
int tz_setup(void){
    char dmvprop[10]={0,};
    int dmvcnt = 0;
    printf("tz_setup...\n");

    if(tz_setup_status){
        printf("already setup tz...success.\n");
        return 0;
    }
#ifdef QSEE_TZ
    const char * tzapp_part_type = "vfat";
    struct stat st;
    if(ensure_path_mounted(EFS_MNT)){
        printf("failed to mount %s\n", EFS_MNT);
    	goto tear_down;
    }
    umount(TZAPP_MOUNT_POINT);

    if(mount(TZAPP_PARTITION, TZAPP_MOUNT_POINT, tzapp_part_type, MS_RDONLY, NULL)){
        printf("failed to mount %s, %s\n", TZAPP_PARTITION, strerror(errno));
        goto tear_down;
    }
#endif
    if(ensure_path_mounted(EFS_MNT)){
        printf("failed to mount %s, %s\n", TZAPP_PARTITION, strerror(errno));
    	goto tear_down;
    }
    __system_property_set("security.dmv", "start");
    do {
        usleep(100*1000);

   	__system_property_get(SVC_STATIC_STATUS,dmvprop);        

	dmvcnt++;
        if (dmvcnt % 200 == 0){
            printf("[DMV] tz_setup status [%s : %s]\n",SVC_STATIC_STATUS,dmvprop);
            __system_property_set("security.dmv", "start");
        }
        if (dmvcnt > 1000){
            printf("[DMV] tz_setup status [%s : %s]\n",SVC_STATIC_STATUS,dmvprop);
            goto tear_down;
        }
    } while (strcmp(dmvprop, "running"));

    tz_setup_status = 1;

    printf("tz_setup success.\n");
    return 0;
 tear_down:
    printf("tz_setup failed\n");
    tz_tear_down();
    return -1;
}

static int check_odin_flag(void)
{
    
    tz_setup();
    usleep(100*1000);      
    
    int fd;
    uint32_t odin_flag;
    const uint32_t success = 0xdeadbeef;
    fd = open("/proc/dmverity_odin_flag", O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "Failed to open proc\n");
        return 0;
    }
    read(fd, &odin_flag, sizeof(odin_flag));
    close(fd);
    printf("Odin flag: %x\n", odin_flag);
        
    tz_tear_down();
    return odin_flag == success;
}

static int check_secure_marker(void){
    int ret = 0;
    char hex_salt[SECURE_MARKER_SEED1_LEN*2+1];
    if(ensure_path_mounted(EFS_MNT)){
        printf("failed to mount /efs\n");
    	return 0;
    }
    int fd = open(SECURE_MARKER_SALT_FILE, O_RDONLY);
    if(fd >= 0){
        if(SECURE_MARKER_SEED1_LEN*2 != read(fd, hex_salt, SECURE_MARKER_SEED1_LEN*2)){
            close(fd);
            printf("failed to read secure marker salt.\n");
            return 0;
        }
        close(fd);
	    hex_salt[SECURE_MARKER_SEED1_LEN*2] = '\0';

        if(tz_setup())
            return 0;
        /* Wait for tz setup */
//#ifdef QSEE_TZ
        usleep(100*1000);
//#endif
        ret = !execute_check_marker(hex_salt);

        tz_tear_down();

	if(ret)
		printf("Found marker..\n");
        fflush(stdout);
        return ret;
    }else{
        printf("secure marker salt file is not present. we assume marker is not set\n");
        fflush(stdout);
        return 0;
    }
    return 0;
}

static int set_secure_marker(void){
    printf("set secure marker...\n");
    struct stat st;
    char hex_salt[SECURE_MARKER_SEED1_LEN*2+1];
    char salt[SECURE_MARKER_SEED1_LEN];
    int ret = 0;
    if(ensure_path_mounted(EFS_MNT)){
        printf("failed to mount /efs\n");
    	return -1;
    }
    //generate salt
    struct timeval t;
    gettimeofday(&t, 0);
    memcpy(salt, &t, sizeof(t));
    void * p = set_secure_marker;
    memcpy(salt+sizeof(t), &p, sizeof(p));
    //generate_marker
    bytes_to_hex(salt, hex_salt, SECURE_MARKER_SEED1_LEN);
    hex_salt[SECURE_MARKER_SEED1_LEN*2] = 0;


    if(tz_setup())
        return -1;
    /* Wait for tz setup */
//#ifdef QSEE_TZ
    usleep(100*1000);
//#endif

    ret = execute_set_marker(hex_salt);

    if(tz_tear_down())
        return -1;

    //write salt
    if(ensure_path_mounted(EFS_MNT)){
        printf("failed to mount %s\n", EFS_MNT);
        return -1;
    }
    int fd = open(SECURE_MARKER_SALT_FILE, O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
    if(fd < 0){
        printf("error opening salt file\n");
        return -1;
    }
    if(SECURE_MARKER_SEED1_LEN*2 != write(fd, hex_salt, SECURE_MARKER_SEED1_LEN*2)){
        printf("error writing salt file\n");
        close(fd);
        return -1;
    }
    fsync(fd);
    close(fd);
    return 0;
}

void dm_verity_recovery_end(void){
    printf("end dm_verity in recovery.\n");
    struct stat st;
    stopwatch_start();
    if(ensure_path_mounted(EFS_MNT)){
        printf("failed to mount %s\n", EFS_MNT);
        return;
    }
    unlink(SECURE_MARKER_SALT_FILE);
    sync();

    if(tz_setup())
        return;

    if(execute_remove_marker()){
        //TODO: how can we better handle this?
        printf("failed to remove marker!!!\n");
    }

    tz_tear_down();

    if(ensure_path_unmounted(EFS_MNT)){
    	printf("failed to umount %s\n", EFS_MNT);
    }
    milestone("dm_verity_recovery_end done\n");
}

int dm_verity_verify(void) {
    int ret = -1;
    int verify_cnt = 2;

    ret = check_verity(SYSTEM_DEV);
    if (!ret)
        printf("verity hash check passed. Continuing\n");
    else {
        do {
            printf("verity check failed. Try to rehash\n");
            if (ret = dm_verity_rehash() < 0) {
                printf("Rehashing failed.\n");
                usleep(100*1000);
            }
            else {
                printf("Rehashing succeed. Verifying\n");
                ret = check_verity(SYSTEM_DEV);
                if (!ret) {
                    printf("verity hash check passed. Continuing\n");
                    return ret;
                }
                else
                    printf("Verify hash failed.\n");
            }
       } while (verify_cnt--);
    }
    return ret;
}

int dm_verity_update_start(void){
	/* Algorithm -> 
	 * 1) Check for ODIN flag set. If yes, skip manual verification of 
	 *    /system image
	 * 2) Verify system image. If verified, then continue
	 * 3) If all of the above fails. return error
	 */
    int ret = -1;
    stopwatch_start();

    //check odin flag
    if(check_odin_flag()){
	    printf("ODIN flag matched. Continuing\n");
    } else {    		
        ret = check_verity(SYSTEM_DEV);
        /* return 2 -> DRK will be not there */
        if (!ret)
            printf("ODIN flag test failed, verity hash check passed. Continuing\n");
        else {
            printf("ODIN flag test failed, verity check failed. Aborting\n");
            return ret;
        }
    }
    if(ensure_path_mounted(EFS_MNT)){
        printf("failed to mount /efs\n");
    	return -1;
    }

#ifdef QSEE_TZ
#if 0
    if(backup_firmware_partition(TZAPP_PARTITION, BACKUP_TZAPP_IMAGE)) {
	printf("Backing up firmware partition failed\n");
        return -1;
    }
#endif
#endif

    if(0 != set_secure_marker())
	    printf("Failed to set secure marker\n");

    //csc package requires that we mount system as rw
    ensure_path_unmounted(SYSTEM_MNT);
    if(ensure_path_mounted_with_option(SYSTEM_MNT,"rw")){
        printf("failed to mount %s\n", SYSTEM_MNT);
	return -1;
    }
    milestone("dm_verity_update_start done\n");
    return 0;
}

//return verity table on success. NULL on failure. caller needs to free the verity table.
//TODO: use the old format
/* static char * generate_dm_verity_hash(const char * dev, uint64_t part_size, uint64_t dev_size, const * tmp_hash_file){ */
/* //flat hash array */
/*     const char * hash_name = "sha1"; */
/*     static char data_buf[DMVERITY_BLOCK_SIZE]; */
/*     static SHA_CTX ctx; */
/*     static SHA_CTX root_hash_ctx; */
/*     int hash_fd, data_fd, i; */
/*     char * table = NULL, *p; */
/*     const long data_blocks = part_size / DMVERITY_BLOCK_SIZE; */
/*     const int digest_size = 20;//sha1 */
/*     const char salt[digest_size]; */
/*     hash_fd = open(TEMP_FILE, O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP); */
/*     if(hash_fd < 0) */
/* 	return table; */
/*     if(lseek(hash_fd, DMVERITY_META_SIZE, SEEK_SET)) */
/* 	goto close_hash_dev; */
/*     data_fd = open(dev, O_RDONLY); */
/*     if(data_fd < 0) */
/* 	goto close_hash_dev; */
/*     SHA_init(&root_hash_ctx); */
/*     for(i=0; i<data_blocks; i++){ */
/* 	if(DMVERITY_BLOCK_SIZE != read(data_fd, data_buf, DMVERITY_BLOCK_SIZE)){ */
/* 	    goto close_data_dev; */
/* 	} */
/* 	SHA_init(&ctx); */
/* 	SHA_update(&ctx, salt, digest_size);	 */
/* 	SHA_update(&ctx, data_buf, DMVERITY_BLOCK_SIZE); */
/* 	SHA_update(&root_hash_ctx, data_buf, DMVERITY_BLOCK_SIZE); */
/* 	if(digest_size != write(hash_fd, SHA_final(&ctx), digest_size)) */
/* 	    goto close_data_dev; */
/*     }     */
/*     //generate verity table here */
/*     const int dm_verity_version = 2; */
/*     const long hash_start = (part_size + DMVERITY_META_SIZE)/DMVERITY_BLOCK_SIZE;     */
/*     int table_size = nDigits(dm_verity_version) + 1 + strlen(dev) + 1 */
/* 	+ strlen(dev) + 1 + nDigits(DMVERITY_BLOCK_SIZE) + 1 */
/* 	+ nDigits(DMVERITY_BLOCK_SIZE) + 1 + nDigits(data_blocks) + 1 */
/* 	+ nDigits(hash_start) + 1 + strlen(hash_name) + 1 + digest_size * 2 */
/* 	+ 1 + digest_size * 2 + 1; */
/*     table = malloc(table_size); */
/*     table[table_size-1] = 0; */
/*     if(NULL == table){ */
/* 	printf("malloc failed\n"); */
/* 	goto close_data_dev; */
/*     } */
/*     i = sprintf(table, "%d %s %s %lld %lld %lld %lld %s ", dm_verity_version, dev, */
/* 		dev, (long long int) DMVERITY_BLOCK_SIZE, */
/* 		(long long int) DMVERITY_BLOCK_SIZE, (long long int) data_blocks, */
/* 		(long long int) hash_start, hash_name); */
/*     if(i <= 0){ */
/* 	error("sprintf error"); */
/* 	free(table); */
/* 	table = NULL; */
/*     } */
/*     p = table + i; */
/*     bytes_to_hex(SHA_final(&root_hash_ctx), p, digest_size); */
/*     p += digest_size * 2;     */
/*     p += sprintf(p, " "); */
/*     bytes_to_hex(salt, p, digest_size);  */
/* close_data_dev: */
/*     close(data_fd); */
/* close_hash_dev: */
/*     close(hash_fd);     */
/*     return table; */
/* } */

int dm_verity_update_end(){
    char * table = NULL;
    struct verity_meta_header meta_header;
    FILE * fp;
    uint64_t part_size, dev_size;
    const char * dev = SYSTEM_DEV;
    const char * tmp_hash_file = TEMP_FILE;
    struct stat st;
    int sign_success = 0;
    int retry_cnt = 3;
    int ret = 0;
    stopwatch_start();
    unlink(tmp_hash_file);

    sync();
    usleep(100*1000);

    if(device_size(dev, &dev_size) || ext4_part_size(dev, &part_size)){
        printf("failed to get part or dev sizes\n");
        return ret;
    }
        table = generate_dm_verity_hash(dev, dev, part_size, tmp_hash_file);
        if(NULL == table){
            printf("failed to generate verity hash\n");
            goto remove_marker;
        }
        meta_header.magic_number = VERITY_METADATA_MAGIC_NUMBER;
        meta_header.protocol_version = 0;
        meta_header.table_length = (unsigned int)strlen(table);//not including trailing NULL
        memset(&meta_header.signature, 0, sizeof(meta_header.signature));
        //tmp_hash_file it should have been created by generate_dm_verity_hash already.
        fp = fopen(tmp_hash_file, "w");
        if (NULL == fp) {
            printf("failed to open temp file\n");
            goto remove_marker;
        }
        if(1 != fwrite(&meta_header, sizeof(struct verity_meta_header), 1, fp)){
            printf("failed to write temp file\n");
            fclose(fp);
            goto remove_marker;
        }
        if(1 != fwrite(table, meta_header.table_length+1, 1, fp)){
            printf("failed to write temp file\n");
            fclose(fp);
            goto remove_marker;
        }
        fflush(fp);
        fsync(fileno(fp));
        fclose(fp);
        if(file_to_device(tmp_hash_file, dev, 1024*1024, part_size)){
            printf("failed to write hash\n");
            goto remove_marker;
        }
        fp = fopen(tmp_hash_file, "w");
        if (NULL == fp) {
            printf("failed to open temp file\n");
            goto remove_marker;
        }
        if(1 != fwrite(table, meta_header.table_length+1, 1, fp)){
            printf("failed to write temp file\n");
            fclose(fp);
            goto remove_marker;
        }
        fflush(fp);
        fsync(fileno(fp));
        fclose(fp);

        if(tz_setup()){
            goto remove_marker;
        }
#ifdef QSEE_TZ
        //wait for tz init
        usleep(100*1000);
#endif
signblob:
        if(ret = execute_sign_blob(tmp_hash_file))
            goto sign_failed;
        if(stat(tmp_hash_file, &st))
            goto remove_marker;
        if(file_to_device(tmp_hash_file, dev, 1024*1024, dev_size - st.st_size)){
            printf("failed to write signature\n");
            goto remove_marker;
        }
        sign_success = 1;
sign_failed:
	//retry sign blob when we failed to sign the hash tree
	// ret == 11 means no DRK, we need to skip retrying for this
    if (!sign_success && retry_cnt > 0 && ret != DMVERITY_DRK_ERROR1 && ret != DMVERITY_DRK_ERROR2) {
        printf("Retry to sign blob\n");
        usleep(1000*1000);
        tz_tear_down();
        usleep(1000*1000);
        tz_setup();
        usleep(1000*1000);
        retry_cnt--;
        if (retry_cnt == 0) {
            printf("Dump log file\n");
        // copy the kernel log to cache and data
            do_dmesg();
            printf("Dump log file Done\n");
        // Reboot into recovery with secure marker
        	if(table) 
        		free(table);
            return SIGN_ERR;

        }
        goto signblob;
    }
 remove_marker:
    unlink(tmp_hash_file);
    sync();
    usleep(100*1000);

    if(table)
        free(table);

    tz_setup();

    if (unlink(SECURE_MARKER_SALT_FILE))
        printf("failed to remove marker salt\n");

    if(execute_remove_marker()){
        //TODO: how can we better handle this?
        printf("failed to remove marker!!!\n");
    }
#ifdef QSEE_TZ
    usleep(100*1000);
#endif
    tz_tear_down();

    milestone("dm_verity_update_end done\n");
#ifdef PRODUCT_SHIP  // not release build
#ifdef __USE_KAP
    if (ret == DMVERITY_DRK_ERROR1 || ret == DMVERITY_DRK_ERROR2) {
        printf("Device does not have DRK, aborting\n");
        return ret;
    }
#endif
#endif
    return 0;
}

int dm_verity_rehash(void)
{
    const char * tmp_hash_file = TEMP_FILE;
    const char * tmp_hash_table = TMP_HASH_TABLE;
    const char * target_dev = SYSTEM_DEV;
    unlink(tmp_hash_file);
    unlink(tmp_hash_table);

    char * table = NULL;
    uint64_t part_size, dev_size;
    struct verity_meta_header meta_header;
    FILE * fp;
    struct stat st;
    int ret = 0;
    stopwatch_start();
    printf("start regenerate full hash on device.\n");

    if(device_size(target_dev, &dev_size) || ext4_part_size(target_dev, &part_size)) {
        printf("failed to get part or dev sizes\n");
        return -1;
    }
    printf("device size is %lld.\n", (long long int)dev_size);
    if (execute_hashgen_rehash()) {
        printf("hash generation failed.\n");
        ret = -1;
        goto out;
    }


    // 3. write tmp hash file to the /system (not signed)
    if(file_to_device(tmp_hash_file, target_dev, 1024*1024, part_size)){
        printf("failed to write hash 001\n");
        goto remove_marker;
    }
    sync();

    // 4. call TZ to sign the hash
    if(tz_setup()){
        //ret = -1;
        goto remove_marker;
    }
#ifdef QSEE_TZ
    //wait for tz init
    usleep(100*1000);
#endif
    if(execute_sign_blob(tmp_hash_table)) {
        //ret = -1;
        goto remove_marker;
    }

    // 5. write tmp hash file to /system (now with signature)
    if(stat(tmp_hash_table, &st)) {
        ret = -1;
        goto remove_marker;
    }
    //printf("st.st_size is %lld.\n", st.st_size);
    //printf("st.st_size is %lld.\n", dev_size -st.st_size);
    if(file_to_device(tmp_hash_table, target_dev, 1024*1024, dev_size - st.st_size)){
        printf("failed to write signature\n");
        ret = -1;
        goto remove_marker;
    }
    sync();

remove_marker:
    //unlink(tmp_hash_file);
    //unlink(tmp_hash_table);
    if(table)
        free(table);

    if(tz_setup()){
        //ret = -1;
    }

    if(execute_remove_marker()){
        //TODO: how can we better handle this?
        printf("failed to remove marker!!!\n");
        //ret = -1;
    }

    tz_tear_down();


out:
    milestone("dm_verity full rehash ends.\n");
    return ret;
}


int dm_verity_check_marker(void){
    return check_secure_marker();
}

int dm_verity_set_marker(void){
    return set_secure_marker();
}

void dm_verity_drop_cache(void){
    FILE *fp;
    fp=fopen("/proc/sys/vm/drop_caches", "w");
    if (fp) {
        printf("\nClean page cache ...\n");
        fwrite("1", 1, 1, fp);
        fclose(fp);
    }
}

static int write_param_lk(struct device_desc *desc)
{
    struct pit_partinfo *ppi;
    struct device *d_param;
    unsigned long long ptn = 0;
    unsigned int length;
    char *tPtr;
    int fd;

    ppi = pit_find_partinfo("PARAM");
    d_param = find_part_device(desc, "PARAM");
    if (!ppi || !d_param) {
        printf("PARAM : param partition table is not exist\n");
        return -1;
    }
    ptn = ppi->blkstart * desc->sectorSize;
    fd = d_param->fd;

    /* Set forced into recovery param */
    m_param.booting_now = RECOVERY_ENTER_MODE;

    memset(buff, 0x0, EMMC_SECTOR_SIZE);
    memcpy(buff, &m_param, sizeof(PARAM));

    lseek(fd, ptn, SEEK_SET);
    length = EMMC_SECTOR_SIZE;

    tPtr = buff;
    while( length )
    {
        long sz = write(fd, tPtr, length);
        if( sz <= 0 ) break;

        tPtr += sz;
        length -= sz;
    }

    if( length )
    {
        printf("PARAM: Cannot write param data\n");
        return -1;
    }

    return 0;
}

static int read_param_lk(struct device_desc *desc)
{
    struct pit_partinfo *ppi;
    struct device *d_param;
    unsigned long long ptn = 0;
    unsigned int length;
    char *tPtr;
    int fd;

    ppi = pit_find_partinfo("PARAM");
	d_param = find_part_device(desc, "PARAM");

    if (!ppi || !d_param) {
        printf("PARAM : param partition table is not exist\n");
        return -1;
    }
    ptn = ppi->blkstart * 512;
	fd = d_param->fd;

    memset(buff, 0x0, EMMC_SECTOR_SIZE);

    lseek(fd, ptn, SEEK_SET);
    length = EMMC_SECTOR_SIZE;

    tPtr = buff;
    while( length )
    {
        long sz = read(fd, tPtr, length);
        if( sz <= 0 ) break;

        tPtr += sz;
        length -= sz;
    }

    if( length )
    {
        printf("PARAM: Cannot read param data\n");
        return -1;
    }

    memcpy(&m_param, buff, sizeof(PARAM));

    return 0;
}


static int write_param_sboot(struct device_desc *desc) 
{
    struct pit_partinfo *ppi;
	struct device *d_param;
    unsigned long long ptn = 0;
    unsigned int length;
    char *tPtr;
	int fd;

    ppi = pit_find_partinfo("PARAM");
	d_param = find_part_device(desc, "PARAM");

    if (!ppi || !d_param) {
        printf("PARAM : param partition table is not exist\n");
        return -1; 
    }   
	// FIXME
	// Need to check!! Last 1KB is always correct??
	ptn = (ppi->blkstart*desc->sectorSize) + ((ppi->blknum-(1048576/desc->sectorSize))*desc->sectorSize);

	fd = d_param->fd;

    /* Set forced into recovery param */
    m_param_env.int_param[PARAM_REBOOT_MODE] = REBOOT_MODE_RECOVERY;

    lseek(fd, ptn, SEEK_SET);
    length = sizeof(m_param_env);

    tPtr = (char*)&m_param_env;

    while( length )
    {   
        long sz = write(fd, tPtr, length);
        if( sz <= 0 ) break;

        tPtr += sz; 
        length -= sz; 
    }   

    if( length )
    {   
        printf("PARAM: Cannot write param data\n");
        return -1; 
    }   

    return 0;
}

static int read_param_sboot(struct device_desc *desc) 
{
    struct pit_partinfo *ppi;
	struct device *d_param;
    uint64_t ptn = 0;
    unsigned int length;
    char *tPtr;
    int fd;

    ppi = pit_find_partinfo("PARAM");
	d_param = find_part_device(desc, "PARAM");
	if (!ppi || !d_param) {
        printf("PARAM : param partition table is not exist\n");
        return -1;
    }
	// FIXME
	// Need to check!! Last 1KB is always correct??
	ptn = (((uint64_t)ppi->blkstart)*((uint64_t)desc->sectorSize)) + ((((uint64_t)ppi->blknum)-(1048576/((uint64_t)desc->sectorSize)))*((uint64_t)desc->sectorSize));
    fd = d_param->fd;

    lseek(fd, ptn, SEEK_SET);
    length = sizeof(m_param_env);

    tPtr = (char*)&m_param_env;
    while( length )
    {
        long sz = read(fd, tPtr, length);
        if( sz <= 0 ) break;

        tPtr += sz;
        length -= sz;
    }

    if( length )
    {
        printf("PARAM: Cannot read param data\n");
        return -1;
    }

    if( m_param_env.header[0] != PARAM_ENV_MAGIC_CODE )
    {
        printf("PARAM: Magic code is not mached. [%x]\n",m_param_env.header[0]);
        return -1;
    }

    return 0;
}

int check_ap()
{
	const char *ap = get_ap_name();

	if( ap == 0 )
	{
		printf("Could not read AP Name.\n");
		return -1;
	}

	printf("AP : %6s",ap);
	if( strncmp("LSI",ap,3) == 0 )
	{
		printf("sboot mode\n");
		currentParam = PARAM_SBOOT;
	}
	else if( strncmp("EXYNOS",ap,6) == 0 )
	{
		printf("sboot mode\n");
		currentParam = PARAM_SBOOT;
	}
	else if( strncmp("Mx",ap,2) == 0 )
	{
		printf("sboot mode\n");
		currentParam = PARAM_SBOOT;
	}
	else
	{
		printf("lk mode\n");
		currentParam = PARAM_LK;
	}
	return currentParam;
}

int set_forced_into_recovery(void)
{
	int dev_fd, dev_ret, result = -1;
	unsigned int stamp;
	int current_mode;
	struct device_desc *devDesc;

    devDesc = openDevice();

    if ( check_ap() < 0)
    {
        printf("Check ap error\n");
        goto failed;
    }
    if ( currentParam == PARAM_SBOOT )
        result = read_param_sboot(devDesc);
    else
        result = read_param_lk(devDesc);

    if ( result )
    {
        printf("Read Param error\n");
        goto failed;
    }
    if ( currentParam == PARAM_SBOOT )
        result = write_param_sboot(devDesc);
    else
        result = write_param_lk(devDesc);

    if ( result )
    {
        printf("Write Param error\n");
        goto failed;
    }
    result = 0;
failed:
    release_device_desc(devDesc);
    return result;
}

#if 0
int dump_dmv_log(const char *title, const char* path, const char* dest_path)
{
    char buffer[32768];
    int fd = open(path, O_RDONLY);
    int i, j;
    if (fd < 0) {
        int err = errno;
        if (title) printf("------ %s (%s) ------\n", title, path);
        printf("*** %s: %s\n", path, strerror(err));
        if (title) printf("\n");
        return -1;
    }

    int fd_dest = open(dest_path, O_WRONLY | O_CREAT | O_TRUNC,
            S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if (fd < 0) {
        int err = errno;
        if (title) printf("------ %s (%s) ------\n", title, dest_path);
        printf("*** %s: %s\n", dest_path, strerror(err));
        if (title) printf("\n");
        close(fd);
        return -1;
    }

    for (i=0;i < 8192 ; i++) {
        int ret = read(fd, buffer, sizeof(buffer));
		printf("%d\n", ret);
        if (ret > 0) {
            ret = write(fd_dest, buffer, ret);
			printf("%s\n\n", buffer);
        }
        if (ret <= 0) break;
    }

    close(fd);
    close(fd_dest);
    return 0;
}
#endif
void do_dmesg() {
    printf("------ KERNEL LOG (dmesg) ------\n");
    /* Get size of kernel buffer */
    int size = klogctl(KLOG_SIZE_BUFFER, NULL, 0);
    if (size <= 0) {
        printf("Unexpected klogctl return value: %d\n\n", size);
        return;
    }
    char *buf = (char *) malloc(size + 1);
    if (buf == NULL) {
        printf("memory allocation failed\n\n");
        return;
    }
    int retval = klogctl(KLOG_READ_ALL, buf, size);
    if (retval < 0) {
        printf("klogctl failure\n\n");
        free(buf);
        return;
    }
    buf[retval] = '\0';
    printf("%s\n\n", buf);
    free(buf);
    return;
}

static void append_qsee_log(){
   
	printf("---- qsee_log starts ----\n");
    	append_file(D_QSEE_LOG , TEMP_RECOVERY_LOG , (off_t)-1);
    	printf("---- qsee_log ends   ----\n"); 
    
    	printf("---- tz_log starts   ----\n");
	    append_file(D_TZ_LOG , TEMP_RECOVERY_LOG , (off_t)-1);
    	printf("---- tz_log ends     ----\n");
}

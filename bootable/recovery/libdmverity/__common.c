#include "ext4_utils.h"
#ifndef _LARGEFILE64_SOURCE
#define _LARGEFILE64_SOURCE     /* See feature_test_macros(7) */
#endif
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/time.h>
#include <time.h>
#include "ext4.h"
#include "mincrypt/sha.h"
#include "libdmverity.h"
#include "libdmverity_hashgen/libdmverity_hashgen.h"
#include "__common.h"

#ifndef	__BUILD_HOST_EXECUTABLE
#include "roots.h"
#include <fs_mgr.h>
#endif
extern int fs_mgr_teardown_verity(struct fstab_rec *fstab, char root_hash[], unsigned int *root_hash_size, int target);


#if defined(EXYNOS_7420)
static const char * SYSTEM_DEV = "/dev/block/platform/15570000.ufs/by-name/SYSTEM";
#elif defined(EXYNOS_8890)
static const char * SYSTEM_DEV = "/dev/block/platform/155a0000.ufs/by-name/SYSTEM";
#elif TRE_PROJECT
static const char * SYSTEM_DEV = "/dev/block/mmcblk0p18";
#elif defined(EXYNOS_7580) || defined(EXYNOS_3475) || defined(EXYNOS_7870)
static const char * SYSTEM_DEV = "/dev/block/platform/13540000.dwmmc0/by-name/SYSTEM";
#elif defined (EXYNOS_5433) || defined(EXYNOS_5430)
static const char * SYSTEM_DEV = "/dev/block/platform/15540000.dwmmc0/by-name/SYSTEM";
#elif defined(APQ_8084)
static const char * SYSTEM_DEV = "/dev/block/platform/msm_sdcc.1/by-name/system";
#else
static const char * SYSTEM_DEV = "/dev/block/bootdevice/by-name/system";
#endif

extern dm_dirty_setup;

struct timeval tv;

void stopwatch_start()
{
    gettimeofday(&tv, 0);
}

/* Stop the stopwatch and return elapsed time in microeconds */
uint64_t stopwatch_stop()
{
    struct timeval t;
    uint64_t v;
    int64_t  d;

    gettimeofday(&t, 0);

    v = t.tv_sec - tv.tv_sec;
    d = t.tv_usec - tv.tv_usec;
    if (d < 0)
    {
        v--;
        d += 1000000;
    }

    return d + (v * 1000000);
}

void milestone(const char * msg){
    printf("milestone: %s: %ld\n", msg, (long int)stopwatch_stop());
    fflush(stdout);
    stopwatch_start();
}

void bytes_to_hex(const char * in, char * out, int size) {
    const char * pin = in;
    const char * hex = "0123456789ABCDEF";
    char * pout = out;
    int i = 0;
    for (; i < size - 1; ++i) {
        *pout++ = hex[(*pin >> 4) & 0xF];
        *pout++ = hex[(*pin++) & 0xF];
    }
    *pout++ = hex[(*pin >> 4) & 0xF];
    *pout++ = hex[(*pin) & 0xF];
}

ssize_t hex_to_bytes(const char *string, char * bytes) {
    char buf[3] = "xx\0", *endp;
    size_t i, len;

    len = strlen(string);
    if (len % 2)
        return -EINVAL;
    len /= 2;

    for (i = 0; i < len; i++) {
        memcpy(buf, &string[i * 2], 2);
        bytes[i] = strtoul(buf, &endp, 16);
        if (endp != &buf[2]) {
            return -EINVAL;
        }
    }
    return i;
}

int file_cmp(const char * file_a, const char * file_b, unsigned long offset_a,
                    unsigned long offset_b, int buffer_size) {
    int r = -1;
    int read_size;
    char * buffer_a = malloc(buffer_size);
    if (NULL == buffer_a) {
        printf("failed to allocate buffer");
        return -1;
    }
    char * buffer_b = malloc(buffer_size);
    if (NULL == buffer_b) {
        printf("failed to allocate buffer");
        free(buffer_a);
        return -1;
    }
    int fda = open(file_a, O_RDONLY);
    if (fda < 0) {
        printf("failed to open file");
        goto malloc_exit;
    }
    int fdb = open(file_b, O_RDONLY);
    if (fdb < 0) {
        printf("failed to open file");
        close(fda);
        goto malloc_exit;
    }
    unsigned long size;
    struct stat st;
    if (0 != fstat(fda, &st)) {
        printf("failed to stat file");
        goto close_exit;
    }
    size = st.st_size - offset_a;
    if (0 != fstat(fdb, &st)) {
        printf("failed to stat file");
        goto close_exit;
    }
    if ((st.st_size - offset_b) < size) {
        size = st.st_size - offset_b;
    }

    if (offset_a != lseek64(fda, offset_a, SEEK_SET)) {
        printf("failed to seek file");
        goto close_exit;
    }
    if (offset_b != lseek64(fdb, offset_b, SEEK_SET)) {
        printf("failed to seek file");
        goto close_exit;
    }
    printf("hash tree size: %ld\n", size);
    while (size > 0) {
        read_size = size;
        if (read_size > buffer_size) {
            read_size = buffer_size;
        }
        if (read_size != read(fda, buffer_a, read_size)) {
            printf("failed to read file");
            goto close_exit;
        }
        if (read_size != read(fdb, buffer_b, read_size)) {
            printf("failed to read file");
            goto close_exit;
        }
        if (0 != memcmp(buffer_a, buffer_b, read_size)) {
            printf("content differ");
            goto close_exit;
        }
        size -= read_size;
    }
    r = 0;
 close_exit: close(fdb);
    close(fda);
 malloc_exit: free(buffer_a);
    free(buffer_b);
    return r;
}
#if 0
int file_to_device(const char * file, const char * dev, int buffer_size,
                          unsigned long offset) {
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
            printf("failed to write %s: %d, %d, %s\n", dev, w_size, write_size, strerror(errno));
            goto close_wfd;
        }
        size -= write_size;
    }
    ret = 0;
 close_wfd:
    close(wfd);
 close_rfd:
    close(rfd);
 free_buffer:
    free(buffer);
    return ret;
}
#endif
int nDigits(int i) {
    if (i < 0)
        i = -i;
    if (i < 10)
        return 1;
    if (i < 100)
        return 2;
    if (i < 1000)
        return 3;
    if (i < 10000)
        return 4;
    if (i < 100000)
        return 5;
    if (i < 1000000)
        return 6;
    if (i < 10000000)
        return 7;
    if (i < 100000000)
        return 8;
    return 9;
    /* if (i < 1000000000) */
    /*     return 9; */
    /* if (i < 10000000000) */
    /*     return 10; */
    return -1; //too large!
}

int ext4_part_size(const char *blk_device, uint64_t *device_size) {
    int data_device;
    struct ext4_super_block sb;
    struct fs_info info = {0};

    data_device = open(blk_device, O_RDONLY);
    if (data_device < 0) {
        printf("Error opening block device (%s)", strerror(errno));
        return -1;
    }

    if (1024 != lseek64(data_device, 1024, SEEK_SET)) {
        close(data_device);
        printf("Error seeking to superblock in %s\n", blk_device);
        return -1;
    }

    if (read(data_device, &sb, sizeof(sb)) != sizeof(sb)) {
        close(data_device);
        printf("Error reading superblock in %s\n", blk_device);
        return -1;
    }

    ext4_parse_sb(&sb, &info);
    *device_size = info.len;

    close(data_device);
    return 0;
}

int device_size(const char *device_file, uint64_t *size) {
    struct stat st;
    int devfd, r = -EINVAL;

    devfd = open(device_file, O_RDONLY);
    if (devfd == -1)
        return -EINVAL;

    if (fstat(devfd, &st) < 0)
        goto out;

    if (S_ISREG(st.st_mode)) {
        *size = (uint64_t) st.st_size;
        r = 0;
    } else if (ioctl(devfd, BLKGETSIZE64, size) >= 0)
        r = 0;
 out: close(devfd);
    return r;
}

static int generate_salt(char * salt, int salt_len) {
    printf("generate random salt.\n");
    FILE *fp;
    int r;
    int amount_read = 0;
    fp=fopen("/dev/urandom", "r");
    if (fp) {
        while (amount_read < salt_len) {
            r = (int)fread(salt + amount_read, 1, salt_len-amount_read, fp);
            if (r > 0) { amount_read += r; }
            else if (!r) { break; }
            else if (errno != EINTR) {
                amount_read = -1;
                break;
            }
        }
        //fread(salt, 1, salt_len, fp);
        fclose(fp);
        //printf("salt2 is generated: %s. amount_read is %d.\n", salt, amount_read);
    } else {
        printf("fopen failed.\n");
    }
    return amount_read;
}

static int get_salt(char * salt, const loff_t meta_off) {
    
    printf("get salt from meta table\n");
   
    int r = -1;
    
    fflush(stdout);
    int fd = open(SYSTEM_DEV, O_RDONLY);
    if (fd < 0){
        printf("error opening device\n");
        return -1;
    }
    if (lseek64(fd, meta_off, SEEK_SET) < 0) {
        printf("Error seeking to meta data");
        goto exit_open;
    }
    struct verity_meta_header header;
    if (sizeof(struct verity_meta_header)
        != read(fd, &header, sizeof(struct verity_meta_header))) {
        printf("Error reading meta data");
        goto exit_open;
    }
    
    if(UINT_MAX == header.table_length){
		printf("integer argument overflow\n");
		goto exit_open;
    }
    
    char * table = malloc(header.table_length+1);
    if(NULL == table){
        printf("failed to malloc for table\n");
        goto exit_open;
    }
    table[header.table_length] = 0;
    if ((ssize_t)(header.table_length) != read(fd, table, header.table_length)) {
        printf("invalid table length");
        goto exit_malloc;
    }
    close(fd);
    fd = -1;
    
    char * version_str = strtok(table, " ");
    char * data_dev_str = strtok(NULL, " ");
    char * hash_dev_str = strtok(NULL, " ");
    char * data_blk_size_str = strtok(NULL, " ");
    char * hash_blk_size_str = strtok(NULL, " ");
    char * data_blocks_size_str = strtok(NULL, " ");
    char * hash_start_size_str = strtok(NULL, " ");
    char * alg_str = strtok(NULL, " ");
    char * digest_str = strtok(NULL, " ");
    char * salt_str = strtok(NULL, " ");
    
    if (strlen(salt_str) % 2) {
        printf("wrong salt size in table.\n");
        goto exit_malloc;
    }
    
    
    
    if (hex_to_bytes(salt_str, salt) < 0) {
        printf("wrong salt in table\n");
        goto exit_malloc;
    }
    r = strlen(salt_str) / 2;

exit_malloc: if (table)
    free(table);
exit_open: if (fd >= 0)
    close(fd);
    return r;
}

char * generate_dm_verity_hash(const char * target_dev, const char * image_file, uint64_t part_size, const char * tmp_hash_file){
#ifdef USE_SHA256
    const char * hash_name = "sha256";
#elif USE_SHA1
    const char * hash_name = "sha1";
#else
    const char * hash_name = "md5";
#endif
    //static SHA_CTX root_hash_ctx;
    int i;
    char * table = NULL, *p;
    const long data_blocks = (long)((uint64_t)part_size / (uint64_t)DMVERITY_BLOCK_SIZE);
#ifdef USE_SHA256
    const int digest_size = 32;//SHA256
#elif USE_SHA1
    const int digest_size = 20;//SHA1
#else
    const int digest_size = 16;//md5
#endif
    char salt[digest_size];
    char root_hash[digest_size];
    const int dm_verity_version = 1;
    const long hash_start = data_blocks + (DMVERITY_META_SIZE/DMVERITY_BLOCK_SIZE);
    const loff_t hash_position = DMVERITY_META_SIZE/DMVERITY_BLOCK_SIZE;
#ifndef __BUILD_HOST_EXECUTABLE
    int digest_size_from_kernel = digest_size;

    printf("partSize(%llu) dataBlocks(%ld) hashStart(%ld)\n", part_size, data_blocks, hash_start);

    printf("unmount /system for dirty finalization.\n");
    while (ensure_path_unmounted("/system")) {
        printf("wait for 10ms.\n");
        usleep(10*1000);
    } 

    if (get_salt(salt, (loff_t) part_size) != digest_size) {
        printf("Error in getting salt.\n");
        return NULL;
    }

    Volume *v = volume_for_path("/system");

    if (fs_mgr_teardown_verity(v, root_hash, &digest_size_from_kernel, DIRTY) != 0) {
	    printf("Error getting root hash and freeing dirty\n");
	    return NULL;
    }
    if (digest_size_from_kernel != digest_size) {
	    printf("digest_size_from_kernel = %d\n", digest_size_from_kernel);
	    return NULL;
    }
    dm_dirty_setup = 0;
#else
    
    if (generate_salt(salt, digest_size) != digest_size) {
        printf("Error generating random salt.\n");
        // how to handle it better? now it will use whatever compiler gives: all 0's
    }

    if(VERITY_create_hash(dm_verity_version, hash_name, tmp_hash_file, image_file, DMVERITY_BLOCK_SIZE, DMVERITY_BLOCK_SIZE, data_blocks, hash_position, (unsigned char *)root_hash, digest_size, (const unsigned char *)salt, digest_size)){
        printf("failed to create hash tree\n");
        return NULL;
    }
#endif

    int table_size = nDigits(dm_verity_version) + 1 + strlen(target_dev) + 1
        + strlen(target_dev) + 1 + nDigits(DMVERITY_BLOCK_SIZE) + 1
        + nDigits(DMVERITY_BLOCK_SIZE) + 1 + nDigits(data_blocks) + 1
        + nDigits(hash_start) + 1 + strlen(hash_name) + 1 + digest_size * 2
        + 1 + digest_size * 2 + 1;
    table = malloc(table_size);
    if(NULL == table){
        printf("malloc failed\n");
        return NULL;
    }
    table[table_size-1] = 0;
    i = sprintf(table, "%d %s %s %lld %lld %lld %lld %s ", dm_verity_version, target_dev,
                target_dev, (long long int) DMVERITY_BLOCK_SIZE,
                (long long int) DMVERITY_BLOCK_SIZE, (long long int) data_blocks,
                (long long int) hash_start, hash_name);
    printf("table print : %s\n", table); 
    if(i <= 0){
        printf("sprintf error");
        free(table);
        return NULL;
    }
    p = table + i;
    bytes_to_hex(root_hash, p, digest_size);
    p += digest_size * 2;
    p += sprintf(p, " ");
    bytes_to_hex(salt, p, digest_size);
    return table;
}

#if 0

#ifndef __BUILD_HOST_EXECUTABLE
char * regenerate_dm_verity_hash(const char * target_dev, uint64_t part_size, const char * tmp_hash_file){
    const char * hash_name = "sha1";
    //static SHA_CTX root_hash_ctx;
    int i;
    char * table = NULL, *p;
    const long data_blocks = part_size / DMVERITY_BLOCK_SIZE;
    const int digest_size = 20;//sha1
    char salt[digest_size];
    char root_hash[digest_size];
    const int dm_verity_version = 1;
    const long hash_start = (part_size + DMVERITY_META_SIZE)/DMVERITY_BLOCK_SIZE;
    const loff_t hash_position = DMVERITY_META_SIZE/DMVERITY_BLOCK_SIZE;
    
    if (generate_salt(salt, digest_size) != digest_size) {
        printf("Error generating random salt.\n");
        // how to handle it better? now it will use whatever compiler gives: all 0's
    }
        

    if(VERITY_create_hash(dm_verity_version,                  \
                      hash_name,                              \
                      tmp_hash_file,                          \
                      target_dev,                             \
                      DMVERITY_BLOCK_SIZE,                    \
                      DMVERITY_BLOCK_SIZE,                    \
                      data_blocks,                            \
                      hash_position,                          \
                      (unsigned char *)root_hash,             \
                      digest_size,                            \
                      (const unsigned char *)salt,            \
                      digest_size))
    {
        printf("failed to create hash tree\n");
        return NULL;
    }  


    int table_size = nDigits(dm_verity_version) + 1 + strlen(target_dev) + 1
        + strlen(target_dev) + 1 + nDigits(DMVERITY_BLOCK_SIZE) + 1
        + nDigits(DMVERITY_BLOCK_SIZE) + 1 + nDigits(data_blocks) + 1
        + nDigits(hash_start) + 1 + strlen(hash_name) + 1 + digest_size * 2
        + 1 + digest_size * 2 + 1;
    table = malloc(table_size);
    if(NULL == table){
        printf("malloc failed\n");
        return NULL;
    }
    table[table_size-1] = 0;
    i = sprintf(table, "%d %s %s %lld %lld %lld %lld %s ", dm_verity_version, target_dev,
                target_dev, (long long int) DMVERITY_BLOCK_SIZE,
                (long long int) DMVERITY_BLOCK_SIZE, (long long int) data_blocks,
                (long long int) hash_start, hash_name);
    if(i <= 0){
        printf("sprintf error");
        free(table);
        return NULL;
    }
    p = table + i;
    bytes_to_hex(root_hash, p, digest_size);
    p += digest_size * 2;
    p += sprintf(p, " ");
    bytes_to_hex(salt, p, digest_size);
    return table;
}
#endif

#endif

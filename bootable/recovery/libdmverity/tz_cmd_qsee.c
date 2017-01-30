#define _LARGEFILE64_SOURCE
#define __STDC_FORMAT_MACROS
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <inttypes.h>
#include <time.h>
#include <stdlib.h>
#include <errno.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <QSEEComAPI.h>
#include <ctype.h>
#include <openssl/sha.h>

#include "secure_marker.h"
/* #include "libdmverity.h" */
/* #include "ext4.h" */
/* #include "ext4_utils.h" */
/* #include "mincrypt/rsa.h" */
/* #include "mincrypt/sha256.h" */
/* #include "mincrypt/sha.h" */

#define	USE_QSEE


#ifdef USE_LIBDEVKM
#include <LibDevKMApi.h>
#endif


#define	TZAPP_ORI	"dmverity"
#define	TZAPP_ALT	"dmv_m"

#define	MAX_TRANSFER_SIZE	4096
uint8_t	buf[MAX_TRANSFER_SIZE];
uint32_t buf_len = MAX_TRANSFER_SIZE;

#define	MAX_HASH_SIZE	32
typedef struct cmd_req
{
    uint32_t cmd_id;
    uint8_t	 hash[MAX_HASH_SIZE];
    uint32_t hash_len; /* To support all kinds of hash techniques */
    uint32_t dataLen;
    uint8_t data[MAX_TRANSFER_SIZE];
} cmd_req_t;

//// Response struct
typedef struct cmd_rsp
{
    int32_t status;
    uint32_t dataLen;
    uint8_t data[MAX_TRANSFER_SIZE];
} cmd_rsp_t;

uint8_t sha256hash[32];

uint8_t	zeroes[32] = {0};

int calc_hash(char *input, int input_len, char *output)
{
    /* data, data_len and hash should be populated */
    int ret;
    SHA256_CTX	ctx;

    ret = SHA256_Init(&ctx);
    if (0 == ret) {
	fprintf(stderr, "Error initing sha256 hash\n");
	return -1;
    }

    ret = SHA256_Update(&ctx, input, input_len);
    if (0 == ret) {
	fprintf(stderr, "Error updating sha has\n");
	return -1;
    }

    ret = SHA256_Final(output, &ctx);
    if (0 == ret) {
	fprintf(stderr, "Error finalizing hash\n");
	return -1;
    }

    return 0;
}

static struct QSEECom_handle *QSEEComHandle = NULL;

void parse_output(cmd_req_t *req_ptr, cmd_rsp_t *rsp_ptr, char **result, uint32_t *result_size)
{
    int fd;
    uint32_t index = 0, size;
    uint8_t *ptr;

#if 0
    printf("dataLen: %d\n", rsp_ptr->dataLen);
    fd = open("/mnt/sdcard/dmverity_data", O_WRONLY | O_CREAT | O_TRUNC, 0777);
    if (fd < 0) {
	fprintf(stderr, "Failed opening data file\n");
	return;
    }
    //write(fd, req_ptr->hash, 32); /* Size of SHA256 hash */
    write(fd, zeroes, 32); /* Size of SHA256 hash */
    close(fd);


    fd = open("/mnt/sdcard/dmverity_all", O_WRONLY | O_CREAT | O_TRUNC, 0777);
    if (fd < 0) {
	fprintf(stderr, "Failed opening sig file\n");
	return;
    }
    write(fd, rsp_ptr->data, rsp_ptr->dataLen); /* Size of signature */
    close(fd);
#endif

    *result = malloc(rsp_ptr->dataLen);
    if (NULL == *result) {
	fprintf(stderr, "Error allocating mem for result\n");
	*result_size = 0;
	return;
    }
    *result_size = rsp_ptr->dataLen;
    memcpy(*result, rsp_ptr->data, rsp_ptr->dataLen);

#if 0
    fd = open("/mnt/sdcard/dmverity_sig", O_WRONLY | O_CREAT | O_TRUNC, 0777);
    if (fd < 0) {
	fprintf(stderr, "Failed opening sig file\n");
	return;
    }
    write(fd, rsp_ptr->data, 256); /* Size of signature */
    close(fd);

    index = 256;
    ptr = rsp_ptr->data;

    size = ((ptr[index] << 8) + ptr[index + 1]);
    index += 2;
    fd = open("/mnt/sdcard/dmverity_root_crt", O_WRONLY | O_CREAT | O_TRUNC, 0777);
    if (fd < 0) {
	fprintf(stderr, "Failed opening root cert file\n");
	return;
    }
    printf("Writing root cert of size: %d\n", size);
    write(fd, ptr + index, size); /* Size of signature */
    close(fd);
    index += size;

    size = ((ptr[index] << 8) + ptr[index + 1]);
    index += 2;
    fd = open("/mnt/sdcard/dmverity_ca_crt", O_WRONLY | O_CREAT | O_TRUNC, 0777);
    if (fd < 0) {
	fprintf(stderr, "Failed opening ca cert file\n");
	return;
    }
    printf("Writing ca cert of size: %d\n", size);
    write(fd, ptr + index, size); /* Size of signature */
    close(fd);
    index += size;
#endif
	
}

int32_t loadTZAPP(void)
{
    int32_t ret = -1;
    int load_cnt = 0 ;

    if (QSEEComHandle != NULL) {
	return 0;
    }

    while(ret!=0 && load_cnt < 3){
    ret = QSEECom_start_app(&QSEEComHandle, "/firmware/image", TZAPP_ORI,
			    QSEECOM_ALIGN(sizeof(cmd_req_t) + sizeof(cmd_rsp_t)));
    
    if(ret) {
    	fprintf(stderr, "Failed to load %s \n" , TZAPP_ORI);
    	fprintf(stderr, "Trying to load %s \n" , TZAPP_ALT);    
    	ret = QSEECom_start_app(&QSEEComHandle, "/firmware/image", TZAPP_ALT,
			    QSEECOM_ALIGN(sizeof(cmd_req_t) + sizeof(cmd_rsp_t)));	
    	
    }
    
    load_cnt ++ ;    
    }
    
    
    if (ret) {
	fprintf(stderr, "Failed to start tzapp\n");
	ret = -1;
    }
    return ret;
}

void unloadTZAPP(void){
    if (QSEEComHandle != NULL) {
	QSEECom_shutdown_app(&QSEEComHandle);
	QSEEComHandle = NULL;
	printf("TZAPP shut down\n");
    }
}

#define MARKER_DATA_LEN  292
//we assume req_ptr->data is already prepared.
static int TZAPPSendMarkerCmd(uint32_t cmd_id){
    cmd_req_t *req_ptr;
    cmd_rsp_t *rsp_ptr;
    int ret, i;
    uint32_t status;
    //we assume req_ptr->data is already prepared.
    req_ptr = (cmd_req_t *)QSEEComHandle->ion_sbuffer;
    rsp_ptr = (cmd_rsp_t *)(QSEEComHandle->ion_sbuffer + sizeof(cmd_req_t));
    req_ptr->cmd_id = cmd_id;
    req_ptr->dataLen = MARKER_DATA_LEN;
    ret = QSEECom_set_bandwidth(QSEEComHandle, true);
    if (ret < 0) {
	fprintf(stderr, "Failed to set bandwidth\n");
	return -3;
    }
    ret = QSEECom_send_cmd(QSEEComHandle, req_ptr, sizeof(cmd_req_t),
			   rsp_ptr, sizeof(cmd_rsp_t));
    if(ret < 0) {
	QSEECom_set_bandwidth(QSEEComHandle, false);
	fprintf(stderr, "Failed to send command\n");
	return -3;
    } else 
	printf("TZAPP send cmd successful\n");

    status = rsp_ptr->status;
    ret = QSEECom_set_bandwidth(QSEEComHandle, false);
    if (ret < 0) {
	fprintf(stderr, "Failed to reset bandwidth\n");
	//can't really do anything here.
    }
    return (int)status;
}

//0: success, -1 failure
int set_marker_cmd(uint32_t success_pattern, uint8_t * hash1, int hash1_len, uint8_t * hash2, int hash2_len){
    int ret;
    cmd_req_t *req_ptr;
    if(hash1_len > 256 || hash2_len > 32){
	printf("hash too long\n");
	return -3;
    }

    if (loadTZAPP()) {
	return -1;
    } 

    req_ptr = (cmd_req_t *)QSEEComHandle->ion_sbuffer;
    memset(req_ptr->data, 0, MARKER_DATA_LEN);
    memcpy(req_ptr->data, &success_pattern, 4);
    if(hash1_len)
	memcpy(req_ptr->data+4, hash1, hash1_len);
    if(hash2_len)
	memcpy(req_ptr->data+4+256, hash2, hash2_len);

    ret = TZAPPSendMarkerCmd(6);
    unloadTZAPP();
    return ret;
}

//-2: file does not exist. -1: internal error. 0: success, 1 success pattern did not match. 2: root hash did not match. 3: fota hash did not match.
int check_marker_cmd(uint32_t success_pattern, uint8_t * hash1, int hash1_len, uint8_t * hash2, int hash2_len){
    int ret;
    cmd_req_t *req_ptr;
    if(hash1_len > 256 || hash2_len > 32){
	printf("hash too long\n");
	return -3;
    }

    if (loadTZAPP()) {
	return -1;
    } 

    req_ptr = (cmd_req_t *)QSEEComHandle->ion_sbuffer;
    memset(req_ptr->data, 0, MARKER_DATA_LEN);
    memcpy(req_ptr->data, &success_pattern, 4);
    if(hash1_len)
	memcpy(req_ptr->data+4, hash1, hash1_len);
    if(hash2_len)
	memcpy(req_ptr->data+4+256, hash2, hash2_len);

    ret = TZAPPSendMarkerCmd(7);
    unloadTZAPP();
    return ret;
}

void remove_marker_cmd(void){
    if (loadTZAPP()) {
	return;
    } 
    TZAPPSendMarkerCmd(8);
    unloadTZAPP();
}

static void TZAPPSendSigningCmd()
{
    cmd_req_t *req_ptr;
    cmd_rsp_t *rsp_ptr;
    int ret, i;

    req_ptr = (cmd_req_t *)QSEEComHandle->ion_sbuffer;
    rsp_ptr = (cmd_rsp_t *)(QSEEComHandle->ion_sbuffer + sizeof(cmd_req_t));

    req_ptr->cmd_id = 5;
    req_ptr->dataLen = buf_len;
    memcpy(req_ptr->data, buf, buf_len);
    memcpy(req_ptr->hash, sha256hash, 32);
    req_ptr->hash_len = 32;

    ret = QSEECom_set_bandwidth(QSEEComHandle, true);
    if (ret < 0) {
	fprintf(stderr, "Failed to set bandwidth\n");
	return;
    }

    ret = QSEECom_send_cmd(QSEEComHandle, req_ptr, sizeof(cmd_req_t),
			   rsp_ptr, sizeof(cmd_rsp_t));
    if(ret < 0) {
	QSEECom_set_bandwidth(QSEEComHandle, false);
	fprintf(stderr, "Failed to send command\n");
	return;
    } else 
	printf("TZAPP send cmd successful\n");

    printf("Return val: %d\n", rsp_ptr->status);
#if 0
    for (i = 1; i <= rsp_ptr->dataLen; i++) {
	if (isalnum(rsp_ptr->data[i-1])) 
	    printf(" %c ", rsp_ptr->data[i-1]);
	else
	    printf("%.2x ", rsp_ptr->data[i-1]);
	if (i%32 == 0)
	    printf("\n");
    }
#endif

    ret = QSEECom_set_bandwidth(QSEEComHandle, false);
    if (ret < 0) {
	fprintf(stderr, "Failed to reset bandwidth\n");
	return;
    }

    if (rsp_ptr->status != 0) {
	fprintf(stderr, "TZAPP returned error %d\n", rsp_ptr->status);
	return;
    }
}

#ifdef USE_LIBDEVKM
char	path[4096];
struct KeyInfo keyInfo;
int generate_signature(char *input, int input_size, char **result, uint32_t *result_size)
{
    int ret, i;
    cmd_req_t	*req_ptr;
    cmd_rsp_t	*rsp_ptr;

    ret = calc_hash(input, input_size, sha256hash);
    if (0 != ret) {
	fprintf(stderr, "Error calculating hash of input\n");
	return 1;
    }
 
    memset(&keyInfo, 0, sizeof(keyInfo)); 
    keyInfo.crt = 1;
    keyInfo.keyLen = 2048;
    strcpy(keyInfo.serviceName, "DMVT");
    ret = generateServiceKey(RSA_KEY, (uint8_t*)&keyInfo, sizeof(keyInfo),
			     TZAPP_ORI, sizeof(TZAPP_ORI));
    if (NO_ERROR != ret) {
	fprintf(stderr, "Generate key failed with returned code %d :(\n", ret);
	return -ret;
    } else {
	printf("Key generation success\n");
    }

    /* At this point keyInfo structure is completely populated, so we can use it as 
     * it is
     */
    
    /*ret = verifyServiceKey(RSA_KEY, (const uint8_t *)&keyInfo, sizeof(keyInfo));
    if (NO_ERROR != ret) {
	fprintf(stderr, "Key verification failed with returned code %d :( \n",ret);
	return 1;
    } else
	printf("Key verification success\n");*/
	printf("Key verification skipped \n");
	
    ret = loadTZAPP();
    if (0 != ret) {
	return 1;
    } else 
	printf("TZAPP loaded successfully\n");

    ret = shareServiceKeyInit();
    if (NO_ERROR != ret) {
	fprintf(stderr, "Error init-ing key sharing with returned code %d :( \n",ret);
	goto unload_app;
    } else
	printf("Key sharing init-ed successfully\n");

    ret = shareServiceKey("DMVT", buf, &buf_len);
    if (NO_ERROR != ret) {
	shareServiceKeyFinal();
	fprintf(stderr, "Failed sharing key with returned code %d :( \n", ret);
	goto unload_app;
    } else {
	printf("Got key blob successfully. buflen: %d\n", buf_len);
		
#if 0
	for (i = 0; i < buf_len; i++) {
	    if (isalnum(buf[i]))
		printf(" %c ", buf[i]);
	    else
		printf("%.2x ", buf[i]);

	    if (i%32 == 0)
		printf("\n");
	}
#endif
		
    }

    TZAPPSendSigningCmd();

    req_ptr = (cmd_req_t *)QSEEComHandle->ion_sbuffer;
    rsp_ptr = (cmd_rsp_t *)(QSEEComHandle->ion_sbuffer + sizeof(cmd_req_t));
    if (rsp_ptr->status == 0) {
	parse_output(req_ptr, rsp_ptr, result, result_size);
    } else {
	*result = NULL;
	*result_size = 0;
	shareServiceKeyFinal();
	return 1;
    }

    ret = shareServiceKeyFinal();
    if (NO_ERROR != ret) {
	fprintf(stderr, "Failed ending key sharing session\n");
	goto unload_app;
    } else
	printf("Key sharing session ended successfully\n");

unload_app:
    unloadTZAPP();
    return 0;
}
#else
int generate_signature(char *input, int input_size, char **result, uint32_t *result_size){
	
	fprintf(stderr, "libdevkm unsupported . Generating signature fails \n");
	return -1 ;
}
#endif

//static int verify_zero(FILE *wr, size_t bytes) {
//	char block[bytes];
//	size_t i;
//
//	if (fread(block, bytes, 1, wr) != 1) {
//		printf("EIO while reading spare area.");
//		return -EIO;
//	}
//	for (i = 0; i < bytes; i++) {
//		if (block[i]) {
//			printf("Spare area is not zeroed at position.\n");
//			return -EPERM;
//		}
//	}
//	return 0;
//}



static ssize_t hex_to_bytes(const char *string, char * bytes) {
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

/* void write_certificate_blob(const char *dev_path, char *blob, unsigned int blob_size) */
/* { */
/*     uint64_t	devsize; */
/*     int r, fd; */

/*     if (blob_size >= 4096) */
/* 	error_errno("Suspicious blob size"); */

/*     r = device_size(dev_path, &devsize); */
/*     if (0 != r) */
/* 	error_errno("failed to get device size"); */

/*     fd = open(dev_path, O_WRONLY); */
/*     if (fd < 0)  */
/* 	error_errno("Failed to open device"); */

/*     r = lseek64(fd, devsize - sizeof(blob_size), SEEK_SET); */
/*     if (-1 == r) */
/* 	error_errno("Failed to seek"); */

/*     r = write(fd, &blob_size, sizeof(blob_size)); */
/*     if (-1 == r) */
/* 	error_errno("Failed to write size"); */

/*     r = lseek64(fd, devsize - (blob_size + sizeof(blob_size)), SEEK_SET); */
/*     if (-1 == r) */
/* 	error_errno("Failed to seek again"); */

/*     r = write(fd, blob, blob_size); */
/*     if (-1 == r) */
/* 	error_errno("Failed to write blob"); */

/*     close(fd); */
/* } */


/*
 * <path to block device> <data block size> <hash block size> <meta data size>(in hash blocks) <alg>
 * */
/* int generate_verity(const int meta_version, const int dm_verity_version, */
/* 		    const char *data_device, const size_t data_block_size, */
/* 		    const size_t hash_block_size, const size_t meta_size, */
/* 		    const char *hash_name) { */
/*     printf("generate_verity\n"); */
/*     loff_t data_blocks = 0; */
/*     int hash_size = 0; */
/* #define DIGEST_SIZE 32 */
/*     char root_hash[DIGEST_SIZE]; */
/* #define SALT_SIZE 32 */
/*     char salt[SALT_SIZE]; */
/*     unsigned char	*result; */
/*     uint32_t	result_size; */
/*     if(0 == strcmp(hash_name, SHA256_NAME)) */
/* 	hash_size = 32; */
/*     else if (0 == strcmp(hash_name, SHA1_NAME)) */
/* 	hash_size = 20; */
/*     else{ */
/* 	printf("hash algorithm %s not supported\n", hash_name); */
/* 	return -1; */
/*     } */
/*     //read_random(salt, 2);//sometimes this takes tooo long */
/*     milestone("salt generated"); */
/*     /\* char salt_str[SALT_SIZE*2+1]; *\/ */
/*     /\* memset(salt_str, 0, SALT_SIZE*2+1); *\/ */
/*     /\* bytes_to_hex(salt, salt_str, SALT_SIZE); *\/ */
/*     /\* printf("salt: %s\n", salt_str); *\/ */
/*     int r; */
/*     uint64_t ext4_size; */
/*     r = ext4_part_size(data_device, &ext4_size); */
/*     if (r < 0) */
/* 	error("error getting invalid ext4 size"); */
/*     else */
/* 	printf("ext4 size: %lld\n", (long long int) ext4_size); */
/*     data_blocks = ext4_size / data_block_size; */

/*     if (VERITY_create_hash(dm_verity_version, hash_name, tmp_hash_file, data_device, */
/* 			   hash_block_size, data_block_size, data_blocks, meta_size, root_hash, */
/* 			   hash_size, salt, hash_size)) { */
/* 	error("error calculating hash"); */
/*     } */
/*     milestone("hash caculated"); */
/*     //////////////////////////write verity meta data */

/*     //now write the table. the table format: */
/*     //<ver> <data_dev> <hash_dev> <data_blk_size> <hash_blk_size> <#blocks> <hash_start> <alg> <digest> <salt> */
/*     char * meta; */
/*     char * table; */
/*     struct verity_meta_header * header; */
/*     long meta_start = (data_blocks * data_block_size + hash_block_size - 1) */
/* 	/ hash_block_size; */
/*     long hash_start = meta_start + meta_size; */
/*     int table_size = nDigits(dm_verity_version) + 1 + strlen(data_device) + 1 */
/* 	+ strlen(data_device) + 1 + nDigits(data_block_size) + 1 */
/* 	+ nDigits(hash_block_size) + 1 + nDigits(data_blocks) + 1 */
/* 	+ nDigits(hash_start) + 1 + strlen(hash_name) + 1 + hash_size * 2 */
/* 	+ 1 + hash_size * 2 + 1; */
/* //	printf("table size is %d\n", table_size); */
/*     if ((table_size + sizeof(struct verity_meta_header)) */
/* 	> meta_size * hash_block_size) { */
/* 	error("meta size exceeded"); */
/*     } */
/*     meta = malloc(table_size + sizeof(struct verity_meta_header)); */
/*     memset(meta, 0, table_size + sizeof(struct verity_meta_header)); */
/*     if (NULL == meta) { */
/* 	error("malloc failed"); */
/*     } */
/*     header = (struct verity_meta_header *) meta; */
/*     header->magic_number = VERITY_METADATA_MAGIC_NUMBER; */
/*     header->protocol_version = meta_version; */
/*     header->table_length = table_size - 1;//not including trailing NULL */
/*     table = meta + sizeof(struct verity_meta_header); */
/*     r = sprintf(table, "%d %s %s %lld %lld %lld %lld %s ", dm_verity_version, data_device, */
/* 		data_device, (long long int) data_block_size, */
/* 		(long long int) hash_block_size, (long long int) data_blocks, */
/* 		(long long int) hash_start, hash_name); */
/*     if (r <= 0) { */
/* 	error("sprintf error"); */
/*     } */
/*     table += r; */
/*     bytes_to_hex(root_hash, table, hash_size); */
/*     table += hash_size * 2; */
/*     r = sprintf(table, " "); */
/*     if (r <= 0) { */
/* 	error("sprintf error"); */
/*     } */
/*     table += r; */
/*     bytes_to_hex(salt, table, hash_size); */
/*     table += hash_size * 2; */
/*     long table_size_2 = table - meta - sizeof(struct verity_meta_header) + 1;//count the ending NULL */
    
/*     table = meta + sizeof(struct verity_meta_header); */
/*     if (table_size_2 != table_size) { */
/* //		printf("%s\n", table); */
/* //		printf("%ld\n", strlen(table)); */
/* 	error("table size error: %ld:%d", table_size_2, table_size); */
/*     } */
/*     r = generate_signature(table, table_size, &result, &result_size); */
/*     if (0 != r) { */
/* 	error("Error generating signature via TIMA: %d", r); */
/*     } else  */
/* 	milestone("TIMA signature generated"); */

/*     FILE * hash_fp = fopen(tmp_hash_file, "r+"); */
/*     if (NULL == hash_fp) { */
/* 	error_errno("error opening tmp hash file"); */
/*     } */
/*     r = fwrite(meta, table_size + sizeof(struct verity_meta_header), 1, */
/* 	       hash_fp); */
/*     if (1 != r) { */
/* 	error_errno("fwrite error: %d:%d", r, 1); */
/*     } */
/*     r = fclose(hash_fp); */
/*     if (r) { */
/* 	error_errno("close error"); */
/*     } */
/*     milestone("header written to ram file"); */
/*     file_to_device(tmp_hash_file, data_device, 1024 * 1024, */
/* 		   data_blocks * data_block_size); */
/*     milestone("meta and hash tree written to flash"); */

/*     /\* Write certificate info at the end of the device *\/ */
/*     write_certificate_blob(data_device, result, result_size); */
/*     milestone("Wrote public cert at end of the device"); */

/*     //unlink(tmp_hash_file); */
/*     printf("success\n"); */
/*     return 0; */
/* } */

const uint32_t MARKER_SUCCESS_PATTERN = 0xdeadbeef;

int set_marker(const char * hex_seed){
    printf("set marker\n");
    char seed[SECURE_MARKER_SEED1_LEN];
    int len = strlen(hex_seed);
    if(2*SECURE_MARKER_SEED1_LEN != len){
	return -1;
    }
    if(hex_to_bytes(hex_seed, seed) < 0)
	return -1;
    return set_marker_cmd(MARKER_SUCCESS_PATTERN, seed, SECURE_MARKER_SEED1_LEN, NULL, 0);
}

int check_marker(const char * hex_seed){
    printf("check marker\n");
    char seed[SECURE_MARKER_SEED1_LEN];
    int len = strlen(hex_seed);
    if(2*SECURE_MARKER_SEED1_LEN != len){
	return -1;
    }
    if(hex_to_bytes(hex_seed, seed) < 0)
	return -1;
    return check_marker_cmd(MARKER_SUCCESS_PATTERN, seed, SECURE_MARKER_SEED1_LEN, NULL, 0);
}

int remove_marker(void){
    printf("remove marker\n");
    remove_marker_cmd();
    return 0;
}

//the last 4 bytes of the blob is the size.
int sign_blob(const char * tmp_blob_file){
    int ret = -1;
    struct stat st;
    if(stat(tmp_blob_file, &st)){
	printf("error stating %s\n", tmp_blob_file);
	return -1;
    }
    char * blob = NULL;
    char * signature = NULL;
    uint32_t signature_size;
    blob = malloc(st.st_size);
    if(NULL == blob){
	return -1;
    }
    int fd = -1;
    fd = open(tmp_blob_file, O_RDONLY);
    if(fd < 0)
	goto free_blob;
    if(st.st_size != read(fd, blob, st.st_size))
	goto close_fd;
    close(fd);
    fd = -1;
    if(ret = generate_signature(blob, st.st_size, &signature, &signature_size))
		goto free_signature;
    fd = open(tmp_blob_file, O_WRONLY);
    if(fd < 0)
	goto free_signature;
    if(signature_size != write(fd, signature, signature_size))
    	goto free_signature;
    if(sizeof(signature_size) != write(fd, &signature_size, sizeof(signature_size)))
    	goto free_signature;
    ret = 0;
free_signature:
    if(signature)
	free(signature);
close_fd:
    if(fd >= 0)
	close(fd);
free_blob:
    if(blob)
	free(blob);
    return ret;
}

void usage(void){
    printf("sign blob:\n");
    printf("sign_blob <path to tmp file contain blob>\n");
    printf("set secure marker:\n");
    printf("set_marker <seed string in hex>\n");
    printf("check secure marker:\n");
    printf("check_marker <seed string in hex>\n");
    printf("remove secure marker:\n");
    printf("remove_marker\n");
}

void redirect(){
    static const char *TEMPORARY_LOG_FILE = "/tmp/recovery.log";
    printf("redirecting stdout and stderr to %s\n", TEMPORARY_LOG_FILE);
    freopen(TEMPORARY_LOG_FILE, "a", stdout); setbuf(stdout, NULL);
    freopen(TEMPORARY_LOG_FILE, "a", stderr); setbuf(stderr, NULL);
}

int main(int argc, const char ** argv) {
    if(argc < 2){
	usage();
	return -1;
    }
    //redirect();
    if(0 == strcmp(argv[1], "sign_blob")){
	return sign_blob(argv[2]);
    }else if(0 == strcmp(argv[1], "set_marker")){
	return set_marker(argv[2]);
    }else if(0 == strcmp(argv[1], "check_marker")){
	return check_marker(argv[2]);
    }else if(0 == strcmp(argv[1], "remove_marker")){
	return remove_marker();
    }
    usage();
    return -1;
}

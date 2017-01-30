#ifndef __LIB_DM_VERITY___
#define __LIB_DM_VERITY___
#define SHA1_NAME "sha1"
#define SHA256_NAME "sha256"
#define DMVERITY_BLOCK_SIZE 4096
#define DMVERITY_META_SIZE (DMVERITY_BLOCK_SIZE*8)

#define VERITY_METADATA_MAGIC_NUMBER 0xb001b001

#define DMVERITY_DRK_ERROR1 9
#define DMVERITY_DRK_ERROR2 11

#define SIGN_ERR 99

//  Google's dm-verity meta data header format:
//	unsigned magic_number; : #define VERITY_METADATA_MAGIC_NUMBER 0xb001b001
//	int protocol_version; : 0
//	char signature[RSANUMBYTES]
//	unsigned table_length;
//	char table[table_length]
struct verity_meta_header {
    unsigned magic_number;
    int protocol_version;
    char signature[256];
    unsigned table_length;
};

//clear secure marker salt and secure marker. to be invoked at the very end of recovery main function.
void dm_verity_recovery_end(void);

//backup tzapp partition to /cache. check odin flag/hash/sfs flag. return none-zero if checking fails. set sfs flag (and generate marker salt) if necessary.
int dm_verity_update_start(void);

//if update_status is zero, generate new hash array and root hash, and sign root hash. clear secure marker salt and secure marker.
int dm_verity_update_end(void);

//regenerate a full hash of /system, and have the hash tree signed. This is typically used when a power failure during the pathcing process.
int dm_verity_rehash(void);

//check sfs marker
int dm_verity_check_marker(void);

// set sfs marker
int dm_verity_set_marker(void);

// drop cache
void dm_verity_drop_cache(void);

int set_forced_into_recovery(void);

int dm_verity_verify(void);
#endif

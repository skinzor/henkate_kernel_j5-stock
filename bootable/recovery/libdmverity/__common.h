#ifndef ___COMMON_____
#define ___COMMON_____
void stopwatch_start();
uint64_t stopwatch_stop();
void milestone(const char * msg);
void bytes_to_hex(const char * in, char * out, int size);
ssize_t hex_to_bytes(const char *string, char * bytes) ;
int file_cmp(const char * file_a, const char * file_b, unsigned long offset_a,
             unsigned long offset_b, int buffer_size);
//int file_to_device(const char * file, const char * dev, int buffer_size,
//                   unsigned long offset);
int ext4_part_size(const char *blk_device, uint64_t *device_size);
int device_size(const char *device_file, uint64_t *size);
char * generate_dm_verity_hash(const char * target_dev, const char * image_file, uint64_t part_size, const char * tmp_hash_file);
char * regenerate_dm_verity_hash(const char * target_dev, uint64_t part_size, const char * tmp_hash_file);
#endif

#include <sparse/sparse.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/mount.h>
#include "libdmverity.h"
#include "libdmverity_hashgen/libdmverity_hashgen.h"
#include "__common.h"
#include <stdlib.h>
#ifndef O_BINARY
#define O_BINARY 0
#endif

#define _LARGEFILE64_SOURCE
#define _FILE_OFFSET_BITS 64
#define SIGNATURE_SIZE 256
static void usage(void){
    printf("img_dm_verity <dev path on target> <dev size> <sparse_ext4_img> <output_file>\n");
    return;
}

static int build_verity_hash(const char * target_dev, const uint64_t dev_size, const char * image_file, uint64_t part_size, const char * tmp_hash_file, const char * tmp_table_file, const char * my_dir){
    char * table = NULL, * cmd_string = NULL;
    FILE * fp;
    int ret = -1;
    struct stat st;
    struct verity_meta_header meta_header;
    char signature[SIGNATURE_SIZE];
    loff_t offset;
    table = generate_dm_verity_hash(target_dev, image_file, part_size, tmp_hash_file);
    if(NULL == table){
        printf("failed to generate verity hash\n");
        return -1;
    }
    printf("verity table: %s\n", table);
    meta_header.magic_number = VERITY_METADATA_MAGIC_NUMBER;
    meta_header.protocol_version = 0;
    meta_header.table_length = strlen(table);
    memset(&meta_header.signature, 0, sizeof(meta_header.signature));
    //not including trailing NULL
    //TODO: sign table and write signature to the end of hash file.
    //tmp_hash_file it should have been created by generate_dm_verity_hash already.
    fp = fopen(tmp_hash_file, "r+");
    if (NULL == fp) {
        printf("failed to open temp hash file\n");
        goto exit;
    }
    if(1 != fwrite(&meta_header, sizeof(struct verity_meta_header), 1, fp)){
        printf("failed to write temp hash file\n");
        goto exit;
    }
    if(1 != fwrite(table, meta_header.table_length+1, 1, fp)){
        printf("failed to write temp hash file\n");
        goto exit;
    }
    fclose(fp);
    fp = fopen(tmp_table_file, "w");
    if (NULL == fp) {
        printf("failed to open temp table file\n");
        goto exit;
    }
    //TODO check whether we are signing table or the whole header.
    if(1 != fwrite(table, meta_header.table_length+1, 1, fp)){
        printf("failed to write temp table file\n");
        goto exit;
    }
    fclose(fp);
    fp = NULL;
    const char * cmd_string_template = "java -jar %s/../../../../../buildscript/tools/signclient.jar -runtype ss_openssl_timadb -model TIMA_DB_ADONIS -input %s -output %s.sign";
    const char * mv_string_template = "mv %s.sign %s";
    int cmd_string_len = strlen(cmd_string_template) + strlen(tmp_table_file) * 2 + strlen(my_dir) + 1;
    cmd_string = malloc(cmd_string_len);
    if(NULL == cmd_string){
        printf("malloc failed\n");
        goto exit;
    }
    memset(cmd_string, 0, cmd_string_len);
    sprintf(cmd_string, cmd_string_template, my_dir, tmp_table_file, tmp_table_file);
    printf("running %s\n", cmd_string);
    if(system(cmd_string)){
        printf("and failed\n");
        goto exit;
    }

    sprintf(cmd_string, mv_string_template, tmp_table_file, tmp_table_file);
    printf("running %s\n", cmd_string);
    if(system(cmd_string)){
        printf("and failed\n");
        goto exit;
    }

    if(stat(tmp_table_file, &st)){
        printf("failed to stat\n");
        goto exit;
    }
    if(st.st_size != (meta_header.table_length+1+SIGNATURE_SIZE)){
        printf("invalided signed file size\n");
        goto exit;
    }
    fp = fopen(tmp_table_file, "r");
    if(NULL == fp){
        printf("failed to open %s\n", tmp_table_file);
        goto exit;
    }
    offset = (unsigned long long)(meta_header.table_length+1);
    if(fseeko(fp, offset, SEEK_SET)){
        printf("failed to seek %s, %Lx\n", tmp_table_file, offset);
        goto exit;
    }
    if(1 != fread(signature, SIGNATURE_SIZE, 1, fp)){
        printf("failed to read %s\n", tmp_table_file);
        goto exit;
    }
    fclose(fp);
    fp = fopen(tmp_hash_file, "r+");
    if(NULL == fp){
        printf("failed to open %s\n", tmp_hash_file);
        goto exit;
    }
    offset = (unsigned long long)(dev_size - part_size - sizeof(unsigned int) - SIGNATURE_SIZE);    
    if(fseeko(fp, offset, SEEK_SET)){
        printf("failed to seek %s, %Lx\n", tmp_hash_file, offset);
        printf("%llu, %llu, %u, %d\n", dev_size, part_size, sizeof(unsigned int), SIGNATURE_SIZE);
        goto exit;
    }
    if(1 != fwrite(signature, SIGNATURE_SIZE, 1, fp)){
        printf("failed to write %s\n", tmp_hash_file);
        goto exit;
    }
    unsigned int size = SIGNATURE_SIZE;
    if(1 != fwrite(&size, sizeof(size), 1, fp)){
        printf("failed to write %s\n", tmp_hash_file);
        goto exit;
    }
    fclose(fp);
    fp = NULL;
    ret = 0;
 exit:
    if(fp)
        fclose(fp);
    if(table)
        free(table);
    if(cmd_string)
        free(cmd_string);
    return ret;
}

int main(int argc, const char ** argv){
    int ret = -1;
    int in = 0, out = 0, i;
    //    char * target_dev, * sparse_ext4_img, * output_file;
    uint64_t part_size, hash_size;

    char * tmp_image_file = NULL, * tmp_hash_file = NULL, * tmp_table_file = NULL;
    struct sparse_file * s = NULL;
    unsigned int block;
    char * table;
    char my_dir[256] = {0,};
    if(5 != argc){
        usage();
        return -1;
    }

    const char * target_dev = argv[1];
    const uint64_t dev_size = (uint64_t)atoll(argv[2]);
    const char * sparse_ext4_img = argv[3];
    const char * output_file = argv[4];
    readlink("/proc/self/exe", my_dir, 256);
    for(i=strlen(my_dir); my_dir[i] != '/' && i>=0; i--){
        ;
    }
    my_dir[i] = 0;
    tmp_image_file = malloc(strlen(output_file)+1+6);//.image
    if(NULL == tmp_image_file){
        printf("malloc failed\n");
        return -1;
    }
    memset(tmp_image_file, 0, strlen(output_file)+1+6);
    sprintf(tmp_image_file, "%s.image", output_file);

    tmp_hash_file = malloc(strlen(output_file)+1+5);//.hash
    if(NULL == tmp_hash_file){
        printf("malloc failed\n");
        goto exit;
    }
    memset(tmp_hash_file, 0, strlen(output_file)+1+5);
    sprintf(tmp_hash_file, "%s.hash", output_file);

    tmp_table_file = malloc(strlen(output_file)+1+6);//.table
    if(NULL == tmp_table_file){
        printf("malloc failed\n");
        goto exit;
    }
    memset(tmp_table_file, 0, strlen(output_file)+1+6);
    sprintf(tmp_table_file, "%s.table", output_file);

    in = open(sparse_ext4_img, O_RDONLY | O_BINARY);
    if (in < 0) {
        printf("Cannot open input file %s\n", sparse_ext4_img);
        goto exit;
    }
    s = sparse_file_import(in, true, false);//same setting as in simg2img.c
    if (!s) {
        printf("Failed to read sparse file\n");
        goto exit;
    }
    out = open(tmp_image_file, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, 0664);
	if (out < 0) {
		printf("Cannot open output file %s\n", tmp_image_file);
        goto exit;
	}
    if (sparse_file_write(s, out, false, false, false) < 0) {
        printf("Cannot write output file\n");
        goto exit;
    }
    close(out);
    out = 0;
    if(ext4_part_size(tmp_image_file, &part_size)){
        printf("failed to get part or dev sizes\n");
        goto exit;
    }
    block = part_size/sparse_file_block_size(s);
    if(build_verity_hash(target_dev, dev_size, tmp_image_file, part_size, tmp_hash_file, tmp_table_file, my_dir)){
        printf("failed to build hash\n");
        goto exit;
    }
    if(device_size(tmp_hash_file, &hash_size)){
        printf("invalid hash file generated\n");
        goto exit;
    }
    printf("adding verity data to block %d\n", block);
    if(sparse_file_add_file(s, tmp_hash_file, 0, hash_size, block)){
        printf("failed to add to sparse file\n");
        goto exit;
    }
    sparse_file_update_len(s);
    out = open(output_file, O_WRONLY | O_CREAT | O_TRUNC | O_BINARY, 0664);
    if (out < 0) {
        printf("Cannot open output file %s\n", output_file);
        goto exit;
    }
	if (sparse_file_write(s, out, false, true, false)) {
		printf("Failed to write sparse file\n");
        goto exit;
	}
    ret = 0;
exit:
    if(tmp_image_file){
        //        unlink(tmp_image_file);
        free(tmp_image_file);
    }
    if(tmp_hash_file){
        //        unlink(tmp_hash_file);
        free(tmp_hash_file);
    }
    if(tmp_table_file){
        //        unlink(tmp_table_file);
        free(tmp_table_file);
    }
    if(s)
        sparse_file_destroy(s);
    if(in>0)
        close(in);
    if(out>0)
        close(out);
    return ret;
}

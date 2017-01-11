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
///#include <QSEEComAPI.h>
#include <ctype.h>
#include <openssl/sha.h>

#include "secure_marker.h"
//#include "tlc_tz_dmverity.h"
/* #include "libdmverity.h" */
/* #include "ext4.h" */
/* #include "ext4_utils.h" */
/* #include "mincrypt/rsa.h" */
/* #include "mincrypt/sha256.h" */
/* #include "mincrypt/sha.h" */

///#define	USE_QSEE
//#include <LibDevKMApi.h>

////////////////////////////////////////////////////

/*  Shyam code PnP                                */

////////////////////////////////////////////////////


//the last 4 bytes of the blob is the size.
int sign_blob_stub(const char * tmp_blob_file){
    printf("start signing blob.\n");

    FILE * fp;
    int blob_size = 128;
    int ret = -1;

    fp = fopen(tmp_blob_file, "a");
    if (fp) {
       if (1 != fwrite(&blob_size, sizeof (int), 1, fp)) {
        printf("fwrite in sign_blob_stub failed.\n");
        goto close_fp;
       }
    } else {
        printf("failed to opn blob file.\n");
        goto close_fp;
    }
    
    ret = 0;

close_fp:
    if(fp) 
        fclose(fp);
    printf("finish signing blob.\n");
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

int main(int argc, const char ** argv) {
    if(argc < 2){
	usage();
	return -1;
    }
    //redirect();
    if(0 == strcmp(argv[1], "sign_blob")){
	return sign_blob_stub(argv[2]);
    //    return 0;
    }else if(0 == strcmp(argv[1], "set_marker")){
	//return set_marker(argv[2]);
        return 0;
    }else if(0 == strcmp(argv[1], "check_marker")){
	//return check_marker(argv[2]);
        return 0;
    }else if(0 == strcmp(argv[1], "remove_marker")){
	//return remove_marker();
        return 0;
    }
    usage();
    return -1;
}

#include <stdio.h>
#include "libdmverity.h"


/* dummy function definitions for eliminate compilation errors */
void ui_print(const char *fmt, ...) {
}

void ui_print_warning(const char *fmt, ...) {
}

void klog_write(int level, const char *fmt, ...){
}
/* end of dummy function definitions */




int main(void)
{
    load_volume_table();

    if (dm_verity_rehash() < 0) {
        printf("The regeneration of full hash on device FAILED!. \n");
    } else {
        printf("The regeneration of full hash on device SUCCEEDED!. \n");
    }

    return 0;
}

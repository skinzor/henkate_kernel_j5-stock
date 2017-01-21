#ifndef __SECURE_MARKER____
#define __SECURE_MARKER____
#define SECURE_MARKER_SEED1_LEN 256
#define SECURE_MARKER_SEED2_LEN 32
#if !defined(APQ_8084) && !defined(MSM_8916) && !defined(MSM_8996)
#define SECURE_MARKER_SALT_FILE "/efs/prov_data/dmvt/sfs_marker_salt"
#else
#define SECURE_MARKER_SALT_FILE "/efs/prov_data/sfs_marker_salt"
#endif
#endif

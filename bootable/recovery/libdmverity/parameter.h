#define RECOVERY_ENTER_MODE 2
#define REBOOT_MODE_RECOVERY 4

typedef struct _param {
	int booting_now;	// 1:boot   0:enter service   5: fota
	int pvs_value;	// 0xfafa or 0x0 for D2 docomo
	int update;
	int movinand_checksum_done;
	int movinand_checksum_pass;
	int nvdata_backup;
	char sales_code[4];
	char str1[32];
	char str2[32];
	int security_mode;
} PARAM;

#define PARAM_ENV_MAGIC_CODE    (0xCAFE0003)
#define MAX_INT_PARAM   (10)
#define MAX_STR_PARAM   (3)

typedef enum {
        PARAM_INVALID = -1,
        PARAM_REBOOT_MODE = 0,
        PARAM_SWITCH_SEL,
        PARAM_DEBUG_LEVEL,
        PARAM_SUD_MODE,
        PARAM_DN_ERROR,
        PARAM_CHECKSUM,
        PARAM_ODIN_DOWNLOAD,
        PARAM_SALES_CODE,
		PARAM_SECURITY_MODE,
        PARAM_INT_RSVD9,
        PARAM_CMDLINE,
        PARAM_STR_RSVD1,
        PARAM_STR_RSVD2,
} prm_id_t;

typedef struct {
        unsigned int header[128];
        int int_param[MAX_INT_PARAM];
        char str_param[MAX_STR_PARAM][1024];
} prm_env_file;

enum PARAM_TYPE
{
	PARAM_UNKNOWN,
	PARAM_SBOOT,
	PARAM_LK
};

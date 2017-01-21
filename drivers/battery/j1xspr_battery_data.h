#define CAPACITY_MAX			1000
#define CAPACITY_MAX_MARGIN     70
#define CAPACITY_MIN			0

static sec_bat_adc_table_data_t temp_table[] = {
  {25991, 900},
  {26160, 850},
  {26398, 800},
  {26697, 750},
  {27067, 700},
  {27478, 650},
  {28035, 600},
  {28437, 550},
  {29094, 500},
  {29841, 450},
  {30679, 400},
  {31595, 350},
  {32605, 300},
  {33629, 250},
  {34707, 200},
  {35809, 150},
  {36906, 100},
  {37994, 50},
  {38900, 0},
  {39745, -50},
  {40475, -100},
  {41075, -150},
  {41483, -200},
};

#define TEMP_HIGHLIMIT_THRESHOLD_EVENT		800
#define TEMP_HIGHLIMIT_RECOVERY_EVENT		750
#define TEMP_HIGHLIMIT_THRESHOLD_NORMAL		800
#define TEMP_HIGHLIMIT_RECOVERY_NORMAL		750
#define TEMP_HIGHLIMIT_THRESHOLD_LPM		800
#define TEMP_HIGHLIMIT_RECOVERY_LPM		750

#define TEMP_HIGH_THRESHOLD_EVENT  550
#define TEMP_HIGH_RECOVERY_EVENT   500
#define TEMP_LOW_THRESHOLD_EVENT   (-30)
#define TEMP_LOW_RECOVERY_EVENT    0
#define TEMP_HIGH_THRESHOLD_NORMAL 550
#define TEMP_HIGH_RECOVERY_NORMAL  500
#define TEMP_LOW_THRESHOLD_NORMAL  (-30)
#define TEMP_LOW_RECOVERY_NORMAL   0
#define TEMP_HIGH_THRESHOLD_LPM    550
#define TEMP_HIGH_RECOVERY_LPM     500
#define TEMP_LOW_THRESHOLD_LPM     (-30)
#define TEMP_LOW_RECOVERY_LPM      0

#if defined(CONFIG_BATTERY_SWELLING)
#define BATT_SWELLING_HIGH_TEMP_BLOCK		500
#define BATT_SWELLING_HIGH_TEMP_RECOV		450
#define BATT_SWELLING_LOW_TEMP_BLOCK		50
#define BATT_SWELLING_LOW_TEMP_RECOV		100
#define BATT_SWELLING_RECHG_VOLTAGE		4150
#define BATT_SWELLING_BLOCK_TIME	10 * 60 /* 10 min */
#endif

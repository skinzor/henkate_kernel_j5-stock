TIMA_DIR = tima3
ifeq ($(TARGET_ARCH),arm64)
TIMA_DIR = arm64/tima3
else
TIMA_DIR = tima3
endif

LOCAL_PATH:= $(call my-dir)
ifneq (sc,$(findstring sc,$(TARGET_BOARD_PLATFORM)))
include $(CLEAR_VARS)

LOCAL_SRC_FILES := libdmverity.c __common.c pit.c device.c

LOCAL_CFLAGS := -Wall

LOCAL_C_INCLUDES += $(LOCAL_PATH)/..
LOCAL_C_INCLUDES += system/extras/ext4_utils
LOCAL_C_INCLUDES += system/core/fs_mgr/include

LOCAL_MODULE := libdmverity

ifeq (exynos,$(findstring exynos,$(TARGET_SOC)))
LOCAL_CFLAGS += -DEXYNOS_TZ
ifeq ($(TARGET_SOC),exynos5433)
LOCAL_CFLAGS += -DEXYNOS_5433
endif
ifeq ($(TARGET_SOC),exynos8890)
LOCAL_CFLAGS += -DEXYNOS_8890
LOCAL_CFLAGS += -DUSE_SHA256
endif
ifeq ($(TARGET_SOC),exynos7420)
LOCAL_CFLAGS += -DEXYNOS_7420
LOCAL_CFLAGS += -DUSE_SHA1
endif
ifeq ($(TARGET_SOC),exynos7870)
LOCAL_CFLAGS += -DEXYNOS_7870
LOCAL_CFLAGS += -DUSE_SHA256
endif
ifeq ($(TARGET_PROJECT), TRE)
LOCAL_CFLAGS += -DTRE_PROJECT
endif
ifeq ($(TARGET_SOC),exynos7580)
LOCAL_CFLAGS += -DEXYNOS_7580
endif
ifeq ($(TARGET_SOC),exynos3475)
LOCAL_CFLAGS += -DEXYNOS_3475
endif
ifeq ($(TARGET_SOC),exynos5430)
LOCAL_CFLAGS += -DEXYNOS_5430
endif
else
LOCAL_CFLAGS += -DQSEE_TZ
ifeq ($(TARGET_BOARD_PLATFORM),apq8084)
LOCAL_CFLAGS += -DAPQ_8084
endif
ifeq ($(TARGET_BOARD_PLATFORM),msm8996)
LOCAL_CFLAGS += -DUSE_SHA256
LOCAL_CFLAGS += -DMSM_8996
endif
ifeq ($(TARGET_BOARD_PLATFORM),msm8916)
LOCAL_CFLAGS += -DMSM_8916
endif
ifeq ($(TARGET_BOARD_PLATFORM),msm8953)
LOCAL_CFLAGS += -DUSE_SHA256
endif
endif

ifeq ($(SEC_BUILD_CONF_USE_KAP),true)
LOCAL_CFLAGS += -D__USE_KAP
endif

#LOCAL_STATIC_LIBRARIES := libcutils libc
include $(BUILD_STATIC_LIBRARY)

#include $(CLEAR_VARS)
#LOCAL_MODULE := libdevkm_dmverity
#LOCAL_MODULE_TAGS := optional
#LOCAL_PREBUILT_LIBS := libdevkm_dmverity.a
#include $(BUILD_MULTI_PREBUILT)

ifeq (,$(findstring exynos, $(TARGET_SOC)))
#include $(CLEAR_VARS)
#LOCAL_MODULE := libdevkm_dmverity
#LOCAL_MODULE_TAGS := optional
#LOCAL_PREBUILT_LIBS := libdevkm_dmverity.a
#include $(BUILD_MULTI_PREBUILT)

include $(CLEAR_VARS)
LOCAL_SRC_FILES:= tz_cmd_qsee.c
LOCAL_C_INCLUDES += bootable/recovery
LOCAL_C_INCLUDES += system/extras/ext4_utils
LOCAL_C_INCLUDES += $(LOCAL_PATH)/inc
LOCAL_C_INCLUDES +=  $(TOP)/vendor/qcom/proprietary/securemsm/QSEEComAPI
LOCAL_C_INCLUDES += $(TOP)/external/boringssl/include

LOCAL_MODULE:= dm_verity_tz_cmd

# dm_verity_tz_cmd will be blamed for build break
# when libdevkm not built.
# Order of static library matters !
LOCAL_STATIC_LIBRARIES = libmincrypt 
ifeq ($(PRODUCT_TRUSTZONE_ENABLED),true)
ifeq ($(PRODUCT_TRUSTZONE_TYPE), $(filter eos2 exynos3xxx exynos4xxx exynos5xxx exynos7xxx exynos8xxx msm8952 msm8953 msm8916 msm8974 msm8994 msm8996 msm89xx msm8x26 QC8064 QC8084,$(PRODUCT_TRUSTZONE_TYPE)))
LOCAL_STATIC_LIBRARIES += libdevkm
LOCAL_CFLAGS := -DUSE_LIBDEVKM
endif
endif
LOCAL_STATIC_LIBRARIES += libminzip libz libQSEEComAPIStatic libc liblog libext4_utils_static libcrypto_static_dmverity

ifeq ($(SEC_BUILD_CONF_DMVERITY_FOTALM),true)
LOCAL_CFLAGS += -DUSE_DMVERITY_FOTALM
endif

LOCAL_FORCE_STATIC_EXECUTABLE := true
LOCAL_CFLAGS += -fno-stack-protector -DQSEE_TZ
# This binary is in the recovery ramdisk, which is otherwise a copy of root.
# It gets copied there in config/Makefile.  LOCAL_MODULE_TAGS suppresses
# a (redundant) copy of the binary in /system/bin for user builds.
# TODO: Build the ramdisk image in a more principled way.
LOCAL_MODULE_TAGS := eng

#LOCAL_FORCE_STATIC_EXECUTABLE := true
LOCAL_MODULE_PATH := $(TARGET_ROOT_OUT)/sbin
# LOCAL_UNSTRIPPED_PATH := $(TARGET_ROOT_OUT_UNSTRIPPED)
include $(BUILD_EXECUTABLE)

else
#include $(CLEAR_VARS)
#LOCAL_SRC_FILES:= tz_cmd_mc.c

#LOCAL_C_INCLUDES += bootable/recovery
#LOCAL_C_INCLUDES += system/extras/ext4_utils
#LOCAL_C_INCLUDES += $(LOCAL_PATH)/inc
#LOCAL_C_INCLUDES += $(TOP)/external/openssl/include
#LOCAL_C_INCLUDES += vendor/samsung/common/external/tima/$(TIMA_DIR)/tlc_tz_dmverity/public
#LOCAL_C_INCLUDES += vendor/samsung/common/external/tima/$(TIMA_DIR)/tlc_tz_dmverity/public/msgs
#LOCAL_C_INCLUDES += \
#    vendor/samsung/common/external/tima/$(TIMA_DIR)/tlc_tima_common \
#    vendor/samsung/common/external/tima/$(TIMA_DIR)/tz_common/public \
#    vendor/samsung/common/external/tima/$(TIMA_DIR)/tlc_comm/public

#LOCAL_C_INCLUDES += \
#    vendor/samsung/common/external/tima/$(TIMA_DIR)/tlc_tima_common \
#    vendor/samsung/common/external/tima/$(TIMA_DIR)/tz_common/comm \
#    vendor/samsung/common/external/tima/$(TIMA_DIR)/tlc_comm/public \
#    vendor/samsung/common/external/tima/$(TIMA_DIR)/tz_common/public \
#    vendor/samsung/common/external/tima/$(TIMA_DIR)/tlc_tz_dmverity/public \
#    vendor/samsung/common/external/tima/$(TIMA_DIR)/tlc_tz_dmverity/public/msgs \
#    vendor/samsung/common/external/tima/$(TIMA_DIR)/tlc_tz_ccm/third_party/openssl/include \
#    vendor/samsung/common/external/tima/$(TIMA_DIR)/tlc_tz_ccm/third_party/openssl/include/openssl

#LOCAL_MODULE:= dm_verity_tz_cmd

#LOCAL_STATIC_LIBRARIES = libmincrypt libminzip libz
#LOCAL_STATIC_LIBRARIES += libc liblog libext4_utils_static libcrypto_static_dmverity
#LOCAL_SHARED_LIBRARIES = libtlc_tz_dmverity libtlc_comm
#LOCAL_FORCE_STATIC_EXECUTABLE := true
#LOCAL_CFLAGS := -fno-stack-protector

# This binary is in the recovery ramdisk, which is otherwise a copy of root.
# It gets copied there in config/Makefile.  LOCAL_MODULE_TAGS suppresses
# a (redundant) copy of the binary in /system/bin for user builds.
# TODO: Build the ramdisk image in a more principled way.
#LOCAL_MODULE_TAGS := eng

#LOCAL_FORCE_STATIC_EXECUTABLE := true
# LOCAL_MODULE_PATH := $(TARGET_ROOT_OUT)/sbin
# LOCAL_UNSTRIPPED_PATH := $(TARGET_ROOT_OUT_UNSTRIPPED)
#include $(BUILD_EXECUTABLE)
endif

ifeq ($(TARGET_ARCH), arm64)
include $(CLEAR_VARS)
LOCAL_MODULE := libcrypto_static_dmverity
LOCAL_MODULE_TAGS := optional
LOCAL_PREBUILT_LIBS := /arm64/libcrypto_static_dmverity.a
include $(BUILD_MULTI_PREBUILT)
else
include $(CLEAR_VARS)
LOCAL_MODULE := libcrypto_static_dmverity
LOCAL_MODULE_TAGS := optional
LOCAL_PREBUILT_LIBS := libcrypto_static_dmverity.a
include $(BUILD_MULTI_PREBUILT)
endif

include $(CLEAR_VARS)
LOCAL_MODULE    := dm_verity_signature_checker
LOCAL_SRC_FILES := dm_verity_signature_checker.c
LOCAL_C_INCLUDES += $(TOP)/external/boringssl/include $(LOCAL_PATH)/inc
ifeq (exynos,$(findstring exynos,$(TARGET_SOC)))
LOCAL_CFLAGS += -DEXYNOS_TZ
ifeq ($(TARGET_SOC),exynos5433)
LOCAL_CFLAGS += -DEXYNOS_5433
endif
ifeq ($(TARGET_SOC),exynos8890)
LOCAL_CFLAGS += -DEXYNOS_8890
endif
ifeq ($(TARGET_SOC),exynos7420)
LOCAL_CFLAGS += -DEXYNOS_7420
endif
ifeq ($(TARGET_SOC),exynos7870)
LOCAL_CFLAGS += -DEXYNOS_7870
endif
ifeq ($(TARGET_PROJECT), TRE)
LOCAL_CFLAGS += -DTRE_PROJECT
endif
ifeq ($(TARGET_SOC),exynos7580)
LOCAL_CFLAGS += -DEXYNOS_7580
endif
ifeq ($(TARGET_SOC),exynos3475)
LOCAL_CFLAGS += -DEXYNOS_3475
endif
ifeq ($(TARGET_SOC),exynos5430)
LOCAL_CFLAGS += -DEXYNOS_5430
endif
else
LOCAL_C_INCLUDES +=  $(TOP)/vendor/qcom/proprietary/securemsm/QSEEComAPI
LOCAL_STATIC_LIBRARIES += libQSEEComAPIStatic
LOCAL_CFLAGS += -DQSEE_TZ
ifeq ($(TARGET_BOARD_PLATFORM),apq8084)
LOCAL_CFLAGS += -DAPQ_8084
endif
ifeq ($(TARGET_BOARD_PLATFORM),msm8996)
LOCAL_CFLAGS += -DUSE_SHA256
LOCAL_CFLAGS += -DMSM_8996
endif
ifeq ($(TARGET_BOARD_PLATFORM),msm8953)
LOCAL_CFLAGS += -DUSE_SHA256
endif
ifeq ($(TARGET_BOARD_PLATFORM),msm8916)
LOCAL_CFLAGS += -DMSM_8916
endif
endif
LOCAL_MODULE_TAGS := optional
LOCAL_FORCE_STATIC_EXECUTABLE := true
LOCAL_MODULE_PATH := $(TARGET_ROOT_OUT_SBIN)
LOCAL_UNSTRIPPED_PATH := $(TARGET_ROOT_OUT_SBIN_UNSTRIPPED)
LOCAL_STATIC_LIBRARIES := libc libcrypto_static libcrypto_static
include $(BUILD_EXECUTABLE)

#include $(CLEAR_VARS)
#LOCAL_MODULE := libdmverity_test
#LOCAL_FORCE_STATIC_EXECUTABLE := true
#LOCAL_MODULE_TAGS := tests
#
#LOCAL_CFLAGS += -D__USE_DM_VERITY
#
#LOCAL_SRC_FILES := libdmverity_test.c ../roots.cpp ../system.cpp
#
#LOCAL_C_INCLUDES += system/extras/ext4_utils
#LOCAL_C_INCLUDES += $(LOCAL_PATH)/..
#
#LOCAL_STATIC_LIBRARIES := \
#   libdmverity \
#   libfs_mgr \
#   libc \
#   libstdc++ \
#   libext4_utils_static \
#   libmtdutils \
#   libdmverity_hashgen \
#   libmincrypt
#
#include $(BUILD_EXECUTABLE)


include $(CLEAR_VARS)
LOCAL_MODULE := signature_test
LOCAL_FORCE_STATIC_EXECUTABLE := true
LOCAL_MODULE_TAGS := tests

LOCAL_CFLAGS += -D__NO_UI_PRINT
LOCAL_CFLAGS += -D__USE_DM_VERITY
LOCAL_CFLAGS += -Wno-narrowing

LOCAL_SRC_FILES := \
    signature_test.c
LOCAL_STATIC_LIBRARIES := libc
#include $(BUILD_EXECUTABLE)



################################################################################
#  libdmverity_rehash is a utility to regenerate the hash of system partition

include $(CLEAR_VARS)
LOCAL_MODULE := dm_verity_rehash
LOCAL_FORCE_STATIC_EXECUTABLE := true
LOCAL_MODULE_TAGS := optional
LOCAL_CFLAGS += -D__NO_UI_PRINT
LOCAL_CFLAGS += -D__USE_DM_VERITY
ifeq ($(TARGET_SOC),exynos5433)
LOCAL_CFLAGS += -DEXYNOS_5433
endif
ifeq ($(TARGET_SOC),exynos8890)
LOCAL_CFLAGS += -DEXYNOS_8890
LOCAL_CFLAGS += -DUSE_SHA256
endif
ifeq ($(TARGET_SOC),exynos7420)
LOCAL_CFLAGS += -DEXYNOS_7420
LOCAL_CFLAGS += -DUSE_SHA1
endif
ifeq ($(TARGET_SOC),exynos7870)
LOCAL_CFLAGS += -DEXYNOS_7870
LOCAL_CFLAGS += -DUSE_SHA256
endif
ifeq ($(TARGET_PROJECT), TRE)
LOCAL_CFLAGS += -DTRE_PROJECT
endif
ifeq ($(TARGET_SOC),exynos7580)
LOCAL_CFLAGS += -DEXYNOS_7580
endif
ifeq ($(TARGET_SOC),exynos3475)
LOCAL_CFLAGS += -DEXYNOS_3475
endif
ifeq ($(TARGET_SOC),exynos5430)
LOCAL_CFLAGS += -DEXYNOS_5430
endif
ifeq ($(TARGET_BOARD_PLATFORM),apq8084)
LOCAL_CFLAGS += -DAPQ_8084
endif
ifeq ($(TARGET_BOARD_PLATFORM),msm8996)
LOCAL_CFLAGS += -DUSE_SHA256
LOCAL_CFLAGS += -DMSM_8996
endif
ifeq ($(TARGET_BOARD_PLATFORM),msm8953)
LOCAL_CFLAGS += -DUSE_SHA256
endif
ifeq ($(TARGET_BOARD_PLATFORM),msm8916)
LOCAL_CFLAGS += -DMSM_8916
endif

LOCAL_SRC_FILES := dm_verity_rehash.c __common.c  ../roots.cpp  ../system.cpp
LOCAL_C_INCLUDES += system/extras/ext4_utils system/vold
LOCAL_C_INCLUDES += system/core/fs_mgr/include $(TOP)/external/boringssl/include
LOCAL_C_INCLUDES += $(LOCAL_PATH)/..

LOCAL_STATIC_LIBRARIES := \
    libdmverity  \
    libext4_utils_static \
    libcutils \
    libstdc++ \
    libmtdutils \
    libmincrypt   \
    libfs_mgr \
    libc \
    libz

LOCAL_MODULE_PATH := $(TARGET_RECOVERY_ROOT_OUT)/sbin

include $(BUILD_EXECUTABLE)

################################################################################


include $(CLEAR_VARS)
LOCAL_MODULE_TAGS := optional
LOCAL_SRC_FILES := img_dm_verity.c __common.c
LOCAL_MODULE := img_dm_verity
LOCAL_STATIC_LIBRARIES := libext4_utils_host libsparse_host libdmverity_hashgen_host libmincrypt libz
LOCAL_SHARED_LIBRARIES := libcrypto-host
LOCAL_C_INCLUDES += $(LOCAL_PATH)/..
LOCAL_C_INCLUDES += system/extras/ext4_utils
LOCAL_CFLAGS += -D__BUILD_HOST_EXECUTABLE
ifeq ($(TARGET_SOC),exynos5433)
LOCAL_CFLAGS += -DEXYNOS_5433
endif
ifeq ($(TARGET_SOC),exynos8890)
LOCAL_CFLAGS += -DEXYNOS_8890
LOCAL_CFLAGS += -DUSE_SHA256
endif
ifeq ($(TARGET_SOC),exynos7420)
LOCAL_CFLAGS += -DEXYNOS_7420
LOCAL_CFLAGS += -DUSE_SHA1
endif
ifeq ($(TARGET_SOC),exynos7870)
LOCAL_CFLAGS += -DEXYNOS_7870
LOCAL_CFLAGS += -DUSE_SHA256
endif
ifeq ($(TARGET_PROJECT), TRE)
LOCAL_CFLAGS += -DTRE_PROJECT
endif
ifeq ($(TARGET_SOC),exynos7580)
LOCAL_CFLAGS += -DEXYNOS_7580
endif
ifeq ($(TARGET_SOC),exynos3475)
LOCAL_CFLAGS += -DEXYNOS_3475
endif
ifeq ($(TARGET_SOC),exynos5430)
LOCAL_CFLAGS += -DEXYNOS_5430
endif
ifeq ($(TARGET_BOARD_PLATFORM),apq8084)
LOCAL_CFLAGS += -DAPQ_8084
endif
ifeq ($(TARGET_BOARD_PLATFORM),msm8996)
LOCAL_CFLAGS += -DUSE_SHA256
LOCAL_CFLAGS += -DMSM_8996
endif
ifeq ($(TARGET_BOARD_PLATFORM),msm8953)
LOCAL_CFLAGS += -DUSE_SHA256
endif
ifeq ($(TARGET_BOARD_PLATFORM),msm8916)
LOCAL_CFLAGS += -DMSM_8916
endif
include $(BUILD_HOST_EXECUTABLE)

include $(CLEAR_VARS)
LOCAL_MODULE := dm_verity_make_ext4fs.py

ifeq (,$(findstring exynos,$(TARGET_SOC)))
ifeq ($(TARGET_BOARD_PLATFORM),apq8084)
LOCAL_SRC_FILES := dm_verity_make_ext4fs_8084.py
else
LOCAL_SRC_FILES := dm_verity_make_ext4fs_qcom.py
endif
endif

ifeq ($(TARGET_SOC),exynos5433)
LOCAL_SRC_FILES := dm_verity_make_ext4fs.py
endif
ifeq ($(TARGET_SOC),exynos8890)
LOCAL_SRC_FILES := dm_verity_make_ext4fs_8890.py
endif
ifeq ($(TARGET_SOC),exynos7420)
LOCAL_SRC_FILES := dm_verity_make_ext4fs_7420.py
endif
ifeq ($(DMVERITY_ZERO),true)
LOCAL_SRC_FILES := dm_verity_make_ext4fs_7420_zero.py
endif
ifeq ($(TARGET_SOC),exynos7870)
LOCAL_SRC_FILES := dm_verity_make_ext4fs_7870.py
endif
ifeq ($(TARGET_PROJECT), TRE)
LOCAL_SRC_FILES := dm_verity_make_ext4fs_tre.py
endif
ifeq ($(TARGET_SOC),exynos7580)
ifeq ($(DMVERITY_CONGO),true)
LOCAL_SRC_FILES := dm_verity_make_ext4fs_7580_congo.py
else
LOCAL_SRC_FILES := dm_verity_make_ext4fs_7580.py
endif
endif
ifeq ($(TARGET_SOC),exynos3475)
LOCAL_SRC_FILES := dm_verity_make_ext4fs_3475.py
endif
ifeq ($(TARGET_SOC),exynos5430)
LOCAL_SRC_FILES := dm_verity_make_ext4fs_5430.py
endif

LOCAL_MODULE_CLASS := EXECUTABLES
LOCAL_IS_HOST_MODULE := true
LOCAL_MODULE_TAGS := optional
include $(BUILD_PREBUILT)


#qseecomfsd should be included either in 1)pre-built or executables built by 2)android build system .  
#models with case 2) should not be included below , otherwise it will cause build failure . 
ifeq ($(TARGET_BOARD_PLATFORM),apq8084)
include $(CLEAR_VARS)
LOCAL_SRC_FILES := qseecomfsd
LOCAL_MODULE := qseecomfsd
LOCAL_MODULE_CLASS := EXECUTABLES
LOCAL_MODULE_PATH := $(TARGET_ROOT_OUT_SBIN)
LOCAL_MODULE_TAGS := optional
include $(BUILD_PREBUILT)
endif

include $(CLEAR_VARS)
LOCAL_MODULE := mount_test
LOCAL_FORCE_STATIC_EXECUTABLE := true
LOCAL_MODULE_TAGS := optional

LOCAL_CFLAGS += -D__NO_UI_PRINT
LOCAL_CFLAGS += -D__USE_DM_VERITY
LOCAL_CFLAGS += -Wno-narrowing

LOCAL_SRC_FILES := \
    libdmverity_test.c \
    ../roots.cpp \
    ../system.cpp 
LOCAL_STATIC_LIBRARIES := \
    libtima_recovery \
    librecovery_parser \
    libext4_utils_static \
    libsparse_static \
    libminzip \
    libz \
    libmtdutils \
    libmincrypt \
    libminadbd \
    libminui \
    libpng \
    libfs_mgr \
    libcutils \
    liblog \
    libselinux \
    libstdc++ \
    libm \
    libc
LOCAL_C_INCLUDES := system/core/fs_mgr/include system/vold
LOCAL_C_INCLUDES += $(LOCAL_PATH)/..
LOCAL_C_INCLUDES += system/extras/ext4_utils $(TOP)/external/boringssl/include

LOCAL_CFLAGS += -D__USE_DM_VERITY
LOCAL_STATIC_LIBRARIES += libdmverity libdmverity_hashgen

LOCAL_MODULE_PATH := $(TARGET_RECOVERY_ROOT_OUT)/sbin

include $(BUILD_EXECUTABLE)
endif

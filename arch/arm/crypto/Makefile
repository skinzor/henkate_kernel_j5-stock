#
# Arch-specific CryptoAPI modules.
#

obj-$(CONFIG_CRYPTO_AES_ARM) += aes-arm.o
obj-$(CONFIG_CRYPTO_SHA1_ARM) += sha1-arm.o
obj-$(CONFIG_CRYPTO_SHA1_ARM_CE) += sha1-arm-ce.o

aes-arm-y  := aes-armv4.o aes_glue.o
sha1-arm-y := sha1-armv4-large.o sha1_glue.o
sha1-arm-ce-y	:= sha1-ce-core.o sha1-ce-glue.o

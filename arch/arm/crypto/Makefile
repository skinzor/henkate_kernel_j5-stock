#
# Arch-specific CryptoAPI modules.
#

obj-$(CONFIG_CRYPTO_AES_ARM) += aes-arm.o
obj-$(CONFIG_CRYPTO_SHA1_ARM) += sha1-arm.o
obj-$(CONFIG_CRYPTO_SHA1_ARM_CE) += sha1-arm-ce.o
obj-$(CONFIG_CRYPTO_SHA2_ARM_CE) += sha2-arm-ce.o

aes-arm-y  := aes-armv4.o aes_glue.o
sha1-arm-y := sha1-armv4-large.o sha1_glue.o
sha1-arm-ce-y	:= sha1-ce-core.o sha1-ce-glue.o
<<<<<<< HEAD
=======
sha2-arm-ce-y	:= sha2-ce-core.o sha2-ce-glue.o

quiet_cmd_perl = PERL    $@
      cmd_perl = $(PERL) $(<) > $(@)

$(src)/aesbs-core.S_shipped: $(src)/bsaes-armv7.pl
	$(call cmd,perl)

.PRECIOUS: $(obj)/aesbs-core.S
>>>>>>> 7179dab... crypto: arm - add support for SHA-224/256 using ARMv8 Crypto Extensions

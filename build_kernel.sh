#!/bin/bash

export ARCH=arm
export CROSS_COMPILE=$(pwd)/../PLATFORM/prebuilts/gcc/linux-x86/arm/arm-eabi-4.8/bin/arm-eabi-
mkdir output

make -C $(pwd) O=output msm8916_sec_defconfig VARIANT_DEFCONFIG=msm8916_sec_j5nlte_eur_defconfig SELINUX_DEFCONFIG=selinux_defconfig
make -j64 -C $(pwd) O=output

<<<<<<< HEAD
cp output/arch/arm/boot/Image $(pwd)/arch/arm/boot/zImage
=======
# zImage copying
	cp output/arch/arm/boot/zImage $(pwd)/ares-out/pack/zImage

# DTS packing
     echo "Moving dtb..."
	./tools/dtbTool -v -s 2048 -o ./ares-out/pack/dtba3ultexx ./output/arch/arm/boot/dts/

# Ramdisk packing
	echo "Building a3ultexx ramdisk..."
	cp -r ares-tools/ramdisk/a3ultexx/* ares-out/pack/rd
	cd $(pwd)/ares-out/pack/rd
	mkdir -p data dev oem proc sys system
	echo "Setting ramdisk file permissions..."
	# set all directories to 0755 by default
	find -type d -exec chmod 755 {} \;
	# set all files to 0644 by default
	find -type f -exec chmod 644 {} \;
	# scripts should be 0750
	find -name "*.rc" -exec chmod 750 {} \;
	find -name "*.sh" -exec chmod 750 {} \;
	# init and everything in /sbin should be 0750
	chmod -Rf 750 init sbin
	chmod 771 data
	find | fakeroot cpio -o -H newc | gzip -9 > ../ares-ramdisk.gz
	cd ../../../

# Generating boot.img for a3ultexx
echo "Generating boot.img..."
echo ""
./ares-tools/mkbootimg --kernel ./ares-out/pack/zImage \
				--ramdisk ./ares-out/pack/ares-ramdisk.gz \
				--cmdline "console=null androidboot.hardware=qcom user_debug=23 msm_rtb.filter=0x3F ehci-hcd.park=3 androidboot.bootdevice=7824900.sdhci" \
				--base 80000000 \
				--pagesize 2048 \
				--kernel_offset 00008000 \
				--ramdisk_offset 02000000 \
				--tags_offset 01e00000 \
				--dt ./ares-out/pack/dtba3ultexx \
				--output $(pwd)/ares-out/zip/boot.img

# Making flashable zip for a3ultexx
cp -r $(pwd)/ares-tools/META-INF $(pwd)/ares-out/zip/
cp -r $(pwd)/output/drivers/staging/prima/wlan.ko $(pwd)/ares-out/zip/wifimodule
cd ares-out/zip
zip -r -9 - * > ../"a3ultexx_aresKernel-$(date +"%Y-%m-%d").zip"
cd ../../
BUILD_END=$(date +"%s")
DIFF=$(($BUILD_END - $BUILD_START))
echo -e "$yellow Build completed in $(($DIFF / 60)) minute(s) and $(($DIFF % 60)) seconds.$nocol"
>>>>>>> 1963b3e... Implement qcom's prima wlan

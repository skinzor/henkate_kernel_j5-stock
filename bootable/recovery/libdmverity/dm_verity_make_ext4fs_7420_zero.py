#! /usr/bin/env python

# make_ext4fs -s -S /home/swei/p4/STA-ESG_SWEI_KLTE_ATT-TRUNK_DMV/android/out/target/product/klteatt/root/file_contexts -l 2654994432 -a system system.img.ext4 system

import os,posixpath,sys,getopt

reserve=1024*1024*32+40*1024

def run(cmd):
    print cmd
#    return 0
    return os.system(cmd)

def main():
    d = posixpath.dirname(sys.argv[0])
    make_ext4fs_opt_list = []
    optlist, args = getopt.getopt(sys.argv[1:], 'l:j:b:g:i:I:L:a:G:fwzJsctrvS:X:')
    if len(args) < 1:
        print 'image file not specified'
        return -1;
    image_file = args[0]
    length = None
    sparse = False
    for o, a in optlist:
        if '-l' == o:
            length = int(a)
            if length > 4*1024*1024*1024:
                print 'Image size over 4GB -> reserve 35MB for Hash tree'
                reserve=1024*1024*35
            else:
                print 'Image size less than 4GB -> reserve 32MB for Hash tree'
                reserve=1024*1024*32+40*1024
            make_ext4fs_opt_list.append(o)
            make_ext4fs_opt_list.append(str(length-reserve))
        elif '-s' == o:
            sparse = True
            make_ext4fs_opt_list.append(o)
        else:
            make_ext4fs_opt_list.append(o)
            if len(a) > 0:
                make_ext4fs_opt_list.append(a)    
        
    if not sparse:
        print 'we can only handle sparse image format for server generated dmverity for now'
        return -1
    if None == length:
        print 'size of system image not taken'
        return -1

    make_ext4fs_opt_list.extend(args)
    cmd = os.path.join(d, 'make_ext4fs') + ' ' +' '.join(make_ext4fs_opt_list)
    if(0 != run(cmd)):
        print 'failed!'
        return -1;


    cmd = ' '.join(['img_dm_verity', '/dev/block/platform/15570000.ufs/by-name/SYSTEM', str(length), image_file, image_file+'.tmp'])
    if(0 != run(cmd)):
        print 'failed!'
        return -1;    
    cmd = ' '.join(['mv', image_file+'.tmp', image_file])
    if(0 != run(cmd)):
        print 'failed!'
        return -1;
    return 0
    #return os.system(cmd)

if __name__ == "__main__":
    ret = main()
    sys.exit(ret)

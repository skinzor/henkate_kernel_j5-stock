#! /usr/bin/env python


import os,posixpath,sys,getopt, math

###############################################
#  below vaues need adjustment if necessary
#
data_block_size = 4096 # size of data block

hash_block_size = 4096 # size of hash block

hash_size = 16 # size of hash (MD5)

hash_prefix_size = 8 * 4096 # meta + table

hash_postfix_size = 4 + 256 # sizeof (int) + SIGNATURE_SIZE (SHA256)
###############################################

def calc_hashtree_size (dev_size):
    
    # dev_size = part_size + hash_size
    # to simplify the calculation, use dev_size instead of part_size
    
    hash_tree_size = 0

    print 'Calculate hash area size according to device size' 
       # if data_block_size <> hash_block_size, we need to handle
       # the first level and the other leves differently, so we put
       # the first level seperately 
    dev_size = math.ceil(dev_size/data_block_size) * hash_size
    print 'level 0: # of blocks to be hashed: ' + str(dev_size/hash_size)
    print "level 0: size of hash tree to add: " + str(dev_size)
    hash_tree_size += dev_size  
    while (dev_size > hash_block_size):
        print '==========================================='
        print "hash_tree_size before is " + str(hash_tree_size)
        dev_size = math.ceil(dev_size/hash_block_size) * hash_size
        print "level *: # of blocks to be hashed: "+str(dev_size/hash_size)
        print 'level *: size of hash tree to add: ' + str(dev_size)
        hash_tree_size += dev_size
    hash_tree_size += 1 * 4096 # add the root of hash tree
    
    hash_tree_size += hash_prefix_size + hash_postfix_size
    print hash_tree_size
    hash_tree_size = int((hash_tree_size + data_block_size -1) / data_block_size) * data_block_size

    print hash_tree_size
    return hash_tree_size
    
def run(cmd):
    print cmd
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
    reserve = None

    for o, a in optlist:
        if '-l' == o:
            length = int(a)
            reserve = calc_hashtree_size (length)
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


    cmd = ' '.join(['img_dm_verity', '/dev/block/platform/15540000.dwmmc0/by-name/SYSTEM', str(length), image_file, image_file+'.tmp'])
    if(0 != run(cmd)):
        print 'failed!'
        return -1;    
    cmd = ' '.join(['mv', image_file+'.tmp', image_file])
    if(0 != run(cmd)):
        print 'failed!'
        return -1;
    return 0

if __name__ == "__main__":
    ret = main()
    sys.exit(ret)
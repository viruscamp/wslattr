# copy the folder to WSL filesystem, eg: ~/wslattr-tests , and then run it
# do not leave the folder in Windows filesystem, eg: /mnt/c/

mknod devb b 37 13
mknod devc c 13 14
mknod devp p

touch x
touch 你好

ln -s x lnx
ln -s 你好 lnnh
ln -s 打发士大夫大多数 lnlong
ln -s 0001020304050607000102030405060700010203040506070001020304050607 ln64

setfattr -n trusted.mdsum -v 343 x
setfattr -n user.abc -v xyz x
setfattr -n user.打发士大夫大多数 -v 打发士大夫大多数 x
setfattr -n user.empty -v "" x

rm -f server.sock
gcc -static sock-server.c -o sock-server
./sock-server

make clean
rm *.txt
make fileserver
# fileclient <server> <networknastiness> <filenastiness> <srcdir>
./fileserver 0 0 TARGET_NASTY0
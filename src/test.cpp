#include <openssl/sha.h>
#include <vector>
#include <unordered_map>
#include <dirent.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <cstring>                // for errno string formatting
#include <cerrno>
#include <cstring>               // for strerro
#include <iostream>               // for cout
#include <fstream>                // for input files

typedef struct Packet{
    unsigned char content[490];
    size_t seqNum;
    uint32_t packet_status;
    Packet(unsigned char* filecontent, size_t num){
        seqNum = num;
        memcpy((void *)content, filecontent, 490);
    }
} *Packet_ptr;

using namespace std;

int main(){
    cout << sizeof(struct Packet) << endl;;
    return 0;
}
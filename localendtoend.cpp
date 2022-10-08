#include "localendtoend.h"
#include <cassert>

#define BUFSIZE 1024
const int UPPERBOUND = 1e6;
using namespace std;


void GetFileNames(vector<string>& filenames, string tardir)
{
    struct dirent *entry = nullptr;
    DIR *dp = nullptr;

    dp = opendir(tardir.c_str());
    if (dp != nullptr) {
        while ((entry = readdir(dp))){
            if (entry->d_type == 8){
                filenames.push_back(tardir + "/" + entry->d_name);
            }
        }
    }
    closedir(dp);
}

/* ReadaFile
 * purpose: read the file content from an initiated C150nastyfile pointer 
 * return: total number of bytes read from the file object
 * notes: *buf_ptr is udpated to point to the read in file content       
 */
ssize_t ReadaFile(C150NETWORK::C150NastyFile *targetFile, unsigned char **buf_ptr)
{
    assert(targetFile != nullptr);
    ssize_t totalBytes = 0;
    vector<unsigned char> allFileContent;
    unsigned char* temporaryBuf = (unsigned char*)malloc(BUFSIZE * sizeof(unsigned char));
    ssize_t chunk = (*targetFile).fread(temporaryBuf, 1, BUFSIZE);
    totalBytes += chunk;
    while(1) { // read until the end
        for (ssize_t t = 0; t <= chunk; t += sizeof(unsigned char)){
            allFileContent.push_back(*(temporaryBuf + t));
        }
        bzero(temporaryBuf, BUFSIZE); // clean up the buf for next read 
        if (chunk <= BUFSIZE) break;
        chunk = (*targetFile).fread(temporaryBuf, 1, BUFSIZE);
        if ((*targetFile).feof() == 0) break;
        totalBytes += chunk;
    }
    unsigned char* prod = (unsigned char*)malloc((totalBytes + 1)*sizeof(unsigned char));
    for (unsigned int i = 0; i < allFileContent.size();i++) {
        *(prod + i) = allFileContent.at(i); 
    }
    *buf_ptr = (unsigned char*)realloc((void *)prod, totalBytes); 
    cout << "current file content [" << *buf_ptr << "]\n";
    
    return totalBytes;
}


/* FileCopyE2ECheck
 * purpose: read the file content from an initiated C150nastyfile pointer 
 * return: total number of bytes read from the file object
 * notes: *buf_ptr is udpated to point to the read in file content       
 */
void FileCopyE2ECheck(int filenastiness, string tardir, vector<fileProp>& allFilesProp_addr)
{
    printf("currently in FileCopyE2ECheck\n\n");
    unsigned char* temporaryBuf = nullptr;
    unordered_map<unsigned char*, unsigned char*> umSha1content; // key rethink
    int iteration = 0;
    ssize_t readedBytes = 0;
    vector<string> filenames;
    GetFileNames(filenames, tardir);
    
    for (long unsigned int i = 0; i < filenames.size(); i++){ // read one file 
        while (iteration < UPPERBOUND)
        {
            C150NETWORK::C150NastyFile C150NF = C150NETWORK::C150NastyFile(filenastiness);
            printf("current filename %s \n", filenames[i].c_str());
            void *success = C150NF.fopen(filenames[i].c_str(), "r");
            assert(success != NULL);
            printf("while loop iteration %d \n", iteration);
            readedBytes = ReadaFile(&C150NF, &temporaryBuf);
            unsigned char obuf[20]; /* calculate SHA1 for overall file */
            SHA1(temporaryBuf, readedBytes, obuf);
            printf("sha1 computed\n");
            unordered_map<unsigned char*, unsigned char*>::const_iterator got = umSha1content.find(obuf);
            printf("after searching in hashmap \n");
            if (got == umSha1content.end()) { // NOT FOUND
                umSha1content[obuf] = temporaryBuf; //populate this into unordered map
                printf("DID NOT find matching sha1\n");
            } else{
                for (int j = 0; j < 20; j++)
                    {
                        printf ("%02x", (unsigned int) obuf[j]);
                    }
                    printf("\n");
                struct fileProp fileInfo = fileProp(filenames[i], obuf, readedBytes, temporaryBuf);
                allFilesProp_addr.push_back(fileInfo);
                break;
            }
            iteration++;
            C150NF.fclose();
        }
        iteration = 0;
    }

}


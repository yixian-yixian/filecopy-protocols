#include "localendtoend.h"
#include <cassert>

#define BUFSIZE 1024
const int UPPERBOUND = 1e6;
using namespace std;
using namespace C150NETWORK;  // for all the comp150 utilities 


void calcSHA1(unsigned char** sha1_val, unsigned char *content, ssize_t contentSize);
// ------------------------------------------------------
//
//                   makeFileName
//
// Put together a directory and a file name, making
// sure there's a / in between
//
// ------------------------------------------------------

string
makeFileName(string dir, string name) {
  stringstream ss;

  ss << dir;
  // make sure dir name ends in /
  if (dir.substr(dir.length()-1,1) != "/")
    ss << '/';
  ss << name;       // append file name to dir
  return ss.str();  // return dir/name
  
}

string
makeTmpFileName(string dir, string name){
    stringstream ss;
    ss << dir;
    // make sure dir name ends in /
    if (dir.substr(dir.length()-1,1) != "/")
        ss << '/';
    // size_t pos = name.find_last_of(".");
    // if (pos != string::npos){ 
    //     ss << name.substr(0, pos);
    // }
    ss << name << ".tmp";   
    return ss.str();  // return dir/name
}

string
renameFileName(string name){
    stringstream ss;
    // remove everything after .tmp
    size_t pos = name.find_last_of(".");
    if (pos != string::npos){ 
        ss << name.substr(0, pos);
    }
    return ss.str();  // return dir/name
}

/* GetFileName 
 * purpose: read in all name strings of available files in the target directory 
 * return: none 
 * notes: filenames vector should now be filled with filenames string
 */
void GetFileNames(vector<string>& filenames, string tardir)
{
    struct dirent *entry = nullptr;
    DIR *dp = nullptr;
    dp = opendir(tardir.c_str());
    if (dp != nullptr) {
        while ((entry = readdir(dp))){
            if (entry->d_type == 8) filenames.push_back(entry->d_name);
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
    ssize_t chunk = 0;
    while(!(*targetFile).feof()) { // read until the end
        chunk = (*targetFile).fread(temporaryBuf, 1, BUFSIZE);
        for (ssize_t t = 0; t < chunk; t += sizeof(unsigned char)){
            allFileContent.push_back(*(temporaryBuf + t));
        }
        bzero(temporaryBuf, BUFSIZE); // clean up the buf for next read 
        totalBytes += chunk;
    }
    unsigned char* prod = (unsigned char*)malloc((allFileContent.size())*sizeof(unsigned char));
    for (unsigned int i = 0; i < allFileContent.size();i++) {
        *(prod + i) = allFileContent.at(i); 
    }
    *buf_ptr = prod;
    return totalBytes;
}


/* FileCopyE2ECheck
 * purpose: read the file content from an initiated C150nastyfile pointer 
 * parameter:
 *      int filenastiness: nastiness level for file read 
 *      string srcdir: source directory string name 
 *      vector<fileProp>& allFilesProp_addr: all Filesproperty passed by reference
 * return: total number of bytes read from the file object
 * notes: allFilesProp_addr is now populated with the fileProp objects based on files
 *        files in target directory       
 */
void FileCopyE2ECheck(int filenastiness, string srcdir, vector<fileProp>& allFilesProp_addr, vector<string>& filenames)
{
    unsigned char* temporaryBuf = nullptr;
    unordered_map<unsigned char*, unsigned char*> umSha1content; 
    int iteration = 0;
    ssize_t readedBytes = 0;
    
    for (long unsigned int i = 0; i < filenames.size(); i++){ // read one file 
        while (iteration < UPPERBOUND) /* limit each file to retry on read under upperbound iterations */
        {
            C150NETWORK::C150NastyFile C150NF = C150NETWORK::C150NastyFile(filenastiness);
            string sourceFileName = makeFileName(srcdir, filenames[i]);
            void *success = C150NF.fopen(sourceFileName.c_str(), "r");
            assert(success != NULL);
            readedBytes = ReadaFile(&C150NF, &temporaryBuf);
            unsigned char obuf[20]; /* calculate SHA1 for overall file */
            SHA1(temporaryBuf, readedBytes, obuf);
            unordered_map<unsigned char*, unsigned char*>::const_iterator got = umSha1content.find(obuf);
            if (got == umSha1content.end()) { /* SHA1 not previously present */
                umSha1content[obuf] = temporaryBuf; /* add SHA1 for this read into table */
                if (iteration != 0){
                    *GRADING << "File: <" << filenames[i] << "> local end-to-end check failed, attempt <" << iteration+1 << ">\n"; 
                }
            } else{ /* same SHA1 for correct file identified from table */
                /* initialize fileProp object based on the current filename, content and totalBytes read */
                struct fileProp fileInfo = fileProp(filenames[i], obuf, readedBytes, temporaryBuf);
                allFilesProp_addr.push_back(fileInfo); /* append file informationto the list */
                *GRADING << "File: <" << filenames[i] << "> local end-to-end check succeeded, attempt <" << iteration+1 << ">\n"; 
                break;
            }
            iteration++; /* unsuccessful find increment the iteration number for file read by 1*/
            C150NF.fclose(); /* close current socket */
        }
        iteration = 0;
    }
}



void 
WriteaFile(fileProp& curFile, int filenastiness, string tardir) {
    struct stat dir_status = {0};
    if (stat(tardir.c_str(), &dir_status) == -1) {
        mkdir(tardir.c_str(), 0700);
    }
    /* make target directory file name */
    string target_file_name = makeTmpFileName(tardir, curFile.filename);
    C150NETWORK::C150NastyFile C150NF = C150NETWORK::C150NastyFile(filenastiness);
    /* variables to track read and write correctness */
    unsigned char *read_back_Buf = nullptr, *file_sha1 = nullptr;
    bool is_matched_content = false;
    ssize_t read_back_size;
    while (!is_matched_content) {
        /* open the file to write */
        void *success = C150NF.fopen(target_file_name.c_str(), "w");
        assert(success != NULL);
        C150NastyFile C150NFR = C150NastyFile(0);
        /* write the file out to file system */
        C150NF.fwrite((const void*)(curFile.contentbuf), 1, curFile.contentSize);
        C150NF.fclose();
        
        /* read the file back for SHA1 comparison */
        void *tmpfile = C150NFR.fopen(target_file_name.c_str(), "r");
        assert(tmpfile != NULL);
        read_back_size = ReadaFile(&C150NFR, &read_back_Buf);
        calcSHA1(&file_sha1, read_back_Buf, read_back_size);
        if (strcmp((char *)file_sha1, (char *)curFile.fileSHA1) == 0) {
            /* matching content leads to exit */
            is_matched_content = true;
        }
        free(read_back_Buf);
        free(file_sha1);
        C150NFR.fclose();
    }
    
    
}

void 
RenameAllFiles(string tardir)
{
    struct dirent *entry = nullptr;
    DIR *dp = nullptr;
    dp = opendir(tardir.c_str());
    if (dp != nullptr) {
        while ((entry = readdir(dp))){
            if (entry->d_type == 8){
                string newname = renameFileName(entry->d_name);
                rename(entry->d_name, newname.c_str());
            }
        }
    }
    closedir(dp);
}


void calcSHA1(unsigned char** sha1_val, unsigned char *content, ssize_t contentSize) {
    *sha1_val = (unsigned char*)malloc(20 * sizeof(unsigned char));
    SHA1((unsigned char*)content, contentSize, *sha1_val);

}





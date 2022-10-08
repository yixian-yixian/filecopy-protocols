#include <stdio.h>
#include <iostream>
#include <dirent.h>
#include <string>

int main(int argc, const char**argv) {
    struct dirent *entry = nullptr;
    DIR *dp = nullptr;

    dp = opendir(argc > 1 ? argv[1] : "/");
    std::string s = argv[1];
    std::cout << s << std::endl;
    if (dp != nullptr) {
        while ((entry = readdir(dp)))
            std::cout << s + "/" + entry->d_name << std::endl;
            //printf ("%s\n", s + entry->d_name);
    }

    closedir(dp);
    return 0;
}

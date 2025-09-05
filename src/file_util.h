#include <SD.h>

bool fileExists(const char* path) {
    File f = SD.open(path, FILE_READ);
    if (f) {
        f.close();
        return true;
    }
    return false;
}
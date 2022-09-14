#include "dump_utils.h"

#include <algorithm>

#ifdef __cplusplus
extern "C" {
#endif

#include <string.h>
#include <unwind.h>
#include <pthread.h>
#include <unistd.h>

void loli_trim(std::string &str) {
    str.erase(std::remove_if(str.begin(), str.end(), [](int ch) {
        return std::isspace(ch);
    }), str.end());
}

// str: 要分割的字符串
// result: 保存分割结果的字符串数组
// delim: 分隔字符串
void loli_split(const std::string& str,
        std::vector<std::string>& tokens,
        const std::string delim) {
    tokens.clear();

    char* buffer = new char[str.size() + 1];
    strcpy(buffer, str.c_str());

    char* tmp;
    char* p = strtok_r(buffer, delim.c_str(), &tmp);
    do {
        tokens.push_back(p);
    } while ((p = strtok_r(nullptr, delim.c_str(), &tmp)) != nullptr);

    delete[] buffer;
}

void loli_demangle(const std::string& name, std::string& demangled) {
    auto slashIndex = name.find_last_of('/');
    demangled = name;
    if (slashIndex != std::string::npos) {
        demangled = name.substr(slashIndex + 1);
    }
    auto dotIndex = demangled.find_last_of('.');
    if (dotIndex != std::string::npos) {
        demangled = demangled.substr(0, dotIndex);
    }
}



void loli_dump(io::buffer& obuffer, void** buffer, size_t count) {
    for (size_t idx = 2; idx < count; ++idx) { // idx = 1 to ignore loli's hook function
        const void* addr = buffer[idx];
        obuffer << reinterpret_cast<uint64_t>(addr);
    }
}
#ifdef __cplusplus
}
#endif


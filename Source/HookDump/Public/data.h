#pragma once
#include <stdint.h>
#include <string>

struct Record {
    uint32_t seq_;
    int64_t time_;
    int32_t size_;
    uint64_t addr_;
    std::string library_;
};

struct PersistentRecord
{
    uint32_t seq_;
    int32_t size_;
    uint64_t addr_;
    std::string library_;
};

// #ifdef __cplusplus
// extern "C" {
// #endif // __cplusplus

// bool loli_server_started();
// int loli_server_start(int port);
// void save_record(const char* data, unsigned int size);
void save_record(const Record &record);
void save_free(const std::pair<uint32_t, uint64_t> &cur_free);
void info_dump();

// void loli_server_shutdown();

// #ifdef __cplusplus
// }
// #endif // __cplusplus

// class DataCache
// {
// public:
//     DataCache(){}

// private:

// };

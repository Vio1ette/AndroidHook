// Copyright Epic Games, Inc. All Rights Reserved.
#ifndef HOOKDUMP_CPP
#define HOOKDUMP_CPP
#include "HookDump.h"

#include <algorithm>
#include <atomic>
#include <cassert>
#include <chrono>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <android/log.h>
#include <cxxabi.h>
#include <dlfcn.h>
#include <malloc.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <inttypes.h>
#include <jni.h>
#include <regex.h>

// #include "HookDump.h"
#include "buffer.h"
#include "dump_dlfcn.h"
#include "dump_utils.h"
#include "wrapper.h"
#include "xhook.h"

#include "data.h"

#define LOCTEXT_NAMESPACE "FHookDumpModule"

std::chrono::system_clock::time_point startTime_;
// int minRecSize_ = 0;
std::atomic<std::uint32_t> callSeq_;

// 现在默认为黑名单模式
bool isBlacklist_ = true;

// std::thread dump_thread;

// loliDataMode mode_ = loliDataMode::STRICT;
// bool isBlacklist_ = false;
// bool isFramePointer_ = false;
// bool isInstrumented_ = false;
// loli::Sampler* sampler_ = nullptr;
// loli::spinlock samplerLock_;

enum loliFlags {
    FREE_ = 0,
    MALLOC_ = 1,
    CALLOC_ = 2,
    MEMALIGN_ = 3,
    REALLOC_ = 4,
    COMMAND_ = 255,
};

inline void loli_maybe_record_alloc(size_t size, void *addr, loliFlags flag,
                                    int index) {
    //   if (ignore_current_ || size == 0) {
    //       return;
    //   }

    if (size == 0) {
        return;
    }
    // bool bRecordAllocation = false;
    size_t recordSize = size;
    // if (mode_ == loliDataMode::STRICT) {  // Strict 会设定阈值
    //     bRecordAllocation = size >= static_cast<size_t>(minRecSize_);
    // } else if(mode_ == loliDataMode::LOOSE) {
    //     {
    //         std::lock_guard<loli::spinlock> lock(samplerLock_);
    //         recordSize = sampler_->SampleSize(size);
    //     }
    //     bRecordAllocation = recordSize > 0;
    // } else { // NOSTACK 模式会记录所有内存分配，没有阈值
    // bRecordAllocation = true;
    // }

    // if(!bRecordAllocation) {
    //     return;
    // }

    // 通过 index 找到对应的 .so
    auto hookInfo = wrapper_by_index(index);
    if (hookInfo == nullptr) {
        return;
    }

    // // static thread_local io::buffer obuffer(2048);
    // // obuffer.clear();

    // LOLILOGI("104 loli_maybe_record");

    // std::string file1 = "HookDump.txt" ;
    // std::ofstream outfile;
    // outfile.open(file1, std::ios::out | std::ios::trunc );

    // std::ostringstream oss;
    // oss.clear();
    // oss.str("");

    auto time = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::system_clock::now() - startTime_)
                    .count();
    // // if (mode_ == loliDataMode::NOSTACK) {
    std::string soname = std::string(hookInfo->so_name) + ".so";
    // obuffer << static_cast<uint8_t>(flag) << static_cast<uint32_t>(++callSeq_)
    // << static_cast<int64_t>(time) << static_cast<uint32_t>(size)
    //   << reinterpret_cast<uint64_t>(addr) << static_cast<uint8_t>(0) <<
    //   soname.c_str(); oss << flag << '\\' << ++callSeq_ << ','
    //   << time << ',' << size << ',' << addr << '\\' << hookInfo->so_name <<
    //   ".so";
    struct Record record;
    record.seq_ = static_cast<uint32_t>(++callSeq_);
    record.time_ = static_cast<int64_t>(time);
    record.size_ = static_cast<uint32_t>(size);
    record.addr_ = reinterpret_cast<uint64_t>(addr);
    record.library_ = soname;

    save_record(record);

    // loli_server_send(obuffer.data(), obuffer.size());
}

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

void loli_index_custom_alloc(void *addr, size_t size, int index) {
    loli_maybe_record_alloc(size, addr, loliFlags::MALLOC_, index);
}

// void *loli_index_malloc(size_t size, int index) {
//     LOLILOGI("before malloc");
//     void* addr = malloc(size);   // malloc 指向分配的内存的起始地址
//     // void* addr = nullptr ;   // malloc 指向分配的内存的起始地址
//     loli_maybe_record_alloc(size, addr, loliFlags::MALLOC_, index);
//     return addr;
//     // return addr;
// }
void *loli_index_malloc(size_t size, int index) {
    // auto cur_info = wrapper_by_index(index);
    // LOLILOGI("before malloc%d, %s", index, cur_info->so_name);
    void *addr = malloc(size); // malloc 指向分配的内存的起始地址
    loli_maybe_record_alloc(size, addr, loliFlags::MALLOC_, index);
    return addr;
    // return addr;
}

void *loli_index_calloc(int n, int size, int index) {
    // auto cur_info = wrapper_by_index(index);
    // LOLILOGI("before calloc%d, %s", index, cur_info->so_name);
    void *addr = calloc(n, size);
    // void* addr = nullptr ;
    loli_maybe_record_alloc(n * size, addr, loliFlags::CALLOC_, index);
    return addr;
    // return addr;
}

void *loli_index_memalign(size_t alignment, size_t size, int index) {
    // auto cur_info = wrapper_by_index(index);
    // LOLILOGI("before memalign%d, %s", index, cur_info->so_name);
    void *addr = memalign(alignment, size);
    loli_maybe_record_alloc(size, addr, loliFlags::MEMALIGN_, index);
    return addr;
    // return nullptr;
}

int loli_index_posix_memalign(void **ptr, size_t alignment, size_t size,
                              int index) {
    // auto cur_info = wrapper_by_index(index);
    // LOLILOGI("before posix_memalign%d, %s", index, cur_info->so_name);
    int ecode = posix_memalign(ptr, alignment, size);
    if (ecode == 0) {
        loli_maybe_record_alloc(size, *ptr, loliFlags::MEMALIGN_, index);
    }
    return ecode;
    // retur
}

void *loli_index_realloc(void *ptr, size_t new_size, int index) {
    // LOLILOGI("before realloc!");
    void *addr = realloc(ptr, new_size);
    // void* addr = nullptr ;
    if (addr != 0) {
        save_free(reinterpret_cast<uint64_t>(addr), static_cast<uint32_t>(++callSeq_));
        loli_maybe_record_alloc(new_size, addr, loliFlags::MALLOC_, index);
    }
    return addr;
}

#ifdef __cplusplus
}
#endif // __cplusplus

void loli_free(void *ptr) {
    if (ptr == nullptr) {
        return;
    }
    // std::ostringstream oss;
    // static thread_local io::buffer obuffer(128);
    // obuffer.clear();
    // obuffer << static_cast<uint8_t>(FREE_) << static_cast<uint32_t>(++callSeq_)
    // << reinterpret_cast<uint64_t>(ptr);
    save_free(reinterpret_cast<uint64_t>(ptr), static_cast<uint32_t>(++callSeq_));

    // oss << FREE_ << '\\' << ++callSeq_ << '\\' << ptr;
    // loli_server_send(obuffer.data(), obuffer.size());
    free(ptr);
}

void loli_custom_free(void *ptr) {
    if (ptr == nullptr)
        return;
    // static thread_local io::buffer obuffer(128);
    // obuffer.clear();
    // obuffer << static_cast<uint8_t>(FREE_) << static_cast<uint32_t>(++callSeq_)
    // << reinterpret_cast<uint64_t>(ptr);
    save_free(reinterpret_cast<uint64_t>(ptr), static_cast<uint32_t>(++callSeq_));

    // loli_server_send(obuffer.data(), obuffer.size());
}

typedef void (*LOLI_SET_ALLOCANDFREE_FPTR)(LOLI_ALLOC_FPTR, FREE_FPTR);

LOLI_SET_ALLOCANDFREE_FPTR loli_get_allocandfree(const char *path) {
    void *handler = fake_dlopen(path, RTLD_LAZY);
    if (handler) {
        LOLI_SET_ALLOCANDFREE_FPTR ptr = nullptr;
        *(void **)(&ptr) = fake_dlsym(handler, "loli_set_allocandfree");
        fake_dlclose(handler);
        return ptr;
    } else {
        LOLILOGI("Error dlopen: %s", path);
    }
    return nullptr;
}

// demangled name, <full name, base address>
using so_info_map = std::unordered_map<std::string, std::pair<std::string, uintptr_t>>;

bool loli_hook_library(const char *library, so_info_map &infoMap) {
    if (auto info = wrapper_by_name(library)) {
        // void *pr = loli_index_malloc(1,0);
        // loli_free(pr);

        auto brief = infoMap[std::string(info->so_name)];
        info->so_baseaddr = brief.second;

        if (auto set_allocandfree = loli_get_allocandfree(brief.first.c_str())) {
            set_allocandfree(info->custom_alloc, loli_custom_free);
        }

        auto regex = std::string(".*/") + library + "\\.so$";
        xhook_register(regex.c_str(), "malloc", (void *)info->malloc, nullptr);
        xhook_register(regex.c_str(), "free", (void *)loli_free, nullptr);
        xhook_register(regex.c_str(), "calloc", (void *)info->calloc, nullptr);
        xhook_register(regex.c_str(), "memalign", (void *)info->memalign, nullptr);
        xhook_register(regex.c_str(), "aligned_alloc", (void *)info->memalign, nullptr);
        xhook_register(regex.c_str(), "posix_memalign", (void *)info->posix_memalign, nullptr);
        xhook_register(regex.c_str(), "realloc", (void *)info->realloc, nullptr);
        return true;
    } else {
        LOLILOGE("Out of wrappers!");
        return false;
    }
}

void loli_hook_blacklist(const std::unordered_set<std::string> &blacklist,
                         so_info_map &infoMap) {
    for (auto &token : blacklist) {
        auto regex = ".*/" + token + "\\.so$";
        xhook_ignore(regex.c_str(), NULL);
    }
    for (auto &pair : infoMap) {
        if (blacklist.find(pair.first) != blacklist.end()) {
            continue;
        }
        if (!loli_hook_library(pair.first.c_str(), infoMap)) {
            return;
        }
    }
}

void loli_hook_whitelist(const std::unordered_set<std::string> &whitelist,
                         so_info_map &infoMap) {
    for (auto &token : whitelist) {
        if (!loli_hook_library(token.c_str(), infoMap)) {
            return;
        }
    }
}

void loli_hook(const std::unordered_set<std::string> &tokens,
               std::unordered_map<std::string, uintptr_t> infoMap) {
    xhook_enable_debug(1);
    xhook_clear();
    // convert absolute path to relative ones, ie: system/lib/libc.so -> libc
    so_info_map demangledMap;
    for (auto &pair : infoMap) {
        auto origion = pair.first;
        if (origion.find(".so") == std::string::npos) {
            continue;
        }
        std::string demangled;
        loli_demangle(origion,
                      demangled); // origin 是绝对路径，demangled 是 .so 的名字
        demangledMap[demangled] = std::make_pair(origion, pair.second);
    }
    if (isBlacklist_) {
        loli_hook_blacklist(tokens, demangledMap);
    } else {
        loli_hook_whitelist(tokens, demangledMap);
    }

    xhook_refresh(0);
}

void loli_smaps_thread(std::unordered_set<std::string> libs) {
    char line[512]; // proc/self/maps parsing code by xhook
    FILE *fp;
    uintptr_t baseAddr;
    char perm[5];
    unsigned long offset;
    int pathNamePos;
    char *pathName;
    size_t pathNameLen;
    std::unordered_set<std::string> loaded;
    std::unordered_set<std::string> desired(libs);
    std::unordered_map<std::string, uintptr_t> libBaseAddrMap;
    int loadedDesiredCount = static_cast<int>(desired.size());
    while (true) {
        if (NULL == (fp = fopen("/proc/self/maps", "r"))) {
            continue;
        }
        bool shouldHook = false;
        while (fgets(line, sizeof(line), fp)) { // 一次读 512 个字符
            if (sscanf(line, "%" PRIxPTR "-%*lx %4s %lx %*x:%*x %*d%n", &baseAddr,
                       perm, &offset, &pathNamePos)
                != 3)
                continue;
            // check permission & offset
            if (perm[0] != 'r')
                continue;
            if (perm[3] != 'p')
                continue; // do not touch the shared memory
            if (0 != offset)
                continue;
            // get pathname
            while (isspace(line[pathNamePos]) && pathNamePos < (int)(sizeof(line) - 1))
                pathNamePos += 1;
            if (pathNamePos >= (int)(sizeof(line) - 1))
                continue;
            pathName = line + pathNamePos;
            pathNameLen =
                strlen(pathName); // strlen 碰到空字符结束，计算的长度不包括空字符
            if (0 == pathNameLen)
                continue;
            if (pathName[pathNameLen - 1] == '\n') {
                pathName[pathNameLen - 1] = '\0';
                pathNameLen -= 1;
            }
            if (0 == pathNameLen)
                continue;
            if ('[' == pathName[0])
                continue;
            // check path
            auto pathnameStr = std::string(pathName);
            if (loaded.find(pathnameStr) == loaded.end()) {
                libBaseAddrMap[pathnameStr] = baseAddr;
                // path in loaded is full path to .so library
                loaded.insert(pathnameStr);
                if (isBlacklist_) {
                    shouldHook = true;
                } else {
                    for (auto &token : desired) {
                        // 当前 map 里有想要 hook 的 lib 信息
                        if (pathnameStr.find(token) != std::string::npos) {
                            shouldHook = true;
                            loadedDesiredCount--;
                            LOLILOGI("%s (%s) is loaded", token.c_str(), pathnameStr.c_str());
                        }
                    }
                }
            }
        }

        fclose(fp);
        if (shouldHook) {
            // desired 是白名单中想要 hook 的 lib，libBaseAddrMap 是当前 maps
            // 文件中记录的所有 lib 的信息

            LOLILOGI("desired size = XXX %lu, libBaseAddrMap size = %lu , shouldHook "
                     "= %d \n",
                     desired.size(), libBaseAddrMap.size(), shouldHook);
            loli_hook(desired, libBaseAddrMap);
        }

        if (loadedDesiredCount <= 0) {
            LOLILOGI("All desired libraries are loaded.");
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(500)); // 每隔 500ms 读一次 maps 文件
    }
}

void FHookDumpModule::StartupModule() {
    // This code will execute after your module is loaded into memory; the exact
    // timing is specified in the .uplugin file per-module

    bool bEnableHook = FParse::Param(FCommandLine::Get(), TEXT("Hook"));
    if (!bEnableHook) {
        return;
    }

    if (!wrapper_init()) {
        LOLILOGI("wrapper_init failed");
        return;
    }

    // tokens 里是要 hook 的库名
    std::unordered_set<std::string> tokens;

    std::ifstream infile("/data/data/com.DZ.AndroidTest/black_hook.txt");

    if (infile) { // black_hook.txt exists, whitelist mode!
        isBlacklist_ = false;
        std::string line;
        std::vector<std::string> words;
        std::vector<std::string> sizes;
        while (std::getline(infile, line)) {
            loli_split(line, words, ".");
            loli_split(line, sizes, " ");
            if (words.size() < 2 || sizes.size() < 2) {
                LOLILOGI("words.size()<2!!");
                continue;
            }
            if (std::stof(sizes[1]) > 100.0) {
                tokens.insert(words[0]);
            }
        }
    }

    if (isBlacklist_) {
        tokens = {"libUE4", "libc"};
    }

    // LOLILOGI("tokens have:");
    // for (auto it = tokens.begin(); it != tokens.end(); it++) {
    //     LOLILOGI(" %s ", (*it).c_str());
    // }

    std::thread(loli_smaps_thread, tokens).detach();

    // dump_thread = std::thread(info_dump);
    std::thread(info_dump).detach();

    return;
}

void FHookDumpModule::ShutdownModule() {
    // This function may be called during shutdown to clean up your module.  For
    // modules that support dynamic reloading, we call this function before
    // unloading the module.
    // LOLILOGI("ShutdownModule!!");
    return;
}

#undef LOCTEXT_NAMESPACE

IMPLEMENT_MODULE(FHookDumpModule, HookDump)

#endif // HOOKDUMP_CPP
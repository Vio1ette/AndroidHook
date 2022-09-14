#pragma once
#include "data.h"
#include "spinlock.h"
#include <fstream>
#include <vector>
#include <list>
#include <thread>
#include <sstream>
#include <unordered_map>
#include "dump_utils.h"

loli::spinlock cacheLock_;
extern bool isBlacklist_;
std::vector<Record> records_;
// <seq_, address_>
// std::vector<std::pair<uint32_t, uint64_t>> freeinfo_;
std::unordered_map<uint64_t, uint32_t> freeinfo_;

std::list<PersistentRecord> persistents;

void save_record(const Record &record) {
    std::lock_guard<loli::spinlock> lock(cacheLock_);
    records_.push_back(record);
    return;
}

void save_free(const uint64_t &addr, const uint32_t &seq) {
    std::lock_guard<loli::spinlock> lock(cacheLock_);
    if (freeinfo_[addr] < seq) {
        freeinfo_[addr] = seq;
    }
    return;
}

// 根据 freeinfo_，尝试更新常驻内存表，删除已经free过的内存记录
void update_persistents() {
    for (auto persis_iter = persistents.begin(); persis_iter != persistents.end();) {
        auto free_it = freeinfo_.find(persis_iter->addr_);
        if (free_it != freeinfo_.end() && free_it->second > persis_iter->seq_) {
            persis_iter = persistents.erase(persis_iter);
        } else {
            ++persis_iter;
        }
    }
    return;
}

// 尝试从 recoreds_ 中筛选出新的常驻内存记录， 加入常驻内存表
void records_to_persistents() {
    std::lock_guard<loli::spinlock> lock(cacheLock_);
    int records_len = records_.size();
    for (int i = 0; i < records_len; i++) {
        auto free_it = freeinfo_.find(records_[i].addr_);
        if (free_it == freeinfo_.end() || free_it->second < records_[i].seq_) {
            PersistentRecord temp;
            temp.size_ = records_[i].size_;
            temp.addr_ = records_[i].addr_;
            temp.library_ = records_[i].library_;
            persistents.insert(persistents.begin(), temp);
        }
    }
    records_.clear();
    return;
}

void info_dump() {

    std::ostringstream ss;

    ss.clear();
    ss.str("");

    const uint64_t time_interval = isBlacklist_ ? 10000 : 5000;

    while (true) {
        std::this_thread::sleep_for(std::chrono::milliseconds(time_interval));
        // LOLILOGI("dump wake! ");
        while (records_.size() > 5000) {
            LOLILOGI(" records_ okkk! ");

            update_persistents();
            records_to_persistents();

            std::unordered_map<std::string, int32_t> local_record;

            for (auto it = persistents.begin(); it != persistents.end(); it++) {
                local_record[it->library_] += it->size_;
            }

            std::ofstream file;

            std::string filename = isBlacklist_ ? "/data/data/com.DZ.AndroidTest/black_hook.txt" : "/data/data/com.DZ.AndroidTest/white_hook.txt";
            file.open(filename, std::ofstream::out);

            if (!file) {
                LOLILOGI("can't open|create black_hook.txt");
            } else {
                ss.clear();
                ss.str("");

                for (auto it = local_record.begin(); it != local_record.end(); it++) {
                    ss << it->first << " " << it->second / 1000.0 << " KB" << std::endl;
                }

                file << ss.str();
                file.close();
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(time_interval)); // 每隔一段时间记录一次数据
        }
    }
}
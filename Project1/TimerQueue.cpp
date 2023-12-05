#include "TimerQueue.h"

TimerQueue::TimerQueue()
    : running_(false),
    timer_cnt_(0) {}

TimerQueue::~TimerQueue() {}

// call run to start timerqueue
bool TimerQueue::Run() {
    running_ = true;
    std::thread([this]() { RunLocal(); }).detach();
    return true;
}

void TimerQueue::RunLocal() {
    while (running_) {
        std::unique_lock<std::mutex> lock(mutex_);
        if (timer_list_.empty()) {
            cond_.wait(lock);
            continue;
        }
        auto s = timer_list_.front();
        auto diff = s.time_point_ - std::chrono::high_resolution_clock::now();
        if (std::chrono::duration_cast<std::chrono::milliseconds>(diff).count() > 0) {
            cond_.wait_for(lock, diff);
            continue;
        }
        else {
            timer_map_.erase(s.timer_id_);
            timer_list_.pop_front();
            lock.unlock();
            s.func_();
        }
    }
}


int TimerQueue::AddFuncAtTimePoint(const std::chrono::time_point<std::chrono::high_resolution_clock>& time_point, TimerFunc&& func) {
    Timer s;
    s.func_ = std::move(func);
    s.time_point_ = time_point;
    s.timer_id_ = timer_cnt_++;
    {
        std::unique_lock<std::mutex> lock(mutex_);
        auto iter = timer_list_.begin();
        while (iter != timer_list_.end() && (*iter) < s) { ++iter; }
        auto insert_iter = timer_list_.insert(iter, s);
        timer_map_.insert({ s.timer_id_, insert_iter });
        cond_.notify_all();
    }
    return s.timer_id_;
}

int TimerQueue::AddFuncAfterDuration(const std::chrono::seconds& time, TimerFunc&& func) {
    Timer s;
    s.func_ = std::move(func);
    s.time_point_ = std::chrono::high_resolution_clock::now() + time;
    s.timer_id_ = timer_cnt_++;
    {
        std::unique_lock<std::mutex> lock(mutex_);
        auto iter = timer_list_.begin();
        while (iter != timer_list_.end() && (*iter) < s) { ++iter; }
        auto insert_iter = timer_list_.insert(iter, s);
        timer_map_.insert({ s.timer_id_, insert_iter });
        cond_.notify_all();
    }
    return s.timer_id_;
}


bool TimerQueue::RemoveTimer(int timer_id) {
    std::unique_lock<std::mutex> lock_guard(mutex_);
    auto iter = timer_map_.find(timer_id);
    if (iter == timer_map_.end()) {
        return false;
    }
    timer_list_.erase(iter->second);
    timer_map_.erase(iter);
    cond_.notify_all();
}





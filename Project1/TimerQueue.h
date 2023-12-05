#pragma once
#pragma once
#include <chrono>
#include <functional>
#include <list>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <map>
class TimerQueue {
public:
    using TimerFunc = std::function<void()>;
public:
    TimerQueue();
    ~TimerQueue();
    // call run to start timerqueue
    bool Run();

    int AddFuncAtTimePoint(const std::chrono::time_point<std::chrono::high_resolution_clock>& time_point, TimerFunc&&);
    int AddFuncAfterDuration(const std::chrono::seconds& time, TimerFunc&&);
    bool RemoveTimer(int timer_id);

private:
    void RunLocal();

private:
    struct Timer {
        std::chrono::time_point<std::chrono::high_resolution_clock> time_point_;
        std::function<void()> func_;
        int timer_id_;
        bool operator<(const Timer& b) const { return time_point_ < b.time_point_; }
        //Timer(const Timer& rhs) { time_point_ = rhs.time_point_; func_ = rhs.func_; timer_id_ = rhs.timer_id_; }
    };
    using TimerList = std::list<Timer>;
    using TimerMap = std::map<int, TimerList::iterator>;

    TimerList timer_list_;
    TimerMap timer_map_;

    std::atomic_bool running_;
    std::atomic_int timer_cnt_;
    std::mutex mutex_;
    std::condition_variable cond_;
};
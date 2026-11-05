#pragma once
// One background run at a time for the packet tools (PacketFilterJob, TcpStreamJob): same model as
// PcapIndexJob / StringsJob. start() cancels a previous run without waiting for it (it finishes in
// the background and publishes nothing); the destructor cancels and joins every run.
#include <atomic>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <thread>
#include <utility>
#include <vector>

namespace hx {

template <class R>
class PcapWorker {
public:
    // work(result, cancel, done): fills `result`, polls `cancel`, counts `done` up to `total`.
    using Work = std::function<void(R&, const std::atomic<bool>&, std::atomic<uint64_t>&)>;

    PcapWorker() = default;
    ~PcapWorker() {
        for (auto& t : threads_) t.second->cancel = true;
        for (auto& t : threads_) t.first.join();
    }
    PcapWorker(const PcapWorker&) = delete;
    PcapWorker& operator=(const PcapWorker&) = delete;

    void start(uint64_t total, Work work) {
        auto run = std::make_shared<Run>();
        run->total = total;
        {
            std::lock_guard<std::mutex> lock(mu_);
            if (run_) run_->cancel = true;
            run_ = run;
        }
        for (auto it = threads_.begin(); it != threads_.end();) {
            if (it->second->finished) {
                it->first.join();
                it = threads_.erase(it);
            } else {
                ++it;
            }
        }
        running_ = true;
        std::thread th([this, run, work = std::move(work)]() {
            auto r = std::make_shared<R>();
            work(*r, run->cancel, run->done);
            {
                std::lock_guard<std::mutex> lock(mu_);
                if (run_ == run) {  // superseded runs publish nothing
                    result_ = std::move(r);
                    run->done = run->total;
                    running_ = false;
                    generation_.fetch_add(1);
                }
            }
            run->finished = true;
        });
        threads_.emplace_back(std::move(th), std::move(run));
    }
    void cancel() {  // non-blocking request
        std::lock_guard<std::mutex> lock(mu_);
        if (run_) run_->cancel = true;
    }
    bool running() const { return running_.load(); }
    double progress() const {  // 0..1
        std::lock_guard<std::mutex> lock(mu_);
        const uint64_t t = run_ ? run_->total : 0, d = run_ ? run_->done.load() : 0;
        if (!t) return running_.load() ? 0.0 : 1.0;
        return d >= t ? 1.0 : double(d) / double(t);
    }
    uint64_t generation() const { return generation_.load(); }  // increments when a run finishes
    std::shared_ptr<const R> result() const {  // last finished run; null before the first
        std::lock_guard<std::mutex> lock(mu_);
        return result_;
    }
    void clear_result() {  // drop the published result (e.g. a big buffer that was handed over)
        std::lock_guard<std::mutex> lock(mu_);
        result_.reset();
    }

private:
    struct Run {
        std::atomic<bool> cancel{false};
        std::atomic<bool> finished{false};
        std::atomic<uint64_t> done{0};
        uint64_t total = 0;
    };
    std::shared_ptr<Run> run_;
    std::vector<std::pair<std::thread, std::shared_ptr<Run>>> threads_;
    std::atomic<bool> running_{false};
    std::atomic<uint64_t> generation_{0};
    mutable std::mutex mu_;
    std::shared_ptr<const R> result_;
};

}  // namespace hx

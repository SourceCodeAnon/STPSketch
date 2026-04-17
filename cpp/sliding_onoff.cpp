#include <algorithm>
#include <cmath>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>
#include <chrono>

using namespace std;

static inline uint32_t hash32_uint(uint32_t key, uint32_t seed) {

    uint32_t x = seed;
    for (int i = 0; i < 4; ++i) {
        uint32_t byte = (key >> (i * 8)) & 0xFFu;
        x = (x * 131u + byte) & 0xFFFFFFFFu;
    }
    return x;
}

class SlidingCounter {
public:
    vector<int> fields;
    bool state;
    int counter_size;

    SlidingCounter() : fields(), state(true), counter_size(0) {}

    SlidingCounter(int d, int counter_size_)
        : fields(d, 0), state(true), counter_size(counter_size_) {}

    void increment() {
        if (state) {
            if (!fields.empty()) {
                fields[0] += 1;
                int max_val = (1 << counter_size) - 1;
                if (fields[0] > max_val) {
                    std::cerr << "SlidingCounter overflow: fields[0] = "
                              << fields[0] << " > " << max_val << std::endl;
                    throw std::runtime_error("SlidingCounter overflow");
                }
            }
            state = false;
        }
    }

    void reset_state() {
        state = true;
    }

    void shift_day() {
        for (int i = static_cast<int>(fields.size()) - 1; i > 0; --i) {
            fields[i] = fields[i - 1];
        }
        if (!fields.empty()) fields[0] = 0;
    }

    int value() const {
        int s = 0;
        for (int v : fields) s += v;
        return s;
    }
};

class BucketEntry {
public:
    uint32_t key;
    bool has_key;
    SlidingCounter counter;

    BucketEntry() : key(0), has_key(false), counter() {}

    BucketEntry(int d, int counter_size)
        : key(0), has_key(false), counter(d, counter_size) {}
};

class OnOffSlidingSketch {
public:
    double total_mem_MB;
    int d;
    int window_count;
    int persistent_threshold;
    int bucket_cell_num;
    int counter_size;
    int id_size;
    uint32_t hash_seed;

    int col_num;
    int bucket_count;

    vector<SlidingCounter> base_counters;
    vector<vector<BucketEntry>> buckets;

    double scan_rate;
    int scan_pos;
    double scan_accum;

    int current_window;

    OnOffSlidingSketch(
        double total_mem_MB_,
        int d_,
        int window_count_,
        int persistent_threshold_,
        int bucket_cell_num_ = 8,
        int id_size_ = 32,
        const vector<uint32_t> &hash_seeds = {}
    )
        : total_mem_MB(total_mem_MB_),
          d(d_),
          window_count(window_count_),
          persistent_threshold(persistent_threshold_),
          bucket_cell_num(bucket_cell_num_),
          id_size(id_size_),
          scan_rate(0.0),
          scan_pos(0),
          scan_accum(0.0),
          current_window(0) {

        if (d < 2) {
            throw std::runtime_error("d must be >= 2 for Sliding Sketch");
        }
        if (window_count <= 0) {
            throw std::runtime_error("window_count must be positive");
        }

        if (!hash_seeds.empty()) {
            hash_seed = hash_seeds[0] & 0xFFFFFFFFu;
        } else {
            hash_seed = 1337u;
        }

        int q = (window_count + (d - 2)) / (d - 1);
        int tmp = 1 + q;
        counter_size = static_cast<int>(std::ceil(std::log2(static_cast<double>(tmp))));

        int cell_mem_bit = d * counter_size + 1;

        int bits_per_loc = cell_mem_bit + bucket_cell_num * (cell_mem_bit + id_size);

        long long total_bits = static_cast<long long>(total_mem_MB * 1024.0 * 1024.0 * 8.0);
        if (total_bits <= 0) {
            throw std::runtime_error("total_mem_MB must be > 0");
        }

        col_num = static_cast<int>(total_bits / bits_per_loc);
        if (col_num <= 0) {
            throw std::runtime_error("Memory too small for given parameters.");
        }

        bucket_count = col_num;

        base_counters.assign(bucket_count, SlidingCounter(d, counter_size));
        buckets.assign(bucket_count, vector<BucketEntry>(bucket_cell_num, BucketEntry(d, counter_size)));

        scan_rate = (d - 1) * col_num / static_cast<double>(window_count);
        scan_pos = 0;
        scan_accum = 0.0;
        current_window = 0;
    }

    int bucket_index(uint32_t key) const {
        uint32_t h = hash32_uint(key, hash_seed);
        return static_cast<int>(h % static_cast<uint32_t>(bucket_count));
    }

    void insert(uint32_t flow_id) {
        int idx = bucket_index(flow_id);
        auto &bucket = buckets[idx];

        BucketEntry *target_entry = nullptr;
        for (auto &entry : bucket) {
            if (entry.has_key && entry.key == flow_id) {
                target_entry = &entry;
                break;
            }
        }

        if (target_entry != nullptr) {
            target_entry->counter.increment();
            return;
        }

        SlidingCounter &base_counter = base_counters[idx];
        base_counter.increment();

        BucketEntry *min_entry = &bucket[0];
        int min_value = bucket[0].counter.value();
        for (size_t i = 1; i < bucket.size(); ++i) {
            int v = bucket[i].counter.value();
            if (v < min_value) {
                min_value = v;
                min_entry = &bucket[i];
            }
        }

        if (base_counter.value() > min_value) {
            min_entry->key = flow_id;
            min_entry->has_key = true;
            swap_counters(base_counter, min_entry->counter);
        }
    }

    void swap_counters(SlidingCounter &a, SlidingCounter &b) {
        a.fields.swap(b.fields);
        std::swap(a.state, b.state);
    }

    void advance_sliding_window() {
        scan_accum += scan_rate;
        int num_to_scan = static_cast<int>(scan_accum);
        if (num_to_scan <= 0) return;
        scan_accum -= num_to_scan;

        int m = col_num;
        int pos = scan_pos;
        for (int k = 0; k < num_to_scan; ++k) {
            if (pos >= m) pos = 0;

            base_counters[pos].shift_day();

            auto &bucket = buckets[pos];
            for (auto &entry : bucket) {
                entry.counter.shift_day();
            }
            pos += 1;
        }
        scan_pos = pos;
    }

    void switch_time_window() {

        for (auto &c : base_counters) {
            c.reset_state();
        }
        for (auto &bucket : buckets) {
            for (auto &entry : bucket) {
                entry.counter.reset_state();
            }
        }

        advance_sliding_window();
        current_window += 1;
    }

    vector<pair<uint32_t, int>> report_persistent() const {
        unordered_map<uint32_t, int> result;
        for (const auto &bucket : buckets) {
            for (const auto &entry : bucket) {
                if (!entry.has_key) continue;
                int v = entry.counter.value();
                if (v >= persistent_threshold) {
                    auto it = result.find(entry.key);
                    if (it == result.end() || v > it->second) {
                        result[entry.key] = v;
                    }
                }
            }
        }

        vector<pair<uint32_t, int>> out;
        out.reserve(result.size());
        for (const auto &kv : result) {
            out.emplace_back(kv.first, kv.second);
        }
        return out;
    }
};

using TimeSlice       = vector<uint32_t>;
using SwitchTimeSlice = vector<TimeSlice>;
using AllTimeSlices   = vector<SwitchTimeSlice>;

using PersistentItem   = pair<uint32_t, int>;
using WindowPersistent = vector<PersistentItem>;
using SwitchPersistent = vector<WindowPersistent>;
using PersistentLists  = vector<SwitchPersistent>;
using PersistentWindowList = vector<vector<PersistentItem>>;

using WidespreadList = vector<vector<pair<uint32_t,int>>>;

AllTimeSlices load_time_slices(const string &base_dir) {
    AllTimeSlices time_slices_lst;
    const size_t MAX_PACKETS = 10000000ULL;
    const size_t WINDOW_SIZE = 20000ULL;

    for (int i = 0; i < 5; ++i) {
        char buf[64];
        std::snprintf(buf, sizeof(buf), "0%d.txt", i);
        string filename = base_dir + string(buf);

        ifstream fin(filename);
        if (!fin.is_open()) {
            cerr << "Failed to open file: " << filename << '\n';
            continue;
        }

        vector<uint32_t> packages;
        packages.reserve(MAX_PACKETS);
        uint32_t ip;
        while (fin >> ip) {
            packages.push_back(ip);
            if (packages.size() >= MAX_PACKETS) break;
        }
        fin.close();

        cout << "IPv4 flow count: " << packages.size()
             << " (file " << filename << ")\n";

        vector<TimeSlice> time_slices;
        for (size_t start = 0; start < packages.size(); start += WINDOW_SIZE) {
            size_t end = std::min(start + WINDOW_SIZE, packages.size());
            time_slices.emplace_back(packages.begin() + start, packages.begin() + end);
        }
        cout << "Time slice count: " << time_slices.size() << '\n';

        time_slices_lst.emplace_back(std::move(time_slices));
    }

    return time_slices_lst;
}

PersistentLists compute_real_persistent(
    const AllTimeSlices &time_slices_lst,
    int window_count,
    int persistent_threshold
) {
    PersistentLists real_persistent_lists;
    real_persistent_lists.reserve(time_slices_lst.size());

    for (size_t switch_index = 0; switch_index < time_slices_lst.size(); ++switch_index) {
        cout << "switch " << switch_index << '\n';
        const auto &time_slices = time_slices_lst[switch_index];

        vector<unordered_set<uint32_t>> appear_lsts;
        appear_lsts.reserve(time_slices.size());
        for (const auto &time_slice : time_slices) {
            unordered_set<uint32_t> appear;
            appear.reserve(time_slice.size());
            for (uint32_t f : time_slice) {
                appear.insert(f);
            }
            appear_lsts.emplace_back(std::move(appear));
        }

        SwitchPersistent real_persistent_lst;
        real_persistent_lst.reserve(time_slices.size());

        int window_record = 0;
        for (size_t index = 0; index < appear_lsts.size(); ++index) {
            if (window_record < window_count) {
                window_record += 1;
            }

            unordered_set<uint32_t> item_set;
            for (int i = 0; i < window_record; ++i) {
                const auto &st = appear_lsts[index - i];
                item_set.insert(st.begin(), st.end());
            }

            vector<PersistentItem> true_persistent_items;
            true_persistent_items.reserve(item_set.size());
            for (uint32_t item : item_set) {
                int appear_count = 0;
                for (int i = 0; i < window_record; ++i) {
                    const auto &st = appear_lsts[index - i];
                    if (st.find(item) != st.end()) {
                        appear_count += 1;
                    }
                }
                if (appear_count >= persistent_threshold) {
                    true_persistent_items.emplace_back(item, appear_count);
                }
            }

            cout << '\r' << (index + 1) << " : " << true_persistent_items.size()
                 << " / " << item_set.size() << std::flush;
            real_persistent_lst.emplace_back(std::move(true_persistent_items));
        }
        cout << '\n';

        real_persistent_lists.emplace_back(std::move(real_persistent_lst));
    }

    return real_persistent_lists;
}

WidespreadList compute_widespread(const PersistentLists &persistent_lists,
                                  int lambda_threshold = 4) {
    int num_switches = static_cast<int>(persistent_lists.size());
    if (num_switches == 0) return {};

    int num_windows = static_cast<int>(persistent_lists[0].size());
    WidespreadList widespread_lists;
    widespread_lists.reserve(num_windows);

    for (int t = 0; t < num_windows; ++t) {
        unordered_map<uint32_t,int> freq;

        for (int s = 0; s < num_switches; ++s) {
            const auto &entries = persistent_lists[s][t];
            unordered_set<uint32_t> item_set;
            item_set.reserve(entries.size());
            for (const auto &e : entries) {
                uint32_t item = e.first;
                item_set.insert(item);
            }
            for (uint32_t item : item_set) {
                freq[item] += 1;
            }
        }

        vector<pair<uint32_t,int>> widespread_items;
        widespread_items.reserve(freq.size());
        for (const auto &kv : freq) {
            if (kv.second >= lambda_threshold) {
                widespread_items.emplace_back(kv.first, kv.second);
            }
        }
        widespread_lists.emplace_back(std::move(widespread_items));
    }

    return widespread_lists;
}

WidespreadList get_real(const AllTimeSlices &time_slices_lst,
                        int window_count,
                        int persistent_threshold,
                        int lambda_threshold = 4) {
    vector<PersistentWindowList> real_persistent_lists;
    real_persistent_lists.reserve(time_slices_lst.size());

    for (size_t switch_index = 0; switch_index < time_slices_lst.size(); ++switch_index) {
        const auto &time_slices = time_slices_lst[switch_index];
        cout << "switch " << switch_index << "\n";

        vector<unordered_set<uint32_t>> appear_lsts;
        appear_lsts.reserve(time_slices.size());
        for (const auto &time_slice : time_slices) {
            unordered_set<uint32_t> appear;
            appear.reserve(time_slice.size());
            for (uint32_t f : time_slice) {
                appear.insert(f);
            }
            appear_lsts.emplace_back(std::move(appear));
        }

        PersistentWindowList real_persistent_lst;
        real_persistent_lst.reserve(time_slices.size());

        int window_record = 0;
        for (size_t index = 0; index < appear_lsts.size(); ++index) {
            if (window_record < window_count) {
                window_record += 1;
            }

            unordered_set<uint32_t> item_set;
            for (int i = 0; i < window_record; ++i) {
                const auto &st = appear_lsts[index - i];
                item_set.insert(st.begin(), st.end());
            }

            vector<PersistentItem> true_persistent_items;
            true_persistent_items.reserve(item_set.size());
            for (uint32_t item : item_set) {
                int appear_count = 0;
                for (int i = 0; i < window_record; ++i) {
                    const auto &st = appear_lsts[index - i];
                    if (st.find(item) != st.end()) {
                        appear_count += 1;
                    }
                }
                if (appear_count >= persistent_threshold) {
                    true_persistent_items.emplace_back(item, appear_count);
                }
            }
            cout << '\r' << (index + 1) << ": " << true_persistent_items.size()
                 << "/" << item_set.size() << flush;
            real_persistent_lst.emplace_back(std::move(true_persistent_items));
        }
        cout << "\n";
        real_persistent_lists.emplace_back(std::move(real_persistent_lst));
    }

    return compute_widespread(real_persistent_lists, lambda_threshold);
}

struct Metrics {
    long long TP;
    long long FP;
    long long FN;
    double precision;
    double recall;
    double f1;
    double AAE;
    double ARE;
};

Metrics eval_widespread(const WidespreadList &real_widespread_lists,
                        const WidespreadList &est_widespread_lists) {
    Metrics m{0, 0, 0, 0.0, 0.0, 0.0, 0.0, 0.0};

    if (real_widespread_lists.size() != est_widespread_lists.size()) {
        std::cerr << "Error: real and est window counts differ" << std::endl;
        return m;
    }

    size_t num_windows = real_widespread_lists.size();

    long long total_TP_pairs = 0;
    double sum_abs_error = 0.0;
    double sum_rel_error = 0.0;

    for (size_t t = 0; t < num_windows; ++t) {
        std::unordered_set<uint32_t> real_items;
        std::unordered_set<uint32_t> est_items;

        std::unordered_map<uint32_t, int> real_map;
        std::unordered_map<uint32_t, int> est_map;

        for (const auto &p : real_widespread_lists[t]) {
            real_items.insert(p.first);
            real_map[p.first] = p.second;
        }
        for (const auto &p : est_widespread_lists[t]) {
            est_items.insert(p.first);
            est_map[p.first] = p.second;
        }

        long long TP = 0, FP = 0, FN = 0;

        for (uint32_t item : real_items) {
            if (est_items.find(item) != est_items.end()) {
                TP++;

                auto it_est = est_map.find(item);
                auto it_real = real_map.find(item);
                if (it_est != est_map.end() && it_real != real_map.end()) {
                    int real_cnt = it_real->second;
                    int est_cnt  = it_est->second;
                    int diff = std::abs(est_cnt - real_cnt);
                    sum_abs_error += diff;
                    if (real_cnt > 0) {
                        sum_rel_error += static_cast<double>(diff) / real_cnt;
                    }
                    total_TP_pairs++;
                }

            } else {
                FN++;
            }
        }

        for (uint32_t item : est_items) {
            if (real_items.find(item) == real_items.end()) {
                FP++;
            }
        }

        m.TP += TP;
        m.FP += FP;
        m.FN += FN;
    }

    if (m.TP + m.FP > 0) m.precision = static_cast<double>(m.TP) / (m.TP + m.FP);
    if (m.TP + m.FN > 0) m.recall    = static_cast<double>(m.TP) / (m.TP + m.FN);
    if (m.precision + m.recall > 0) {
        m.f1 = 2.0 * m.precision * m.recall / (m.precision + m.recall);
    }

    if (total_TP_pairs > 0) {
        m.AAE = sum_abs_error / total_TP_pairs;
        m.ARE = sum_rel_error / total_TP_pairs;
    } else {
        m.AAE = 0.0;
        m.ARE = 0.0;
    }

    return m;
}

int main() {
    ios::sync_with_stdio(true);
    cin.tie(nullptr);

    string base_dir = "/mnt/c/Users/45512/Documents/dataset/mawi/ip_num/";

    AllTimeSlices time_slices_lst = load_time_slices(base_dir);
    if (time_slices_lst.empty()) {
        cerr << "No data loaded. Check file paths.\n";
        return 1;
    }

    vector<pair<int,int>> persistent_thresholds = {
        {12, 16}
    };

    vector<uint32_t> hash_seeds = {0};
    int bucket_cell_count = 2;
    int total_window_count = 500;
    (void)total_window_count;
    cout << "bucket_cell_count " << bucket_cell_count << '\n';

    vector<int> mem_kb_list = {10, 20, 30, 40, 50, 60, 70, 80, 90, 100};
    vector<double> mem_lst_MB;
    for (int kb : mem_kb_list) {
        mem_lst_MB.push_back(kb / 1024.0);
    }

    int lambda_threshold = 4;
    for (auto pw : persistent_thresholds) {

        int persistent_threshold = pw.first;
        int window_count = pw.second;
        WidespreadList real_widespread_lists = get_real(time_slices_lst, window_count, persistent_threshold, 4);

        for (double total_mem_MB : mem_lst_MB) {
            cout << "total_mem_MB: " << (total_mem_MB * 1024.0) << " KB\n";

            PersistentLists est_persistent_lists;
            est_persistent_lists.resize(time_slices_lst.size());

            auto t_start = std::chrono::steady_clock::now();

            for (size_t switch_index = 0; switch_index < time_slices_lst.size(); ++switch_index) {
                const auto &time_slices = time_slices_lst[switch_index];

                OnOffSlidingSketch sof_sketch(
                    total_mem_MB,
                    2,
                    window_count,
                    persistent_threshold,
                    bucket_cell_count,
                    32,
                    hash_seeds
                );

                SwitchPersistent &est_for_switch = est_persistent_lists[switch_index];
                est_for_switch.reserve(time_slices.size());

                for (size_t index = 0; index < time_slices.size(); ++index) {
                    const auto &time_slice = time_slices[index];
                    for (uint32_t f : time_slice) {
                        sof_sketch.insert(f);
                    }
                    sof_sketch.switch_time_window();
                    auto persistent_items = sof_sketch.report_persistent();
                    est_for_switch.emplace_back(std::move(persistent_items));
                }
            }

            auto t_end = std::chrono::steady_clock::now();
            double elapsed_sec =
                std::chrono::duration<double>(t_end - t_start).count();

            double throughput_mpps = 0.0;
            if (elapsed_sec > 0.0) {
                throughput_mpps =
                    static_cast<double>(20000000ULL * 5) / elapsed_sec / 1e6;
            }
            cout << "Throughput = " << throughput_mpps << " Mpps\n";

            WidespreadList est_widespread_lists  = compute_widespread(est_persistent_lists,  lambda_threshold);

            Metrics metrics = eval_widespread(real_widespread_lists, est_widespread_lists);
            cout << "TP = " << metrics.TP << '\n';
            cout << "FP = " << metrics.FP << '\n';
            cout << "FN = " << metrics.FN << '\n';
            cout << "Precision = " << metrics.precision << '\n';
            cout << "Recall    = " << metrics.recall << '\n';
            cout << "F1        = " << metrics.f1 << '\n';
            cout << "AAE       = " << metrics.AAE << '\n';
            cout << "ARE       = " << metrics.ARE << '\n';
        }

        return 0;
    }
}

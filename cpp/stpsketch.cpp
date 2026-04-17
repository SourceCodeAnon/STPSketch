#include <algorithm>
#include <cstdint>
#include <cmath>
#include <fstream>
#include <iostream>
#include <limits>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>
#include <chrono>

using namespace std;

static inline uint32_t hash32(uint32_t key, uint32_t seed) {
    uint32_t h = key ^ seed;
    h ^= h >> 16;
    h *= 0x85ebca6bU;
    h ^= h >> 13;
    h *= 0xc2b2ae35U;
    h ^= h >> 16;
    return h;
}

class Decay_Cell {
public:
    int counter_size;
    int last_time_window_size;
    int counter;
    int last_time_window;
    int recent_window_count;

    Decay_Cell() = default;

    Decay_Cell(int counter_size_, int last_time_window_size_, int recent_window_count_)
        : counter_size(counter_size_),
          last_time_window_size(last_time_window_size_),
          counter(0),
          last_time_window(0),
          recent_window_count(recent_window_count_) {}

    void decay(int current_time_window) {
        if (current_time_window < recent_window_count || counter == 0) {
            return;
        }
        int delta = current_time_window - last_time_window;
        int decay_count = static_cast<int>((static_cast<double>(delta) / recent_window_count) * counter);
        if (decay_count > counter) {
            counter = 0;
        } else {
            counter -= decay_count;
        }
    }

    void increment(int current_time_window) {
        if (last_time_window == current_time_window) {
            return;
        }
        decay(current_time_window);
        last_time_window = current_time_window;
        if (counter < recent_window_count) {
            counter += 1;
        }
    }

    int query() const {
        return counter;
    }
};

class Decay_CM {
public:
    int row_num;
    int col_num;
    int counter_size;
    int last_time_window_size;
    vector<vector<Decay_Cell>> arrays;
    vector<uint32_t> hash_seeds;

    Decay_CM(int row_num_, double mem_MB, int counter_size_, int last_time_window_size_,
             const vector<uint32_t>& hash_seeds_, int recent_window_count) {
        row_num = row_num_;
        counter_size = counter_size_;
        last_time_window_size = last_time_window_size_;
        hash_seeds = hash_seeds_;

        int cell_mem_bit = counter_size + last_time_window_size;

        long long total_bits = static_cast<long long>(mem_MB * 1024.0 * 1024.0 * 8.0);
        col_num = static_cast<int>(total_bits / row_num / cell_mem_bit);
        if (col_num <= 0) col_num = 1;

        arrays.assign(row_num, vector<Decay_Cell>(col_num));
        for (int r = 0; r < row_num; ++r) {
            for (int c = 0; c < col_num; ++c) {
                arrays[r][c] = Decay_Cell(counter_size, last_time_window_size, recent_window_count);
            }
        }
    }

    void insert(uint32_t f, int current_time_window) {
        for (int row_index = 0; row_index < row_num; ++row_index) {
            uint32_t seed = hash_seeds[row_index];
            uint32_t index = hash32(f, seed) % static_cast<uint32_t>(col_num);
            arrays[row_index][index].increment(current_time_window);
        }
    }

    int query(uint32_t f) const {
        int res = std::numeric_limits<int>::max();
        for (int i = 0; i < row_num; ++i) {
            uint32_t seed = hash_seeds[i];
            uint32_t index = hash32(f, seed) % static_cast<uint32_t>(col_num);
            int q = arrays[i][index].query();
            if (q < res) res = q;
        }
        return res == std::numeric_limits<int>::max() ? 0 : res;
    }

    void set_new_value(uint32_t f, int value) {
        for (int row_index = 0; row_index < row_num; ++row_index) {
            uint32_t seed = hash_seeds[row_index];
            uint32_t index = hash32(f, seed) % static_cast<uint32_t>(col_num);
            if (arrays[row_index][index].query() < value) {
                arrays[row_index][index].counter = value;
            }
        }
    }

    void decline(uint32_t f, int num) {
        for (int row_index = 0; row_index < row_num; ++row_index) {
            uint32_t seed = hash_seeds[row_index];
            uint32_t index = hash32(f, seed) % static_cast<uint32_t>(col_num);
            Decay_Cell &cell = arrays[row_index][index];
            cell.counter = std::max(0, cell.counter - num);
        }
    }
};

class Bucket_Cell {
public:
    uint32_t f;
    int window_count;
    __uint128_t flags;

    Bucket_Cell() = default;

    Bucket_Cell(uint32_t f_, int window_count_)
        : f(f_), window_count(window_count_), flags(0ULL) {}

    void set_0(int idx) {
        flags &= ~(1ULL << idx);
    }

    void set_1(int idx) {
        flags |= (1ULL << idx);
    }

    void insert(int current_time_window) {
        int idx = current_time_window % window_count;
        set_1(idx);
    }

    int query() const {
#ifdef __GNUG__
        return static_cast<int>(__builtin_popcountll(flags));
#else

        uint64_t x = flags;
        int cnt = 0;
        while (x) {
            x &= (x - 1);
            ++cnt;
        }
        return cnt;
#endif
    }

    void switch_time_window(int new_time_window) {
        int idx = new_time_window % window_count;
        set_0(idx);
    }

    int query_flag(int idx) const {
        if (idx < 0 || idx >= 64) return 0;
        return static_cast<int>((flags >> idx) & 1ULL);
    }
};

class Bucket {
public:
    vector<Bucket_Cell> cells;
    int window_count;
    int bucket_cell_count;

    Bucket(int bucket_cell_count_, int window_count_)
        : cells(bucket_cell_count_, Bucket_Cell(0, window_count_)),
          window_count(window_count_),
          bucket_cell_count(bucket_cell_count_) {}

    struct InsertResult {
        bool inserted;
        Bucket_Cell* cell;
        int min_val;
    };

    InsertResult insert(uint32_t f, int current_time_window) {
        Bucket_Cell* empty_cell = nullptr;
        Bucket_Cell* min_cell = nullptr;
        int min_val = std::numeric_limits<int>::max();

        for (auto &cell : cells) {
            if (cell.f == f && cell.f != 0) {
                cell.insert(current_time_window);
                return {true, &cell, min_val};
            }
            if (cell.f == 0 && empty_cell == nullptr) {
                empty_cell = &cell;
            }
            if (cell.f != 0) {
                int q = cell.query();
                if (q < min_val) {
                    min_val = q;
                    min_cell = &cell;
                }
            }
        }

        if (empty_cell != nullptr) {
            empty_cell->f = f;
            empty_cell->insert(current_time_window);
            return {true, empty_cell, min_val};
        }

        return {false, min_cell, min_val};
    }

    int query(uint32_t f) const {
        for (const auto &cell : cells) {
            if (cell.f == f && cell.f != 0) {
                return cell.query();
            }
        }
        return -1;
    }

    void switch_time_window(int new_time_window) {
        for (auto &cell : cells) {
            if (cell.f != 0) {
                cell.switch_time_window(new_time_window);
            }
        }
    }
};

class Persistent_Part {
public:
    int window_count;
    int bucket_cell_count;
    uint32_t hash_seed;
    int bucket_count;
    vector<Bucket> buckets;

    Persistent_Part(int window_count_, double mem_MB, uint32_t hash_seed_, int bucket_cell_count_)
        : window_count(window_count_),
          bucket_cell_count(bucket_cell_count_),
          hash_seed(hash_seed_) {

        int cell_mem_bit = window_count + 32;
        int bucket_mem_bit = cell_mem_bit * bucket_cell_count;
        long long total_bits = static_cast<long long>(mem_MB * 1024.0 * 1024.0 * 8.0);
        bucket_count = static_cast<int>(total_bits / bucket_mem_bit);
        if (bucket_count <= 0) bucket_count = 1;
        buckets.reserve(bucket_count);
        for (int i = 0; i < bucket_count; ++i) {
            buckets.emplace_back(bucket_cell_count, window_count);
        }
    }

    Bucket::InsertResult insert(uint32_t f, int current_time_window) {
        uint32_t bucket_index = hash32(f, hash_seed) % static_cast<uint32_t>(bucket_count);
        return buckets[bucket_index].insert(f, current_time_window);
    }

    int query(uint32_t f) const {
        uint32_t bucket_index = hash32(f, hash_seed) % static_cast<uint32_t>(bucket_count);
        return buckets[bucket_index].query(f);
    }

    void switch_time_window(int new_time_window) {
        for (auto &bucket : buckets) {
            bucket.switch_time_window(new_time_window);
        }
    }
};

class P2Sketch {
public:
    double mem_MB;
    double bucket_mem_rate;
    vector<uint32_t> hash_seeds;
    double bucket_mem;
    double CM_mem;
    Persistent_Part persistent_part;
    Decay_CM CM_part;
    int current_time_window;
    int window_count;
    int persistent_threshold;

    P2Sketch(double mem_MB_, double bucket_mem_rate_, const vector<uint32_t>& hash_seeds_,
             int window_count_, int bucket_cell_count, int CM_row_num,
             int CM_counter_size, int CM_window_size, int persistent_threshold_)
        : mem_MB(mem_MB_),
          bucket_mem_rate(bucket_mem_rate_),
          hash_seeds(hash_seeds_),
          bucket_mem(mem_MB_ * bucket_mem_rate_),
          CM_mem(mem_MB_ - mem_MB_ * bucket_mem_rate_),
          persistent_part(window_count_, mem_MB_ * bucket_mem_rate_, hash_seeds_[0], bucket_cell_count),
          CM_part(CM_row_num, mem_MB_ - mem_MB_ * bucket_mem_rate_, CM_counter_size, CM_window_size,
                  vector<uint32_t>(hash_seeds_.begin() + 1, hash_seeds_.begin() + 1 + CM_row_num), window_count_),
          current_time_window(0),
          window_count(window_count_),
          persistent_threshold(persistent_threshold_) {}

    void insert(uint32_t f) {
        auto res = persistent_part.insert(f, current_time_window);
        if (res.inserted) {
            return;
        } else {
            Bucket_Cell* cell = res.cell;
            int min_val = res.min_val;
            if (cell == nullptr) return;

            CM_part.insert(f, current_time_window);
            int cm_res = CM_part.query(f);
            int idx = current_time_window % window_count;

            if (cm_res > min_val && cell->query_flag(idx) != 1) {

                uint32_t old_f = cell->f;
                int old_cnt = cell->query();

                CM_part.decline(f, cm_res);
                CM_part.set_new_value(old_f, old_cnt);

                cell->f = f;

                cell->flags = 0;

                int m = cm_res;
                if (m <= 0) return;
                if (m > window_count) m = window_count;

                int step = window_count / m;
                if (step < 1) step = 1;

                int placed = 0;
                int offset = 0;

                for (int k = 0; k < m && placed < m; ++k) {

                    int bit_idx = (current_time_window + offset) % window_count;
                    cell->set_1(bit_idx);
                    ++placed;
                    offset += step;
                }
            }
        }
    }

    vector<pair<uint32_t,int>> report_persistent() const {
        vector<pair<uint32_t,int>> res;
        for (const auto &bucket : persistent_part.buckets) {
            for (const auto &cell : bucket.cells) {
                if (cell.f != 0) {
                    int q = cell.query();
                    if (q >= persistent_threshold) {
                        res.emplace_back(cell.f, q);
                    }
                }
            }
        }
        return res;
    }

    void switch_time_window() {
        current_time_window += 1;
        persistent_part.switch_time_window(current_time_window);
    }
};

using TimeSlice = vector<uint32_t>;
using SwitchTimeSlices = vector<TimeSlice>;
using AllTimeSlices = vector<SwitchTimeSlices>;

using PersistentItem = pair<uint32_t,int>;
using PersistentWindowList = vector<vector<PersistentItem>>;
using WidespreadList = vector<vector<pair<uint32_t,int>>>;

WidespreadList compute_widespread(const vector<PersistentWindowList>& persistent_lists,
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
        widespread_lists.push_back(std::move(widespread_items));
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
            cerr << "Failed to open file: " << filename << endl;
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

        cout << "IPv4 flow count: " << packages.size() << " (file " << filename << ")" << endl;

        vector<TimeSlice> time_slices;
        for (size_t start = 0; start < packages.size(); start += WINDOW_SIZE) {
            size_t end = std::min(start + WINDOW_SIZE, packages.size());
            time_slices.emplace_back(packages.begin() + start, packages.begin() + end);
        }
        cout << "Time slice count: " << time_slices.size() << endl;

        time_slices_lst.emplace_back(std::move(time_slices));
    }

    return time_slices_lst;
}

int main() {
    ios::sync_with_stdio(false);
    cin.tie(nullptr);

    string base_dir = "/mnt/c/Users/45512/Documents/dataset/mawi/ip_num/";

    AllTimeSlices time_slices_lst = load_time_slices(base_dir);
    if (time_slices_lst.empty()) {
        cerr << "No data loaded. Check file paths." << endl;
        return 1;
    }

    double bucket_mem_rate = 0.8;

    vector<int> bucket_cell_counts = {4};

    vector<double> mem_kB = {10, 20, 30, 40, 50, 60, 70, 80, 90, 100};
    vector<double> mem_lst_MB;
    for (int kb: mem_kB) {
        mem_lst_MB.push_back(kb / 1024.0);
    }

    vector<int> row_num_list = {2};

    vector<pair<int,int>> persistent_thresholds = {
        {12, 16},
    };

    int total_window_count = 500;

    vector<uint32_t> hash_seeds = {0,1,2,3,4};

    for (auto pw : persistent_thresholds) {
        int persistent_threshold = pw.first;
        int window_count = pw.second;
        int CM_counter_size = static_cast<int>(std::ceil(std::log2(static_cast<double>(window_count + 1))));
        int CM_window_size  = static_cast<int>(std::ceil(std::log2(static_cast<double>(total_window_count))));

        WidespreadList real_widespread_lists = get_real(time_slices_lst, window_count, persistent_threshold, 4);

        for (double total_mem_MB : mem_lst_MB) {
            for (int CM_row_num : row_num_list) {
                for (int bucket_cell_count : bucket_cell_counts) {
                    cout << "-------------------------------" << std::endl;
                    cout << "persistent_threshold: " << persistent_threshold << " / " << window_count << '\n';
                    cout << "bucket_cell_count: " << bucket_cell_count << '\n';
                    cout << "total_mem_MB: " << (total_mem_MB * 1024.0) << " KB" << '\n';
                    cout << "CM_row_num: " << CM_row_num << '\n';

                    vector<PersistentWindowList> est_persistent_lists;
                    est_persistent_lists.resize(time_slices_lst.size());

                    auto t_start = std::chrono::steady_clock::now();

                    for (size_t switch_index = 0; switch_index < time_slices_lst.size(); ++switch_index) {
                        const auto &time_slices = time_slices_lst[switch_index];
                        P2Sketch p2sketch(total_mem_MB, bucket_mem_rate, hash_seeds,
                                          window_count, bucket_cell_count, CM_row_num,
                                          CM_counter_size, CM_window_size, persistent_threshold);

                        auto &est_for_switch = est_persistent_lists[switch_index];
                        est_for_switch.reserve(time_slices.size());

                        for (size_t index = 0; index < time_slices.size(); ++index) {
                            const auto &time_slice = time_slices[index];
                            for (uint32_t f : time_slice) {
                                p2sketch.insert(f);
                            }
                            auto persistent_items = p2sketch.report_persistent();
                            p2sketch.switch_time_window();
                            est_for_switch.emplace_back(std::move(persistent_items));
                        }
                    }
                    WidespreadList est_widespread_lists = compute_widespread(est_persistent_lists, 4);

                    auto t_end = std::chrono::steady_clock::now();
                    double elapsed_sec =
                        std::chrono::duration<double>(t_end - t_start).count();

                    double throughput_mpps = 0.0;
                    if (elapsed_sec > 0.0) {
                        throughput_mpps =
                            static_cast<double>(20000000ULL * 5) / elapsed_sec / 1e6;
                    }
                    cout << "Throughput = " << throughput_mpps << " Mpps\n";

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
            }
        }
    }

    return 0;
}

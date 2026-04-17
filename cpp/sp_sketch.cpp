#include <algorithm>
#include <cmath>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <random>
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

using TimeSlice       = vector<uint32_t>;
using SwitchTimeSlice = vector<TimeSlice>;
using AllTimeSlices   = vector<SwitchTimeSlice>;

using PersistentItem   = pair<uint32_t,int>;
using WindowPersistent = vector<PersistentItem>;
using SwitchPersistent = vector<WindowPersistent>;
using PersistentLists  = vector<SwitchPersistent>;
using PersistentWindowList = vector<vector<PersistentItem>>;

using WidespreadList = vector<vector<pair<uint32_t,int>>>;

class Cell {
public:
    uint32_t f;
    bool has_flow;
    int counter;
    int last_time_window;
    int counter_size;

    Cell() : f(0), has_flow(false), counter(0), last_time_window(0), counter_size(0) {}
    explicit Cell(int counter_size_)
        : f(0), has_flow(false), counter(0), last_time_window(0), counter_size(counter_size_) {}
};

class SPSketch {
public:
    double total_mem_MB;
    int window_count;
    int persistent_threshold;
    int row_num;
    vector<uint32_t> hash_seeds;
    int current_time_window;
    int col_num;
    vector<Cell> cells;

    std::mt19937 rng;
    std::uniform_real_distribution<double> uni01;

    SPSketch(double total_mem_MB_,
             int window_count_,
             int persistent_threshold_,
             int row_num_,
             const vector<uint32_t> &hash_seeds_,
             int counter_size,
             int window_counter_size)
        : total_mem_MB(total_mem_MB_),
          window_count(window_count_),
          persistent_threshold(persistent_threshold_),
          row_num(row_num_),
          hash_seeds(hash_seeds_),
          current_time_window(0),
          rng(0x12345678),
          uni01(0.0, 1.0) {

        int bits_per_cell = 32 + counter_size + window_counter_size;
        long long total_bits = static_cast<long long>(total_mem_MB * 1024.0 * 1024.0 * 8.0);
        long long total_cells = std::max(1LL, total_bits / bits_per_cell);
        col_num = static_cast<int>(std::max(1LL, total_cells / row_num));

        cells.assign(row_num * col_num, Cell(counter_size));
    }

    int index_of(uint32_t f, int row) const {
        uint32_t seed = hash_seeds[row];
        uint32_t h = hash32_uint(f, seed);
        int col = static_cast<int>(h % static_cast<uint32_t>(col_num));
        return row * col_num + col;
    }

    void decay_cell(Cell &cell) {
        if (!cell.has_flow) return;

        int delta = current_time_window - cell.last_time_window;
        if (delta <= 0) return;

        if (delta >= window_count) {
            cell.counter = 0;
            return;
        }

        for (int i = 0; i < delta; ++i) {
            if (cell.counter <= 0) break;
            double p = cell.counter / static_cast<double>(window_count);
            double r = uni01(rng);
            if (r < p) {
                cell.counter -= 1;
            }
        }
    }

    void insert(uint32_t f) {
        vector<Cell*> candidate_cells;
        candidate_cells.reserve(row_num);
        Cell *empty_cell = nullptr;

        for (int row = 0; row < row_num; ++row) {
            int idx = index_of(f, row);
            Cell &cell = cells[idx];
            candidate_cells.push_back(&cell);

            if (!cell.has_flow && empty_cell == nullptr) {
                empty_cell = &cell;
            } else if (cell.has_flow && cell.f == f) {
                if (cell.last_time_window != current_time_window) {
                    decay_cell(cell);
                    cell.counter = std::min(cell.counter + 1, window_count);
                    cell.last_time_window = current_time_window;
                }
                return;
            }
        }

        if (empty_cell != nullptr) {
            empty_cell->has_flow = true;
            empty_cell->f = f;
            empty_cell->counter = 1;
            empty_cell->last_time_window = current_time_window;
            return;
        }

        Cell *victim = candidate_cells[0];
        for (size_t i = 1; i < candidate_cells.size(); ++i) {
            if (candidate_cells[i]->counter < victim->counter) {
                victim = candidate_cells[i];
            }
        }

        if (victim->last_time_window != current_time_window && victim->counter > 0) {
            victim->counter -= 1;
        }

        if (victim->counter <= 0) {
            victim->has_flow = true;
            victim->f = f;
            victim->counter = 1;
            victim->last_time_window = current_time_window;
        }

    }

    void switch_window() {
        ++current_time_window;
    }

    vector<pair<uint32_t,int>> report_persistent() const {
        vector<pair<uint32_t,int>> res;
        for (const auto &cell : cells) {
            if (!cell.has_flow) continue;
            if (cell.counter >= persistent_threshold) {
                res.emplace_back(cell.f, cell.counter);
            }
        }
        return res;
    }
};

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
    ios::sync_with_stdio(false);
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

    vector<uint32_t> hash_seeds = {3, 4, 5};
    int row_num = 3;
    int total_window_count = 500;

    int window_size  = static_cast<int>(std::ceil(std::log2(static_cast<double>(total_window_count))));

    vector<int> mem_kb_list = {10, 20, 30, 40, 50, 60, 70, 80, 90, 100};
    vector<double> mem_lst_MB;
    for (int kb : mem_kb_list) {
        mem_lst_MB.push_back(kb / 1024.0);
    }

    int lambda_threshold = 4;
    for (auto pw : persistent_thresholds) {

        int persistent_threshold = pw.first;
        int window_count = pw.second;
        int counter_size = static_cast<int>(std::ceil(std::log2(static_cast<double>(window_count))));
        WidespreadList real_widespread_lists = get_real(time_slices_lst, window_count, persistent_threshold, 4);

        for (double total_mem_MB : mem_lst_MB) {
            cout << "-------------------------------" << std::endl;
            cout << "persistent_threshold: " << persistent_threshold << " / " << window_count << '\n';
            cout << "total_mem_MB: " << (total_mem_MB * 1024.0) << " KB\n";

            PersistentLists est_persistent_lists;
            est_persistent_lists.resize(time_slices_lst.size());

            auto t_start = std::chrono::steady_clock::now();

            for (size_t switch_index = 0; switch_index < time_slices_lst.size(); ++switch_index) {
                const auto &time_slices = time_slices_lst[switch_index];

                SPSketch sp_sketch(
                    total_mem_MB,
                    window_count,
                    persistent_threshold,
                    row_num,
                    hash_seeds,
                    counter_size,
                    window_size
                );

                SwitchPersistent &est_for_switch = est_persistent_lists[switch_index];
                est_for_switch.reserve(time_slices.size());

                for (size_t index = 0; index < time_slices.size(); ++index) {
                    const auto &time_slice = time_slices[index];
                    for (uint32_t f : time_slice) {
                        sp_sketch.insert(f);
                    }
                    sp_sketch.switch_window();
                    auto persistent_items = sp_sketch.report_persistent();
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

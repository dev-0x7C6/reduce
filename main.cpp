#include <cstdint>
#include <fcntl.h>
#include <filesystem>
#include <future>
#include <iostream>
#include <map>
#include <ranges>
#include <thread>
#include <vector>

#include <cryptopp/sha.h>
#include <fcntl.h>
#include <range/v3/all.hpp>

#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>

static auto console = []() {
    auto console = spdlog::stdout_color_mt("console");
    console->set_pattern("[%L] %v");
    return console;
}();

namespace fs = std::filesystem;

auto map_by_filesize(const std::vector<fs::path> &sources) -> std::map<std::size_t, std::vector<fs::path>> {
    std::map<std::size_t, std::vector<fs::path>> ret;
    fs::directory_options opts{fs::directory_options::skip_permission_denied};
    std::error_code ec{};

    for (auto &&source : sources) {
        for (auto &&entry : fs::recursive_directory_iterator(source, opts, ec)) {
            if (!entry.is_regular_file()) continue;
            auto size = entry.file_size(ec);
            auto path = entry.path();
            ret[size].emplace_back(std::move(path));
        }
    }

    return ret;
}

struct stats {
    std::uint64_t file_count{};
    std::uint64_t files_with_unique_size{};
    std::uint64_t file_to_scan{};
};

struct ext_path {
    fs::path path;
    std::uint64_t size{};
    std::vector<CryptoPP::byte> hash;
};

namespace raii {
struct open {
    template <typename... Ts>
    open(Ts &&...args)
            : descriptor(::open(std::forward<Ts>(args)...)) {}

    ~open() {
        if (descriptor != -1)
            ::close(descriptor);
    }

    operator auto() const noexcept {
        return descriptor;
    }

private:
    const int descriptor{};
};
} // namespace raii

template <typename Algorithm = CryptoPP::SHA256>
auto compute(const fs::path &path, int flags = {}, std::optional<std::int64_t> limit = {}) -> std::vector<CryptoPP::byte> {
    const auto fd = raii::open(path.c_str(), O_RDONLY);
    if (!fd) return {};

    Algorithm algo;
    static thread_local std::vector<CryptoPP::byte> buffer(4096);
    ::posix_fadvise(fd, 0, 0, flags);
    ::lseek64(fd, 0, SEEK_SET);
    for (;;) {
        const auto size = ::read(fd, buffer.data(), buffer.size());
        if (size == 0) break;
        if (size <= 0) return {};

        algo.Update(buffer.data(), size);

        if (limit) {
            limit.value() -= size;
            if (limit <= 0)
                break;
        }
    }

    buffer.resize(algo.DigestSize());
    algo.Final(buffer.data());

    return buffer;
}

auto to_string(const std::vector<CryptoPP::byte> &digest) {
    return fmt::format("{:02x}", fmt::join(digest, {}));
}

auto find_duplicates(::ranges::range auto &&to_scan, int flags = {}, std::optional<std::uint64_t> limit = {}) -> std::vector<ext_path> {
    const auto total_size = ranges::accumulate(to_scan, std::uint64_t{0}, [](auto &&acc, auto &&entry) {
        return acc + entry.size;
    });

    const auto size_per_thread = total_size / std::thread::hardware_concurrency();

    console->info("total size: {:.3f} MiB", total_size / 1024.0 / 1024.0);
    console->info("files count: {}", to_scan.size());
    console->info("cpu threads: {}", std::thread::hardware_concurrency());
    console->info("cpu size per thread: {:.3f} MiB", size_per_thread / 1024.0 / 1024.0);

    auto workloads = to_scan | ranges::views::chunk_by([size_per_thread](auto &&l, auto &&r) {
        static std::uint64_t acc{};
        if (size_per_thread > (acc += l.size)) return true;
        acc = 0;
        return false;
    });

    console->info("threads to be used: {}", ranges::distance(workloads));
    using result = std::map<std::vector<CryptoPP::byte>, std::vector<ext_path>>;

    std::vector<std::jthread> threads;
    std::vector<std::future<result>> results;
    for (auto &&workload : workloads) {
        std::packaged_task task([workload{std::move(workload)}, flags, limit]() -> result {
            result ret;
            for (auto &&file : workload) {
                file.hash = compute(file.path, flags, limit);
                console->debug("processing {}, {}", file.path.c_str(), to_string(file.hash));
                ret[file.hash].emplace_back(std::move(file));
            }
            return ret;
        });

        results.emplace_back(task.get_future());
        threads.emplace_back(std::move(task));
    }

    threads.clear(); // wait

    std::vector<ext_path> ret;
    ret.reserve(to_scan.size());
    for (auto &&mapped : results | ranges::views::transform([](auto &&f) { return std::move(f.get()); }))
        for (auto &&[_, paths] : mapped)
            if (paths.size() > 1)
                std::move(std::begin(paths), std::end(paths), std::back_inserter(ret));

    return ret;
}

auto main(int argc, const char **argv) -> int {
    std::vector<fs::path> sources;

    for (auto i = 1; i < argc; ++i)
        sources.emplace_back(fs::path(argv[i]));

    if (sources.empty())
        sources.emplace_back(".");

    std::vector<ext_path> paths_to_scan;
    std::vector<std::vector<fs::path>> equivalent_path_groups;

    const auto mapped_by_filesize = map_by_filesize(sources);

    stats stats{};
    for (auto &&[size, paths] : mapped_by_filesize) {
        stats.file_count += paths.size();
        if (paths.size() == 1) {
            stats.files_with_unique_size++;
            continue;
        }

        auto groups = paths | ranges::views::chunk_by([](auto &&l, auto &&r) {
            return fs::equivalent(l, r);
        });

        for (auto &&group : groups) {
            if (ranges::distance(group) <= 1) {
                paths_to_scan.emplace_back(ext_path{
                    .path = std::move(group.front()), //
                    .size = size, //
                });
                stats.file_to_scan++;
                continue;
            }

            static std::vector<fs::path> equivalents;
            for (auto &&path : group)
                equivalents.emplace_back(std::move(path));

            equivalent_path_groups.emplace_back(std::move(equivalents));
        }
    }
    auto &&out = *console;
    out.info("files found: {}", stats.file_count);
    out.info("files with unique size: {}", stats.files_with_unique_size);
    out.info("files to scan: {}", stats.file_to_scan);

    ranges::sort(paths_to_scan, [](auto &&l, auto &&r) {
        return l.size < r.size;
    });

    out.info("stage 0: {}", paths_to_scan.size());
    auto stage1 = find_duplicates(paths_to_scan, POSIX_FADV_NOREUSE, 4096);
    out.info("stage 1: {}", stage1.size());
    auto stage2 = find_duplicates(stage1, POSIX_FADV_SEQUENTIAL, 4096 * 16);
    out.info("stage 2: {}", stage2.size());
    auto stage3 = find_duplicates(stage2, POSIX_FADV_SEQUENTIAL);
    out.info("stage 3: {}", stage3.size());

    for (auto &&group : equivalent_path_groups) {
        std::cout << "same: ";
        for (auto &&path : group)
            std::cout << path << " ";
        std::cout << std::endl;
    }

    return {};
}

#include <array>
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

using algo = CryptoPP::SHA1;
using digest_t = std::array<CryptoPP::byte, 20>;

template <typename... Ts>
using map_container = std::map<Ts...>;

auto map_by_filesize(const std::vector<fs::path> &sources) -> map_container<std::size_t, std::vector<fs::path>> {
    map_container<std::size_t, std::vector<fs::path>> ret;
    fs::directory_options opts{fs::directory_options::skip_permission_denied};

    for (auto &&source : sources) {
        std::error_code ec{};
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

struct compute_strategy {
    std::int64_t offset{};
    int fadvise_flags{};
    int seek_flags{SEEK_SET};
    std::optional<std::int64_t> read_limit;
};

struct sequential {};
struct corners {};
struct middle {};

template <typename Algorithm = algo, auto buffer_size = 4096>
auto compute_fd(sequential, const raii::open &fd, std::uint64_t, compute_strategy strategy = {}) -> digest_t {
    if (!fd) return {};

    Algorithm processor;
    std::array<CryptoPP::byte, buffer_size> buffer{};

    ::posix_fadvise(fd, 0, 0, strategy.fadvise_flags);
    ::lseek64(fd, strategy.offset, strategy.seek_flags);

    for (;;) {
        const auto size = ::read(fd, buffer.data(), buffer.size());
        if (size == 0) break;
        if (size <= 0) return {};

        processor.Update(buffer.data(), size);

        if (strategy.read_limit) {
            strategy.read_limit.value() -= size;
            if (strategy.read_limit <= 0)
                break;
        }
    }

    digest_t digest{};
    processor.Final(digest.data());
    return digest;
}

template <typename Algorithm = algo, auto buffer_size = 4096>
auto compute_fd(corners, const raii::open &fd, std::uint64_t size, compute_strategy = {}) -> digest_t {
    if (!fd) return {};

    if (size <= buffer_size * 2)
        return compute_fd(sequential{}, fd, size, {
                                                      .fadvise_flags = POSIX_FADV_SEQUENTIAL, //
                                                  });

    Algorithm processor;
    std::array<CryptoPP::byte, buffer_size> buffer{};

    ::posix_fadvise(fd, 0, 0, POSIX_FADV_RANDOM);

    ::lseek64(fd, 0, SEEK_SET);
    processor.Update(buffer.data(), ::read(fd, buffer.data(), buffer.size()));

    ::lseek64(fd, -buffer.size(), SEEK_END);
    processor.Update(buffer.data(), ::read(fd, buffer.data(), buffer.size()));

    digest_t digest{};
    processor.Final(digest.data());
    return digest;
}

template <typename Algorithm = algo, auto buffer_size = 4096>
auto compute_fd(middle, const raii::open &fd, std::uint64_t size, compute_strategy = {}) -> digest_t {
    if (!fd) return {};

    if (size <= buffer_size)
        return compute_fd(sequential{}, fd, size, {
                                                      .fadvise_flags = POSIX_FADV_SEQUENTIAL, //
                                                  });

    ::posix_fadvise(fd, 0, 0, POSIX_FADV_RANDOM);
    ::lseek64(fd, size / 2 - buffer_size / 2, SEEK_SET);

    Algorithm processor;
    std::array<CryptoPP::byte, buffer_size> buffer{};
    processor.Update(buffer.data(), ::read(fd, buffer.data(), buffer.size()));

    digest_t digest{};
    processor.Final(digest.data());
    return digest;
}

template <typename Algorithm = algo, auto buffer_size = 4096, typename strategy_t>
auto compute(const ext_path &ex, compute_strategy strategy = {}, strategy_t = {}) -> digest_t {
    return compute_fd(strategy_t{}, raii::open(ex.path.c_str(), O_RDONLY), ex.size, strategy);
}

auto to_string(const std::vector<CryptoPP::byte> &digest) {
    return fmt::format("{:02x}", fmt::join(digest, {}));
}

template <typename strategy>
auto find_duplicates(strategy, ::ranges::range auto &&to_scan, int flags = {}, std::optional<std::uint64_t> limit = {}) -> std::vector<ext_path> {

    // const auto size_per_thread = total_size / std::thread::hardware_concurrency();

    // console->info("total size: {:.3f} MiB", total_size / 1024.0 / 1024.0);
    // console->info("files count: {}", to_scan.size());
    // console->info("cpu threads: {}", std::thread::hardware_concurrency());
    // console->info("cpu size per thread: {:.3f} MiB", size_per_thread / 1024.0 / 1024.0);
    // console->info("threads to be used: {}", ranges::distance(workloads));
    using result = map_container<digest_t, std::vector<ext_path>>;

    const auto concurrency_count = std::thread::hardware_concurrency();

    std::vector<std::jthread> threads;
    std::vector<std::future<result>> results;
    std::vector<std::vector<ext_path>> tasks(concurrency_count);

    threads.reserve(concurrency_count);
    results.reserve(concurrency_count);

    for (auto &&task : tasks)
        task.reserve(to_scan.size() / concurrency_count);

    for (auto &&va : to_scan | ranges::views::chunk(concurrency_count)) {
        for (std::size_t i = 0; auto &value : va)
            tasks[i++].emplace_back(value);
    }

    for (std::size_t i = 0; auto &&task : tasks) {
        const auto total = ranges::accumulate(task, std::size_t{}, [](auto &&acc, auto &&r) {
            return acc + r.size;
        });

        if (task.size()) {
            console->debug("thread [{}]: files to scan: {}", i, task.size());
            console->debug("thread [{}]: total size MiB: {:.3f} MiB", i, total / 1024.0 / 1024.0);
        }
        ++i;
    }

    for (int i{}; auto &&workload : tasks) {
        if (workload.size() == 0) continue;

        std::packaged_task task([workload{std::move(workload)}, flags, limit, i]() -> result {
            console->debug("thread [{}]: started", i);
            result ret;
            for (auto &&file : workload) {
                const auto hash = compute(file, compute_strategy{
                                                    .fadvise_flags = flags, //
                                                    .read_limit = limit, //
                                                },
                    strategy{});
                ret[hash].emplace_back(std::move(file));
            }
            console->debug("thread [{}]: finished", i);
            return ret;
        });

        results.emplace_back(task.get_future());
        threads.emplace_back(std::move(task));
        i++;
    }

    std::vector<ext_path> ret;
    ret.reserve(to_scan.size());
    threads.clear(); // wait

    auto &&from_future = [](auto &&f) { return std::move(f.get()); };
    auto &&sync_results = results | ranges::views::transform(from_future);

    for (auto &&mapped : sync_results)
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

    std::vector<ext_path> stage;
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
            stage.emplace_back(ext_path{
                .path = std::move(group.front()), //
                .size = size, //
            });
            stats.file_to_scan++;

            if ((ranges::distance(group) == 1)) continue;

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

    out.info("Eliminating by 4KiB corners: {} files", stage.size());
    stage = find_duplicates(corners{}, stage, POSIX_FADV_RANDOM, 4096);

    if (stage.empty()) {
        out.info("Finished");
        return {};
    }

    out.info("Eliminating by 64KiB corners: {} files", stage.size());
    stage = find_duplicates(corners{}, stage, POSIX_FADV_RANDOM, 4096 * 16);

    if (stage.empty()) {
        out.info("Finished");
        return {};
    }

    out.info("Eliminating by 64KiB middle: {} files", stage.size());
    stage = find_duplicates(middle{}, stage, POSIX_FADV_RANDOM, 4096 * 16);

    if (stage.empty()) {
        out.info("Finished");
        return {};
    }

    out.info("Eliminating by whole read: {} files", stage.size());
    stage = find_duplicates(sequential{}, stage, POSIX_FADV_SEQUENTIAL);

    if (stage.empty()) {
        out.info("Finished");
        return {};
    }

    for (auto &&group : equivalent_path_groups) {
        auto &&paths = group | ranges::views::transform([](auto &&path) {
            return path.c_str();
        });

        out.debug("same {}", fmt::join(paths, " "));
    }

    return {};
}

#include <cstdint>
#include <filesystem>
#include <iostream>
#include <map>
#include <ranges>
#include <vector>

#include <cryptopp/sha.h>
#include <fcntl.h>
#include <range/v3/all.hpp>

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

template <typename Algorithm = CryptoPP::SHA1>
auto compute(const fs::path &path) -> std::vector<CryptoPP::byte> {
    const auto fd = raii::open(path.c_str(), O_RDONLY);
    if (!fd) return {};

    Algorithm algo;
    std::vector<CryptoPP::byte> buffer(4096);

    ::lseek64(fd, 0, SEEK_SET);
    for (;;) {
        const auto size = ::read(fd, buffer.data(), buffer.size());
        if (size == 0) break;
        if (size <= 0) return {};

        algo.Update(buffer.data(), size);
    }

    buffer.resize(algo.DigestSize());
    algo.Final(buffer.data());

    return buffer;
}

auto main(int argc, const char **argv) -> int {
    std::vector<fs::path> sources;

    for (auto i = 1; i < argc; ++i)
        sources.emplace_back(fs::path(argv[i]));

    if (sources.empty())
        sources.emplace_back(".");

    std::vector<fs::path> paths_to_scan;
    std::vector<std::vector<fs::path>> equivalent_path_groups;

    const auto mapped_by_filesize = map_by_filesize(sources);

    stats stats;
    for (auto &&[_, paths] : mapped_by_filesize) {
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
                paths_to_scan.emplace_back(std::move(group.front()));
                stats.file_to_scan++;
                continue;
            }

            static std::vector<fs::path> equivalents;
            for (auto &&path : group)
                equivalents.emplace_back(std::move(path));

            equivalent_path_groups.emplace_back(std::move(equivalents));
        }
    }

    std::cout << "files found: " << stats.file_count << std::endl;
    std::cout << "files with unique size: " << stats.files_with_unique_size << std::endl;
    std::cout << "files to scan: " << stats.file_to_scan << std::endl;

    for (auto &&file : paths_to_scan) {
        std::cout << "calc: " << file << std::endl;
        compute(file);
    }

    for (auto &&group : equivalent_path_groups) {
        std::cout << "same: ";
        for (auto &&path : group)
            std::cout << path << " ";
        std::cout << std::endl;
    }

    return {};
}

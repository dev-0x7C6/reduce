#include <cstdint>
#include <filesystem>
#include <iostream>
#include <map>
#include <ranges>
#include <vector>

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

auto main() -> int {
    fs::path path{"."};
    std::vector<fs::path> paths_to_scan;
    std::vector<std::vector<fs::path>> equivalent_path_groups;

    const auto mapped_by_filesize = map_by_filesize({path});

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
    std::cout << "files unique: " << stats.files_with_unique_size << std::endl;
    std::cout << "files to scan: " << stats.file_to_scan << std::endl;

    for (auto &&group : equivalent_path_groups) {
        std::cout << "same: ";
        for (auto &&path : group)
            std::cout << path << " ";
        std::cout << std::endl;
    }

    return {};
}

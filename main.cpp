#include <filesystem>
#include <iostream>
#include <map>
#include <ranges>
#include <vector>

#include <range/v3/all.hpp>

namespace fs = std::filesystem;

auto main() -> int {
    std::error_code ec{};
    fs::path path{"."};
    fs::directory_options opts{fs::directory_options::skip_permission_denied};
    std::map<std::size_t, std::vector<fs::path>> size_reduce;
    std::vector<fs::path> paths;
    std::vector<std::vector<fs::path>> equivalent_path_groups;

    for (auto &&entry : fs::recursive_directory_iterator(path, opts, ec)) {
        if (!entry.is_regular_file()) continue;
        auto size = entry.file_size(ec);
        auto path = entry.path();
        size_reduce[size].emplace_back(std::move(path));
    }

    std::size_t cnt{};
    for (auto &&[key, value] : size_reduce) {
        cnt += value.size();
        if (value.size() == 1) continue;

        auto groups = value | ranges::views::chunk_by([](auto &&l, auto &&r) {
            return fs::equivalent(l, r);
        });

        for (auto &&group : groups) {
            if (ranges::distance(group) <= 1) {
                paths.emplace_back(std::move(group.front()));
                continue;
            }

            static std::vector<fs::path> equivalents;
            for (auto &&path : group)
                equivalents.emplace_back(std::move(path));

            equivalent_path_groups.emplace_back(std::move(equivalents));
        }
    }

    std::cout << "files found: " << cnt << std::endl;
    std::cout << "files unique: " << cnt - paths.size() << std::endl;
    std::cout << "files process: " << paths.size() << std::endl;

    for (auto &&group : equivalent_path_groups) {
        std::cout << "same: ";
        for (auto &&path : group)
            std::cout << path;
        std::cout << std::endl;
    }

    return {};
}

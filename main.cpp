#include <filesystem>
#include <iostream>
#include <map>
#include <set>
#include <vector>

namespace fs = std::filesystem;

auto main() -> int {
    std::error_code ec{};
    fs::path path{"."};
    fs::directory_options opts{fs::directory_options::skip_permission_denied};
    std::map<std::size_t, std::vector<fs::path>> size_reduce;
    std::vector<fs::path> paths;

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

        for (auto &&path : value)
            paths.emplace_back(std::move(path));
    }

    std::cout << "files found: " << cnt << std::endl;
    std::cout << "files unique: " << cnt - paths.size() << std::endl;
    std::cout << "files process: " << paths.size() << std::endl;

    return {};
}

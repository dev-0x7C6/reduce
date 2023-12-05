cmake_minimum_required(VERSION 3.26)

project(reduce LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(spdlog REQUIRED)
find_package(range-v3 REQUIRED)
find_package(PkgConfig REQUIRED)

pkg_check_modules(cryptopp REQUIRED IMPORTED_TARGET libcryptopp)

add_executable(reduce main.cpp)

target_link_libraries(
  reduce PRIVATE range-v3::meta range-v3::concepts range-v3::range-v3
                 PkgConfig::cryptopp spdlog::spdlog)

include(GNUInstallDirs)
install(
  TARGETS reduce
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})

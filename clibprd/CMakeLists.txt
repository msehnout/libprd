cmake_minimum_required(VERSION 3.14)
project(libprd C)

set(CMAKE_C_STANDARD 11)

# load pkg-config first; it's required by other modules
find_package(PkgConfig REQUIRED)
pkg_check_modules(OpenSSL REQUIRED openssl>=1.1)
pkg_check_modules(unbound REQUIRED libunbound>=1.8)
pkg_check_modules(cmocka REQUIRED cmocka)

add_library(libprd SHARED libprd.c libprd.h)
add_executable(test test.c)
target_link_libraries(test libprd unbound ssl crypt cmocka)

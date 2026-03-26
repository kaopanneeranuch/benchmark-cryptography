cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})

project(supersonic)

zephyr_include_directories(
    ../BC__Butterknife/include
    src/forkskinny-opt32
    src
)

target_sources(app PRIVATE 
    src/main.c
    src/supersonic_butterknife.c
    src/supersonic_forkskinny.c
    ../BC__Butterknife/source/butterknife256_tks.c
    ../BC__Butterknife/source/butterknife256.c
    src/forkskinny-opt32/internal-forkskinny.c
)

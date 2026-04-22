cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})

project(supersonic)

zephyr_include_directories(
    ../BC__Butterknife/include
    ../forkskinny-opt32
    ../deoxysi256/deoxysi256/ref
    src
)

target_sources(app PRIVATE
    src/main.c
    src/supersonic-star_butterknife_skinny.c
    src/supersonic-star_butterknife.c
    src/supersonic-star_forkskinny.c
    ../BC__Butterknife/source/butterknife256_tks.c
    ../BC__Butterknife/source/butterknife256.c
    ../forkskinny-opt32/internal-forkskinny.c
    ../forkskinny-opt32/skinny.c
    ../deoxysi128/deoxysi128/ref/tweakableBC.c
)

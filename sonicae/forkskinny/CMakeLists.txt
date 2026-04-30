cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})

project(forkskinny)

target_include_directories(app PRIVATE
    ../../forkskinny-opt32
    ../../BC__Butterknife/include
    ../../supersonic/src/include
    ../../GCTR-3/forkskinny
    src
)

target_sources(app PRIVATE
    src/main.c
    src/bench.c
    src/forkskinny_sonicae.c
    ../../supersonic/src/supersonic_forkskinny.c
    ../../GCTR-3/forkskinny/gctr-3-prime.c
    ../../forkskinny-opt32/internal-forkskinny.c
)

cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})

project(supersonic)

zephyr_include_directories(
    ../BC__Butterknife/include
    ../GCTR-3/forkskinny
    ../GCTR-3/butterknife
    ../forkskinny-opt32
    src/include
)

target_sources(app PRIVATE 
    src/main.c
    src/supersonic_butterknife.c
    src/supersonic_forkskinny.c
    ../GCTR-3/forkskinny/gctr-3-fs.c
    ../GCTR-3/forkskinny/gctr-3-prime.c
    ../GCTR-3/butterknife/gctr-3-bk.c
    ../GCTR-3/butterknife/gctr-3-prime-bk.c
    ../BC__Butterknife/source/butterknife256_tks.c
    ../BC__Butterknife/source/butterknife256.c
    ../forkskinny-opt32/internal-forkskinny.c
)

cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})

project(block)

zephyr_include_directories(
    ../BC__Butterknife/include
    ../SKINNY-AEAD
    ../forkskinny-opt32
    ../deoxysi256/deoxysi256/ref
    ../deoxysi
)

target_sources(app PRIVATE
    src/main.c
    ../BC__Butterknife/source/butterknife256.c
    ../BC__Butterknife/source/butterknife256_tks.c
    ../SKINNY-AEAD/internal-skinny128.c
    ../forkskinny-opt32/internal-forkskinny.c
    ../deoxysi256/deoxysi256/ref/tweakableBC.c
    ../deoxysi256/deoxysi256/ref/deoxysi.c
    ../deoxysi/deoxys.c
)

cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})

project(forkskinny)

target_include_directories(app PRIVATE ../../forkskinny-opt32 ../../)

target_sources(app PRIVATE
	src/main.c
	src/forkskinny_gcm.c
	src/ghash.c
	src/gf.c
	src/utils.c
	src/bench.c
	../../forkskinny-opt32/internal-forkskinny.c
)

cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})

project(forkskinny)

target_include_directories(app PRIVATE ../../ ../../forkskinny_tbc)

target_sources(app PRIVATE
	src/main.c
	src/bench.c
	src/forkskinny_sct.c
	../../forkskinny_tbc/forkskinny_tbc.c
	../../ForkAE/internal-forkskinny.c
	../../ForkAE/forkae.c
	../../ForkAE/aead-common.c
)

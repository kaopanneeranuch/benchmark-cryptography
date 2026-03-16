cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})

project(skinny)

target_include_directories(app PRIVATE ../../)

target_sources(app PRIVATE
	src/main.c
	src/skinny_gcm.c
	src/ghash.c
	src/gf.c
	src/utils.c
	src/bench.c
	../../SKINNY-AEAD/internal-skinny128.c
)

cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})

project(aes)

target_sources(app PRIVATE
	src/main.c
	src/utils.c
	src/gf.c
	src/ghash.c
	src/aes_gcm.c
	src/bench.c
)

cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})

project(butterknife)

target_include_directories(app PRIVATE src/BC__Butterknife/include)

target_sources(app PRIVATE
	src/main.c
	src/butterknife-gcm.c
	src/ghash.c
	src/gf.c
	src/utils.c
	src/bench.c
	src/BC__Butterknife/source/butterknife256.c
	src/BC__Butterknife/source/butterknife256_tks.c
)

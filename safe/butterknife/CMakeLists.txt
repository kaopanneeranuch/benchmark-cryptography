cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})

project(butterknife)

target_include_directories(app PRIVATE src/BC__ButterKnife/include)

target_sources(app PRIVATE
	src/main.c
	src/bench.c
	src/butterknife_safe.c
	src/BC__Butterknige/source/butterknife256.c
	src/BC__Butterknige/source/butterknife256_tks.c
)

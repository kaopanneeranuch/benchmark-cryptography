cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})

project(forkskinny)

target_include_directories(app PRIVATE
	../../forkskinny-opt32
	../../
	../../GCTR-3/forkskinny
	${CMAKE_CURRENT_SOURCE_DIR}/src
	${CMAKE_CURRENT_SOURCE_DIR}/src/libopencm3
)

target_sources(app PRIVATE
	src/main.c
	src/bench.c
	src/forkskinny_zafe.c
	src/stm32wrapper_zephyr.c
	../../GCTR-3/forkskinny/fenc.c
	../../forkskinny-opt32/internal-forkskinny.c
)

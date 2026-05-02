cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})

project(aes)

target_sources(app PRIVATE
	src/main.c
	src/aes_gcm.c
	src/rijndael_256_gcm.c
	${CMAKE_CURRENT_LIST_DIR}/../../block/src/rijndael256.c
	src/bench.c
)

target_include_directories(app PRIVATE
	${CMAKE_CURRENT_LIST_DIR}/../../block/src
)

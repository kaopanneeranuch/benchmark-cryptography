cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})

project(aes-128)

target_sources(app PRIVATE
	src/main.c
	src/utils.c
	src/gf.c
	src/ghash.c
	src/aesgcm.c
    src/bench.c
)

## Use default mbed TLS AES symbols (no MBEDTLS_AES_ALT)

# When TF-M is not built, the top-level build still expects a
# tfm_merged.hex. Create it by copying zephyr.hex so merge step succeeds.
if(NOT CONFIG_BUILD_WITH_TFM)
	set(_zephyr_hex ${CMAKE_BINARY_DIR}/zephyr/zephyr.hex)
	set(_tfm_merged ${CMAKE_BINARY_DIR}/zephyr/tfm_merged.hex)
	add_custom_command(
		OUTPUT ${_tfm_merged}
		COMMAND ${CMAKE_COMMAND} -E copy_if_different ${_zephyr_hex} ${_tfm_merged}
		DEPENDS ${_zephyr_hex}
		COMMENT "Creating tfm_merged.hex by copying zephyr.hex (no TF-M build)"
	)
	add_custom_target(tfm_merged_copy ALL DEPENDS ${_tfm_merged})
endif()

cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})

project(block)

zephyr_include_directories(
    ../BC__Butterknife/include
    ../SKINNY-AEAD
    ../forkskinny-opt32
    ../deoxysi128/deoxysi128/ref
    ../deoxysi128/deoxysi128
    ../deoxysi256/deoxysi256/ref
    ../deoxysi
)

target_sources(app PRIVATE
    src/main.c
    src/rijndael256.c
    ../deoxysi128/deoxysi128/deoxysbc256_opt.c
    ../BC__Butterknife/source/butterknife256.c
    ../BC__Butterknife/source/butterknife256_tks.c
    ../SKINNY-AEAD/internal-skinny128.c
    ../forkskinny-opt32/internal-forkskinny.c
    ../forkskinny-opt32/skinny.c
    ../deoxysi128/deoxysi128/ref/tweakableBC.c
    ../deoxysi128/deoxysi128/ref/deoxysi.c
    ../deoxysi256/deoxysi256/ref/tweakableBC.c
    ../deoxysi256/deoxysi256/ref/deoxysi.c
    ../deoxysi/deoxys.c
)

# forkskinny-opt32/skinny.c and SKINNY-AEAD both define skinny_128_256_encrypt
# with different signatures. Prefix the forkskinny variant used by deoxysi.
set_source_files_properties(
    ../forkskinny-opt32/skinny.c
    ../deoxysi/deoxys.c
    PROPERTIES COMPILE_DEFINITIONS
    "skinny_128_256_encrypt=fs_skinny_128_256_encrypt"
)

# deoxysi128/ref and deoxysi256/ref export identical symbol names.
# Prefix deoxysi128/ref symbols so both variants can coexist in one image.
set_source_files_properties(
    ../deoxysi128/deoxysi128/ref/tweakableBC.c
    ../deoxysi128/deoxysi128/ref/deoxysi.c
    PROPERTIES COMPILE_DEFINITIONS
    "choose_lfsr=deoxysi128_ref_choose_lfsr;G=deoxysi128_ref_G;H=deoxysi128_ref_H;deoxysKeySetupEnc=deoxysi128_ref_deoxysKeySetupEnc;deoxysKeySetupDec=deoxysi128_ref_deoxysKeySetupDec;aesTweakEncrypt=aesTweakEncrypt_deoxysi128_ref;aesTweakDecrypt=aesTweakDecrypt_deoxysi128_ref;deoxys_aead_encrypt=deoxys128_ref_aead_encrypt;deoxys_aead_decrypt=deoxys128_ref_aead_decrypt"
)

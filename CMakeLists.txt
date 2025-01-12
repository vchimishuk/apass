cmake_minimum_required(VERSION 3.27)
project(apass)

# -g -O0
add_compile_options(-std=c99 -Wall -Wextra -Wpedantic)

add_executable(apass
               array.c
               crypt.c
               error.c
               exit.c
               file.c
               main.c
               mem.c
               rand.c)

# Based on https://github.com/KDE/ksecrets/blob/master/cmake/FindLibGcrypt.cmake
FIND_PROGRAM(LIBGCRYPTCONFIG_EXECUTABLE NAMES libgcrypt-config)
IF(NOT LIBGCRYPTCONFIG_EXECUTABLE)
    message(FATAL_ERROR "libgcrypt-config executable not found")
ENDIF(NOT LIBGCRYPTCONFIG_EXECUTABLE)
EXECUTE_PROCESS(COMMAND sh ${LIBGCRYPTCONFIG_EXECUTABLE} --libs RESULT_VARIABLE
    _return_VALUE OUTPUT_VARIABLE LIBGCRYPT_LIBS
    OUTPUT_STRIP_TRAILING_WHITESPACE)
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} ${LIBGCRYPT_LIBS}")
EXECUTE_PROCESS(COMMAND sh ${LIBGCRYPTCONFIG_EXECUTABLE} --cflags RESULT_VARIABLE
    _return_VALUE OUTPUT_VARIABLE LIBGCRYPT_CFLAGS
    OUTPUT_STRIP_TRAILING_WHITESPACE)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${LIBGCRYPT_CFLAGS}")

install(TARGETS apass DESTINATION bin)

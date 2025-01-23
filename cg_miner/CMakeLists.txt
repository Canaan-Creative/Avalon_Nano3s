cmake_minimum_required(VERSION 3.5)

project(cgminer)
set(PROJECT_VERSION 1.0.0)
#set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if (DEFINED RELEASE_LVL)
    message(STATUS "[DEBUG]\tRELEASE_LVL = ${RELEASE_LVL}")
else ()
    message(FATAL_ERROR "RELEASE_LVL must be setted. e.g. -DRELEASE_LVL=XXX")
endif()

string(TIMESTAMP YEAR_DATE "%y%m%d")
set(GIT_EXECUTABLE git)
execute_process(
                COMMAND "${GIT_EXECUTABLE}" describe --match=NeVeRmAtCh --always --abbrev=7 --dirty=t
                WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
                OUTPUT_VARIABLE GIT_SHA1)
string(REGEX REPLACE "\n$" "" GIT_SHA1 "${GIT_SHA1}")

set(MMVER "\"${YEAR_DATE}${FW_VERSION}_${GIT_SHA1}\"")

set(BOARD_CONF_HEADER "${CMAKE_SOURCE_DIR}/boardconf.h")
file(WRITE ${BOARD_CONF_HEADER} "#define FWVERSION		${MMVER}\n")

set(TARGET_CPU "${AVALON_CPU}")

if(TARGET_CPU STREQUAL "k230")
    add_definitions(-DCPU_K230)
    set(TOOLCHAIN_PREFIX riscv64-unknown-linux-gnu-)
    set(CMAKE_C_COMPILER ${TOOLCHAIN_PREFIX}gcc)
    set(CMAKE_CXX_COMPILER ${TOOLCHAIN_PREFIX}g++)
else()
    message(FATAL_ERROR "[ERROR]\tCOMPILE TYPE")
endif()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -rdynamic -funwind-tables")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DRELEASE_LVL=${RELEASE_LVL}")

message("----------------------------------------------------------------------------")
message("-- CMake ${CMAKE_VERSION}")
message("-- Build ${CMAKE_BUILD_TYPE} / ${CMAKE_SYSTEM}")
message("-- Version ${MMVER}")
message("----------------------------------------------------------------------------")
message("")

include_directories(.)
include_directories(cgminer)
include_directories(cgminer/compat/jansson-2.9/src)
include_directories(web)
include_directories(web/http)
include_directories(thirdlibs/zlog/src)
include_directories(thirdlibs/mbedtls/include)
include_directories(utils)

add_subdirectory(api)
add_subdirectory(cgminer)
add_subdirectory(web)
add_subdirectory(thirdlibs)
add_subdirectory(utils)

set(EXECUTABLE cg_miner)
aux_source_directory(. SRC_LIST)
file(GLOB HEADERS "*.h")
add_executable(${EXECUTABLE} ${SRC_LIST} ${HEADERS})
target_link_libraries(${EXECUTABLE} PRIVATE cgminercore web mbed)

file(GLOB sources "zlog/src/*.c")
file(GLOB headers "zlog/src/*.h")
file(GLOB m_sources "mbedtls/library/*.c")

include_directories(mbedtls/include)
include_directories(mbedtls/library)

add_library(zlog ${sources} ${headers})
add_library(mbed ${m_sources} ${m_headers})

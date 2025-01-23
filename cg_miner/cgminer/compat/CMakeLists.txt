
file(GLOB sources "jansson-2.9/src/*.c")
file(GLOB headers "jansson-2.9/src/*.h")


add_library(json ${sources} ${headers})

include_directories(jansson-2.9/src)
include_directories(jansson-2.9)
# and tell the source code to include it
add_definitions(-DHAVE_CONFIG_H)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -w")

file(GLOB sources "opt/*.c")
file(GLOB headers "opt/*.h")

add_library(ccan ${sources} ${headers})

#add_subdirectory(libpool)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -w")
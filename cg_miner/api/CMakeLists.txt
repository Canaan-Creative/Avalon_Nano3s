
file(GLOB sources "*.c")
file(GLOB headers "*.h")
add_library(apicore ${sources} ${headers})

target_link_libraries(apicore PRIVATE klist)

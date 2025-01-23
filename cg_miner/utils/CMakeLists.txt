file(GLOB sources "*.c")
file(GLOB headers "*.h")
add_library(sysutils ${sources} ${headers})

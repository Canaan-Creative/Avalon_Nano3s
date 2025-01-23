
add_subdirectory(ccan)
add_subdirectory(compat)


file(GLOB sources "*.c")
file(GLOB headers "*.h")

file(GLOB sources_klist "klist.c")
file(GLOB headers_klist "klist.h")

#remove item of klist.c klist.h
list(REMOVE_ITEM sources ${sources_klist})
list(REMOVE_ITEM headers ${headers_klist})

include_directories(.)
include_directories(compat/jansson-2.9/src)

add_library(klist ${sources_klist} ${headers_klist})

add_library(cgminercore ${sources} ${headers})


target_link_libraries(cgminercore PRIVATE ccan json pthread -lm zlog apicore klist sysutils)

file(GLOB sources "http/*.c" "cgi/cgi.c")
file(GLOB headers "http/*.h" "cgi/cgi.h")

include_directories(http)
#include_directories(include)
include_directories(cgi)

add_library(web ${sources} ${headers})
target_link_libraries(web PRIVATE pthread cgminercore sysutils)

cmake_minimum_required(VERSION 3.22.1)
project(termexec C)

add_library(termexec SHARED termexec.c)

# Full RELRO + immediate binding: hardens the .so against GOT overwrite attacks.
target_link_options(termexec PRIVATE "-Wl,-z,relro" "-Wl,-z,now" "-Wl,-z,noexecstack")

find_library(log-lib log)
target_link_libraries(termexec ${log-lib})

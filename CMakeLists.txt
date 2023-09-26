project(pipedance-client LANGUAGES C)

set(CMAKE_COMPILE_WARNING_AS_ERROR ON)

add_executable(client "main.c" "client.c" "communication.c" "helpers.c" "rc4.c")
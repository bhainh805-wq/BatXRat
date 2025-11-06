cmake_minimum_required(VERSION 3.20)
project(SSHServerStatic CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(BUILD_SHARED_LIBS OFF)

include_directories("C:/vcpkg/packages/libssh_x64-windows-static/include")
include_directories("C:/vcpkg/packages/openssl_x64-windows-static/include")

add_executable(bat main.cpp ssh.cpp)

target_compile_definitions(bat PRIVATE _WIN32_WINNT=0x0601 LIBSSH_STATIC)

target_link_libraries(bat PRIVATE
    "C:/vcpkg/packages/libssh_x64-windows-static/lib/ssh.lib"
    "C:/vcpkg/packages/openssl_x64-windows-static/lib/libcrypto.lib"
    "C:/vcpkg/packages/openssl_x64-windows-static/lib/libssl.lib"
    "${CMAKE_SOURCE_DIR}/lib/test_agent.lib"
    Ws2_32.lib
    Crypt32.lib
    Bcrypt.lib
    Advapi32.lib
    Iphlpapi.lib
    Userenv.lib
    Ntdll.lib
)

target_link_options(bat PRIVATE /NODEFAULTLIB:LIBCMT)

add_custom_command(TARGET bat POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E echo "Compressing with UPX..."
    COMMAND "${CMAKE_SOURCE_DIR}/upx-5.0.2-win64/upx.exe" --best --lzma "$<TARGET_FILE:bat>"
    COMMENT "Compressing executable with UPX"
)

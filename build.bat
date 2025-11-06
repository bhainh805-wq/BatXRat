@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" x64
cl /EHsc /MT main.cpp /link kernel32.lib user32.lib advapi32.lib userenv.lib ntdll.lib bcrypt.lib "C:\Users\Administrator\Desktop\Data\playit-agent-master\test\target\release\test_agent.lib" /subsystem:console /out:Bat.exe

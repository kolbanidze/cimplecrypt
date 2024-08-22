REM Windows only!
cl.exe /Zi /nologo /DEBUG:NONE /Fo: "bin"\ /Fe:bin\windows_decrypt.exe decrypt.c cargs.c -Iinclude /link /LIBPATH:include libsodium.lib
cl.exe /Zi /nologo /DEBUG:NONE /Fo: "bin"\ /Fe:bin\windows_encrypt.exe encrypt.c cargs.c -Iinclude /link /LIBPATH:include libsodium.lib
tar -cf bin\cimplecrypt_windows.zip -C bin\ windows_decrypt.exe windows_encrypt.exe -C ..\include libsodium.dll

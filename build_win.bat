cl.exe /Zi /nologo /DEBUG:NONE /Fo: "bin"\ /Fe:bin\windows_decrypt.exe decrypt.c cargs.c -Iinclude /link /LIBPATH:include libsodium.lib
cl.exe /Zi /nologo /DEBUG:NONE /Fo: "bin"\ /Fe:bin\windows_encrypt.exe encrypt.c cargs.c -Iinclude /link /LIBPATH:include libsodium.lib

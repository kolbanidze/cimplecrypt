# Cimplecrypt

Cross platform simple file encryption in C. Supports Windows, Linux and MacOS (x64 builds available).

## Encryption
For encryption it uses AEGIS-256. As a KDF - Argon2 ID (libsodium implementation).

Default KDF parameters - OPSLIMIT (CPU cycles) = 3, MEMLIMIT (memory usage) = 256 MiB

## Build

### Linux

Libraries: [libsodium](https://doc.libsodium.org/), [cargs](https://github.com/likle/cargs). Licenses for those libraries available in the root of repository.

Required to build: libsodium >= 1.0.19, gcc, make, cargs (located in include directory).

#### Fedora:

`sudo dnf install make gcc libsodium libsodium-devel libsodium-static glibc-static`

`git clone https://github.com/kolbanidze/cimplecrypt`

`cd cimplecrypt`

`make`

Compiled binaries will be in bin/ directory

At the time of writing, the Ubuntu repositories contain Libsodium version 1.0.18. To build, you will need to install a newer version (1.0.19 and above). This can be done by [building Libsodium yourself](https://libsodium.gitbook.io/doc/installation#compilation-on-unix-like-systems).

### Windows

Download repo. Install [visual studio](https://visualstudio.microsoft.com/downloads/) build tools. From developer command prompt for visual studio execute `build_win.bat`.

### MacOS

`brew install libsodium`

`git clone https://github.com/kolbanidze/cimplecrypt`

`cd cimplecrypt`

`make`

### Termux

`pkg update`

`pkg upgrade`

`pkg install git make clang libsodium`

`git clone https://github.com/kolbanidze/cimplecrypt`

`cd cimplecrypt`

`make clean` by default bin folder contain x64 builds

`make`

## Usage

`./encrypt file` to encrypt file
`./decrypt file.cc` to decrypt file.cc

For help use -h (--help)

## Encrypted file format
```
+-------+----------------+---------------------+
| Order |      Name      |        Type         |
+-------+----------------+---------------------+
|     1 | Magic Header   | 32-bit integer (LE) |
|     2 | OPSLIMIT       | 32-bit integer (LE) |
|     3 | MEMLIMIT       | 32-bit integer (LE) |
|     4 | SALTLEN        | 8-bit integer (LE)  |
|     5 | SALT           | Bytes               |
|     6 | NONCE          | Bytes               |
|     7 | Ciphertext+tag | Bytes               |
+-------+----------------+---------------------+
P.S. LE = Little Endian
P.P.S. by default encrypted file will be 93 bytes larger than unencrypted.
```

## Guide

```
Usage: encrypt [OPTIONS] file
  -h, --help                       show this help message and exit
  -c, --opslimit=OPSLIMIT          libsodium argon2id opslimit (cpu cycles)
  -m, --memlimit=MEMLIMIT          libsodium argon2id memlimit (memory usage)
  -s, --saltlen=SALT_LENGTH        argon2 salt size. Default 16 bytes
  -p, --password=PASSWORD          password
  -o, --output=OUTPUT              output file
  -Q, --i-know-what-i-am-doing     use KDF parameters values less than recommended
  -d, --delete                     delete original (unencrypted) file without overwriting (not secure)
  -x, --secure-delete              delete original (unencrypted) file with US DoD 5220.22-M 3 pass
  -f, --overwrite-file             if directory contains 'test.cc' that parameter will allow overwriting
  -v, --version                    shows version
```

```
Usage: decrypt [OPTIONS] file
  -h, --help                  show this help message and exit
  -p, --password=PASSWORD     password
  -o, --output=OUTPUT         output file
  -d, --delete                delete original (encrypted) file without overwriting (not secure)
  -x, --secure-delete         delete original (encrypted) file with US DoD 5220.22-M 3 pass
  -f, --overwrite-file        if directory contains 'test.cc' that parameter will allow overwriting
  -v, --version               shows version
```

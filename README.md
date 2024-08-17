# Cimplecrypt

Simple file encryption in C with libsodium. Created out of boredom during summer vacation. Linux only (of course it is possible to port it to Windows, but I am too lazy).

## Encryption
For encryption it uses AEGIS-256. As a KDF - Argon2 ID (libsodium implementation).

Default KDF parameters - OPSLIMIT (CPU cycles) = 3, MEMLIMIT (memory usage) = 256 MiB

## Build

Install requirements

Fedora: `sudo dnf install make gcc libsodium libsodium-devel`

Ubuntu: `sudo dnf install make gcc libsodium libsodium-dev`

`git clone https://github.com/kolbanidze/cimplecrypt`

`cd cimplecrypt`

`make`

Compiled binaries will be in bin/ directory

## Usage

`./encrypt` to encrypt
`./decrypt` to decrypt

For help use -h (--help)

## Usage example

```
user@linux:~$ dd if=/dev/urandom of=1MiB.bin bs=1MiB count=1
1+0 records in
1+0 records out
1048576 bytes (1.0 MB, 1.0 MiB) copied, 0.0116245 s, 90.2 MB/s
user@linux:~$ sha256sum 1MiB.bin 
35e0259a18b034ee9a8408df107a75cbb3619a63298deb94138f2cf7122c23d4  1MiB.bin
user@linux:~$ ./encrypt 1MiB.bin -P 123 -x
[Success] File 1MiB.bin was encrypted. Output file: 1MiB.bin.cc
user@linux:~$ ./decrypt 1MiB.bin.cc -P 123 -x
[Success] File '1MiB.bin.cc' was decrypted. Output file: '1MiB.bin'
user@linux:~$ sha256sum 1MiB.bin 
35e0259a18b034ee9a8408df107a75cbb3619a63298deb94138f2cf7122c23d4  1MiB.bin
```
-x (--secure-delete) securely deletes file ¯\\_(ツ)_/¯

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
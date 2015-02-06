The IDEA Project - Data encryption program based on the IDEA (International Data Encryption Algorithm)

Author: Quoc-Nam Dessoulles
Version: 0.1
Last build: 06/02/2015
License: GNU GPL v2.0 (see the file "LICENSE.txt")

The executable file was built with Eclipse CDT Luna (MinGW GCC 32 bits toolchain) under Windows 8.1 64 bits.

This program uses the IDEA to encrypt separate files with a 128 bits key. The key is generated from a password by using SHA256 and then MD5.
The program can encrypt a single file or every file in a given directory.
The user can choose to automatically delete the files after a successful encryption.
It is also possible to encrypt the names of the files as well.
The decryption works the same way. The files are checked thanks to a MD5 checksum after decryption.

Please note that this is an experimental software which should not be used to secure sensitive data.
If you want to protect your data efficiently, you should consider using alternative applications like TrueCrypt, which are much faster and more secure.
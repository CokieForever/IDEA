/**** LICENSE INFORMATION ****
IDEA - idea.h
Data encryption program
Copyright (C) 2015  Quoc-Nam Dessoulles

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

#ifndef IDEA_H_
#define IDEA_H_

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <pthread.h>

#include "Md5.h"
#include "sha256.h"
#include "utility.h"

typedef int32_t Sint32;
typedef uint32_t Uint32;
typedef uint16_t Uint16;
typedef uint8_t Uint8;

int EncryptString(const char *string, Uint16 *out, int md5Only);
int DecryptString(Uint16 *string, int n, char *out);
int EncryptFile(const char *fileNameIn, const char *fileNameOut, const Uint16 *keySha);
int DecryptFile(const char *fileNameIn, const char *fileNameOut, const Uint16 *keySha);
int DecryptFileName(const char *fileNameIn, char **fileNameOut, const Uint16 *keySha0);
int Process_MT(const Uint16 *in, Uint16 *out, size_t size, int encrypt);
void Encrypt(const Uint16 *in, Uint16 *out);
void Decrypt(const Uint16 *in, Uint16 *out);

void SetMainKey(const Uint16 *partialKeys);

int ComputeMD5(const char *in, Uint16 *out, size_t l);
int ComputeSHA256(const char *in, Uint16 *out, size_t l);
int ComputeSHAThenMD5(const char *in, Uint16 *out);
int ComputeFileMD5Checksum(FILE *file, Uint16 *checkSum);


#endif /* IDEA_H_ */

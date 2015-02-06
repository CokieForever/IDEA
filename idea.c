/**** LICENSE INFORMATION ****
IDEA - idea.c
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

#include "idea.h"

//#define INCLUDE_USELESS

static Uint16 mainPartialKeys[9][6] = {{0}};
static Uint16 mainPartialInvertedKeys[9][6] = {{0}};

#ifdef INCLUDE_USELESS
static Uint16 StrToUint16(const char *str, const char **p);
static Uint8 CharToUint8(char c);
#endif	//INCLUDE_USELESS

static void ShiftKey(Uint16 *partialKeys);
static const Uint16* GetPartialKeys(unsigned int roundNum);
static const Uint16* GetPartialInvertedKeys(unsigned int roundNum);

static void MakeRound(const Uint16 *in, Uint16 *out, const Uint16 *keys);
static void MakeTransfo(const Uint16 *in, Uint16 *out, const Uint16 *keys);
static Uint16 ModuloMult(Uint16 x1, Uint16 x2);
static Uint16 ModuloMultInv(Uint16 x);
static Uint16 ModuloAddInv(Uint16 x);


#ifdef INCLUDE_USELESS

static Uint16 StrToUint16(const char *str, const char **p)
{
	int l = strlen(str), m = 1, i;
	Uint16 r = 0;
	Uint8 u;

	if (l > 4)
		l = 4;

	for (i=l-1 ; i >= 0 ; i--)
	{
		u = CharToUint8(str[i]);
		if (u > 15)
		{
			if (p)
				*p = &(str[i]);
			return r;
		}

		r += u * m;
		m *= 16;
	}

	return r;
}

static Uint8 CharToUint8(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	else if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	else if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	else
		return 16;
}

#endif	//INCLUDE_USELESS


int EncryptString(const char *string, Uint16 *out, int md5Only)
{
	Uint16 part[4] = {0};
	Uint16 md5[8] = {0};
	int i, l = strlen(string);

	if (!ComputeMD5(string, md5, l))
		return 0;
	memcpy(out, md5, sizeof(Uint16) * 8);

	if (md5Only)
		return 1;

	for (i=0 ; i < l ; i += 8)
	{
		memcpy(part, &(string[i]), i+7 < l ? 8 : l-i);
		Encrypt(part, &(out[8+i/2]));
		memset(part, 0, sizeof(Uint16)*4);
	}

	return 1;
}

int DecryptString(Uint16 *string, int n, char *out)
{
	Uint16 part[4] = {0};
	Uint16 md5[8] = {0}, md5_0[8] = {0};
	int i, l;

	if (n <= 8 || n % 4)
	{
		printf("The string %04x[...]%04x is not a valid string.\n", string[0], string[n-1]);
		return 0;
	}

	memcpy(md5_0, string, sizeof(Uint16)*8);

	for (i=8 ; i < n ; i += 4)
	{
		memcpy(part, &(string[i]), sizeof(Uint16)*4);
		Decrypt(part, (Uint16*)&(out[(i-8)*2]));
		memset(part, 0, sizeof(Uint16)*4);
	}

	out[(n-8) * 2] = '\0';
	l = strlen(out);

	if (!ComputeMD5(out, md5, l))
		return 0;

	for (i=0 ; i < 8 ; i++)
	{
		if (md5[i] != md5_0[i])
		{
			printf("The MD5 checksum of the encrypted file name %04x[...]%04x is not valid. The string may have been corrupted.\n", string[0], string[n-1]);
			return 0;
		}
	}

	return 1;
}

int EncryptFile(const char *fileNameIn, const char *fileNameOut, const Uint16 *keySha)
{
	FILE *fileIn = fopen(fileNameIn, "rb");
	FILE *fileOut = NULL;
	Uint16 data[4], checkSum[8], l;
	size_t n;
	Uint8 padding;
	Uint16 *cryptedFileName = NULL;
	const char *p = NULL;

	if (!strcmp(fileNameIn, fileNameOut))
	{
		printf("The source and destination files are identical (%s)\n", fileNameIn);
		return 0;
	}

	if (!fileIn)
	{
		printf("Unable to open the input file %s: %s\n.", fileNameIn, strerror(errno));
		return 0;
	}

	fseek(fileIn, 0, SEEK_END);
	padding = (8 - (ftell(fileIn) % 8)) % 8;
	rewind(fileIn);

	if (!ComputeFileMD5Checksum(fileIn, checkSum))
	{
		fclose(fileIn);
		return 0;
	}

	if (!(fileOut = fopen(fileNameOut, "wb")))
	{
		printf("Unable to create the output file %s: %s\n.", fileNameOut, strerror(errno));
		fclose(fileIn);
		return 0;
	}

	if (fwrite(keySha, 1, 32, fileOut) != 32 || fwrite(checkSum, 1, 16, fileOut) != 16 || fwrite(&padding, 1, 1, fileOut) != 1)
	{
		printf("An error occurred during writing in %s: %s\n", fileNameOut, strerror(ferror(fileOut)));
		fclose(fileIn); fclose(fileOut);
		remove(fileNameOut);
		return 0;
	}

	p = GetFileNameFromAddr((char*)fileNameIn);
	l = 16 + (strlen(p)+7)/8 * 8;
	cryptedFileName = malloc(sizeof(char) * l);
	if (!cryptedFileName || !EncryptString(p, cryptedFileName, 0))
	{
		if (!cryptedFileName)
			printf("Unable to allocate the buffer for the encrypted file name.\n");
		fclose(fileIn); fclose(fileOut);
		remove(fileNameOut);
		return 0;
	}

	if (fwrite(&l, 2, 1, fileOut) != 1 || fwrite(cryptedFileName, 1, l, fileOut) != l)
	{
		printf("An error occurred during writing in %s: %s\n", fileNameOut, strerror(ferror(fileOut)));
		fclose(fileIn); fclose(fileOut);
		remove(fileNameOut);
		return 0;
	}
	free(cryptedFileName);

	while ((n = fread(data, 1, 8, fileIn)) > 0)
	{
		Encrypt(data, data);
		if (fwrite(data, 1, 8, fileOut) != 8)
		{
			printf("An error occurred during writing in %s: %s\n", fileNameOut, strerror(ferror(fileOut)));
			fclose(fileIn); fclose(fileOut);
			remove(fileNameOut);
			return 0;
		}
		memset(data, 0, 8);
	}

	fclose(fileOut);
	if (!feof(fileIn))
	{
		printf("An error occurred during reading from %s: %s\n", fileNameIn, strerror(ferror(fileIn)));
		fclose(fileIn);
		remove(fileNameOut);
		return 0;
	}

	fclose(fileIn);
	return 1;
}

int DecryptFile(const char *fileNameIn, const char *fileNameOut, const Uint16 *keySha0)
{
	FILE *fileIn = fopen(fileNameIn, "rb");
	FILE *fileOut = NULL;
	Uint16 keySha[16];
	Uint16 checkSum[8], checkSum0[8], data[4];
	Uint16 c = 0;
	size_t n, nbBlocks = 0, l;
	Uint8 padding = 0;
	int i, r;

	if (!strcmp(fileNameIn, fileNameOut))
	{
		printf("The source and destination files are identical (%s).\n", fileNameIn);
		return 0;
	}

	if (!fileIn)
	{
		printf("Unable to open the input file %s: %s\n.", fileNameIn, strerror(errno));
		return 0;
	}

	fseek(fileIn, 0, SEEK_END);
	nbBlocks = ftell(fileIn);
	rewind(fileIn);

	if (!(fileOut = fopen(fileNameOut, "wb+")))
	{
		printf("Unable to create the output file %s: %s\n.", fileNameOut, strerror(errno));
		fclose(fileIn);
		return 0;
	}

	if (fread(keySha, 1, 32, fileIn) != 32 || fread(checkSum0, 1, 16, fileIn) != 16 || fread(&padding, 1, 1, fileIn) != 1
			|| fread(&c, 1, 2, fileIn) != 2)
	{
		if (feof(fileIn))
			printf("%s is not a valid file.\n", fileNameIn);
		else
			printf("An error occurred during reading from %s: %s\n", fileNameIn, strerror(ferror(fileIn)));
		fclose(fileIn); fclose(fileOut);
		remove(fileNameOut);
		return 0;
	}
	for (i=0 ; i < 16 ; i++)
	{
		if (keySha[i] != keySha0[i])
		{
			printf("Wrong password for file %s, or not a valid file.\n", fileNameIn);
			fclose(fileIn); fclose(fileOut);
			remove(fileNameOut);
			return 0;
		}
	}

	nbBlocks = (nbBlocks-(51+c)+7) / 8;
	fseek(fileIn, c, SEEK_CUR);

	for (i=1 ; (n = fread(data, 1, 8, fileIn)) > 0 ; i++)
	{
		Decrypt(data, data);
		l = n;
		if (i == nbBlocks)
			l -= padding;
		if (fwrite(data, 1, l, fileOut) != l)
		{
			printf("An error occurred during writing in %s: %s\n", fileNameOut, strerror(ferror(fileOut)));
			fclose(fileIn); fclose(fileOut);
			remove(fileNameOut);
			return 0;
		}
	}

	if (!feof(fileIn))
	{
		printf("An error occurred during reading from %s: %s\n", fileNameIn, strerror(ferror(fileIn)));
		fclose(fileIn); fclose(fileOut);
		remove(fileNameOut);
		return 0;
	}

	r = ComputeFileMD5Checksum(fileOut, checkSum);
	fclose(fileIn); fclose(fileOut);

	if (!r)
	{
		printf("Unable to check the decrypted file %s. Keep it anyway? (y/n): ", fileNameOut);
		if (toupper(EnterChar("yYnN")) == 'N')
		{
			remove(fileNameOut);
			return 0;
		}
		return 1;
	}

	for (i=0 ; i < 8 ; i++)
	{
		if (checkSum[i] != checkSum0[i])
		{
			printf("The MD5 checksum of the file %s is incorrect. It may have been corrupted.\n", fileNameIn);
			remove(fileNameOut);
			return 0;
		}
	}

	return 1;
}

int DecryptFileName(const char *fileNameIn, char **fileNameOut, const Uint16 *keySha0)
{
	FILE *fileIn = fopen(fileNameIn, "rb");
	Uint16 keySha[16], l=0;
	Uint8 buf[17];
	int i, r=0;
	const char *p = NULL;
	Uint16 *cryptedFileName = NULL;

	if (!fileIn)
	{
		printf("Unable to open the input file %s: %s\n.", fileNameIn, strerror(errno));
		return -1;
	}

	if (fread(keySha, 1, 32, fileIn) == 32 && fread(buf, 1, 17, fileIn) == 17 && fread(&l, 1, 2, fileIn) == 2)
	{
		if (!l)
		{
			printf("%s is not a valid file.\n", fileNameIn);
			fclose(fileIn);
			return -1;
		}

		if (!(cryptedFileName = malloc(l)))
		{
			printf("Unable to allocate memory for the encrypted file name.\n");
			fclose(fileIn);
			return -1;
		}

		if (fread(cryptedFileName, 1, l, fileIn) == l)
			r = 1;
	}

	if (!r)
	{
		if (feof(fileIn))
			printf("%s is not a valid file.\n", fileNameIn);
		else
			printf("An error occurred during reading from %s: %s\n", fileNameIn, strerror(ferror(fileIn)));
		fclose(fileIn);
		if (cryptedFileName)
			free(cryptedFileName);
		return -1;
	}

	fclose(fileIn);

	for (i=0 ; i < 16 ; i++)
	{
		if (keySha[i] != keySha0[i])
		{
			printf("Wrong password for file %s, or not a valid file.\n", fileNameIn);
			free(cryptedFileName);
			return -1;
		}
	}

	p = GetFileNameFromAddr((char*)fileNameIn);
	i = p - fileNameIn;

	if (!(*fileNameOut = malloc(sizeof(char) * (l+1+i-16))))
	{
		printf("Unable to allocate memory for the decrypted file name.\n");
		free(cryptedFileName);
		return -1;
	}

	strncpy(*fileNameOut, fileNameIn, i);
	r = DecryptString(cryptedFileName, l/2, &((*fileNameOut)[i])) ? 1 : 0;

	free(cryptedFileName);
	if (!r)
		free(*fileNameOut);
	return r;
}

void Encrypt(const Uint16 *in, Uint16 *out)
{
	int i;
	Uint16 tmp[4] = {0};

	memcpy(tmp, in, sizeof(Uint16) * 4);

	for (i=0 ; i < 8 ; i++)
		MakeRound(tmp, tmp, GetPartialKeys(i));

	MakeTransfo(tmp, out, GetPartialKeys(i));
}

void Decrypt(const Uint16 *in, Uint16 *out)
{
	int i;
	Uint16 tmp[4] = {0};

	memcpy(tmp, in, sizeof(Uint16) * 4);

	for (i=0 ; i < 8 ; i++)
		MakeRound(tmp, tmp, GetPartialInvertedKeys(i));

	MakeTransfo(tmp, out, GetPartialInvertedKeys(i));
}


void SetMainKey(const Uint16 *partialKeys0)
{
	int i, k=0, r;
	Uint16 partialKeys[8] = {0};

	memcpy(partialKeys, partialKeys0, sizeof(Uint16)*8);
	for (r=0 ; r < 9 ; r++)
	{
		for (i=0 ; i < 6 ; i++)
		{
			if (k % 8 == 0 && k > 0)
			{
				ShiftKey(partialKeys);
				k = 0;
			}
			mainPartialKeys[r][i] = partialKeys[k];
			if (i == 2 || i == 1)
			{
				if (r >= 1 && r <= 7)
					mainPartialInvertedKeys[8-r][i==2 ? 1 : 2] = ModuloAddInv(partialKeys[k]);
				else
					mainPartialInvertedKeys[8-r][i] = ModuloAddInv(partialKeys[k]);
			}
			else if (i == 4 || i == 5)
			{
				if (r > 0)
					mainPartialInvertedKeys[8-r][i] = mainPartialKeys[r-1][i];
			}
			else
				mainPartialInvertedKeys[8-r][i] = ModuloMultInv(partialKeys[k]);
			k++;
		}
	}
}

static void ShiftKey(Uint16 *partialKeys)
{
	int i;
	Uint16 pKey = partialKeys[0];

	for (i=0 ; i < 7 ; i++)
		partialKeys[i] = partialKeys[i+1];
	partialKeys[7] = pKey;

	pKey = partialKeys[0] >> 7;
	for (i=0 ; i < 7 ; i++)
		partialKeys[i] = (partialKeys[i] << 9) + (partialKeys[i+1] >> 7);
	partialKeys[7] = (partialKeys[7] << 9) + pKey;
}

static const Uint16* GetPartialKeys(unsigned int roundNum)
{
	return mainPartialKeys[roundNum];
}

static const Uint16* GetPartialInvertedKeys(unsigned int roundNum)
{
	return mainPartialInvertedKeys[roundNum];
}


static void MakeRound(const Uint16 *in, Uint16 *out, const Uint16 *keys)
{
	Uint16 a1 = ModuloMult(in[0], keys[0]);
	Uint16 a2 = in[2] + keys[2];
	Uint16 a3 = in[1] + keys[1];
	Uint16 a4 = ModuloMult(in[3], keys[3]);
	Uint16 a5 = ModuloMult(keys[4], a1 ^ a2);
	Uint16 a6 = ModuloMult(keys[5], a5 + (a3 ^ a4));

	a5 += a6;
	out[0] = a1 ^ a6;
	out[1] = a6 ^ a2;
	out[2] = a3 ^ a5;
	out[3] = a5 ^ a4;
}

static void MakeTransfo(const Uint16 *in, Uint16 *out, const Uint16 *keys)
{
	out[0] = ModuloMult(keys[0], in[0]);
	out[1] = in[2] + keys[1];
	out[2] = in[1] + keys[2];
	out[3] = ModuloMult(keys[3], in[3]);
}

static Uint16 ModuloMult(Uint16 x1, Uint16 x2)
{
	if (x1 == 0 && x2 != 0)
		return 0x10001 - x2;
	else if (x1 != 0 && x2 == 0)
		return 0x10001 - x1;
	else if (x1 == 0 && x2 == 0)
		return 1;
	else
	{
		Uint32 m = x1 * x2;
		Uint16 r = m & 0xFFFF;
		Uint16 q = m >> 16;
		if (r >= q)
			return r - q;
		else
			return 0x10001 + r - q;
	}
}

static Uint16 ModuloMultInv(Uint16 x)
{
	if (x == 0)
		return 0;
	else if (x == 1)
		return 1;

	Uint32 r2 = 0x10001;
	Uint16 r1 = x;
	Sint32 v2 = 0, v1 = 1;

	Uint16 r, k;
	Sint32 v;
	do
	{
		r = r2 % r1;
		k = r2 / r1;
		v = v2 - k*v1;

		r2 = r1;
		r1 = r;
		v2 = v1;
		v1 = v;

	} while (r != 1);

	return (Uint16) ((v + 0x10001) % 0x10001);
}

static Uint16 ModuloAddInv(Uint16 x)
{
	return (0x10000 - x) % 0x10000;
}


int ComputeMD5(const char *in0, Uint16 *out, size_t l)
{
	MD5_CTX mdContext = {{0}};
	unsigned char *in = malloc(l);
	if (!in)
		return 0;
	memcpy(in, in0, l);

	MD5Init(&mdContext);
	MD5Update(&mdContext, in, l);
	MD5Final(&mdContext);

	memcpy(out, mdContext.digest, sizeof(char)*16);
	free(in);
	return 1;
}

int ComputeSHA256(const char *in0, Uint16 *out, size_t l)
{
	sha256_context shaContext = {{0}};
	Uint8 tabOut[32] = {0};
	uint8 *in = malloc(l);
	if (!in)
		return 0;
	memcpy(in, in0, l);

	sha256_starts(&shaContext);
	sha256_update(&shaContext, in, l);
	sha256_finish(&shaContext, tabOut);

	memcpy(out, tabOut, sizeof(Uint8) * 32);
	free(in);
	return 1;
}

int ComputeSHAThenMD5(const char *in, Uint16 *out)
{
	Uint16 out1[16] = {0};
	char out1c[32] = "";

	if (!ComputeSHA256(in, out1, strlen(in)))
		return 0;

	memcpy(out1c, out1, sizeof(char) * 32);

	if (!ComputeMD5(out1c, out, 32))
		return 0;

	return 1;
}

int ComputeFileMD5Checksum(FILE *file, Uint16 *checkSum)
{
	size_t n = 0;
	long int t;
	unsigned char buf[1000] = "";
	MD5_CTX mdContext = {{0}};

	MD5Init(&mdContext);
	t = ftell(file);
	rewind(file);

	while ((n = fread(buf, 1, 1000, file)) > 0)
		MD5Update(&mdContext, buf, n);

	if (!feof(file))
	{
		printf("An error occurred while reading from file 0x%x: %s\n", (unsigned int)file, strerror(ferror(file)));
		fseek(file, t, SEEK_SET);
		return 0;
	}
	fseek(file, t, SEEK_SET);

	MD5Final(&mdContext);
	memcpy(checkSum, mdContext.digest, sizeof(char)*16);
	return 1;
}


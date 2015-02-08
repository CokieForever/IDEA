/**** LICENSE INFORMATION ****
IDEA - main.c
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

//#define __MSVCRT_VERSION__	0x0601

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <conio.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <sys/stat.h>
#include <time.h>
#include <math.h>

#include "utility.h"
#include "idea.h"

#define _VERSION	"0.1.1"

#define ENCRYPT		1
#define DECRYPT		2

#define MAX_ENTRIES	10000

typedef __int64	Sint64;

static void Purge(void);
static void Clean(char chaine[]);

static int CheckDirOrFile(const char *fullAddr);
static Sint64 GetFileSize(const char *fullAddr);
static int ListDirectory(const char *dirAddr, int listSubDirs, char **addrLists, int max, Sint64 *size);

static void FreeStrTab(char **strTab, int num);
static void Wait();

static int IsLittleEndian();


int main(void)
{
	char passwd[MAX_STR] = "", addr[MAX_PATH]="";
	char *addrLists[MAX_ENTRIES] = {NULL};
	char fileOutAddr[MAX_PATH+1] = "";
	char *p = NULL;
	Uint16 partialKeys[8] = {0}, keySha[16] = {0};
	int i, ok = 0, r = 0, count = 0, nbFails = 0;
	int autoOverwrite = 0, autoDelete = 0, encryptName = 0;
	int mode = 0;
	Sint64 totalSize = 0;
	clock_t t;
	double delay;

	atexit(Wait);

	printf("Welcome on the IDEA project.\nAuthor: cokie\nLast build: %s\nVersion: %s\n\n", __DATE__, _VERSION);
	if (!IsLittleEndian())
	{
		printf("Your processor uses the Big Endian convention for storing integers.\n");
		printf("Unfortunately, this program is not compatible with this convention yet,\nso we have to leave.\n\n");
		return EXIT_SUCCESS;
	}

	printf("Do you want to encrypt [1], decrypt [2], or leave [3]? (1/2/3): ");
	switch (EnterChar("123"))
	{
		case '1':
			mode = ENCRYPT;
			break;
		case '2':
			mode = DECRYPT;
			break;
		default:
			printf("\n");
			return EXIT_SUCCESS;
	}

	printf(mode == ENCRYPT ? "\nPlease choose a password:\n" : "\nPlease enter your password:\n");
	GetText(passwd, MAX_STR);
	ComputeSHAThenMD5(passwd, partialKeys);
	ComputeSHA256((char*)partialKeys, keySha, 16);
	printf("Key: %04x %04x %04x %04x %04x %04x %04x %04x\n", partialKeys[0], partialKeys[1], partialKeys[2], partialKeys[3],
			partialKeys[4], partialKeys[5], partialKeys[6], partialKeys[7]);

	SetMainKey(partialKeys);

	while (!ok)
	{
		printf("\nPlease type the address of the file / directory to process:\n");
		GetText(addr, MAX_PATH);
		switch (CheckDirOrFile(addr))
		{
			case 0:
				printf("The specified file / directory does not exist or cannot be reached.\n");
				break;
			case 1:
				printf("Do you want to process files in the subdirectories too? (y/n): ");
				r = toupper(EnterChar("yYnN")) == 'Y';

				printf("\nListing in progress, please wait...\n");
				count = ListDirectory(addr, r, addrLists, MAX_ENTRIES, &totalSize);
				if (count < 0)
				{
					printf("An error occurred during the listing: %s\nExiting now.\n", strerror(errno));
					FreeStrTab(addrLists, MAX_ENTRIES);
					return EXIT_FAILURE;
				}
				printf("Done. %d entries found, %.2f MB.\n", count, totalSize / pow(2,20));

				ok = count > 0;
				break;
			case 2:
				ok = 1;
				addrLists[0] = malloc(sizeof(char) * MAX_PATH);
				strcpy(addrLists[0], addr);
				count = 1;
				break;
			default:
				printf("An error occurred: %s\n", strerror(errno));
				break;
		}
	}

	printf("\nDo you want to automatically delete the processed files? (y/n): ");
	autoDelete = toupper(EnterChar("yYnN")) == 'Y';

	if (mode == ENCRYPT)
	{
		printf("Do you want to encrypt the files names too? (y/n): ");
		encryptName = toupper(EnterChar("yYnN")) == 'Y';
	}

	printf("\nPress a key to start.\n");
	getch();

	printf("Starting...\n\n");
	t = clock();

	for (i=0 ; i < count ; i++)
	{
		printf("Processing file %d of %d...\n", i+1, count);

		if (mode == ENCRYPT)
		{
			if (encryptName)
			{
				Uint16 md5[8] = {0};
				strncpy(fileOutAddr, addrLists[i], MAX_PATH);
				p = GetFileNameFromAddr(fileOutAddr);
				EncryptString(addrLists[i], md5, 1);
				snprintf(p, MAX_PATH-(int)(p-fileOutAddr), "%04x%04x%04x%04x%04x%04x%04x%04x.crpt",
						md5[0], md5[1], md5[2], md5[3], md5[4], md5[5], md5[6], md5[7]);
			}
			else
				snprintf(fileOutAddr, MAX_PATH, "%s.crpt", addrLists[i]);
		}
		else
		{
			char *ptFileOutAddr = NULL;
			r = DecryptFileName(addrLists[i], &ptFileOutAddr, keySha);
			if (r == -1)
			{
				nbFails++;
				continue;
			}
			else if (!r)
			{
				strncpy(fileOutAddr, addrLists[i], MAX_PATH);
				if ((p = strrchr(fileOutAddr, '.')) && !strcmp(p, ".crpt"))
					*p = '\0';
				else
				{
					if ( (p = GetFileNameFromAddr(fileOutAddr)) )
						snprintf(p, MAX_PATH-(int)(p-fileOutAddr), "~DCPT-%s", addrLists[i]+(p-fileOutAddr));
					else
						snprintf(fileOutAddr, MAX_PATH, "~DCPT-%s", addrLists[i]);
				}
			}
			else
			{
				strncpy(fileOutAddr, ptFileOutAddr, MAX_PATH);
				free(ptFileOutAddr);
			}
		}

		if (autoOverwrite <= 0 && CheckDirOrFile(fileOutAddr) == 2)
		{
			if (autoOverwrite < 0)
				continue;

			printf("The output file %s already exists. Overwrite? (y/n/Y/N): ", fileOutAddr);
			r = EnterChar("yYnN");
			if (r == 'n' || r == 'N')
			{
				if (r == 'N')
					autoOverwrite = -1;
				continue;
			}
			if (r == 'Y')
				autoOverwrite = 1;
		}

		r = mode == ENCRYPT ? EncryptFile(addrLists[i], fileOutAddr, keySha) : DecryptFile(addrLists[i], fileOutAddr, keySha);
		if (!r)
			nbFails++;
		else if (autoDelete && remove(addrLists[i]))
			printf("Unable to delete the file %s: %s\n", addrLists[i], strerror(errno));
	}

	delay = (clock() - t) / (double)CLOCKS_PER_SEC;
	printf("\nAll done.\n%d file(s) processed, %d error(s).\n", count-nbFails, nbFails);
	printf("Total time: %.1f sec\n", delay);
	if (delay > 0)
		printf("%.2f files / sec, %.2f MB / sec.\n", count / delay, totalSize / (pow(2,20) * delay));
	printf("\n");

	FreeStrTab(addrLists, MAX_ENTRIES);
	return EXIT_SUCCESS;
}


void GetText(char buf[], unsigned int size)
{
    fgets(buf, size, stdin);
    Clean(buf);
}

static void Purge(void)
{
    int c;
    while ((c = getchar()) != '\n' && c != EOF);
}

static void Clean(char chaine[])
{
    char *p = strchr(chaine, '\n');

    if (p)
        *p = 0;
    else
    	Purge();
}

char EnterChar(const char *allowedChars)
{
	int ok = 0;
	char c = '\0';
	char choice = '\0';

	while (!ok)
	{
		c = getch();
		if (strchr(allowedChars, c))
		{
			printf(choice ? "\b%c" : "%c", c);
			choice = c;
		}
		else if (c == '\b')
		{
			choice = '\0';
			printf("\b \b");
		}
		else if ((c == '\n' || c == '\r') && choice != '\0')
			ok = 1;
	}
	putc('\n', stdout);
	return choice;
}


static int CheckDirOrFile(const char *fullAddr)
{
	struct _stati64 s;
	int err = _stati64(fullAddr, &s);

	if(-1 == err)
	{
		if(ENOENT == errno)
			return 0;	//does not exist
		else
			return -1;	//error
	}
	else
	{
		if(S_ISDIR(s.st_mode))
			return 1;	//it's a dir
		else
			return 2;	//exists but not a dir
	}
}

static Sint64 GetFileSize(const char *fullAddr)
{
	struct _stati64 s;
	return (_stati64(fullAddr, &s) < 0 || S_ISDIR(s.st_mode)) ? 0 : s.st_size;
}

static int ListDirectory(const char *dirAddr, int listSubDirs, char **addrLists, int max, Sint64 *size)
{
	DIR *dp;
	struct dirent *ep;
	int i, r=0;
	char curAddr[MAX_PATH+1] = "";

	dp = opendir(dirAddr);
	if (dp != NULL)
	{
		for (i=0 ; i < max && (ep = readdir (dp)) ; i++)
		{
			if (!strcmp(ep->d_name, "..") || !strcmp(ep->d_name, "."))
				i--;
			else
			{
				snprintf(curAddr, MAX_PATH, "%s/%s", dirAddr, ep->d_name);
				r = CheckDirOrFile(curAddr);
				if (r == 1 && listSubDirs)
				{
					Sint64 s = 0;
					r = ListDirectory(curAddr, 1, &(addrLists[i]), max-i, size ? &s : NULL);
					if (size)
						*size = (*size) + s;
					if (r >= 0)
						i += r-1;
					else
						return -1;
				}
				else if (r == 2)
				{
					addrLists[i] = malloc(sizeof(char) * (MAX_PATH+1));
					if (addrLists[i])
					{
						strcpy(addrLists[i], curAddr);
						if (size)
							*size = (*size) + GetFileSize(curAddr);
					}
					else
						i--;
				}
				else
					i--;
			}

		}
		closedir(dp);
		return i;
	}
	else
		return -1;
}

char* GetFileNameFromAddr(char *fileAddr)
{
	char *p1 = strrchr(fileAddr, '/');
	char *p2 = strrchr(fileAddr, '\\');
	char *p = p1 > p2 ? p1 : p2;
	return p ? p+1 : fileAddr;
}

FILE* Fopen_Ex(const char *fileName, const char *mode)
{
	FILE *file = NULL;
	size_t l1 = strlen(fileName), l2 = strlen(mode);
	wchar_t *wFileName = malloc(sizeof(wchar_t) * (l1+1));
	wchar_t *wMode = NULL;

	if (!wFileName)
		return NULL;

	if (!(wMode = malloc(sizeof(wchar_t) * (l2+1))))
	{
		free(wFileName);
		return NULL;
	}

	mbstowcs(wFileName, fileName, l1+1);
	mbstowcs(wMode, mode, l2+1);
	file = _wfopen(wFileName, wMode);

	free(wFileName);
	free(wMode);
	return file;
}


static void FreeStrTab(char **strTab, int num)
{
	int i;
	for (i=0 ; i < num ; i++)
	{
		if (strTab[i])
			free(strTab[i]);
		strTab[i] = NULL;
	}
}

static void Wait()
{
	printf("Please press a key to continue.\n");
	getch();
}

static int IsLittleEndian()
{
    Uint32 magic = 0x00000001;
    Uint8 black_magic = *(Uint8*)&magic;
    return black_magic;
}

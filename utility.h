/**** LICENSE INFORMATION ****
IDEA - utility.h
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

#ifndef DEFINES_H_
#define DEFINES_H_

#ifdef MAX_PATH
#undef MAX_PATH
#endif
#define MAX_PATH 	1000

#define MAX_STR		250

char* GetFileNameFromAddr(char *fileAddr);
char EnterChar(const char *allowedChars);
void GetText(char buf[], unsigned int size);
FILE* Fopen_Ex(const char *fileName, const char *mode);

#ifdef WIN32
//#define fopen Fopen_Ex
#endif

#endif /* DEFINES_H_ */

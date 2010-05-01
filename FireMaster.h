/**************************************************************************************

	FireMaster :  Firefox Master Password Recovery Tool
	Copyright (C) 2006  Nagareshwar Y Talekar ( tnagareshwar@gmail.com )

	This program is free software; you can redistribute it and/or
	modify it under the terms of the GNU General Public License
	as published by the Free Software Foundation; either version 2
	of the License, or (at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program; if not, write to the Free Software
	Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

**************************************************************************************/



// #include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>	
// #include <conio.h>
#include <math.h>
#include <time.h>


#include "lowpbe.h"
#include "sha_fast.h"


#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

#define FIREMASTER_VERSION  "3.1"

#define HEADER_VERSION "#2c"
#define CRYPT_PREFIX "~"

#define MAX_CRACKS_PER_SECOND 100000
#define MAX_PASSWORD_LENGTH   128


int FireMasterInit(char *dirProfile);
void FireMasterExit();

void DictCrack(char *dictFile,int isHybrid);
void HybridCrack(int index );

// ** brosideon mod ** //
void PrintUsage(char *progName, bool waitForInput=FALSE);
// ** brosideon mod ** //
void ParseArg(int argc, char *argv[]);



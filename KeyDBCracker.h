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



#ifndef __KEYDBCRACKER_H__
#define __KEYDBCRACKER_H__


#include "FireMaster.h"

#define KEYDB_FILENAME			"key3.db"
//#define KEYDB_MAGIC_OFFSET		0x1000
#define KEYDB_MAX_BLOCK_SIZE    512
#define KEYDB_PW_CHECK_STR      "password-check"
#define KEYDB_PW_CHECK_LEN      14


// This represents offset information block from key3.db file
struct KeyCrackOffset
{
	unsigned char invalid[3];         // Just junk data
	unsigned char verOff[2];          // Offset to Version information
	unsigned char glbSaltStrOff[2];   // Offset of global salt string
	unsigned char glbSaltOff[2];      // Offset of global salt data
	unsigned char invalid2[2];        // Another junk data
	unsigned char mainOff[2];         // Offset to main information
	unsigned char invalid3[4];        // Non important data
};


struct KeyCrackData
{
	unsigned char version;       // Version information
	unsigned char saltLen;       // Salt length
	unsigned char nnLen;         // Nick name length
	unsigned char *salt;         // Salt data
	unsigned char *nickName;     // Nick name
	unsigned char oidLen;        // OID Length
	unsigned char *oidData;      // OID Data
	unsigned char encDataLen;    // Encrypted data length ...extra field
	unsigned char encData[17];   // Encrypted data 16 + 1
	unsigned char *pwCheckStr;   // Password check string "password-check"
	unsigned char globalSaltLen; // Global Salt Length ...extra field
	unsigned char globalSalt[17];// Global Salt  16 + 1
};


// ** brosideon mod ** //
//BOOL OpenKeyDBFile(char *profilePath);
bool OpenKeyDBFile(char *profilePath);
//BOOL CrackKeyData(char *profilePath, KeyCrackData &keyCrackData);
bool CrackKeyData(char *profilePath, KeyCrackData &keyCrackData);
// ** brosideon mod ** //

#endif

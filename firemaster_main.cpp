#include <stdio.h>
#include <math.h>
#include "lowpbe.h"
#include "KeyDBCracker.h"
#include <openssl/sha.h>
#include <unistd.h>
#include <time.h>

#define MAX_PASSWORD_LENGTH 128

/***** Function Prototypes ******/
void usage();
static int CheckMasterPassword(char*);
int FireMasterInit(char *);
void BruteCrack(const char *, char *, const int, int);
void parseArgs(int, char **);
void DictCrack(char *);
void HybridCrack(char *);
void shiftCase(char&);
/**** End Function Prototypes ***/


/************* GLobal Declarations **************/

// General Control
bool isQuiet = false;
int crackMethod = -1;
// Database items
SHA_CTX pctx;
unsigned char encString[128];
NSSPKCS5PBEParameter *paramPKCS5 = NULL;
KeyCrackData keyCrackData;
// General Bruteforce
int bruteCharCount;
int brutePosMaxCount=-1;
int brutePosMinCount=-1;
const char* bruteCharSet = "";
char brutePassword[MAX_PASSWORD_LENGTH]="";
// Pattern Cracking
char brutePattern[128];
int brutePatternBitmap[MAX_PASSWORD_LENGTH];
// Dictionary Cracking
char dictPasswd[256];
char fileBuffer[51200];
int fileBufferSize = 51200;
char *dictionaryFile;
// Hybrid Cracking
int hybridCrackMode = 0;	// Defaults to chracter shift
bool isHybrid = false;
int extraChars;
// Performance monitoring
long bruteCount = 0;
time_t start, end;

/************ End GLobal Declarations ************/

int main(int argc, char* argv[]){

	char* profileDir = argv[1];
	if ((argc < 2)|| (profileDir[0] != '/')){
		printf("\nPlease input the absolute directory of the firefox profile as argument 1\n\n");
		usage();
	}

	FireMasterInit(profileDir);

	parseArgs(argc, argv);
	time(&start);
	switch(crackMethod){
		case 0:
			// Let the user know what they're cracking
			printf("Parameters supplied:\n");
			printf("\tCharacter Set = %s\n", bruteCharSet);
			printf("\tMinimum password length = %i\n", brutePosMinCount);
			printf("\tMaximum password length = %i\n", brutePosMaxCount);
			printf("\tPattern to crack = %s\n", brutePattern);

			BruteCrack(bruteCharSet, brutePassword, 0, 0);
			break;
		case 1:
			printf("Parameters supplied:\n");
			printf("\tDictionary File = %s\n", dictionaryFile);
			DictCrack(dictionaryFile);
			break;
		case 2:
			printf("Parameters supplied:\n");
			printf("\tHybrid Crack Type = %d\n", hybridCrackMode);
			printf("\tDictionary File = %s\n", dictionaryFile);
			printf("\tAppend/Prefix character set = %s\n", bruteCharSet);
			printf("\t# Characters to Append/Prefix = %i\n", extraChars);
			isHybrid = true;
			DictCrack(dictionaryFile);
			exit(0);
		default:
			printf("Please specify a crack method using either -b (bruteforce), -d (dictionary), or -h (hybrid)\n");
			break;
	}
	printf("\n%s\n", "No Luck: try again with better options");

	return 0;
}
void parseArgs(int argc, char* argv[]){

	// Start at two, since argv[1] is the profile directory
	for (int i = 2; i < argc; i++){
		if ((strcmp(argv[i], "-b")==0))
			crackMethod = 0;
		else if ((strcmp(argv[i], "-d")==0))
			crackMethod = 1;
		else if ((strcmp(argv[i], "-h")==0))
			crackMethod = 2;
		else if ((strcmp(argv[i], "-0")==0))
			hybridCrackMode = 0;
		else if ((strcmp(argv[i], "-1")==0))
			hybridCrackMode = 1;
		else if ((strcmp(argv[i], "-2")==0))
			hybridCrackMode = 2;
		else if ((strcmp(argv[i], "-l")==0) && (i+1<argc)){
			brutePosMaxCount = atoi(argv[++i]);
			if (!((brutePosMaxCount > 0) && (brutePosMaxCount <= MAX_PASSWORD_LENGTH)))
				usage();
		}
		else if ((strcmp(argv[i], "-m")==0) && (i+1<argc)){
			brutePosMinCount = atoi(argv[++i]);
			if (!((brutePosMinCount > 0) && (brutePosMinCount <= MAX_PASSWORD_LENGTH) && (brutePosMinCount<=brutePosMaxCount)))
				usage();
		}
		else if ((strcmp(argv[i], "-c")==0) && (i+1<argc))
			bruteCharSet = argv[++i];
		else if ((strcmp(argv[i], "-f")==0) && (i+1<argc))
			dictionaryFile = argv[++i];
		else if ((strcmp(argv[i], "-p")==0) && (i+1<argc)){
			strcpy(brutePattern, argv[++i]);
		}
		else if ((strcmp(argv[i], "-a")==0) && (i+1<argc))
			extraChars = atoi(argv[++i]);
		else if ((strcmp(argv[i], "-q")==0))
			isQuiet = true;

		else usage();
	}

	// Parameter Verification
	if (crackMethod == 0){
		// Default bruteCharSet
		if (strlen(bruteCharSet) == 0)
			bruteCharSet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
		bruteCharCount = strlen(bruteCharSet);

		// Pattern Matching
		if (strlen(brutePattern)!= 0){
			int i;
			brutePosMaxCount = strlen(brutePattern);
			for(i=0; i< brutePosMaxCount; i++)
			{
				if( brutePattern[i] == '*' )
					brutePatternBitmap[i] = 0;
				else
					brutePatternBitmap[i] = 1;
			}
			brutePatternBitmap[i]=0; // Null terminate the string
		}

		// Default lengths
		if (brutePosMinCount < 0)
			brutePosMinCount = 1;
		if (brutePosMaxCount < 0){
			brutePosMaxCount = MAX_PASSWORD_LENGTH;
			printf("WARNING: You have not specified a max password length, which is wildly inefficient. Supply one now? (y/n)\n");
			char yesno;
			scanf("%c", &yesno);
			if ((yesno == 'y') || (yesno == 'Y')){
				printf("Enter the max password length:\n");
				scanf("%i", &brutePosMaxCount);
			}
			else if ((yesno == 'n') || (yesno == 'N')){
				printf("If you insist...\n");
				sleep(1);
			}
			else exit(3);
		}
	}
	if (crackMethod == 2){
		if (dictionaryFile == NULL)
			usage();

		switch(hybridCrackMode){
			case 0:
				break;
			case 1:
				if ((bruteCharSet == NULL)||(extraChars == NULL))
					usage();
				bruteCharCount = strlen(bruteCharSet);
				break;
			case 2:
				if ((bruteCharSet == NULL)||(extraChars == NULL))
					usage();
				bruteCharCount = strlen(bruteCharSet);
				break;
		}
	}

}

void DictCrack(char *dictFile)
{

	FILE *f = NULL;
	int index, fileOffset=0;
	int i,j,readCount;
	int isLastBlock;

	f = fopen(dictFile, "rb");

    if( !f )
	{
		printf("Error opening dictionary file \n");
		return;
	}

	fileOffset = 0;

    do
	{
		// read bulk data from file....
		readCount = fread(fileBuffer, 1,fileBufferSize, f);

		if( readCount == 0 )
			break;

		// If we have read less chars..then this is the last block...
		if( readCount < fileBufferSize )
			isLastBlock = 1;
		else
			isLastBlock = 0;

		index = 0;

		// check if the begining contains 10,13 chars..if so just skip them...
		for(index=0; index < readCount && (fileBuffer[index]==13 || fileBuffer[index]==10) ; index++);

		do
		{

			// Go through the file buffer..extracting each password....
			dictPasswd[0]=0;

			for(i=index,j=0; i < readCount && fileBuffer[i] != 10 ; i++,j++)
				dictPasswd[j]=fileBuffer[i];

			dictPasswd[j]=0;

			// check if reading finished before '13' i.e we hit the wall
			if( i >= readCount && !( isLastBlock && dictPasswd[0]!=0) )
			{

				if(fileBuffer[i] != 10 )
				{
					fileOffset += index;
					fseek(f, index-readCount,SEEK_CUR);  // negative makes it to move backward
				}
				else
				{
					fileOffset +=readCount;
				}

				break;
			}

			index += strlen(dictPasswd) + 1;

			if (!isQuiet)
				printf("%s\n", dictPasswd);
			if( CheckMasterPassword(dictPasswd) )
			{
				printf("Password:\t \"%s\"\n", dictPasswd);
				fclose(f);
				exit(0);
			}

			if (isHybrid)
				HybridCrack(dictPasswd);

		}
		while(1);
    }
	while(1);

	fclose(f);
}

void HybridCrack(char *hybridPassword){
	int i;							// Iterator
	int count = 1;					// Total number of possible cracks
	int n = strlen(hybridPassword);	// Just what it looks like
	int bin = 0;					// For binary conversion

	switch(hybridCrackMode)
	{
		// Shift Case
		case 0:
			while (count < pow(2, n) ){
				shiftCase(hybridPassword[n-1]);
				for (i = 1; i < n; i++){
					bin = (int)pow(2,i);
					if (count % bin == 0)
						shiftCase(hybridPassword[n-i-1]);
				}

				if (!isQuiet)
					printf("%s\n", hybridPassword, count);

				if (CheckMasterPassword(hybridPassword)){
					printf("Password:\t \"%s\"\n", hybridPassword);
					exit(0);
				}
				count++;
			}
			break;

		// Prefix
		case 1:
			// Set the brute pattern to ***[dictionaryPassword]
			for (i = 0; i< extraChars; i++)
				brutePattern[i] = '*';
			for (i; i< strlen(hybridPassword)+extraChars; i++)
				brutePattern[i] = hybridPassword[i-extraChars];

			brutePosMaxCount = strlen(brutePattern);
			for(i=0; i< brutePosMaxCount; i++)
			{
				if( brutePattern[i] == '*' )
					brutePatternBitmap[i] = 0;
				else
					brutePatternBitmap[i] = 1;
			}
			brutePatternBitmap[i]=0;

			BruteCrack(bruteCharSet, hybridPassword, 0, 0);
			break;
		// Append
		case 2:
			// Set the brute pattern to [dictionaryPassword]***
			for (i = 0; i< strlen(hybridPassword); i++)
				brutePattern[i] = hybridPassword[i];
			for (i; i< strlen(hybridPassword)+extraChars; i++)
				brutePattern[i] = '*';

			brutePosMaxCount = strlen(brutePattern);
			for(i=0; i< brutePosMaxCount; i++)
			{
				if( brutePattern[i] == '*' )
					brutePatternBitmap[i] = 0;
				else
					brutePatternBitmap[i] = 1;
			}
			brutePatternBitmap[i]=0;

			BruteCrack(bruteCharSet, hybridPassword, 0, 0);
			break;
	}
}

void shiftCase(char &c){
	/*	CAPS
	a-z = 97-122	A-Z = 65-90

	NUMBER ROW
	0-9 = 48-57 	!-) = 33,64,35,36,37,94,38,42,40,41		' " = 39-34

	RANDOMS
	` ~ = 96-126	- _ = 45-95		= + = 61-43
	[ { = 91-123	] } = 93-125	; : = 59-58
	, < = 44-60		. > = 46-62		/ ? = 47-63
	\ | = 92-124  */

	int numValue = (int)c;

	// Caps
	if ((numValue >= 97) && (numValue <=122))
		c-=32;
	else if ((numValue >= 65) && (numValue <= 90))
		c+=32;

	// number row
	else if( ((numValue >= 33) && (numValue <= 42)) || ((numValue >= 48) && (numValue <= 57)) || (numValue == 64) || (numValue ==94) )
	{
	// 1,3-5 <-> !#$%
		if ((numValue == 49) || ((numValue >=51) && (numValue <= 53)))
			c-=16;
		if ((numValue == 33) || ((numValue >=35) && (numValue <= 37)))
			c+=16;
		// 2 <-> @
		switch(numValue)
		{
			// 6 <-> ^
			case 50: c = 64; break;
			case 64: c = 50; break;

			case 54: c = 94; break;
			case 94: c = 54; break;
			// 7 <-> &
			case 55: c = 38; break;
			case 38: c = 55; break;
			// 8 <-> *
			case 56: c = 42; break;
			case 42: c = 56; break;
			// 9 <-> (
			case 57: c = 40; break;
			case 40: c = 57; break;
			// 0 <-> )
			case 48: c = 41; break;
			case 41: c = 48; break;
			// ' <-> "
			case 39: c = 34; break;
			case 34: c = 39; break;
		}
	}

	// randoms
	else if( ((numValue >= 43) && (numValue <= 126)))
	{
		// ` <-> ~
		switch(numValue)
		{
			case 96: c = 126; break;
			case 126: c = 96; break;
			// - <-> _
			case 45: c = 95; break;
			case 95: c = 45; break;
			// = <-> +
			case 61: c = 43; break;
			case 43: c = 61; break;
			// [ <-> {
			case 91: c = 123; break;
			case 123: c = 91; break;
			// ] <-> }
			case 93: c = 125; break;
			case 125: c = 93; break;
			// ; <-> :
			case 59: c = 58; break;
			case 58: c = 59; break;
			// , <-> <
			case 44: c = 60; break;
			case 60: c = 44; break;
			// . <-> >
			case 46: c = 62; break;
			case 62: c = 46; break;
			// / <-> ?
			case 47: c = 63; break;
			case 63: c = 47; break;
			// \ <-> | = 92-124
			case 92: c = 124; break;
			case 124: c = 92; break;
		}
	}
	// if not a value to be shifted, then return the origional value
}

void BruteCrack(const char *bruteCharSet, char *brutePasswd, const int index, int next )
{
	int i;
	if (index >= brutePosMaxCount) return;
	for(i=0; i< bruteCharCount; i++ )
	{
		// Plain Brute Crack
		if (strlen(brutePattern) == 0)
		{
			brutePasswd[index] = bruteCharSet[next%bruteCharCount];
			brutePasswd[index+1] = 0;
			next++;

			if( index >= (brutePosMinCount-1) )
			{
				if(!isQuiet)
					printf("%s\n", brutePasswd);
				bruteCount++;
				if( CheckMasterPassword(brutePasswd) )
				{
					time(&end);
					int diff = difftime(end,start);
					printf("\nPassword: \t\"%s\"\tElapsed Time: %d \tCracks/sec: %d\n", brutePasswd, diff, bruteCount/diff);
					exit(0);
				}
			}
		}
		// Patten Matching
		else
		{
			if( brutePatternBitmap[index] == 1 )
				brutePasswd[index] = brutePattern[index];
			else{
				brutePasswd[index] = bruteCharSet[next%bruteCharCount];
				next++;
			}

			if( index == (brutePosMaxCount-1) )
			{
				brutePasswd[index+1] = 0;

				if(!isQuiet)
					printf("%s\n", brutePasswd);
				bruteCount++;
				if( CheckMasterPassword(brutePasswd) )
				{
					time(&end);
					int diff = difftime(end,start);
					printf("\nPassword: \t\"%s\"\tElapsed Time: %d \tCracks/sec: %d\n", brutePasswd, diff, bruteCount/diff);
					exit(0);
				}
			}
		}
		//printf("%i, %i, %s, %s\n",index, next, brutePattern, brutePasswd);
		BruteCrack(bruteCharSet, brutePasswd,index+1, next);
		if( brutePatternBitmap[index] == 1 )
			break;
	}
}


static int CheckMasterPassword(char *password)
{
		unsigned char passwordHash[SHA1_LENGTH+1];

        SHA_CTX ctx;

        // Copy already calculated partial hash data..
        memcpy(&ctx, &pctx, sizeof(SHA_CTX) );
        SHA1_Update(&ctx, (unsigned char *)password, strlen(password));
    	SHA1_Final(passwordHash, &ctx);

        return nsspkcs5_CipherData(paramPKCS5, passwordHash, encString);  //&encStringItem );
}



void usage(){
	printf("Usage\n\t./firemaster_linux [firefox profile directory] [crack type] [options]\n\n");
	printf("Brute Force Options:\t(-b)\n");
	printf("\t-l\tmaximum length of password, not to exceed 128\n");
	printf("\t-m\tminimum length of password\n");
	printf("\t-p\tpattern to use for cracking - use single quotes (i.e. 'p***word')\n");
	printf("\t-c\tcharacter set to use for cracking (i.e. 'abcABC')\n\n");
	printf("Dictionary Options:\t(-d)\n");
	printf("\t-f\tdictionary file to use for cracking\n\n");
	printf("Hybrid Crack Options:\t(-h)\n");
	printf("\t-f\tdictionary file to use for hybrid modification (defaults to -0)\n");
	printf("\t-0\tshift Cracking on individual characters i.e. 'a'->'A' '1'->'!'\n");
	printf("\t-1\tprefix i.e. 'pass' -> '1pass' \n");
	printf("\t-2\tappend i.e. 'pass' -> 'pass2' \n");
	printf("\t\t-a\tnumber of characters to append/prefix (required for -1 and -2)\n");
	printf("\n");

	exit(2);
}

int FireMasterInit(char *dirProfile)
{
    SECItem saltItem;

	if( CrackKeyData(dirProfile, keyCrackData) == false)
	{
		exit(0);
	}

	// Initialize the pkcs5 structure...
	saltItem.type = (SECItemType) 0;
	saltItem.len  = keyCrackData.saltLen;
	saltItem.data = keyCrackData.salt;
	paramPKCS5 = nsspkcs5_NewParam(NULL, &saltItem, 1);

	if( paramPKCS5 == NULL)
	{
		printf("\n Failed to initialize NSSPKCS5 structure");
		exit(0);
   	}

	// Current algorithm is
	// SEC_OID_PKCS12_PBE_WITH_SHA1_AND_TRIPLE_DES_CBC

	// Setup the encrypted password-check string
    memcpy(encString, keyCrackData.encData, keyCrackData.encDataLen );

	if( CheckMasterPassword("") == true )
	{
		printf("\n Master password is not set ...exiting FireMaster \n\n");
		exit(0);
	}

	// Calculate partial sha1 data for password hashing...
    SHA1_Init(&pctx);
	SHA1_Update(&pctx, keyCrackData.globalSalt, keyCrackData.globalSaltLen);

	return true;
}





#include <stdio.h>
#include "lowpbe.h"
#include "sha_fast.h"
#include <unistd.h>

#define MAX_PASSWORD LENGTH 128

/***** Function Prototypes ******/
void usage();
static int CheckMasterPassword(char*);
int FireMasterInit(char *);
void BruteCrack(const char *, char *, const int, int);
void parseArgs(int, char **);
void DictCrack(char *);
/**** End Function Prototypes ***/


/************* GLobal Declarations **************/

// General Control
bool isQuiet = false;
int crackMethod = -1;
// Database items
SHA1Context pctx;
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
char *brutePattern=NULL;
int brutePatternBitmap[MAX_PASSWORD_LENGTH];
// Dictionary Cracking
char dictPasswd[256];
char fileBuffer[51200];
int fileBufferSize = 51200;
char *dictionaryFile;

/************ End GLobal Declarations ************/

int main(int argc, char* argv[]){
	
	char* patternmatch;
	char* profileDir = argv[1];
	if (profileDir[0] != '/'){
		printf("\nPlease input the absolute directory of the firefox profile as argument 1\n");
		usage();
	}

	int i;

	FireMasterInit(profileDir);

	parseArgs(argc, argv);

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
			printf("Still working on this...\n");
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
			brutePattern = argv[++i];
			printf("Brute Pattern set... %s\n", brutePattern);
		}
		else if ((strcmp(argv[i], "-q")==0))
			isQuiet = true;
		else usage();
	}

	if (crackMethod == 0){
		// Default bruteCharSet
		if (strlen(bruteCharSet) == 0)
			bruteCharSet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
		bruteCharCount = strlen(bruteCharSet);

		// Pattern Matching
		if (brutePattern != NULL){
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
		}
		while(1);
    }
	while(1); 
    
	fclose(f);
}



void BruteCrack(const char *bruteCharSet, char *brutePasswd, const int index, int next )
{	
	int i;

	if (index >= brutePosMaxCount) return;

	for(i=0; i< bruteCharCount; i++ )
	{
		if (brutePattern == NULL){
			brutePasswd[index] = bruteCharSet[next%bruteCharCount];
			brutePasswd[index+1] = 0;
			next++;
			
			if( index >= (brutePosMinCount-1) )
			{
				if(!isQuiet)
					printf("%s\n", brutePasswd);
				if( CheckMasterPassword(brutePasswd) )
				{
					printf("\nPassword: \t\"%s\"\n", brutePasswd);
					exit(0);
				}
			}
		}
		else{
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
		
				if( CheckMasterPassword(brutePasswd) )
				{
					printf("\nPassword: \t\"%s\"\n", brutePasswd);
					exit(0);
				}
			}
		}
		BruteCrack(bruteCharSet, brutePasswd,index+1, next);
		if( brutePatternBitmap[index] == 1 )
			break;
	}
}


static int CheckMasterPassword(char *password)
{
		unsigned char passwordHash[SHA1_LENGTH+1];

        SHA1Context ctx;

        // Copy already calculated partial hash data..
        memcpy(&ctx, &pctx, sizeof(SHA1Context) );
        SHA1_Update(&ctx, (unsigned char *)password, strlen(password));
    	SHA1_End(&ctx, passwordHash);

        return nsspkcs5_CipherData(paramPKCS5, passwordHash, encString);  //&encStringItem );
}



void usage(){
	printf("Usage\n\t./firemaster_linux [firefox profile directory] [options]\n\n");	
	printf("Options:\n");	
	printf("\t-l\tmaximum length of password, not to exceed 128\n");
	printf("\t-m\tminimum length of password\n");
	printf("\t-p\tpattern to use for cracking - use single quotes (i.e. 'p***word')\n");
	printf("\t-c\tcharacter set to use for cracking (i.e. 'abcABC')\n");
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
    SHA1_Begin(&pctx);
	SHA1_Update(&pctx, keyCrackData.globalSalt, keyCrackData.globalSaltLen);

	return true;
}





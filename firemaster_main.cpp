#include <stdio.h>
#include "lowpbe.h"
#include "sha_fast.h"
#include <unistd.h>

/***** Function Prototypes ******/
void usage();
static int CheckMasterPassword(char*);
int FireMasterInit(char *);
void BruteCrack(const char *, char *, const int, int);
/**** End Function Prototypes ***/


/***** GLobal Declarations ******/

//SECItem encStringItem;
SHA1Context pctx;
unsigned char encString[128];
NSSPKCS5PBEParameter *paramPKCS5 = NULL;
KeyCrackData keyCrackData;
const char* bruteCharSet;
int bruteCharCount;
int brutePosMaxCount;

/**** End GLobal Declarations ****/

int main(int argc, char* argv[]){
	
	char* patternmatch;
	char* profileDir = "/home/m107038/.mozilla/firefox/0zp3wtho.default/";
	int i;

	// parse arguments

	/* Work on this later
	if (argc == 1){ usage(); } 
	for (i = 0 ; i < argc ; i++){	
		if (argv[i] == "-p"){
			// Can use a question mark colon upon determining syntax			
			if (i+i < argc){
				patternmatch = argv[i+1];
			}			
			else
				usage();	
		}
	}	
	*/

	// argv[1] is the profile directory
	if (argc >= 2) { profileDir = argv[1]; } 	
	FireMasterInit(profileDir);
	bruteCharSet = "abcdefghijklmnopqrstuvwxyz*@#!$123";
	bruteCharCount = strlen( bruteCharSet );
	
	printf("%s\n", "Max number of characters for the password?");
	scanf("%i",&brutePosMaxCount);

	char brutePassword[brutePosMaxCount];
	BruteCrack(bruteCharSet, brutePassword, 0, 0);

	printf("\n%s\n\n", "No Luck: try again with better options");

	return 0;		
}

void BruteCrack(const char *bruteCharSet, char *brutePasswd, const int index, int next )
{	
	int i;
	
	if (index >= brutePosMaxCount) return;

	for(i=0; i< bruteCharCount; i++ )
	{
		brutePasswd[index] = bruteCharSet[next%bruteCharCount];
		brutePasswd[index+1] = 0;
		next++;

		//Now verify if this is the master password
		if( CheckMasterPassword(brutePasswd) )
		{
			printf("\n%s\t%s","Password : ", brutePasswd);
			exit(0);
		}
		BruteCrack(bruteCharSet, brutePasswd,index+1, next);
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
	printf("Usage\n\t./firemaster_linux [options]\n\n");
	printf("\t-p  [pattern]t\tex. a**a*1\n");
	printf("\t-i  [location of key3.db]\n"); 
	printf("\n");	
}

int FireMasterInit(char *dirProfile)
{
    SECItem saltItem;

	if( CrackKeyData(dirProfile, keyCrackData) == FALSE)
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

	
	// Calculate partial sha1 data for password hashing...
    SHA1_Begin(&pctx);
	SHA1_Update(&pctx, keyCrackData.globalSalt, keyCrackData.globalSaltLen);

	return true;
}





#include <iostream>
#include <cryptoki.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>

using namespace std;

HINSTANCE libHandle = 0;
CK_FUNCTION_LIST *p11Func = NULL;
CK_SLOT_ID slotId = 0;
CK_SESSION_HANDLE hSession = 0;
CK_BYTE *slotPin = NULL;
const char *libPath = NULL;
CK_OBJECT_HANDLE objHandle = 0;
CK_BYTE IV[] = "1234567812345678";
CK_BYTE *plainData = NULL;
CK_BYTE *encryptedData = NULL;
CK_BYTE *decryptedData = NULL;
CK_ULONG encLen;
CK_ULONG decLen;

// This function loads a pkcs11 library. Path of the pkcs11 library is read using P11_LIB environment variable.
void loadHSMLibrary()
{
    libPath = getenv("P11_LIB");
    if (libPath == NULL)
    {
        cout << "P11_LIB environment variable not set." << endl;
        exit(1);
    }

    libHandle = LoadLibrary(libPath);

    if (!libHandle)
    {
        cout << "Failed to load P11 library. " << libPath << endl;
        exit(1);
    }

    CK_C_GetFunctionList C_GetFunctionList = (CK_C_GetFunctionList)GetProcAddress(libHandle, "C_GetFunctionList");

    if (!C_GetFunctionList)
    {
        cout << "Failed to get function list from the PKCS#11 library." << endl;
        exit(1);
    }

    C_GetFunctionList(&p11Func);
    if (!p11Func)
    {
        cout << "Failed to load P11 Functions." << endl;
        exit(1);
    }
}

// Before exiting, this functions performs some memory cleanup.
void freeResource()
{
    FreeLibrary(libHandle);
    p11Func = NULL;
    slotPin = NULL;
}

// Converts byte array to Hex String.
void printHex(CK_BYTE *bytes, int len)
{
    for (int ctr = 0; ctr < len; ctr++)
    {
        printf("%02x", bytes[ctr]);
    }
    cout << endl;
}

// This function checks if a requested PKCS #11 operation was a success or a failure.
void checkOperation(CK_RV rv, const char *message)
{
    if (rv != CKR_OK)
    {
        cout << message << " failed with : " << rv << endl;
        printf("RV : %#08lx\n", rv);
        freeResource();
        exit(1);
    }
}

// This function connects this sample to a slot. It initializes the library, opens a new session and performs login.
void connectToSlot()
{
    checkOperation(p11Func->C_Initialize(NULL_PTR), "C_Initialize");
    checkOperation(p11Func->C_OpenSession(slotId, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL_PTR, NULL_PTR, &hSession), "C_OpenSession");
    checkOperation(p11Func->C_Login(hSession, CKU_USER, slotPin, strlen((const char*)slotPin)), "C_Login");
}

// This function disconnects this sample from a slot. It first logs out of the slot, closes the session and then finalizes the library.
void disconnectFromSlot()
{
    checkOperation(p11Func->C_Logout(hSession), "C_Logout");
    checkOperation(p11Func->C_CloseSession(hSession), "C_CloseSession");
    checkOperation(p11Func->C_Finalize(NULL_PTR), "C_Finalize");
}

// This function generates an AES-256 Key.
void generateAesKey()
{
    CK_MECHANISM mech = {CKM_AES_KEY_GEN};
    CK_BBOOL yes = CK_TRUE;
    CK_BBOOL no = CK_FALSE;
    CK_UTF8CHAR label[] = "aes_key";
    CK_ULONG keySize = 32;

    CK_ATTRIBUTE attrib[] = 
    {
        {CKA_TOKEN, &no, sizeof(CK_BBOOL)},
        {CKA_PRIVATE, &yes, sizeof(CK_BBOOL)},
        {CKA_SENSITIVE, &yes, sizeof(CK_BBOOL)},
        {CKA_EXTRACTABLE, &no, sizeof(CK_BBOOL)},
        {CKA_MODIFIABLE, &no, sizeof(CK_BBOOL)},
        {CKA_ENCRYPT, &yes, sizeof(CK_BBOOL)},
        {CKA_DECRYPT, &yes, sizeof(CK_BBOOL)},
        {CKA_VALUE_LEN, &keySize, sizeof(CK_ULONG)}
    };
    CK_ULONG attribLen = sizeof(attrib) / sizeof(*attrib);

    checkOperation(p11Func->C_GenerateKey(hSession, &mech, attrib, attribLen, &objHandle), "C_GenerateKey");

    cout << "AES-256 Key generated as handle : " << objHandle << endl;
}

// This function Encrypts data using CKM_AES_CBC_PAD
void encryptData()
{
    CK_MECHANISM mech = {CKM_AES_CBC_PAD, IV, sizeof(IV) - 1};
    checkOperation(p11Func->C_EncryptInit(hSession, &mech, objHandle), "C_EncryptInit");
    checkOperation(p11Func->C_Encrypt(hSession, plainData, strlen((char*)plainData), NULL, &encLen), "C_Encrypt");
    encryptedData = new unsigned char[encLen];
    checkOperation(p11Func->C_Encrypt(hSession, plainData, strlen((char*)plainData), encryptedData, &encLen), "C_Encrypt");
    cout << "Encrypted Data (Hex) - " << endl;
    printHex(encryptedData, encLen);
}

// This function Decrypts data using CKM_AES_CBC_PAD
void decryptData()
{
    CK_MECHANISM mech = {CKM_AES_CBC_PAD, IV, sizeof(IV) - 1};
    checkOperation(p11Func->C_DecryptInit(hSession, &mech, objHandle), "C_DecryptInit");
    checkOperation(p11Func->C_Decrypt(hSession, encryptedData, encLen, NULL, &decLen), "C_Decrypt");
    decryptedData = new unsigned char[decLen];
    checkOperation(p11Func->C_Decrypt(hSession, encryptedData, encLen, decryptedData, &decLen), "C_Decrypt");
    cout << "Decrypted data (Hex) -" << endl;
    printHex(decryptedData, decLen);
    // Print decrypted data as plain text
    cout << "Decrypted data (Plain text) -" << endl;
    cout.write(reinterpret_cast<char*>(decryptedData), decLen);
    cout << endl;
}

// This function shows the usage of the executable.
void usage(char exeName[30])
{
    cout << "Command usage is :-" << endl;
    cout << exeName << "  " << "" << endl;
    exit(0);
}

int main(int argc, char **argv)
{
    if (argc != 3)
        usage(argv[0]);
    else
    {
        slotId = atoi(argv[1]);
        slotPin = new CK_BYTE[strlen(argv[2])];
        slotPin = (CK_BYTE_PTR)argv[2];
    }

    loadHSMLibrary();
    cout << "P11 library loaded." << endl;
    connectToSlot();
    cout << "Connected via session : " << hSession << endl;
    generateAesKey();

    // Ask the user for the plain text
    string input;
    cout << "Enter the plain text: ";
    getline(cin, input);

    // Allocate memory and copy input to plainData
    plainData = new unsigned char[input.size() + 1];
    strcpy((char*)plainData, input.c_str());

    cout << endl << "Plaindata as Hex -" << endl;
    printHex(plainData, strlen((char*)plainData));

    encryptData();
    decryptData();

    disconnectFromSlot();
    cout << "Disconnected from slot." << endl;
    freeResource();
    delete[] plainData; // Free allocated memory for plainData
    return 0;
}

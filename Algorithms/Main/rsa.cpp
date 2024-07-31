#include <iostream>
#include <cryptoki.h>
#include <windows.h>
#include <psapi.h>
#include <ctime>
#include <cstdlib>
#include <cstring>

using namespace std;

// Global variables
HINSTANCE libHandle = nullptr;
CK_FUNCTION_LIST_PTR p11Func = nullptr;
CK_SLOT_ID slotId = 0;
CK_SESSION_HANDLE hSession = 0;
CK_BYTE *slotPin = nullptr;
const char *libPath = nullptr;
CK_OBJECT_HANDLE pubKeyHandle = 0;
CK_OBJECT_HANDLE privKeyHandle = 0;
unsigned char plainData[] = "Earth is the third planet of our Solar System.";
CK_BYTE *encryptedData = nullptr;
CK_BYTE *decryptedData = nullptr;
CK_ULONG encLen = 0;
CK_ULONG decLen = 0;

// Function declarations
void loadHSMLibrary();
void freeResource();
void printHex(CK_BYTE *bytes, int len);
void printData(const char* label, CK_BYTE *data, CK_ULONG len);
void checkOperation(CK_RV rv, const char *message);
void connectToSlot();
void disconnectFromSlot();
void generateRsaKeyPair();
void encryptData();
void decryptData();
void measureKeyGenerationTime();
void measureEncryptionTime();
void measureDecryptionTime();
size_t getCurrentMemoryUsage();
double getCurrentCpuUsage();
void calculateThroughput(void (*operation)(), const char* operationName, int numOperations);
void usage(char exeName[]);

// Function to load PKCS#11 library
void loadHSMLibrary()
{
    libPath = getenv("P11_LIB");
    if (libPath == nullptr)
    {
        cout << "P11_LIB environment variable not set." << endl;
        exit(1);
    }

    libHandle = LoadLibrary(libPath);
    if (libHandle == nullptr)
    {
        cout << "Failed to load P11 library: " << libPath << endl;
        exit(1);
    }

    CK_C_GetFunctionList C_GetFunctionList = (CK_C_GetFunctionList)GetProcAddress(libHandle, "C_GetFunctionList");
    if (C_GetFunctionList == nullptr)
    {
        cout << "Failed to load P11 Functions." << endl;
        exit(1);
    }

    C_GetFunctionList(&p11Func);
    if (p11Func == nullptr)
    {
        cout << "Failed to get function list." << endl;
        exit(1);
    }
}

// Function to free allocated resources
void freeResource()
{
    if (libHandle)
        FreeLibrary(libHandle);

    p11Func = nullptr;
    slotPin = nullptr;
    delete[] encryptedData;
    delete[] decryptedData;
}

// Function to print byte array as hex string
void printHex(CK_BYTE *bytes, int len)
{
    for (int ctr = 0; ctr < len; ctr++)
    {
        printf("%02x", bytes[ctr]);
    }
    cout << endl;
}

// Function to print data (hexadecimal and plain text)
void printData(const char* label, CK_BYTE *data, CK_ULONG len)
{
    cout << label << " (Hex): ";
    printHex(data, len);

    cout << label << " (Plain Text): ";
    for (CK_ULONG i = 0; i < len; ++i)
    {
        cout << static_cast<char>(data[i]);
    }
    cout << endl;
}

// Function to check if PKCS#11 operation was successful
void checkOperation(CK_RV rv, const char *message)
{
    if (rv != CKR_OK)
    {
        cout << message << " failed with: " << rv << endl;
        freeResource();
        exit(1);
    }
}

// Function to connect to HSM
void connectToSlot()
{
    checkOperation(p11Func->C_Initialize(nullptr), "C_Initialize");
    checkOperation(p11Func->C_OpenSession(slotId, CKF_SERIAL_SESSION | CKF_RW_SESSION, nullptr, nullptr, &hSession), "C_OpenSession");
    checkOperation(p11Func->C_Login(hSession, CKU_USER, slotPin, strlen((const char*)slotPin)), "C_Login");
}

// Function to disconnect from HSM
void disconnectFromSlot()
{
    checkOperation(p11Func->C_Logout(hSession), "C_Logout");
    checkOperation(p11Func->C_CloseSession(hSession), "C_CloseSession");
    checkOperation(p11Func->C_Finalize(nullptr), "C_Finalize");
}

// Function to generate RSA key pair and measure time
void generateRsaKeyPair()
{
    CK_MECHANISM mech = { CKM_RSA_PKCS_KEY_PAIR_GEN, nullptr, 0 };
    CK_BBOOL yes = CK_TRUE;
    CK_BBOOL no = CK_FALSE;
    CK_ULONG modulusBits = 2048;
    CK_BYTE pubExp[] = { 0x01, 0x00, 0x01 }; // 65537

    CK_ATTRIBUTE pubTemplate[] =
    {
        {CKA_TOKEN,          &no,        sizeof(CK_BBOOL)},
        {CKA_PRIVATE,        &no,        sizeof(CK_BBOOL)},
        {CKA_ENCRYPT,        &yes,       sizeof(CK_BBOOL)},
        {CKA_VERIFY,         &yes,       sizeof(CK_BBOOL)},
        {CKA_MODULUS_BITS,   &modulusBits, sizeof(CK_ULONG)},
        {CKA_PUBLIC_EXPONENT, pubExp,    sizeof(pubExp)}
    };

    CK_ATTRIBUTE privTemplate[] =
    {
        {CKA_TOKEN,          &no,        sizeof(CK_BBOOL)},
        {CKA_PRIVATE,        &yes,       sizeof(CK_BBOOL)},
        {CKA_SENSITIVE,      &yes,       sizeof(CK_BBOOL)},
        {CKA_DECRYPT,        &yes,       sizeof(CK_BBOOL)},
        {CKA_SIGN,           &yes,       sizeof(CK_BBOOL)}
    };

    clock_t start = clock();
    checkOperation(p11Func->C_GenerateKeyPair(hSession, &mech, pubTemplate, sizeof(pubTemplate) / sizeof(*pubTemplate),
        privTemplate, sizeof(privTemplate) / sizeof(*privTemplate), &pubKeyHandle, &privKeyHandle), "C_GenerateKeyPair");
    clock_t end = clock();
    double elapsedTime = double(end - start) / CLOCKS_PER_SEC;
    cout << "RSA Key Pair generation time: " << elapsedTime << " seconds" << endl;
}

// Function to encrypt data and measure time using RSA public key
void encryptData()
{
    CK_MECHANISM mech = { CKM_RSA_PKCS, nullptr, 0 };
    checkOperation(p11Func->C_EncryptInit(hSession, &mech, pubKeyHandle), "C_EncryptInit");
    checkOperation(p11Func->C_Encrypt(hSession, plainData, sizeof(plainData)-1, nullptr, &encLen), "C_Encrypt");
    encryptedData = new CK_BYTE[encLen];
    checkOperation(p11Func->C_Encrypt(hSession, plainData, sizeof(plainData)-1, encryptedData, &encLen), "C_Encrypt");
}

// Function to decrypt data and measure time using RSA private key
void decryptData()
{
    CK_MECHANISM mech = { CKM_RSA_PKCS, nullptr, 0 };
    checkOperation(p11Func->C_DecryptInit(hSession, &mech, privKeyHandle), "C_DecryptInit");
    checkOperation(p11Func->C_Decrypt(hSession, encryptedData, encLen, nullptr, &decLen), "C_Decrypt");
    decryptedData = new CK_BYTE[decLen];
    checkOperation(p11Func->C_Decrypt(hSession, encryptedData, encLen, decryptedData, &decLen), "C_Decrypt");
}

// Function to measure key generation time
void measureKeyGenerationTime()
{
    generateRsaKeyPair();
}

// Function to measure encryption time
void measureEncryptionTime()
{
    encryptData();
}

// Function to measure decryption time
void measureDecryptionTime()
{
    decryptData();
}

// Function to get current memory usage
size_t getCurrentMemoryUsage()
{
    PROCESS_MEMORY_COUNTERS pmc;
    if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc)))
    {
        return pmc.WorkingSetSize;
    }
    else
    {
        cerr << "Failed to get memory usage information." << endl;
        return 0;
    }
}

// Function to get current CPU usage
double getCurrentCpuUsage()
{
    static LARGE_INTEGER lastCounter;
    static bool isFirstTime = true;

    LARGE_INTEGER currentCounter;
    QueryPerformanceCounter(&currentCounter);

    double elapsedTime = 0.0;
    if (!isFirstTime)
    {
        LARGE_INTEGER freq;
        QueryPerformanceFrequency(&freq);
        elapsedTime = double(currentCounter.QuadPart - lastCounter.QuadPart) / freq.QuadPart;
    }

    lastCounter = currentCounter;
    isFirstTime = false;

    // Assuming single core usage for simplicity
    const double processorUsage = elapsedTime * 100.0;

    return processorUsage;
}

// Function to calculate throughput for a given operation
void calculateThroughput(void (*operation)(), const char* operationName, int numOperations)
{
    clock_t start = clock();
    for (int i = 0; i < numOperations; ++i)
    {
        operation();
    }
    clock_t end = clock();
    double elapsedTime = double(end - start) / CLOCKS_PER_SEC;
    double throughput = numOperations / elapsedTime;

    cout << "Throughput for " << operationName << ": " << throughput << " operations/second" << endl;
}

// Function to show usage of the executable
void usage(char exeName[])
{
    cout << "Command usage: " << endl;
    cout << exeName << " <slotId> <slotPin>" << endl;
    exit(0);
}

int main(int argc, char **argv)
{
    if (argc != 3)
    {
        usage(argv[0]);
    }
    else
    {
        slotId = atoi(argv[1]);
        slotPin = new CK_BYTE[strlen(argv[2]) + 1];
        strcpy((char*)slotPin, argv[2]);
    }

    loadHSMLibrary();
    cout << "P11 library loaded." << endl;
    connectToSlot();
    cout << "Connected via session: " << hSession << endl;

    size_t initialMemoryUsage = getCurrentMemoryUsage();
    double initialCpuUsage = getCurrentCpuUsage();

    measureKeyGenerationTime();
    measureEncryptionTime();
    measureDecryptionTime();

    // Calculate throughput for encryption and decryption
    calculateThroughput(encryptData, "Encryption", 100); // Adjust numOperations as needed
    calculateThroughput(decryptData, "Decryption", 100); // Adjust numOperations as needed

    size_t finalMemoryUsage = getCurrentMemoryUsage();
    double finalCpuUsage = getCurrentCpuUsage();

    cout << "Initial Memory Usage: " << initialMemoryUsage << " bytes" << endl;
    cout << "Final Memory Usage: " << finalMemoryUsage << " bytes" << endl;
    cout << "Memory Usage Change: " << (finalMemoryUsage - initialMemoryUsage) << " bytes" << endl;

    cout << "Initial CPU Usage: " << initialCpuUsage << "%" << endl;
    cout << "Final CPU Usage: " << finalCpuUsage << "%" << endl;
    cout << "CPU Usage Change: " << (finalCpuUsage - initialCpuUsage) << "%" << endl;

    // Print plain data, encrypted data, and decrypted data
    printData("Plain Data", plainData, sizeof(plainData) - 1);
    printData("Encrypted Data", encryptedData, encLen);
    printData("Decrypted Data", decryptedData, decLen);

    disconnectFromSlot();
    freeResource();

    delete[] slotPin;
    return 0;
}

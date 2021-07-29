/*
* Program           : given a poc in custom format, Generates .ktest files-KLEE test case files
* Author            : Pansilu Pitigalaarachchi
* Date              : 02-07-2021
* Arguments         : ./ktestGen <input-poc-file-name> <target-bitcode> eg: ./ktestGen inpoc.txt program01
* Inpt poc file fmt : Sample format
                      STDIN0000000a00010a000000050e00000001
                      |___||______||______________________|
                       hdr data-len data-in-hex-conv-to-char
                            4char
                      if symbol is stdin   " header >> STDIN
                      if symbol is argv[1] : header >> ARG00
                      
* Refered programs  : https://github.com/klee/klee/blob/df04aeadefb4e1c34c7ef8b9123947ff045a34d9/include/klee/ADT/KTest.h#L24
                      https://github.com/klee/klee/blob/292600cf54d5fd73278f67a4f98c2f955cbdaa10/lib/Basic/KTest.cpp#L94
*/

#include <iostream>
#include <cstring>
#include <stdint.h>

/* Information for .ktest fields */
#define ar                 "test01.ktest"
#define KTEST_HDR                       "KTEST"
#define KTEST_VER                       3

/* Input types to be included in .ktest*/
#define KTEST_ARG_SYM_STDIN             "-sym-stdin"
#define KTEST_ARG_SYM_ARG               "-sym-arg"
#define KTEST_ARG_SYM_ARGS              "-sym-args"
#define KTEST_ARG_SYM_FILES             "-sym-files"

/* Symbol names to be used in different data input types */
#define SYM_NAME_STDIN                  "stdin"
#define SYM_NAME_ARG                    "arg00"
#define SYM_NAME_ARGS_PREFIX            "arg"
#define SYM_NAME_FILES_SYFIX            "-data"

#define STDIN_STAT                      "stdin-stat"
#define STDIN_STAT_SIZE                 144

#define MODEL_VERSION_NAME              "model_version"
#define MODEL_VERSION_SIZE              4

#define IN_HDR_SIZE                     5
/* headers to be used in input POC file for different symbolic input types */
#define SYM_DATA_IN_STDIN               "STDIN"
#define SYM_DATA_IN_ARG                 "ARG00"
#define SYM_DATA_IN_ARGS                "ARGSS"
#define SYM_DATA_IN_FILES               "FILES"

enum Types                             { TYPE_STDIN, TYPE_ARG00, TYPE_ARGSS, TYPE_FILES };
static unsigned char stdin_stat[]    = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
                                         0x00, 0xff, 0xff, 0xff, 0xff, 0x01, 0x00, 0x00, 0x00, 0x00,
                                         0x00, 0x00, 0x00, 0xa4, 0x81, 0x00, 0x00, 0xe8, 0x03, 0x00,
                                         0x00, 0xe8, 0x03, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x00,
                                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff,
                                         0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0x10, 0x00, 0x00, 0x00,
                                         0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                         0xff, 0xa3, 0xb4, 0xe2, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff,
                                         0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xe4, 0xb8, 0xe2, 0x00,
                                         0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                         0xff, 0xe4, 0xb8, 0xe2, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff,
                                         0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                         0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                         0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
static unsigned char model_version[] = { 0x01, 0x00, 0x00, 0x00 };

using namespace std;                                                                                                                                                                                               
                                                                                                                                                                                                                   
typedef struct KTestObject KTestObject;                                                                                                                                                                            
struct KTestObject {                                                                                                                                                                                               
    char* name;
    unsigned numBytes;
    unsigned char* bytes;
};

typedef struct KTest KTest;
struct KTest {
    /* file format version */
    unsigned version;

    unsigned numArgs;
    char** args;

    unsigned symArgvs;
    unsigned symArgvLen;

    unsigned numObjects;
    KTestObject* objects;
};

/* Frees dynamic memory objects before exit*/
int freeMem(KTest *kt) {
    int i;
    if(kt != NULL)
        return 0;
    if(kt->args != NULL && kt->numArgs > 0){
            for (i = 0; i < kt->numArgs; i++)
                delete[] kt->args[i];
            delete[] kt->args;
    }                
    if(kt->objects != NULL && kt->numObjects > 0){
        for (i = 0; i < kt->numObjects; i++){
            KTestObject* o = &kt->objects[i];
            delete[] o->name;
            delete[] o->bytes;
            delete o;
        }
        delete[] kt->objects;
    }
    delete kt;
    
    return 1;
}

/* given two hex values(in char form), constructs the corresponding byte */
char cnv_hexchar_to_i(unsigned char tmp1, unsigned char tmp2){	
    unsigned    bt1 = 0;
    unsigned    bt2 = 0;
    
    if(tmp1 <= 57 && tmp1 >= 48)
        bt1 = tmp1-48;     
    else if(tmp1 <= 102 && tmp1 >= 97)
        bt1 = tmp1-97+10;
        bt1 = bt1 << 4;
    if(tmp2 <= 57 && tmp2 >= 48)
        bt2 = tmp2-48;          
    else if(tmp2 <= 102 && tmp2 >= 97)
        bt2 = tmp2-97+10;

    return bt1 + bt2; 
}

static int read_uint32_from_hexchar(FILE *f, unsigned *value_out) {
  unsigned char data[4];
  unsigned char tmp[8];
 
  if (fread(tmp, 8, 1, f)!=1)
    return 0;
  for(int i = 0; i < 8; i = i+2){
        data[i/2] = cnv_hexchar_to_i(tmp[i], tmp[i+1]);
  }
  *value_out = (((((data[0]<<8) + data[1])<<8) + data[2])<<8) + data[3];

  return 1;
  
error:
        cout << "Error, invalid input data...\n";
        return 0;
}

static int read_string_from_hexchar(FILE *f, unsigned char *value_out, unsigned len) {
    unsigned char data[len*2];
    
    if (fread(data, len*2, 1, f)!=1)
        return 0;
    for(int i = 0; i < len*2; i = i+2){
        value_out[i/2] = cnv_hexchar_to_i(data[i], data[i+1]);
    }
    
  return 1;
}

static int write_uint32(FILE* f, unsigned value) {
    unsigned char data[4];
    data[0] = value >> 24;
    data[1] = value >> 16;
    data[2] = value >> 8;
    data[3] = value >> 0;
    return fwrite(data, 1, 4, f) == 4;
}

static int write_string(FILE* f, const char* value) {
    unsigned len = strlen(value);
    if (!write_uint32(f, len))
        return 0;
    if (fwrite(value, len, 1, f) != 1)
        return 0;
    return 1;
}

char * uIntToStr(unsigned n) {
    char * str;
    int len = 6;
    unsigned max = 1000000;
    unsigned divisor = 1;
    unsigned previous;
    unsigned tmp = 0;

    if (n > 999999)         /*max symbol size 1 million -1 bytes*/
        return NULL;
    previous = n % max;
    while (len > 0) {
        max = max / 10;
        if (!((n % max) == previous))
            break;
        len--;
    }
    str = new char[len];
    for (int i = len-1; i >= 0; i--) {
        tmp = n % (divisor*10);
        str[i] = tmp/divisor + '0';
        divisor = divisor * 10;
        n = n - tmp;
    }

    return str;
}

/* Writes a KTest object in to a .ktest file */
int kTest_toFile(KTest* kt, const char* path) {
    FILE* f = fopen(path, "wb");
    unsigned i;

    if (!f)
        goto error;
    if (fwrite(KTEST_HDR, strlen(KTEST_HDR), 1, f) != 1)
        goto error;
    if (!write_uint32(f, KTEST_VER))
        goto error;
    if (!write_uint32(f, kt->numArgs))
        goto error;
    for (i = 0; i < kt->numArgs; i++) {
        if (!write_string(f, kt->args[i]))
            goto error;
    }
    if (!write_uint32(f, kt->symArgvs))
        goto error;
    if (!write_uint32(f, kt->symArgvLen))
        goto error;

    if (!write_uint32(f, kt->numObjects))
        goto error;
    for (i = 0; i < kt->numObjects; i++) {
        KTestObject* o = &kt->objects[i];
        if (!write_string(f, o->name))
            goto error;
        if (!write_uint32(f, o->numBytes))
            goto error;
        if (fwrite(o->bytes, o->numBytes, 1, f) != 1)
            goto error;
    }

    fclose(f);

    return 1;
error:
    if (f) fclose(f);
    freeMem(kt);

    return 0;
}

/* Reads input file and constructs Ktest object */
int inputToKTest(FILE *f, char *bitcodeName) {
    char                *ktestPath;
    char                *inputType;
    char                *symbolSizeStr;
    unsigned            symbolSizeInt;
    KTest               *kt;
	KTestObject         *o_one;
	KTestObject         *o_two;
	KTestObject         *o_tre;
    char                **args;
    char                *arg0;
    char                *arg1;
    char                *arg2;
    char                inhdr[IN_HDR_SIZE];
    Types               current_type;

    if (fread(inhdr, IN_HDR_SIZE, 1, f)!=1){
            cout << "Error while reading input data header...\n";
            return 0;
    }
    if(!memcmp(inhdr, SYM_DATA_IN_STDIN, IN_HDR_SIZE))
            current_type = TYPE_STDIN;
    else if(!memcmp(inhdr, SYM_DATA_IN_ARG, IN_HDR_SIZE))
             current_type = TYPE_ARG00;
    else if(!memcmp(inhdr, SYM_DATA_IN_ARGS, IN_HDR_SIZE))
            current_type = TYPE_ARGSS;
    else if(!memcmp(inhdr, SYM_DATA_IN_FILES, IN_HDR_SIZE))
            current_type = TYPE_FILES;
    else{
            cout << "Error, invalid input header...\n";
            return 0;
    }
	
	ktestPath = new char[strlen(bitcodeName)+6];
    strcpy(ktestPath, bitcodeName);
	strcat(ktestPath, ".ktest");
	
    kt = new KTest;
    kt->version = KTEST_VER;
    kt->symArgvs = 0;
    kt->symArgvLen = 0;
        
    switch (current_type){
            case TYPE_STDIN:
                        {   inputType = new char[strlen(KTEST_ARG_SYM_STDIN)];
                            strcpy(inputType, KTEST_ARG_SYM_STDIN);
                            if(!read_uint32_from_hexchar(f, &symbolSizeInt))
                                    goto error;
                                symbolSizeStr = uIntToStr(symbolSizeInt);
                            if (symbolSizeStr == NULL) {
                                cout << "ERROR while converting symbol size to string...\n";
                                return 0;
                            }

                            kt->numArgs = 3;
                            args = new char* [kt->numArgs];
                            kt->args = args;
                            arg0 = new char[strlen(bitcodeName)+3];
                            arg1 = new char[strlen(inputType)];
                            arg2 = new char[strlen(symbolSizeStr)];
                            strcpy(arg0, bitcodeName);
							strcat(arg0,".bc");
                            strcpy(arg1, inputType);
                            strcpy(arg2, symbolSizeStr);
                            args[0] = arg0;
                            args[1] = arg1;
                            args[2] = arg2;

                            kt->numObjects = 3;
                            kt->objects = new KTestObject[3*sizeof(*kt->objects)];
                            
                            o_one = &kt->objects[0];							
                            o_one->name = new char[strlen(SYM_NAME_STDIN)];
                            strcpy(o_one->name, SYM_NAME_STDIN);
                            o_one->numBytes = symbolSizeInt;
                            o_one->bytes = new unsigned char[symbolSizeInt];
                            if(!read_string_from_hexchar(f, o_one->bytes, symbolSizeInt))
                                goto error;

                            o_two = &kt->objects[1];
                            o_two->name = new char[strlen(STDIN_STAT)];
                            strcpy(o_two->name, STDIN_STAT);
                            o_two->numBytes = STDIN_STAT_SIZE;
                            o_two->bytes = new unsigned char[STDIN_STAT_SIZE];
                            for (int i = 0; i < STDIN_STAT_SIZE; i++)
                                o_two->bytes[i] = stdin_stat[i];

                            o_tre = &kt->objects[2];
                            o_tre->name = new char[strlen(MODEL_VERSION_NAME)];
                            strcpy(o_tre->name, MODEL_VERSION_NAME);
                            o_tre->numBytes = MODEL_VERSION_SIZE;
                            o_tre->bytes = new unsigned char[MODEL_VERSION_SIZE];
                            for (int i = 0; i < MODEL_VERSION_SIZE; i++)
                                o_tre->bytes[i] = model_version[i];

                            break;
                        }
            case TYPE_ARG00:
							inputType = new char[strlen(KTEST_ARG_SYM_ARG)];
                            strcpy(inputType, KTEST_ARG_SYM_ARG);
                            if(!read_uint32_from_hexchar(f, &symbolSizeInt))
                                    goto error;
                                symbolSizeStr = uIntToStr(symbolSizeInt);
							if (symbolSizeStr == NULL) {
								cout << "ERROR while converting symbol size to string...\n";
								return 0;
							}
								
							kt->numArgs = 3;
							args = new char* [kt->numArgs];
							kt->args = args;
							arg0 = new char[strlen(bitcodeName)];
							arg1 = new char[strlen(inputType)];
							arg2 = new char[strlen(symbolSizeStr)];
							strcpy(arg0, bitcodeName);
							strcpy(arg1, inputType);
							strcpy(arg2, symbolSizeStr);
							args[0] = arg0;
							args[1] = arg1;
							args[2] = arg2;

                            kt->numObjects = 2;
                            kt->objects = new KTestObject[2*sizeof(*kt->objects)];

							o_one = &kt->objects[0];							
                            o_one->name = new char[strlen(SYM_NAME_ARG)];
                            strcpy(o_one->name, SYM_NAME_ARG);
                            o_one->numBytes = symbolSizeInt+1; /*this is because the 'arg' has to have a null character at the end */
                            o_one->bytes = new unsigned char[symbolSizeInt];
                            if(!read_string_from_hexchar(f, o_one->bytes, symbolSizeInt-1))
                                goto error;
							o_one->bytes[symbolSizeInt] = '\0'; /* ading the null character at the end of 'arg' data */

							o_two = &kt->objects[1];
                            o_two->name = new char[strlen(MODEL_VERSION_NAME)];
                            strcpy(o_two->name, MODEL_VERSION_NAME);
                            o_two->numBytes = MODEL_VERSION_SIZE;
                            o_two->bytes = new unsigned char[MODEL_VERSION_SIZE];
                            for (int i = 0; i < MODEL_VERSION_SIZE; i++)
                                o_two->bytes[i] = model_version[i];

                            break;
            case TYPE_ARGSS:
                            cout << "TYPE_ARGSS, ktest files with multiple sym args not supported yet...\n";
                            goto error;
							/*
							inputType = new char[strlen(KTEST_ARG_SYM_ARGS)];
                            strcpy(inputType, KTEST_ARG_SYM_ARGS);
							*/
                            break;
            case TYPE_FILES:
                            cout << "TYPE_FILES, ktest files with sym files not supported yet...\n";
                            goto error;
							/*
							inputType = new char[strlen(KTEST_ARG_SYM_FILES)];
                            strcpy(inputType, KTEST_ARG_SYM_FILES);
							*/
                            break;
    }    
    
	if(!kTest_toFile(kt, ktestPath))
        return 0;
    freeMem(kt);	
    return 1;

error:
    if (f) fclose(f);
    freeMem(kt);
    return 0;
}

int main(int argc, char *argv[]) {

    FILE* f;
    
    if(argc != 3){
        cout << "Error, invalid no of args...\n";
        return 0;
    }
    f = fopen(argv[1], "r");
    if (!f){
        cout << "Error while opening input file...\n";
        return 0;
    }
    
    
    if (!inputToKTest(f, argv[2])){
        cout << "Error while constructing Ktest object...\n";
        return 0;
    }
    cout << "\nklee test case generated, " << argv[2] << ".ktest" << "\n\n";

    return 1;
}



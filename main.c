#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "num_utils.h"
#include "sbox_utils.h"
#include "awd.h"

#define BIT     8
#define BITP    4

unsigned int sbox_present[16]   = {12, 5, 6, 11, 9, 0, 10, 13, 3, 14, 15, 8, 4, 7, 1, 2};
unsigned int sbox_sample[8]     = {2, 7, 0, 6, 3, 1, 5, 4};
unsigned int sbox_aes[256]      = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};
unsigned int sbox_pattimura[256] = {
    0xc0, 0x5d, 0x5b, 0xfc, 0x73, 0x46, 0x16, 0xc3, 0x3c, 0xbb, 0xdc, 0x15, 0x19, 0x79, 0x63, 0x62,
    0x39, 0x0e, 0xa2, 0xfe, 0xe7, 0xc5, 0x03, 0x1a, 0x2e, 0xc7, 0x3b, 0x08, 0xda, 0xd1, 0xcf, 0xee,
    0x37, 0x5a, 0x2f, 0x44, 0x71, 0xba, 0x24, 0x7b, 0xd3, 0x43, 0xde, 0x95, 0xdf, 0x4f, 0x2b, 0xf1,
    0xeb, 0xc4, 0xae, 0x5c, 0x7d, 0xbe, 0x11, 0x52, 0xd4, 0xfb, 0x2d, 0x51, 0x34, 0xf3, 0x82, 0xef,
    0x7e, 0x33, 0x76, 0x64, 0xf6, 0x7c, 0x9f, 0xff, 0x91, 0x97, 0xe2, 0xe9, 0x89, 0xec, 0x17, 0x9b,
    0xa5, 0x31, 0x32, 0xe4, 0x65, 0xd0, 0xac, 0x0c, 0xb1, 0x92, 0xb0, 0x42, 0x8c, 0x69, 0x2c, 0xf4,
    0xd8, 0xaa, 0x8f, 0xe6, 0x1e, 0xb2, 0x00, 0xd7, 0x59, 0x0d, 0xb8, 0x38, 0xe5, 0x3f, 0x29, 0xed,
    0x8b, 0x58, 0x21, 0x57, 0xb9, 0xf2, 0x2a, 0x12, 0x30, 0x02, 0x3d, 0xf7, 0xb5, 0x05, 0x35, 0xad,
    0x23, 0xa8, 0x3e, 0x68, 0xa4, 0x72, 0xd5, 0x77, 0x7f, 0xa7, 0x90, 0x9c, 0x54, 0x53, 0x6e, 0x70,
    0xcd, 0x74, 0xd6, 0x66, 0xe8, 0xca, 0x9a, 0x01, 0xdd, 0xcc, 0x6f, 0xd9, 0x25, 0x80, 0x06, 0x20,
    0x48, 0xf5, 0xa9, 0xf8, 0x6c, 0xf0, 0xe3, 0x45, 0x14, 0x49, 0x85, 0xb6, 0xbf, 0x84, 0xbc, 0x9e,
    0x26, 0x93, 0xe1, 0xcb, 0xc2, 0xb4, 0xb7, 0x6a, 0x28, 0xd2, 0xab, 0xce, 0x8e, 0x41, 0x47, 0x22,
    0x0a, 0x1f, 0x3a, 0x10, 0x50, 0x1c, 0x94, 0xaf, 0x4d, 0x07, 0xa1, 0xfd, 0xb3, 0x83, 0x75, 0xbd,
    0x0f, 0x4a, 0x78, 0x0b, 0x98, 0x96, 0x1b, 0x60, 0xa3, 0xdb, 0xea, 0x04, 0x09, 0x56, 0x4e, 0x61,
    0xc6, 0x36, 0xf9, 0xfa, 0x5e, 0x18, 0xe0, 0x4c, 0x99, 0x6b, 0x4b, 0x87, 0xc8, 0x1d, 0xa6, 0xc1,
    0x81, 0xc9, 0x55, 0x40, 0x9d, 0x67, 0x13, 0x88, 0x5f, 0x7a, 0x27, 0x8d, 0x8a, 0x6d, 0x86, 0xa0
};

int main() {

    unsigned int i,j,m,n;
    unsigned int samples = 10000;
    unsigned int bit_aes = 128;    
    double error1 = 0, error2 = 0;
    double maxAC1 = 0, maxSAC1 = 0, maxAWDR1 = 0;
    double maxAC2 = 0, maxSAC2 = 0, maxAWDR2 = 0;
    int bit_flip, weight, maxXor1 = 0, maxXor2 = 0;
    m = n = BIT;
    FILE *filePlaintext, *fileKey, *fileOutput;
    FILE *fileACAES, *fileSACAES, *fileXorTableAES, *fileLATAES, *fileAWDAES;
    FILE *fileACPattimura, *fileSACPattimura, *fileLATPattimura, *fileXorTablePattimura, *fileAWDPattimura;
    filePlaintext   = fopen("plaintext1.txt","r");
    fileKey         = fopen("key.txt","r");
    fileOutput      = fopen("OutputUjiPattimura.txt","w");

    fileAWDAES      = fopen("AES/UjiAWD_AES_File.xls","w");
    fileLATAES      = fopen("AES/NilaiLAT_AES.txt","w");
    fileXorTableAES = fopen("AES/XorTable_AES.txt","w");
    fileACAES       = fopen("AES/HasilAC_AES.txt","w");
    fileSACAES      = fopen("AES/HasilSAC_AES.txt","w");

    fileAWDPattimura        = fopen("Pattimura/UjiAWD_Pattimura_File.xls","w");
    fileLATPattimura        = fopen("Pattimura/NilaiLAT_Pattimura.txt","w");
    fileXorTablePattimura   = fopen("Pattimura/XorTable_Pattimura.txt","w");
    fileACPattimura         = fopen("Pattimura/HasilAC_Pattimura.txt","w");
    fileSACPattimura        = fopen("Pattimura/HasilSAC_Pattimura.txt","w");

    time_t start, stop;
    time(&start);

    // Algorithm Test [AC, SAC, BIC, AWD]
    double *acAES   = ac_AES_file(filePlaintext,fileKey,samples,bit_aes);
    double *acPatt  = ac_Pattimura_file(filePlaintext,fileKey,samples,bit_aes);
    float **sacAES  = sac_AES_file(filePlaintext,fileKey,samples,bit_aes);
    float **sacPatt = sac_Pattimura_file(filePlaintext,fileKey,samples,bit_aes);
    double bicAES   = bic_AES_file(filePlaintext,fileKey,samples,bit_aes);
    double bicPatt  = bic_Pattimura_file(filePlaintext,fileKey,samples,bit_aes);
    unsigned int **awdAES   = awd_count_AES_file(filePlaintext,fileKey,samples,bit_aes);
    unsigned int **awdPatt  = awd_count_Pattimura_file(filePlaintext,fileKey,samples,bit_aes);
    unsigned int *binomAll  = awd_binom_distrib(samples,bit_aes +1);

    // S-Box Test [XorTable, LAT, Non-Linierity]
    unsigned int **xortable_aes  = sbox_differential_table(sbox_aes,BIT,BIT);
    unsigned int **xortable_patt = sbox_differential_table(sbox_pattimura,BIT,BIT);
    unsigned int **lat_aes       = sbox_linearity(sbox_aes,BIT,BIT);
    unsigned int **lat_patt      = sbox_linearity(sbox_pattimura,BIT,BIT);
    unsigned int nonLin_AES      = sbox_nonlinearity(sbox_aes,BIT,BIT);
    unsigned int nonLin_Patt     = sbox_nonlinearity(sbox_pattimura,BIT,BIT);

    // Print to File
    // #1. Avalanche Criterion :
    for (i = 0; i < bit_aes; ++i) {
        fprintf(fileACAES,      " %.6lf\n", acAES[i]);
        fprintf(fileACPattimura," %.6lf\n", acPatt[i]);
        error1 = fabs(0.5 - acAES[i]);
        error2 = fabs(0.5 - acPatt[i]);
        if (error1 > maxAC1) maxAC1 = error1;
        if (error2 > maxAC2) maxAC2 = error2;
    }
    error1 = error2 = 0;

    // #2. Strict Avalanche Criterion :
    for (i = 0; i < bit_aes; ++i) {
        for (j = 0; j < bit_aes; ++j) {
            fprintf(fileSACAES,      " %.6lf\n", sacAES[i][j]);
            fprintf(fileSACPattimura," %.6lf\n", sacPatt[i][j]);
            error1 = fabs(0.5 - sacAES[i][j]);
            error2 = fabs(0.5 - sacPatt[i][j]);
            if (error1 > maxSAC1) maxSAC1 = error1;
            if (error2 > maxSAC2) maxSAC2 = error2;
        }
        fprintf(fileSACAES,"\n");
        fprintf(fileSACPattimura,"\n");
    }
    error1 = error2 = 0;

    // #3. Avalanche Weight Distribution :
    for (bit_flip = 0; bit_flip < bit_aes; ++bit_flip) {
        for (weight = 0; weight < bit_aes +1; ++weight) {
            fprintf(fileAWDAES,         " %d\t",awdAES[bit_flip][weight]);
            fprintf(fileAWDPattimura,   " %d\t",awdPatt[bit_flip][weight]);
        }
        fprintf(fileAWDAES,"\n");
        fprintf(fileAWDPattimura,"\n");
    }

    double resemAES[bit_aes],resemPatt[bit_aes];
    for (i = 0; i < bit_aes; ++i) {
        resemAES[i]     = awd_resemblance(awdAES[i],binomAll,bit_aes +1, samples);
        resemPatt[i]    = awd_resemblance(awdPatt[i],binomAll,bit_aes +1, samples);
        if (resemAES[i] > maxAWDR1)    maxAWDR1 = resemAES[i];
        if (resemPatt[i] > maxAWDR2)   maxAWDR2 = resemPatt[i];
    }

    // #4. XorTable SBox :
    for (i = 0; i < two_power(BIT); ++i) {
        for (j = 0; j < two_power(BIT); ++j) {
            if (xortable_aes[i][j] != 0) {
                fprintf(fileXorTableAES," [%.2x][%.2x] : %d\n",i,j,xortable_aes[i][j]);
                if (xortable_aes[i][j] > maxXor1 && xortable_aes[i][j] != two_power(BIT)) {
                    maxXor1 = xortable_aes[i][j];
                }
            }
            if (xortable_patt[i][j] != 0) {
                fprintf(fileXorTablePattimura," [%.2x][%.2x] : %d\n",i,j,xortable_patt[i][j]);
                if (xortable_patt[i][j] > maxXor2 && xortable_patt[i][j] != two_power(BIT)) {
                    maxXor2 = xortable_patt[i][j];
                }
            }
        }
    }

    fprintf(fileOutput," ===============================================================\n");
    fprintf(fileOutput," ==========================Hasil Uji============================\n");
    fprintf(fileOutput," ===============================================================\n");
    fprintf(fileOutput,"           |     AC     |    SAC     |    BIC    |     AWD      \n");
    fprintf(fileOutput," ===============================================================\n");
    fprintf(fileOutput,"    AES    |   %.5f     %.5f     %lf     %lf\n",maxAC1,maxSAC1,bicAES,maxAWDR1);
    fprintf(fileOutput," ===============================================================\n");
    fprintf(fileOutput," Pattimura |   %.5f     %.5f     %lf     %lf\n",maxAC2,maxSAC2,bicPatt,maxAWDR2);
    fprintf(fileOutput," ===============================================================\n");
    fprintf(fileOutput,"           |  XorTable  |    LAT     | NonLinier |\n");
    fprintf(fileOutput," ===============================================================\n");
    fprintf(fileOutput,"    AES    |     %d           %d           %d\n",maxXor1,lat_aes,nonLin_AES);
    fprintf(fileOutput," ===============================================================\n");
    fprintf(fileOutput," Pattimura |     %d           %d           %d\n",maxXor2,lat_patt,nonLin_Patt);
    fprintf(fileOutput," ===============================================================\n");

    time(&stop);
    fprintf(fileOutput," =========================End of File===========================\n");
    fprintf(fileOutput," \t\t\t\t Finnished in %.2f seconds. \n", difftime(stop, start));

    fclose(filePlaintext);      fclose(fileKey);                    fclose(fileOutput);
    fclose(fileAWDAES);         fclose(fileLATAES);                 fclose(fileXorTableAES);
    fclose(fileACAES);          fclose(fileSACAES);
    fclose(fileAWDPattimura);   fclose(fileXorTablePattimura);      fclose(fileLATPattimura);
    fclose(fileACPattimura);    fclose(fileSACPattimura);

    free(acAES);    free(acPatt);   free(sacAES);   free(sacPatt);
    free(awdAES);   free(awdPatt);  free(binomAll);
    free(xortable_aes); free(xortable_patt);

    printf("Selesai..\n");

    return 0;
}

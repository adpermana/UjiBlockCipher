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

int main() {

    unsigned int i,j,m,n;
    unsigned int samples = 10000;
    unsigned int bit_aes = 128;    
    double error = 0, maxError = 0;
    int bit_flip, weight;
    m = n = BIT;
    FILE *filePlaintext, *fileKey, *fileOutput, *fileAWDFile, *fileAWDRandom;
    FILE *fileXorTablePresent, *fileXorTableAES, *fileLATPresent, *fileLATAES;
    filePlaintext   = fopen("plaintext1.txt","r");
    fileKey         = fopen("key.txt","r");
    fileOutput      = fopen("OutputUji.txt","w");
    fileAWDFile     = fopen("UjiAWD_AES_File.xls","w");
    fileAWDRandom   = fopen("UjiAWD_AES_Random.xls","w");
    fileLATPresent  = fopen("NilaiLAT_Present.txt","w");
    fileLATAES      = fopen("NilaiLAT_AES.txt","w");
    fileXorTablePresent = fopen("XorTable_Present.txt","w");
    fileXorTableAES     = fopen("XorTable_AES.txt","w");

    time_t start, stop;
    time(&start);

    fprintf(fileOutput," ============================================================\n");
    fprintf(fileOutput," [1] Avalanche Criterion [SBox AES] :\n");
    fprintf(fileOutput," ============================================================\n");
    float *ac = sbox_ac(sbox_aes,m);
    for (i = 0; i < m; ++i) {
        fprintf(fileOutput," %.2f", ac[i]);
        error = fabs(0.5 - ac[i]);
        if (error > maxError) {
            maxError = error;
        }
    }
    fprintf(fileOutput,"\n Max Error : %.5f\n",maxError);
    fprintf(fileOutput,"\n");
    maxError = error = 0;

    fprintf(fileOutput," ============================================================\n");
    fprintf(fileOutput," [2] Avalanche Criterion [AES Algorithm - Random] :\n");
    fprintf(fileOutput," ============================================================\n");
    srand(samples);
    double *acAlg = ac_AES(samples,bit_aes);
    for (i = 0; i < bit_aes; ++i) {
        fprintf(fileOutput," %.6lf\n", acAlg[i]);
        error = fabs(0.5 - acAlg[i]);
        if (error > maxError) {
            maxError = error;
        }
    }
    fprintf(fileOutput," Max Error : %.5f\n",maxError);
    fprintf(fileOutput,"\n");
    maxError = error = 0;

    fprintf(fileOutput," ============================================================\n");
    fprintf(fileOutput," [3] Avalanche Criterion [AES Algorithm - File] :\n");
    fprintf(fileOutput," ============================================================\n");
    double *acAlgFile = ac_AES_file(filePlaintext,fileKey,samples,bit_aes);
    for (i = 0; i < bit_aes; ++i) {
        fprintf(fileOutput," %.6lf\n", acAlgFile[i]);
        error = fabs(0.5 - acAlgFile[i]);
        if (error > maxError) {
            maxError = error;
        }
    }
    fprintf(fileOutput," Max Error : %.5f\n",maxError);
    fprintf(fileOutput,"\n");
    maxError = error = 0;

    fprintf(fileOutput," ============================================================\n");
    fprintf(fileOutput," [4] Strict Avalanche Criterion [SBox AES] :\n");
    fprintf(fileOutput," ============================================================\n");
    float **sac = sbox_sac_matrix(sbox_aes,m,n);
    for (i = 0; i < m; ++i) {
        for (j = 0; j < n; ++j) {
            fprintf(fileOutput," %5.3f ", sac[i][j]);
            error = fabs(0.5 - sac[i][j]);
            if (error > maxError) {
                maxError = error;
            }
        }
        fprintf(fileOutput,"\n");
    }
    fprintf(fileOutput," Max Error : %.5f\n",maxError);
    fprintf(fileOutput,"\n");
    maxError = error = 0;

    fprintf(fileOutput," ============================================================\n");
    fprintf(fileOutput," [5] Strict Avalanche Criterion [AES Algorithm - Random] :\n");
    fprintf(fileOutput," ============================================================\n");
    float **sacAlg = sac_AES(samples,bit_aes);
    for (i = 0; i < bit_aes; ++i) {
        for (j = 0; j < bit_aes; ++j) {
            fprintf(fileOutput," %5.3f ", sacAlg[i][j]);
            error = fabs(0.5 - sacAlg[i][j]);
            if (error > maxError) {
                maxError = error;
            }
        }
        fprintf(fileOutput,"\n");
    }
    fprintf(fileOutput," Max Error : %.5f\n",maxError);
    fprintf(fileOutput,"\n");
    maxError = error = 0;

    fprintf(fileOutput," ============================================================\n");
    fprintf(fileOutput," [6] Strict Avalanche Criterion [AES Algorithm - File] :\n");
    fprintf(fileOutput," ============================================================\n");
    float **sacAlgFile = sac_AES_file(filePlaintext,fileKey,samples,bit_aes);
    for (i = 0; i < bit_aes; ++i) {
        for (j = 0; j < bit_aes; ++j) {
            fprintf(fileOutput," %5.3f ", sacAlgFile[i][j]);
            error = fabs(0.5 - sacAlgFile[i][j]);
            if (error > maxError) {
                maxError = error;
            }
        }
        fprintf(fileOutput,"\n");
    }
    fprintf(fileOutput," Max Error : %.5f\n",maxError);
    fprintf(fileOutput,"\n");
    maxError = error = 0;

    fprintf(fileOutput," ============================================================\n");
    fprintf(fileOutput," [7] Avalanche Weight Distribution [AES Algorithm - Random] :\n");
    fprintf(fileOutput," ============================================================\n");
    fprintf(fileOutput," ===========================NILAI AWD========================\n");
    fprintf(fileOutput," \t\t\t[ Ada pada file : UjiAWD_AES_Random.xls ]\n");
    unsigned int **awd_array_random = awd_count_AES(samples,bit_aes);
    unsigned int *binomAll = awd_binom_distrib(samples,bit_aes +1);
    for (bit_flip = 0; bit_flip < bit_aes; ++bit_flip) {
        for (weight = 0; weight < bit_aes +1; ++weight) {
            fprintf(fileAWDRandom," %d\t",awd_array_random[bit_flip][weight]);
        }
        fprintf(fileAWDRandom,"\n");
    }

    fprintf(fileOutput," ============================================================\n");
    fprintf(fileOutput," =======================NILAI RESEMBLANCE====================\n");
    double nilaiRRandom[bit_aes];
    for (i = 0; i < bit_aes; ++i) {
        nilaiRRandom[i] = awd_resemblance(awd_array_random[i],binomAll,bit_aes +1, samples);
        fprintf(fileOutput," R[%d] : %lf\n",i,nilaiRRandom[i]);
    }
    fprintf(fileOutput,"\n");

    fprintf(fileOutput," ============================================================\n");
    fprintf(fileOutput," [8] Avalanche Weight Distribution [AES Algorithm - File] :\n");
    fprintf(fileOutput," ============================================================\n");
    fprintf(fileOutput," ===========================NILAI AWD========================\n");
    fprintf(fileOutput," \t\t\t[ Ada pada file : UjiAWD_AES_File.xls ]\n");
    unsigned int **awd_array_file = awd_count_AES_file(filePlaintext,fileKey,samples,bit_aes);
    for (bit_flip = 0; bit_flip < bit_aes; ++bit_flip) {
        for (weight = 0; weight < bit_aes + 1; ++weight) {
            fprintf(fileAWDFile," %d\t",awd_array_file[bit_flip][weight]);
        }
        fprintf(fileAWDFile,"\n");
    }

    fprintf(fileOutput," ============================================================\n");
    fprintf(fileOutput," =======================NILAI RESEMBLANCE====================\n");
    double nilaiR[bit_aes];
    for (i = 0; i < bit_aes; ++i) {
        nilaiR[i] = awd_resemblance(awd_array_file[i],binomAll,bit_aes +1, samples);
        fprintf(fileOutput," R[%d] : %lf\n",i,nilaiR[i]);
    }
    fprintf(fileOutput,"\n");

//    fprintf(fileOutput," ============================================================\n");
//    fprintf(fileOutput," [9] Bit Independence Criterion [SBox AES] :\n");
//    fprintf(fileOutput," ============================================================\n");
//    double bic = sbox_bic(sbox_aes,m,n);
//    fprintf(fileOutput," Nilai MAX BIC SBox AES : %lf\n",bic);
//    fprintf(fileOutput,"\n");

//    fprintf(fileOutput," ============================================================\n");
//    fprintf(fileOutput," [10] Bit Independence Criterion [AES Algorithm - File] :\n");
//    fprintf(fileOutput," ============================================================\n");
//    double bicFile = bic_AES_file(filePlaintext,fileKey,1000,bit_aes);
//    fprintf(fileOutput," Nilai MAX BIC AES Algorithm - File : %lf\n",bicFile);
//    fprintf(fileOutput,"\n");

//    fprintf(fileOutput," ============================================================\n");
//    fprintf(fileOutput," [11] Bit Independence Criterion [AES Algorithm - Random] :\n");
//    fprintf(fileOutput," ============================================================\n");
//    double bicRandom = bic_AES_random(1000,bit_aes);
//    fprintf(fileOutput," Nilai MAX BIC AES Algorithm - Random : %lf\n",bicRandom);
//    fprintf(fileOutput,"\n");

    fprintf(fileOutput," ============================================================\n");
    fprintf(fileOutput," [12] XORTable Test [SBox Present] :\n");
    fprintf(fileOutput," ============================================================\n");
    unsigned int **xortable_present = sbox_differential_table(sbox_present,BITP,BITP);
    int maxXor = 0;
    for (i = 0; i < two_power(BITP); ++i) {
        for (j = 0; j < two_power(BITP); ++j) {
            if (xortable_present[i][j] != 0) {
                fprintf(fileXorTablePresent," [%.2x][%.2x] : %d\n",i,j,xortable_present[i][j]);
                if (xortable_present[i][j] > maxXor && xortable_present[i][j] != two_power(BITP)) {
                    maxXor = xortable_present[i][j];
                }
            }
        }
    }
    fprintf(fileOutput," Nilai Max XORTable Present : %d\n",maxXor);
    fprintf(fileOutput,"\n");

    fprintf(fileOutput," ============================================================\n");
    fprintf(fileOutput," [13] XORTable Test [SBox AES] :\n");
    fprintf(fileOutput," ============================================================\n");
    unsigned int **xortable_aes = sbox_differential_table(sbox_aes,BIT,BIT);
    maxXor = 0;
    for (i = 0; i < two_power(BIT); ++i) {
        for (j = 0; j < two_power(BIT); ++j) {
            if (xortable_aes[i][j] != 0) {
                fprintf(fileXorTableAES," [%.2x][%.2x] : %d\n",i,j,xortable_aes[i][j]);
                if (xortable_aes[i][j] > maxXor && xortable_aes[i][j] != two_power(BIT)) {
                    maxXor = xortable_aes[i][j];
                }
            }
        }
    }
    fprintf(fileOutput," Nilai Max XORTable AES : %d\n",maxXor);
    fprintf(fileOutput,"\n");

    fprintf(fileOutput," ============================================================\n");
    fprintf(fileOutput," [14] Liniear Approximation Table [SBox Present] :\n");
    fprintf(fileOutput," ============================================================\n");
    unsigned int **lat_present = sbox_linear_approx_table(sbox_present,BITP,BITP);
    int maxLAT = 0;
    for (i = 0; i < two_power(4); ++i) {
        for (j = 0; j < two_power(4); ++j) {
            fprintf(fileLATPresent," [%.2x][%.2x] : %d\n",i,j,lat_present[i][j] - two_power(BITP)/2);
            if (lat_present[i][j] > maxLAT && lat_present[i][j] != two_power(BITP)) {
                maxLAT = lat_present[i][j];
            }
        }
    }
    fprintf(fileOutput," Nilai Max LAT Present : %d\n",maxLAT - two_power(BITP)/2);
    fprintf(fileOutput,"\n");

    fprintf(fileOutput," ============================================================\n");
    fprintf(fileOutput," [15] Liniear Approximation Table [SBox AES] :\n");
    fprintf(fileOutput," ============================================================\n");
    unsigned int **lat_aes = sbox_linear_approx_table(sbox_aes,BIT,BIT);
    maxLAT = 0;
    for (i = 0; i < two_power(BIT); ++i) {
        for (j = 0; j < two_power(BIT); ++j) {
            fprintf(fileLATAES," [%.2x][%.2x] : %d\n",i,j,lat_aes[i][j] - two_power(BIT)/2);
            if (lat_aes[i][j] > maxLAT && lat_aes[i][j] != two_power(BIT)) {
                maxLAT = lat_aes[i][j];
            }
        }
    }
    fprintf(fileOutput," Nilai Max LAT AES : %d\n",maxLAT - two_power(BIT)/2);
    fprintf(fileOutput,"\n");

    fprintf(fileOutput," ============================================================\n");
    fprintf(fileOutput," [15] Non-Linierity [SBox AES] :\n");
    fprintf(fileOutput," ============================================================\n");
    unsigned int nonLin = sbox_nonlinearity(sbox_aes,m,n);
    fprintf(fileOutput," Nilai NonLinierity [SBox AES] : %d\n",nonLin);
    fprintf(fileOutput,"\n");

    time(&stop);
    fprintf(fileOutput," ========================End of File=========================\n");
    fprintf(fileOutput," \t\t\t\t Finnished in %.2f seconds. \n", difftime(stop, start));

    fclose(filePlaintext);      fclose(fileKey);        fclose(fileOutput);
    fclose(fileAWDFile);        fclose(fileAWDRandom);  fclose(fileXorTablePresent);
    fclose(fileLATPresent);     fclose(fileLATAES);     fclose(fileXorTableAES);

    free(ac);   free(acAlg);    free(acAlgFile);        free(lat_aes);free(lat_present);
    free(sac);  free(sacAlg);   free(sacAlgFile);       free(xortable_aes); free(xortable_present);
    free(awd_array_file);       free(awd_array_random); free(binomAll);

    printf("Selesai..\n");

    return 0;
}

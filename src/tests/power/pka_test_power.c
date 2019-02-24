#define _GNU_SOURCE

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>
#include <inttypes.h>
#include <sys/time.h>
#include <sys/types.h>
#include <ctype.h>
#include <sched.h>
#include <pthread.h>
#include <stdbool.h>

#include "pka.h"
#include "pka_utils.h"

#include "pka_test_utils.h"

#define PKA_MAX_OBJS                16       // 16  objs
#define PKA_CMD_DESC_MAX_DATA_SIZE  (1 << 14) // 16K bytes.
#define PKA_RSLT_DESC_MAX_DATA_SIZE (1 << 12) //  4K bytes.

// Test duration in seconds
#define PKA_TEST_DURATION_IN_SEC    10

// Macro to print the current application mode
#define PRINT_APPL_MODE(x) printf("%s(bit %i)\n", #x, (x))

// Get rid of path in filename
#define NO_PATH(file_name) (strrchr((file_name), '/') ? \
                strrchr((file_name), '/') + 1 : (file_name))

// Parsed command line application arguments
typedef struct
{
    uint32_t       duration;       ///< Time to run app
    uint32_t       queue_size;     ///< Number of object per queue
    uint8_t        ring_count;     ///< Number of Rings to use
    uint8_t        key_size;       ///< Key size whether 2K or 4K
    uint8_t        mode;           ///< Application mode
    uint8_t        sync;           ///< Synchronization mode
} app_args_t;

/// Global pointer to args
static app_args_t app_args;

static pka_instance_t   pka_instance;
static pka_handle_t     pka_hdl;

static pka_operand_t   *test_operands[10];

/// RSA test vectors
// Vector A : exponent (public key)
// Vector B : modulus
// Vector C : plaintext

static uint8_t RSA2048_VectorA[] =
{
    0xbe, 0x2e, 0x3d, 0x81, 0xc8, 0x94, 0x99, 0x8b,
    0xb5, 0x10, 0x69, 0x13, 0x45, 0x8a, 0xd0, 0x13,
    0x77, 0x88, 0x5a, 0xa7, 0x00, 0x67, 0x3d, 0xcd,
    0x6c, 0xdd, 0x87, 0x7d, 0x59, 0xca, 0xbd, 0x8a,
    0xb0, 0x18, 0x59, 0xb9, 0x0a, 0xd1, 0x72, 0x3d,
    0x03, 0xc1, 0x5b, 0xb7, 0x25, 0xbb, 0xcd, 0xec,
    0x8e, 0x59, 0x62, 0x8d, 0x64, 0xc5, 0x38, 0x63,
    0xbd, 0x85, 0xbe, 0xb6, 0x42, 0x87, 0x90, 0xcb,
    0xf6, 0x94, 0x26, 0x7f, 0x76, 0x54, 0xff, 0x0c,
    0x5b, 0x70, 0xd9, 0x85, 0xaa, 0xf9, 0x6a, 0xf3,
    0x71, 0x49, 0xfe, 0xbc, 0x57, 0x38, 0xf6, 0x92,
    0xa5, 0x23, 0x41, 0xbf, 0xde, 0x8c, 0x3f, 0x24,
    0xed, 0xda, 0x88, 0x7b, 0xaf, 0x0a, 0x53, 0xec,
    0x95, 0x97, 0x53, 0x95, 0x2b, 0x35, 0xd4, 0x18,
    0xa5, 0xa4, 0x0f, 0xe3, 0x4e, 0x26, 0x70, 0x04,
    0x72, 0x8a, 0x6c, 0x28, 0xb0, 0x3c, 0x32, 0x3f,
    0x7e, 0x5f, 0x19, 0x46, 0x77, 0x74, 0xe0, 0x32,
    0x3d, 0x4c, 0xca, 0xea, 0x21, 0xc8, 0xc1, 0x50,
    0x05, 0xe6, 0xa5, 0x34, 0x03, 0x42, 0x38, 0x9f,
    0xaf, 0x01, 0x40, 0xdb, 0xed, 0xd1, 0x22, 0x50,
    0x29, 0x09, 0x40, 0x1c, 0x34, 0x7f, 0xf1, 0xc5,
    0x79, 0x0f, 0xc6, 0xe0, 0xde, 0x0c, 0x5b, 0x6c,
    0x5b, 0x34, 0xc7, 0x24, 0xd8, 0xb0, 0x2f, 0x4f,
    0xca, 0x33, 0x19, 0xd3, 0x15, 0x48, 0xff, 0x29,
    0x3a, 0x92, 0xd0, 0x66, 0x18, 0xb0, 0xb2, 0x8b,
    0x84, 0x71, 0xe5, 0x86, 0x5b, 0xf8, 0x35, 0x2b,
    0x51, 0xb9, 0x6b, 0xef, 0x54, 0xe7, 0xe9, 0xa9,
    0x08, 0xdd, 0x8a, 0x26, 0xe9, 0xaf, 0xca, 0xb4,
    0xdf, 0x24, 0x02, 0x2b, 0xf1, 0x84, 0x62, 0x11,
    0x48, 0xff, 0xc6, 0x98, 0x24, 0x97, 0xca, 0xd7,
    0xad, 0x44, 0xcf, 0x68, 0x2c, 0x79, 0x17, 0x9a,
    0x3c, 0xed, 0x4a, 0xd6, 0x3d, 0x29, 0x6f, 0xb7
};

static uint8_t RSA2048_VectorB[] =
{
    0xfd, 0x75, 0xe7, 0xb1, 0x47, 0x48, 0x2a, 0x94,
    0xbf, 0x8a, 0x16, 0x3b, 0x34, 0xde, 0x79, 0x55,
    0x0d, 0x27, 0x9c, 0x3b, 0x86, 0x86, 0x29, 0x28,
    0x50, 0x0a, 0xae, 0x99, 0xe7, 0xa2, 0x5d, 0x1f,
    0x92, 0x99, 0xaa, 0x53, 0x28, 0x5a, 0x2a, 0xad,
    0x47, 0x9f, 0xa9, 0x3a, 0x43, 0xc3, 0x5d, 0xd8,
    0x23, 0xd5, 0x85, 0xbc, 0x68, 0xcb, 0x08, 0xd0,
    0xe7, 0xaa, 0x40, 0xda, 0xdf, 0xdc, 0x52, 0xc0,
    0x7b, 0x3c, 0xfd, 0xc6, 0x19, 0x9f, 0xc6, 0xf4,
    0xe3, 0x87, 0x4f, 0x24, 0x6e, 0xa4, 0xca, 0xf0,
    0xc9, 0xf7, 0x9c, 0xd4, 0xa5, 0xae, 0x05, 0xcd,
    0x8c, 0xbe, 0x72, 0x8b, 0x85, 0x43, 0x2f, 0xbb,
    0x66, 0xe4, 0xd0, 0xdb, 0xaf, 0x21, 0xb2, 0xb9,
    0xc2, 0x76, 0x82, 0x34, 0xdd, 0x19, 0x16, 0x30,
    0xac, 0xda, 0x12, 0xad, 0xcf, 0x95, 0x36, 0x65,
    0xac, 0xbf, 0xd8, 0x27, 0x1a, 0x44, 0x18, 0x45,
    0x45, 0x93, 0xbb, 0xc2, 0x40, 0xa2, 0xed, 0xdf,
    0xe7, 0xd3, 0x8c, 0x4d, 0xe5, 0x89, 0x6d, 0xe1,
    0x1a, 0x6d, 0x02, 0xf9, 0x3b, 0xd2, 0x2b, 0xab,
    0xe4, 0xeb, 0x6e, 0x95, 0x8c, 0x2b, 0x6b, 0x14,
    0x8e, 0xef, 0x4e, 0x16, 0x66, 0x78, 0x86, 0x47,
    0xe3, 0xbd, 0x4e, 0x1d, 0xff, 0xd8, 0x19, 0x56,
    0x47, 0xc4, 0x4e, 0xd9, 0x1e, 0xaa, 0xf5, 0xc5,
    0x94, 0x73, 0x27, 0xaa, 0xb7, 0x13, 0x36, 0xff,
    0x83, 0x23, 0xaf, 0x31, 0xd7, 0xce, 0x06, 0x11,
    0xa8, 0xe7, 0x85, 0x1c, 0x9b, 0x41, 0x2d, 0x9b,
    0xd3, 0x3f, 0x8b, 0x3c, 0x54, 0xe5, 0x93, 0x46,
    0x19, 0x70, 0x21, 0x03, 0xd2, 0x84, 0xca, 0xf4,
    0x18, 0x71, 0xa2, 0x14, 0xec, 0x41, 0x13, 0xfc,
    0xdd, 0x01, 0x9e, 0x09, 0x64, 0xf3, 0xb5, 0xb9,
    0x1e, 0xde, 0xe7, 0xb6, 0xee, 0x72, 0xb9, 0xf4,
    0x94, 0xa4, 0x53, 0x61, 0xa3, 0x27, 0x5c, 0xb9
};

static uint8_t RSA2048_VectorC[] =
{
    0xb4, 0x5d, 0xfc, 0x48, 0x5f, 0xee, 0x7b, 0xbc,
    0x25, 0xbf, 0x31, 0xd8, 0x1e, 0xf5, 0x49, 0xd5,
    0xbd, 0xc7, 0xd1, 0x7e, 0x1e, 0xa2, 0xb0, 0xc1,
    0xf3, 0x52, 0x78, 0xe8, 0xc4, 0xec, 0x1f, 0xa6,
    0xb1, 0xee, 0xf6, 0xb7, 0x90, 0xf6, 0x80, 0x0a,
    0xef, 0xba, 0xae, 0x38, 0x42, 0xfa, 0x52, 0x68,
    0xcc, 0x5b, 0x75, 0xed, 0xd4, 0xdd, 0x6f, 0xbb,
    0xb3, 0x65, 0x51, 0x35, 0x55, 0x48, 0x86, 0xda,
    0x3e, 0x52, 0x5d, 0x48, 0x1b, 0xad, 0xad, 0x3d,
    0x6d, 0xd6, 0x20, 0xed, 0x43, 0x98, 0x7e, 0x28,
    0x83, 0xae, 0xa5, 0xc7, 0xc5, 0xe1, 0x15, 0x02,
    0x5b, 0xfd, 0x41, 0x36, 0xc4, 0x74, 0x66, 0x11,
    0x58, 0x57, 0x57, 0x80, 0xc8, 0xce, 0x39, 0x9d,
    0xbb, 0xd7, 0x26, 0xee, 0x61, 0xb7, 0xb0, 0xa5,
    0x3c, 0xd9, 0x6f, 0x9e, 0xba, 0xbb, 0xcd, 0xd6,
    0xe6, 0x88, 0x5a, 0x81, 0x17, 0x38, 0x76, 0x4a,
    0xf0, 0x37, 0x8e, 0xd2, 0x44, 0xe1, 0x17, 0x68,
    0x39, 0x90, 0x1c, 0x37, 0x76, 0x3f, 0xb5, 0x36,
    0x32, 0x5a, 0x2d, 0x6a, 0x73, 0x5a, 0x25, 0x0d,
    0x3c, 0xba, 0x36, 0x59, 0x76, 0x52, 0xf7, 0xfb,
    0x81, 0x1c, 0xd8, 0x2d, 0xc1, 0x41, 0x3e, 0xe4,
    0x71, 0xf8, 0xcf, 0x4f, 0x4f, 0x8a, 0x16, 0xbc,
    0x38, 0x6f, 0x78, 0x40, 0x32, 0x0b, 0xb7, 0x68,
    0x48, 0xfe, 0x42, 0x90, 0x95, 0x9d, 0x2d, 0x51,
    0xd0, 0x85, 0xe2, 0x13, 0x10, 0xb3, 0xbb, 0x70,
    0xa5, 0x48, 0x0b, 0x3a, 0x64, 0x03, 0x11, 0xe3,
    0x2f, 0x41, 0xf5, 0xe6, 0x30, 0xef, 0x6c, 0xe3,
    0xfa, 0x22, 0x6d, 0x5b, 0x8c, 0xff, 0x48, 0x5b,
    0xc0, 0x6e, 0xc5, 0xa8, 0xf4, 0xbf, 0x02, 0xc9,
    0x9f, 0x25, 0xa2, 0xcf, 0x4f, 0x1a, 0xba, 0xe2,
    0x92, 0x3f, 0xb6, 0x65, 0x94, 0x57, 0x10, 0x16,
    0xd2, 0x56, 0x83, 0x6b, 0x6d, 0x7d, 0x4b, 0xf4
};

static uint8_t RSA2048_Result[] =
{
    0x53, 0x7B, 0x0B, 0xB3, 0x99, 0xEB, 0x28, 0xBD,
    0x95, 0x31, 0xAD, 0x3C, 0xEC, 0x37, 0x9A, 0x24,
    0xF9, 0xEE, 0x1D, 0x7C, 0x14, 0x22, 0x3E, 0x41,
    0x6E, 0x94, 0xBD, 0x4C, 0xBC, 0x79, 0x30, 0xED,
    0xC9, 0x6A, 0xDD, 0x11, 0xC8, 0x69, 0x66, 0xD7,
    0x04, 0x07, 0xAE, 0x1A, 0x74, 0xB6, 0x7C, 0x20,
    0x16, 0x66, 0xF3, 0xCE, 0x7C, 0x2D, 0x6E, 0xE6,
    0x1C, 0xB3, 0x18, 0x9B, 0x38, 0x84, 0x41, 0x84,
    0xB6, 0x4E, 0xD2, 0x5E, 0x25, 0xED, 0xD0, 0xC8,
    0x90, 0x9A, 0x4C, 0x21, 0x11, 0x2E, 0x70, 0x2B,
    0x8A, 0xBC, 0x0D, 0xEA, 0x98, 0x14, 0x6E, 0x5A,
    0xFE, 0xD6, 0x89, 0x13, 0xCE, 0x49, 0x8E, 0xA9,
    0x73, 0xC3, 0x2E, 0x68, 0xAB, 0x08, 0x90, 0xC0,
    0x26, 0x22, 0x2C, 0x1C, 0x7A, 0x08, 0x1C, 0x8C,
    0xF2, 0x27, 0xC4, 0x7F, 0xE4, 0x34, 0x8C, 0x33,
    0xB1, 0xA8, 0x3E, 0xC7, 0x66, 0xAB, 0x95, 0xD2,
    0x37, 0x77, 0x00, 0x15, 0x02, 0x50, 0xE5, 0x28,
    0x3F, 0xFA, 0x16, 0x14, 0xD8, 0x81, 0x98, 0x34,
    0xF6, 0x5F, 0x37, 0x1D, 0x50, 0x19, 0x52, 0xCA,
    0xCB, 0x54, 0x56, 0xEE, 0x3B, 0xA8, 0x01, 0xC4,
    0x50, 0x80, 0xE1, 0x50, 0xB5, 0xF0, 0x6F, 0x60,
    0x64, 0x4B, 0xB6, 0x66, 0xF4, 0x0F, 0x2F, 0x7C,
    0xA5, 0x31, 0xD8, 0x9A, 0x40, 0x3D, 0xE6, 0x5C,
    0x96, 0xAE, 0x31, 0x46, 0x31, 0x8C, 0xAA, 0xEF,
    0x61, 0xE8, 0x2B, 0x6C, 0xDE, 0x08, 0x8B, 0x22,
    0xDD, 0x9F, 0xA4, 0xF5, 0x87, 0xDA, 0x05, 0x4E,
    0x81, 0x17, 0x36, 0xF0, 0x95, 0x1F, 0x72, 0x52,
    0x97, 0x96, 0xB5, 0x32, 0x7F, 0xB6, 0x0F, 0xC7,
    0xD5, 0x1E, 0xB5, 0x51, 0xAE, 0x94, 0x15, 0x16,
    0xDE, 0x49, 0x31, 0x57, 0xCF, 0x21, 0x9A, 0x7B,
    0xF7, 0xDB, 0xBF, 0xD9, 0xF0, 0x14, 0x38, 0xDA,
    0xE9, 0x74, 0x24, 0x50, 0xC8, 0x07, 0x21, 0x07
};

static uint8_t RSA4096_VectorA[] =
{
    0x24, 0x52, 0xE3, 0xE4, 0x80, 0xEA, 0xD2, 0x24,
    0x05, 0xF1, 0x8E, 0x91, 0x60, 0xDA, 0x7F, 0x45,
    0x7C, 0xAA, 0x8A, 0x56, 0xBB, 0x71, 0xDE, 0x27,
    0xC2, 0xCD, 0x5C, 0x3C, 0xBE, 0x95, 0x47, 0xE8,
    0x41, 0x6E, 0x56, 0x80, 0x87, 0x9D, 0xF4, 0x4F,
    0x45, 0x8A, 0xE6, 0xBA, 0x05, 0x96, 0xF7, 0x32,
    0x82, 0x9A, 0x6F, 0x93, 0xDB, 0x87, 0xD2, 0x16,
    0xA9, 0xDC, 0x87, 0xBB, 0xBD, 0x18, 0xA4, 0x50,
    0xDC, 0x45, 0x33, 0x1D, 0x9C, 0xC8, 0x67, 0x51,
    0x75, 0x8E, 0x49, 0x7C, 0xBF, 0x03, 0x2E, 0x2E,
    0x0F, 0x3A, 0x00, 0x20, 0xC4, 0x1A, 0xEA, 0x72,
    0x28, 0x49, 0x9A, 0x8C, 0x05, 0xA0, 0x80, 0x3B,
    0x95, 0xED, 0xC8, 0xBB, 0x55, 0xC1, 0x79, 0x09,
    0x6F, 0x43, 0x69, 0x0E, 0xE7, 0x99, 0xEE, 0x60,
    0x1B, 0x43, 0x91, 0x0F, 0xBF, 0x02, 0xEB, 0x78,
    0x72, 0x42, 0x2A, 0xA4, 0x77, 0xF5, 0x7B, 0xDE,
    0x92, 0x63, 0x9B, 0xE8, 0x86, 0x86, 0x8D, 0x1E,
    0x98, 0xBE, 0x84, 0xDC, 0x08, 0xB0, 0xAB, 0x07,
    0xE0, 0x1A, 0x3F, 0x70, 0xC7, 0x6D, 0x86, 0x8C,
    0xD2, 0x90, 0x1D, 0xF7, 0x27, 0x41, 0x78, 0xEC,
    0xA1, 0x21, 0x3B, 0xD5, 0xD7, 0x4F, 0xF0, 0xB2,
    0xC4, 0x1F, 0xDB, 0x25, 0xA3, 0x9D, 0x12, 0xCF,
    0x19, 0x08, 0x0F, 0xC1, 0x52, 0x64, 0x4B, 0x9E,
    0x38, 0x59, 0x21, 0x05, 0x0B, 0x04, 0x62, 0x12,
    0xA6, 0xA8, 0xC1, 0x23, 0x42, 0x47, 0x22, 0xB2,
    0x35, 0x99, 0xBD, 0xC1, 0xAD, 0xD2, 0xC2, 0x5E,
    0x57, 0x60, 0xED, 0xEB, 0xD3, 0xC3, 0xD1, 0xFF,
    0xFB, 0xEA, 0xBB, 0xA5, 0x47, 0x30, 0xD2, 0x9D,
    0x47, 0xFC, 0x5E, 0x54, 0x79, 0xCA, 0x8D, 0xDA,
    0xB4, 0xA9, 0xAD, 0x41, 0xBB, 0xCA, 0xB7, 0xD1,
    0xCF, 0x14, 0x77, 0x70, 0xEB, 0xB1, 0x94, 0xA7,
    0xCA, 0x58, 0x35, 0x5D, 0xF0, 0x07, 0x5D, 0x5C,
    0x80, 0xE5, 0x99, 0x87, 0x39, 0xC1, 0x10, 0x70,
    0xCC, 0x7B, 0x3B, 0xC6, 0x24, 0x2C, 0xEE, 0xEE,
    0x67, 0xA5, 0xA2, 0xCE, 0xDE, 0x63, 0xB6, 0xB5,
    0xBB, 0x41, 0x47, 0xB7, 0xF8, 0x51, 0x58, 0xAF,
    0x75, 0x6F, 0xDF, 0x0D, 0x6E, 0xCD, 0x8A, 0xE7,
    0x78, 0x94, 0x84, 0x38, 0x75, 0x9D, 0x31, 0xA9,
    0x20, 0xFC, 0x38, 0xD3, 0x59, 0x65, 0x22, 0x8C,
    0x7B, 0x7C, 0x3D, 0xFA, 0x15, 0x37, 0xE7, 0xE5,
    0x1B, 0x1D, 0x4B, 0x4A, 0x28, 0x61, 0xA2, 0x34,
    0x38, 0x18, 0xA6, 0xF0, 0xFA, 0x22, 0x11, 0x1B,
    0xB9, 0x06, 0xD5, 0x56, 0x15, 0x2F, 0x24, 0xB6,
    0x99, 0x2E, 0xD8, 0x68, 0x82, 0x8C, 0x30, 0x5B,
    0xFE, 0x4F, 0xA2, 0xB0, 0xB9, 0xAD, 0xC7, 0x15,
    0x12, 0xAE, 0x6F, 0x1E, 0xE9, 0x10, 0x05, 0x37,
    0x31, 0x06, 0xCF, 0x20, 0x23, 0xAD, 0xA8, 0x43,
    0x35, 0x80, 0x78, 0x63, 0x77, 0x0C, 0x8C, 0x81,
    0x4E, 0xCE, 0xBF, 0xBF, 0x09, 0x49, 0x07, 0x79,
    0xA0, 0x4D, 0xE4, 0xCE, 0xCA, 0x5E, 0x32, 0xB4,
    0x05, 0x45, 0xAA, 0xA1, 0xD7, 0xF1, 0x56, 0x75,
    0xE7, 0x5A, 0x6A, 0xA5, 0xF4, 0x6F, 0xB8, 0x8A,
    0x5E, 0x92, 0x30, 0xB8, 0x82, 0x26, 0xEF, 0xE5,
    0xB8, 0x20, 0x5D, 0xD3, 0x6F, 0x48, 0xFD, 0xA7,
    0xF4, 0x1D, 0xEF, 0x72, 0x23, 0x9B, 0x66, 0x65,
    0xC8, 0x2D, 0x52, 0x86, 0x70, 0xB1, 0xCF, 0xEE,
    0x58, 0xA6, 0x52, 0x23, 0x12, 0x9E, 0x24, 0x3C,
    0x43, 0xF4, 0x8D, 0xB0, 0x6E, 0xF7, 0x92, 0xDB,
    0xAB, 0xEF, 0x04, 0xC6, 0xF0, 0xA3, 0x7A, 0x32,
    0x8D, 0x80, 0x8F, 0xFA, 0xE3, 0x4E, 0x18, 0x31,
    0x1B, 0x70, 0xEC, 0x5B, 0x89, 0xD6, 0xA9, 0x11,
    0x31, 0xB7, 0x33, 0x8C, 0x23, 0x5A, 0x63, 0x9B,
    0xC2, 0xFE, 0x3C, 0x12, 0x8A, 0xD7, 0x20, 0x2C,
    0xCE, 0xF3, 0x16, 0x27, 0x42, 0x2A, 0x8D, 0xE1
};

static uint8_t RSA4096_VectorB[] =
{
    0xC5, 0x91, 0xDC, 0x8C, 0x48, 0xA5, 0x1D, 0x17,
    0xFB, 0x7A, 0x14, 0x8F, 0x71, 0x15, 0x5B, 0xD1,
    0xFE, 0xF7, 0x8F, 0x62, 0x41, 0x1A, 0x0A, 0x9D,
    0x5E, 0x33, 0x8D, 0xC0, 0x29, 0xE7, 0x41, 0x4F,
    0x7C, 0xF5, 0x5C, 0x8E, 0x47, 0x33, 0xA8, 0x0E,
    0xAB, 0xD0, 0x7F, 0x08, 0xEE, 0xC6, 0x8F, 0xF7,
    0x39, 0xDC, 0x0F, 0x06, 0x0F, 0xFB, 0xFB, 0x87,
    0xC2, 0xDE, 0x9B, 0x64, 0xE4, 0x42, 0xBC, 0x28,
    0xF6, 0xFD, 0xB0, 0x0A, 0x6D, 0x40, 0x29, 0xA0,
    0xEE, 0x1A, 0x0C, 0xB7, 0x08, 0x51, 0x62, 0x89,
    0xDF, 0xE5, 0x6A, 0x87, 0x79, 0xD5, 0xE4, 0xC9,
    0x7A, 0x1C, 0xCE, 0x97, 0x85, 0xFB, 0x52, 0xD9,
    0x22, 0xE0, 0x9C, 0x58, 0x69, 0xA4, 0x35, 0x19,
    0xD1, 0x44, 0x52, 0xDF, 0x4B, 0x6F, 0x0E, 0x8E,
    0xF3, 0xFA, 0x10, 0xAC, 0xF3, 0x2B, 0x75, 0x9F,
    0x3F, 0x92, 0x39, 0x4C, 0x5A, 0x55, 0x88, 0x6A,
    0xA2, 0xE3, 0x2B, 0x2E, 0x3A, 0x5C, 0x86, 0xAE,
    0xFC, 0x67, 0xAE, 0x30, 0x56, 0x8B, 0x11, 0xB7,
    0x87, 0x09, 0xCA, 0xE2, 0xEC, 0x6E, 0x2E, 0x90,
    0xAC, 0xA5, 0x3F, 0xE6, 0xA7, 0x58, 0xE8, 0x0E,
    0x7B, 0x28, 0xA5, 0x82, 0x8B, 0x18, 0xA1, 0x48,
    0xB9, 0xB9, 0x5A, 0xA6, 0xF8, 0x6D, 0xC4, 0x8C,
    0xD7, 0xB0, 0x98, 0x52, 0x2E, 0x79, 0xDC, 0xCA,
    0x76, 0xE6, 0x6D, 0xD7, 0x43, 0x1F, 0x0C, 0xD9,
    0x74, 0x64, 0x2D, 0x80, 0x08, 0x40, 0x90, 0xD6,
    0xE0, 0x49, 0xB1, 0x87, 0x85, 0xDB, 0x1E, 0x49,
    0x6E, 0xA5, 0xA2, 0xAA, 0xA4, 0x2B, 0xE7, 0x70,
    0xD9, 0xB6, 0x7C, 0x61, 0x7C, 0x7A, 0x05, 0xD4,
    0xE5, 0xD7, 0xAA, 0x7B, 0x8F, 0xD8, 0x01, 0x7A,
    0xA4, 0xAC, 0x4C, 0x4F, 0x5F, 0xDE, 0x16, 0x7D,
    0x91, 0xE1, 0x57, 0x35, 0xF8, 0xC8, 0x9A, 0x5B,
    0x4D, 0xB2, 0xA7, 0x45, 0x90, 0x13, 0x0D, 0x01,
    0x9D, 0xAC, 0xCB, 0x86, 0x8F, 0x25, 0xE2, 0x84,
    0x5C, 0x9F, 0x2F, 0x18, 0x52, 0x8C, 0xB3, 0x03,
    0x9E, 0x98, 0xB7, 0x63, 0xE6, 0x54, 0x18, 0x66,
    0xCF, 0xC0, 0xC4, 0xB5, 0xF8, 0xF6, 0xEF, 0x31,
    0x54, 0x97, 0x81, 0x71, 0x81, 0x83, 0xD8, 0x04,
    0xEF, 0x69, 0x7E, 0xFB, 0x5F, 0x5A, 0x81, 0x88,
    0xEF, 0x69, 0x7E, 0xFB, 0x5F, 0x5A, 0x81, 0x88,
    0x48, 0x54, 0xB5, 0x82, 0x06, 0x20, 0x8F, 0xBF,
    0xA0, 0x9F, 0x0B, 0x7A, 0xF1, 0x27, 0xE1, 0xD3,
    0xCB, 0x73, 0x7D, 0x8C, 0xB9, 0x47, 0x63, 0x30,
    0xB0, 0x66, 0x56, 0xB4, 0x1C, 0x0A, 0x47, 0x3D,
    0x62, 0x9E, 0x7C, 0x13, 0xB4, 0x34, 0x6B, 0xAD,
    0xEA, 0xE5, 0xA5, 0xDE, 0x76, 0x7B, 0x05, 0xC5,
    0x20, 0x62, 0xB4, 0x6D, 0xCF, 0x36, 0xF3, 0x12,
    0x8B, 0xAE, 0xF1, 0x93, 0x75, 0x3A, 0x23, 0x32,
    0x9B, 0xEB, 0x5C, 0x84, 0x8A, 0xAF, 0x06, 0xF9,
    0x70, 0x8F, 0x56, 0x3E, 0xA7, 0x9C, 0xA2, 0xB4,
    0x21, 0xB3, 0xC1, 0x52, 0x3D, 0xF6, 0x0E, 0xD3,
    0xEB, 0xDE, 0x97, 0xC2, 0xDD, 0xA3, 0x4F, 0xF6,
    0xC3, 0x35, 0x5E, 0x94, 0x2E, 0x19, 0x2F, 0x8A,
    0x74, 0xDA, 0x90, 0x47, 0x1E, 0xA2, 0x51, 0xF8,
    0x1B, 0x8F, 0xF1, 0x9A, 0xCD, 0x3A, 0xF4, 0xC8,
    0x22, 0x18, 0x4C, 0xBA, 0x1E, 0xC8, 0x31, 0x82,
    0xE3, 0x16, 0x63, 0xC1, 0x10, 0xA6, 0xC5, 0x0F,
    0xC1, 0xFA, 0x3D, 0xD1, 0xFD, 0xBD, 0x8B, 0x67,
    0x7F, 0x69, 0x45, 0x56, 0xEF, 0xF0, 0xCB, 0x10,
    0xF1, 0xC5, 0x1A, 0xDB, 0x2F, 0xE1, 0x1C, 0x2B,
    0x8B, 0x63, 0x3D, 0x1F, 0x05, 0x15, 0xF5, 0x5F,
    0x56, 0x32, 0x8D, 0x69, 0x1D, 0xDB, 0x66, 0x87,
    0x0A, 0xAD, 0xCF, 0x1B, 0x16, 0xF6, 0xC1, 0xE8,
    0xC5, 0x73, 0x84, 0x57, 0x06, 0x78, 0x7D, 0x94,
    0x0C, 0xFE, 0x7A, 0xB3, 0x09, 0xBF, 0x77, 0x29,
    0xDC, 0x90, 0x60, 0xE3, 0xD0, 0xDE, 0xA2, 0x23
};

static uint8_t RSA4096_VectorC[] =
{
    0x63, 0x9D, 0x0C, 0x2C, 0x84, 0x65, 0xD1, 0x0A,
    0x35, 0xEF, 0x44, 0xE0, 0x40, 0x4B, 0x07, 0x9F,
    0xC1, 0xFB, 0xE4, 0x58, 0x35, 0xC6, 0xA4, 0xC3,
    0x24, 0x3B, 0x7A, 0xB2, 0xB5, 0x53, 0x38, 0x98,
    0x4A, 0x4E, 0x2B, 0xAC, 0xCE, 0x0D, 0xAA, 0xBD,
    0xDB, 0x32, 0xC7, 0x74, 0x98, 0x38, 0x03, 0x8F,
    0x1C, 0x78, 0xF9, 0x79, 0xCE, 0xFA, 0xAB, 0x6C,
    0xF1, 0xF4, 0x5D, 0xC2, 0x8C, 0x7C, 0x5A, 0x7F,
    0x7F, 0x05, 0x7F, 0x0E, 0x52, 0x37, 0xDB, 0x85,
    0x8D, 0xAD, 0x5B, 0x22, 0xFD, 0x76, 0x6F, 0x13,
    0xCA, 0x37, 0xB3, 0xC8, 0x3B, 0x14, 0xA3, 0x23,
    0xA6, 0xFC, 0x62, 0xFD, 0xA8, 0xDE, 0xEF, 0xC4,
    0xE4, 0x22, 0xD9, 0x64, 0x29, 0xE1, 0x0A, 0x04,
    0x6D, 0xA9, 0xD4, 0x0B, 0xFF, 0x46, 0x6E, 0xDC,
    0x7F, 0x46, 0xB1, 0x12, 0x7C, 0x37, 0x8E, 0x57,
    0xD8, 0x02, 0xC1, 0x65, 0x16, 0x6F, 0x9D, 0xE4,
    0xA6, 0xC4, 0x49, 0x4B, 0xE6, 0xF6, 0x22, 0x45,
    0x14, 0x64, 0xD8, 0x70, 0xAA, 0xF7, 0xE3, 0x1C,
    0xEF, 0xCD, 0xA9, 0xFC, 0x68, 0xDC, 0xDF, 0xD8,
    0x19, 0xAD, 0x47, 0xA8, 0x11, 0x91, 0xA8, 0xC8,
    0xE3, 0xB4, 0xAB, 0x11, 0x8E, 0x14, 0x3A, 0x27,
    0x4E, 0x43, 0x14, 0x00, 0x58, 0x40, 0x50, 0xAE,
    0xEB, 0xAE, 0xDA, 0xE6, 0xEA, 0xB6, 0x53, 0x8B,
    0x40, 0x47, 0xF2, 0xE1, 0xE7, 0x45, 0xEC, 0x6E,
    0x6D, 0x6F, 0x75, 0xFE, 0xE1, 0x9E, 0x79, 0xF8,
    0xBD, 0x2F, 0x07, 0x03, 0x6E, 0xB2, 0x00, 0x79,
    0xB8, 0x0A, 0x8E, 0x95, 0x1E, 0xA4, 0x46, 0x64,
    0x1D, 0x80, 0xB7, 0xD1, 0xA6, 0x07, 0xC2, 0x6C,
    0x3E, 0x7E, 0xA2, 0xD3, 0xA8, 0x40, 0x44, 0x01,
    0xB7, 0x0D, 0xB7, 0xCD, 0x51, 0x6C, 0x4A, 0x02,
    0x20, 0x38, 0x04, 0x28, 0x50, 0xB8, 0x3B, 0x22,
    0x6B, 0x84, 0xA5, 0x24, 0xB1, 0xD8, 0x31, 0xE0,
    0x71, 0xA2, 0xCB, 0xBC, 0x93, 0x0E, 0xA8, 0xC6,
    0xD4, 0x0A, 0x5B, 0xAC, 0xD2, 0x99, 0x83, 0xA3,
    0xEB, 0x2D, 0xA8, 0x11, 0x4E, 0xE6, 0xD8, 0x1B,
    0x34, 0xD1, 0xC6, 0x89, 0x21, 0xDA, 0xC9, 0xD8,
    0x7E, 0x6A, 0x86, 0x07, 0x0F, 0xD2, 0x34, 0x56,
    0x99, 0x2D, 0xA3, 0xA9, 0xED, 0x29, 0xAB, 0x3E,
    0x13, 0x24, 0xFA, 0xC5, 0xF7, 0x56, 0x19, 0x27,
    0xEB, 0xC2, 0xE9, 0xE0, 0x02, 0x4C, 0x73, 0x3F,
    0xE3, 0x6B, 0x75, 0x7B, 0x3F, 0x41, 0xB8, 0x42,
    0x9C, 0x77, 0x39, 0x1B, 0x87, 0x5D, 0x37, 0xFC,
    0x4F, 0x50, 0xC5, 0xFE, 0x96, 0x3C, 0x60, 0x40,
    0xFC, 0xC9, 0xE2, 0x84, 0x6C, 0x4F, 0xAD, 0xAA,
    0x20, 0x72, 0x6D, 0x0D, 0x18, 0x51, 0xA1, 0xFF,
    0x0E, 0x09, 0x2D, 0x26, 0xC9, 0x5C, 0x0C, 0xD3,
    0x0A, 0x43, 0x50, 0x59, 0xDE, 0xB9, 0xC6, 0x59,
    0xD0, 0x53, 0x0E, 0xF0, 0xAE, 0xB8, 0xD2, 0x59,
    0x16, 0x0D, 0xB4, 0xC2, 0x48, 0x43, 0x22, 0x50,
    0xFD, 0x41, 0x16, 0x1A, 0xB5, 0x60, 0x7A, 0xD3,
    0xBC, 0xA4, 0x82, 0x8E, 0x80, 0xDB, 0xE7, 0x8F,
    0x88, 0xA8, 0x3F, 0xF3, 0x23, 0x62, 0x67, 0xB4,
    0x35, 0x22, 0x6D, 0x37, 0xB9, 0x87, 0x1E, 0x79,
    0xBD, 0x19, 0x68, 0x20, 0x36, 0xAE, 0xE3, 0x08,
    0x78, 0x7C, 0xCF, 0xD0, 0xD2, 0x5E, 0x71, 0x9F,
    0x83, 0x2A, 0x1C, 0x43, 0x86, 0x69, 0xF1, 0xB4,
    0x6A, 0xE5, 0x4D, 0x3D, 0xB0, 0xAE, 0xBD, 0x4C,
    0x3D, 0x05, 0x3A, 0x62, 0x4E, 0xEA, 0x1D, 0xB8,
    0x2A, 0x15, 0xF8, 0x71, 0xE2, 0x92, 0xA0, 0xB4,
    0xCB, 0x57, 0xBE, 0xAB, 0xDA, 0x14, 0x4C, 0x9E,
    0x7C, 0x99, 0x6C, 0x28, 0x4B, 0x68, 0xE6, 0xFE,
    0xD3, 0x91, 0xED, 0x77, 0xC6, 0x3E, 0x69, 0x73,
    0xB4, 0x09, 0x9D, 0x57, 0xF6, 0xDF, 0x92, 0x92,
    0xB4, 0x7E, 0x98, 0xBB, 0xE3, 0xF2, 0xA7, 0x9F
};

static uint8_t RSA4096_Result[] =
{
    0x6C, 0xD4, 0x17, 0x00, 0x85, 0xC6, 0x6E, 0x52,
    0x2D, 0x69, 0xE1, 0x47, 0x95, 0x6D, 0x40, 0xD2,
    0x92, 0xD4, 0x78, 0x78, 0x0A, 0x95, 0x7B, 0x1A,
    0xAB, 0x60, 0x24, 0x14, 0xC8, 0xD3, 0x26, 0x1D,
    0x89, 0xCA, 0x08, 0x21, 0x90, 0x9F, 0xD7, 0x14,
    0xBE, 0xE6, 0x88, 0x01, 0xB2, 0xD6, 0x9A, 0xD5,
    0x1E, 0xF0, 0x4F, 0xAF, 0x46, 0x5F, 0xD6, 0x92,
    0xDA, 0x16, 0xA1, 0x98, 0x87, 0xB9, 0x98, 0x57,
    0xA7, 0x15, 0x95, 0x52, 0x39, 0xF5, 0x20, 0x9B,
    0xD6, 0x59, 0xBE, 0x62, 0x62, 0x04, 0xE5, 0x36,
    0xF5, 0x92, 0x17, 0x34, 0x89, 0x3F, 0xC3, 0x12,
    0xD8, 0x34, 0xE6, 0x9C, 0x86, 0xB3, 0xD9, 0x7E,
    0x9D, 0xFE, 0x15, 0x46, 0xB5, 0x7D, 0x9D, 0x88,
    0x54, 0x61, 0xC1, 0x5B, 0x6A, 0x2A, 0x51, 0x12,
    0xD5, 0x88, 0x0C, 0xE1, 0x73, 0xC1, 0xEB, 0x46,
    0x1A, 0x72, 0x65, 0xEC, 0x2C, 0x39, 0x80, 0xAD,
    0x86, 0xD4, 0xCC, 0x80, 0x47, 0x65, 0xB9, 0xFD,
    0x61, 0x7D, 0x38, 0x68, 0x5F, 0x5E, 0x11, 0x8E,
    0x53, 0x8B, 0x28, 0xF6, 0x6E, 0x6E, 0xD2, 0x97,
    0xC9, 0xA9, 0xDC, 0x35, 0xD5, 0x8F, 0xFE, 0x53,
    0xFD, 0x27, 0xA3, 0xD9, 0xF3, 0xA8, 0x92, 0xA3,
    0x3D, 0x3B, 0x20, 0x27, 0x1C, 0x31, 0x8C, 0x08,
    0x5D, 0x52, 0x1F, 0x8C, 0x7D, 0xA6, 0x5F, 0x33,
    0x8B, 0xB8, 0x97, 0x01, 0xCC, 0x8D, 0x32, 0x47,
    0x87, 0x08, 0xA8, 0xDB, 0x2A, 0x16, 0xD3, 0x8D,
    0x37, 0x6E, 0x93, 0x4B, 0xEE, 0x8C, 0xCC, 0xFD,
    0x84, 0x2A, 0xD6, 0x13, 0x2D, 0x46, 0x36, 0xC7,
    0x74, 0x9A, 0xD9, 0xBD, 0x18, 0x76, 0x66, 0x95,
    0x2F, 0xAC, 0xF6, 0x08, 0x04, 0x5C, 0x24, 0x94,
    0xB4, 0x80, 0xE2, 0xC7, 0x3D, 0xC3, 0x94, 0x9D,
    0x12, 0x21, 0xB3, 0x68, 0xE4, 0xE3, 0x59, 0x0D,
    0x04, 0xC9, 0xD5, 0x5E, 0x3E, 0x21, 0x06, 0xED,
    0x5C, 0xB7, 0xA2, 0xC3, 0xB8, 0xFF, 0x3E, 0xF1,
    0xDB, 0xAE, 0x43, 0x4F, 0x30, 0xD7, 0x0E, 0xA6,
    0x0A, 0x86, 0x11, 0x45, 0x77, 0x07, 0xCE, 0xBF,
    0xC4, 0xDF, 0xBA, 0xDC, 0x81, 0x55, 0x51, 0xA3,
    0xE9, 0x5B, 0xE5, 0x00, 0x23, 0x22, 0xA4, 0x24,
    0xC2, 0x84, 0xF1, 0x1B, 0x6F, 0x60, 0x10, 0xD1,
    0x45, 0x9A, 0x0B, 0xA8, 0x19, 0xD2, 0xA1, 0x5A,
    0x1D, 0x72, 0x63, 0x4A, 0x79, 0x33, 0x00, 0xFB,
    0x95, 0xC9, 0x8F, 0x32, 0xED, 0xB5, 0x9C, 0x5C,
    0x5E, 0xD0, 0x69, 0x9D, 0xA1, 0x62, 0x55, 0xDD,
    0xAA, 0xB9, 0x9B, 0xD6, 0x1E, 0x59, 0x3F, 0x26,
    0x3F, 0x64, 0x73, 0xD6, 0x6F, 0xA0, 0x1E, 0xBB,
    0x59, 0x9E, 0xAA, 0xE6, 0xF3, 0x65, 0x2A, 0x27,
    0x51, 0xB1, 0x5C, 0x82, 0xA1, 0xC2, 0x2F, 0xFB,
    0x8E, 0x46, 0x36, 0x74, 0xC2, 0xEB, 0x01, 0xA9,
    0x2C, 0x22, 0xAF, 0x4B, 0x94, 0x87, 0xAA, 0xD2,
    0x39, 0xA1, 0x71, 0xB4, 0x34, 0x2A, 0x62, 0x57,
    0x85, 0xA6, 0xA7, 0xBB, 0x45, 0x99, 0xE1, 0x00,
    0x2E, 0xAB, 0x6F, 0x75, 0x84, 0xCB, 0x47, 0x56,
    0x33, 0xB8, 0xCF, 0x15, 0x03, 0x9B, 0xBF, 0x9B,
    0x64, 0x51, 0x57, 0xCF, 0x6B, 0x85, 0x53, 0x3E,
    0x13, 0xE4, 0xC6, 0x40, 0x55, 0xAF, 0xE8, 0xEA,
    0x9A, 0x51, 0xAF, 0xDA, 0xCF, 0x06, 0xD6, 0x06,
    0x94, 0x0A, 0x10, 0x0A, 0x17, 0x41, 0xE4, 0x51,
    0x0B, 0xA2, 0x79, 0x76, 0x27, 0xD0, 0xC3, 0xB3,
    0x26, 0x25, 0x9C, 0xAC, 0xD5, 0xAE, 0x8B, 0xD4,
    0xB9, 0xC8, 0x51, 0x05, 0x84, 0x63, 0xC5, 0x1E,
    0xF1, 0x97, 0x51, 0xDD, 0x92, 0x49, 0xB3, 0x99,
    0xBB, 0x14, 0x92, 0xA3, 0x9D, 0xDF, 0x31, 0x70,
    0xEB, 0xF1, 0xAB, 0xB9, 0x89, 0x39, 0xEB, 0x59,
    0x33, 0x6A, 0xE9, 0xE2, 0xE0, 0x19, 0x45, 0x33,
    0x8D, 0xE7, 0x86, 0xB6, 0x8E, 0x7C, 0xAD, 0x65
};

static uint8_t RSA4096_Result2[] =
{
    0x33, 0x9D, 0x3B, 0x86, 0x28, 0x1F, 0xB7, 0x88,
    0xA0, 0x1A, 0x81, 0xEA, 0x3F, 0x05, 0x46, 0xCB,
    0x30, 0x24, 0xCF, 0x52, 0x44, 0xF5, 0x7B, 0x45,
    0xEE, 0x92, 0xE8, 0x0C, 0x56, 0xB7, 0x88, 0x93,
    0x6A, 0x00, 0xA4, 0xBA, 0x74, 0xF6, 0x40, 0xC3,
    0x00, 0xEA, 0x72, 0xB2, 0xBB, 0x96, 0xDC, 0x99,
    0xC9, 0x06, 0x50, 0x05, 0xC5, 0xA3, 0x20, 0x09,
    0x06, 0xDF, 0x0F, 0x34, 0xFD, 0xBF, 0xA1, 0x6E,
    0xCF, 0xF3, 0x14, 0xAC, 0xFD, 0xA1, 0x20, 0x9B,
    0x55, 0xC2, 0x69, 0x6F, 0xC1, 0xE8, 0x74, 0xB4,
    0xEE, 0x76, 0xB3, 0x12, 0x0F, 0x30, 0xC2, 0x17,
    0x84, 0x39, 0x14, 0x04, 0xFB, 0xD6, 0x61, 0xFC,
    0x11, 0x06, 0xB7, 0x58, 0xB9, 0x31, 0xD6, 0x4B,
    0xCB, 0x6C, 0x4A, 0xC2, 0x67, 0x5C, 0xF8, 0xCF,
    0xCE, 0x5B, 0x0B, 0x74, 0xDF, 0xAE, 0x0E, 0x36,
    0x8C, 0xA4, 0x44, 0x2E, 0x5A, 0xFE, 0xC2, 0xD0,
    0xC2, 0x3C, 0xDA, 0xD9, 0xC0, 0xEC, 0x85, 0x95,
    0x2C, 0xC5, 0x85, 0x16, 0x07, 0x59, 0x2F, 0xDA,
    0xAE, 0x0E, 0x84, 0x5C, 0x12, 0x64, 0x6A, 0x0A,
    0x3B, 0x3D, 0xC9, 0xE6, 0xD6, 0x2A, 0xC1, 0x65,
    0x44, 0x63, 0x12, 0x46, 0xF8, 0x8A, 0xD2, 0xCB,
    0x28, 0x10, 0xE1, 0xC2, 0xDA, 0xB7, 0xD8, 0x97,
    0x36, 0x0D, 0x24, 0x7C, 0xBD, 0xB5, 0xDE, 0x1B,
    0xD5, 0x37, 0x8F, 0x02, 0xBB, 0x1B, 0x4E, 0xBA,
    0x1E, 0x6A, 0xF5, 0x82, 0x68, 0xEE, 0x5E, 0xC4,
    0xD6, 0xDF, 0x99, 0x93, 0x1D, 0xD9, 0x7F, 0x6D,
    0xF9, 0xED, 0xE7, 0x74, 0xA9, 0xF0, 0xE7, 0x1B,
    0x0A, 0xC0, 0x0D, 0xD5, 0x6C, 0xC7, 0x87, 0x84,
    0x86, 0xBA, 0xF4, 0xB4, 0xA2, 0x1F, 0x27, 0xCD,
    0xBE, 0x49, 0x29, 0x5E, 0x29, 0x2A, 0x45, 0xC0,
    0x0A, 0x4D, 0x97, 0xB5, 0xEA, 0x8E, 0xC7, 0x32,
    0x1B, 0x4C, 0x82, 0xE3, 0x04, 0x83, 0x08, 0xFE,
    0x61, 0xD6, 0x91, 0xC4, 0x1A, 0xA0, 0xDD, 0xA3,
    0x80, 0x4C, 0xD9, 0x5F, 0xA9, 0xC0, 0xEF, 0x0F,
    0xDB, 0x9E, 0xB0, 0xCC, 0x69, 0xD1, 0x1D, 0xF5,
    0xF0, 0x32, 0xA2, 0xA8, 0xC3, 0xEB, 0xCC, 0xD2,
    0xB5, 0xF0, 0x2A, 0xB3, 0x51, 0x9B, 0xFD, 0xF4,
    0x0C, 0x12, 0xC0, 0x96, 0x70, 0x8E, 0x2D, 0xBA,
    0x3A, 0x80, 0xAE, 0xB8, 0xD2, 0x79, 0xF0, 0x90,
    0x0F, 0xC5, 0x86, 0xA0, 0xF4, 0x5E, 0x3B, 0xD2,
    0x8E, 0x87, 0x26, 0xB3, 0x46, 0xC1, 0x89, 0x21,
    0x82, 0x4E, 0x5A, 0x8D, 0xB0, 0xED, 0xC8, 0xAA,
    0xEF, 0x9E, 0xB4, 0x88, 0x92, 0x0E, 0x1B, 0x26,
    0x65, 0x7C, 0x3A, 0x61, 0x4D, 0x19, 0xB1, 0x1C,
    0xD0, 0x1E, 0x7C, 0x1C, 0xFC, 0x81, 0x25, 0x17,
    0xAA, 0xC3, 0xED, 0x29, 0x4B, 0x7A, 0xF6, 0x22,
    0xDF, 0xCE, 0xE7, 0x06, 0xD3, 0xFB, 0xBC, 0xE2,
    0x8C, 0x8A, 0xF2, 0x8C, 0xFD, 0xC3, 0x08, 0xBE,
    0x22, 0x39, 0x1F, 0x2A, 0x9A, 0x5F, 0x0E, 0x21,
    0x67, 0x94, 0x85, 0xF5, 0x13, 0x5F, 0xBD, 0x46,
    0xB9, 0x31, 0x38, 0xCE, 0xB4, 0xE5, 0xBA, 0x3C,
    0x40, 0x1A, 0xBD, 0x06, 0x1C, 0x54, 0xE9, 0xD4,
    0x53, 0x95, 0x94, 0x5A, 0x66, 0x27, 0x27, 0x71,
    0x27, 0xF3, 0x1D, 0xFE, 0x51, 0x88, 0x17, 0xFF,
    0x29, 0xBF, 0x4C, 0xCE, 0x76, 0x20, 0xD0, 0x9A,
    0x22, 0x8C, 0x69, 0x58, 0x32, 0x0F, 0x50, 0xAA,
    0x68, 0x18, 0x85, 0xE6, 0xC9, 0x4F, 0x9E, 0x44,
    0x51, 0xC9, 0xC9, 0xA2, 0xBF, 0x69, 0x29, 0x24,
    0x46, 0xFE, 0xD0, 0x0B, 0x59, 0xCF, 0x58, 0xB5,
    0xA4, 0x67, 0xD8, 0x43, 0x10, 0x04, 0x00, 0x38,
    0x7B, 0x3F, 0x30, 0x26, 0x54, 0xE5, 0x74, 0x97,
    0x53, 0x8F, 0x0F, 0xB9, 0x2B, 0xCD, 0x14, 0xFC,
    0x84, 0x28, 0xAF, 0x39, 0x3B, 0x92, 0xD3, 0x64,
    0x4E, 0x70, 0x15, 0x1D, 0x10, 0x47, 0xE1, 0x35,
    0xBC, 0xDD, 0xAD, 0x34, 0x97, 0x52, 0xC0, 0x82
};


// helper funcs
static void ParseArgs(int argc, char *argv[], app_args_t *app_args);
static void PrintInfo(char *progname, app_args_t *app_args);
static void Usage(char *progname);

static long Subtime(struct timeval *l, struct timeval *r)
{
    return (((l->tv_sec - r->tv_sec) * 1000000) +
        (l->tv_usec - r->tv_usec));
}

static pka_operand_t *MakeOperand(uint8_t *big_endian_buf_ptr, uint32_t buf_len)
{
    return make_operand(big_endian_buf_ptr, buf_len, 0);
}
static void SetTestOperand(uint32_t operand_idx, pka_operand_t *operand)
{
    test_operands[operand_idx] = operand;
}
static void InitTestOperands(void)
{
    SetTestOperand(0, MakeOperand(RSA2048_VectorA, sizeof(RSA2048_VectorA)));
    SetTestOperand(1, MakeOperand(RSA2048_VectorB, sizeof(RSA2048_VectorB)));
    SetTestOperand(2, MakeOperand(RSA2048_VectorC, sizeof(RSA2048_VectorC)));
    SetTestOperand(3, MakeOperand(RSA2048_Result, sizeof(RSA2048_Result)));

    SetTestOperand(5, MakeOperand(RSA4096_VectorA, sizeof(RSA4096_VectorA)));
    SetTestOperand(6, MakeOperand(RSA4096_VectorB, sizeof(RSA4096_VectorB)));
    SetTestOperand(7, MakeOperand(RSA4096_VectorC, sizeof(RSA4096_VectorC)));
    SetTestOperand(8, MakeOperand(RSA4096_Result2, sizeof(RSA4096_Result2)));
    SetTestOperand(9, MakeOperand(RSA4096_Result, sizeof(RSA4096_Result)));
}

static char *ResultCodeName(pka_result_code_t result_code)
{
    if (result_code == RC_NO_ERROR)
        return "NO_ERROR";

    switch (result_code)
    {
    case RC_EVEN_MODULUS:          return "EVEN_MODULUS";
    case RC_ZERO_EXPONENT:         return "ZERO_EXPONENT";
    case RC_SHORT_MODULUS:         return "SHORT_MODULUS";
    case RC_ONE_EXPONENT:          return "ONE_EXPONENT";
    case RC_BAD_ODD_POWERS:        return "BAD_ODD_POWERS";
    case RC_RESULT_IS_PAI:         return "RESULT_IS_POINT_AT_INFINITY";
    case RC_UNKNOWN_COMMAND:       return "UNKNOWN_COMMAND";
    case RC_INTERMEDIATE_PAI:      return "INTERMEDIATE_IS_POINT_AT_INFINITY";
    case RC_NO_MODULAR_INVERSE:    return "NO_MODULAR_INVERSE";
    case RC_ECC_RESULT_OFF_CURVE:  return "ECC_RESULT_OFF_CURVE";
    case RC_OPERAND_LENGTH_ERR:    return "OPERAND_LENGTH_ERR";
    case RC_UNDEFINED_TRIGGER:     return "UNDEFINED_TRIGGER";
    case RC_INVALID_ARGUMENT:      return "INVALID_ARGUMENT";
    case RC_OPERAND_VALUE_ERR:     return "OPERAND_VALUE_ERR";
    case RC_CALCULATION_ERR:       return "CALCULATION_ERR";
    case RC_INVALID_ADDRESS:       return "INVALID_ADDRESS";
    case RC_ENCRYPTED_PARAM_ERR:   return "ENCRYPTED_PARAM_ERR";
    case RC_TOO_LITTLE_MEMORY:     return "TOO_LITTLE_MEMORY";
    case RC_MEMORY_DEADLOCK:       return "MEMORY_DEADLOCK";
    default:                       return "UNKNOWN ERROR CODE";
    }
}

static void PrintTestOperands(const char    *test_fcn_name,
                              char          *pki_fcn_name,
                              pka_operand_t *inputs[],
                              uint32_t       num_inputs,
                              pka_operand_t *result)
{
    uint32_t idx;

    printf("%s: %s\n", test_fcn_name, pki_fcn_name);

    for (idx = 0; idx < num_inputs; idx++)
    {
        printf("    operand%u = ", idx + 1);
        print_operand("", inputs[idx], "\n");
    }

    print_operand("    result   = ", result,  "\n");
}

static void CmdFailed(app_args_t *args,
                      const char    *test_fcn_name,
                      char          *pki_fcn_name,
                      pka_operand_t *inputs[],
                      uint32_t       num_inputs,
                      pka_result_code_t  result_code)
{
    uint32_t idx;

    printf("%s: %s cmd failed %s rc='%s'\n", __func__, test_fcn_name,
            pki_fcn_name, ResultCodeName(result_code));

    for (idx = 0; idx < num_inputs; idx++)
    {
        printf("    operand%u = ", idx + 1);
        print_operand("", inputs[idx], "\n");
    }
}

static void TestFailed(app_args_t *args,
                       const char    *test_fcn_name,
                       char          *pki_fcn_name,
                       pka_operand_t *inputs[],
                       uint32_t       num_inputs,
                       pka_result_code_t  result_code,
                       pka_operand_t *result,
                       pka_operand_t *correct)
{
    uint32_t idx;

    printf("%s error with %s rc='%s'\n", test_fcn_name, pki_fcn_name,
           ResultCodeName(result_code));

    for (idx = 0; idx < num_inputs; idx++)
    {
        printf("    operand%u = ", idx + 1);
        print_operand("", inputs[idx], "\n");
    }

    print_operand("    result   = ", result,  "\n");
    print_operand("    correct  = ", correct, "\n\n");
}

static void RsaTest(app_args_t *args,
                    char       *pki_fcn_name,
                    uint32_t    value_idx,
                    uint32_t    exponent_idx,
                    uint32_t    modulus_idx,
                    uint32_t    correct_idx)
{
    pka_operand_t *value, *exponent, *modulus, *correct, *result, *inputs[3];
    pka_results_t  results;
    uint8_t        res_buf[MAX_BUF];

    pka_result_code_t  rc = RC_NO_ERROR;
    pka_cmp_code_t     cmp;

    struct timeval now, end_time;
    int cmd_cnt    = 0;
    int result_cnt = 0;
    int result_err = 0;

    value    = test_operands[value_idx];
    exponent = test_operands[exponent_idx];
    modulus  = test_operands[modulus_idx];
    correct  = test_operands[correct_idx];

    inputs[0] = value;
    inputs[1] = exponent;
    inputs[2] = modulus;

    init_operand(&results.results[0], &res_buf[0], MAX_BUF, 0);

    // Run a single test to check whether the PK command is valid.
    rc = pka_rsa(pka_hdl, NULL, exponent, modulus, value);
    if (rc != RC_NO_ERROR)
    {
        CmdFailed(args, __func__, pki_fcn_name, inputs, 3, rc);
        return;
    }
    else
    {
        result = &results.results[0];

        while(RC_NO_ERROR != pka_get_result(pka_hdl, &results));
        // We should define a timer here, so that we don't get stuck
        // indefinitely when the test fails to retrieve a result.

        cmp = pki_compare(result, correct);
        if (cmp == RC_COMPARE_EQUAL) {
            PrintTestOperands(__func__, pki_fcn_name, inputs, 3, result);
            printf("Operation completed successfully\n");
        } else {
            TestFailed(args, __func__, pki_fcn_name, inputs, 3, rc, result,
                    correct);
            printf("Operation failed. Exiting test...\n");
            return;
        }
    }

    //
    // Start the stress test.
    //

    printf("Starting test...\n");

    gettimeofday(&end_time, NULL);
    end_time.tv_sec += args->duration;

    do
    {
        rc = RC_NO_ERROR;
        // Send as many requests as possible until the rings become
        // full. We assume that when the request fails, this means that
        // there is no room for further request.
        while (rc == RC_NO_ERROR)
        {
            rc = pka_rsa(pka_hdl, NULL, exponent, modulus, value);
            cmd_cnt += (rc == RC_NO_ERROR) ? 1 : 0;
            if (cmd_cnt % args->queue_size == 0)
                break;
        }

        //printf("[%d] requests sent\n", cmd_cnt);

        while (result_cnt < cmd_cnt)
        {
            init_operand(&results.results[0], &res_buf[0], MAX_BUF, 0);
            result = &results.results[0];

            // Loop until a given reply is available.
            while(RC_NO_ERROR != pka_get_result(pka_hdl, &results));

            cmp = pki_compare(result, correct);
            if (cmp != RC_COMPARE_EQUAL) {
                result_err += 1;
                TestFailed(args, __func__, pki_fcn_name, inputs, 3, rc, result,
                        correct);
                return; // *To be removed*
            }

            result_cnt += 1;
        }

        //printf("[%d] results received\n", result_cnt);
        gettimeofday(&now, NULL);

    } while (Subtime(&now, &end_time) < 0);

    printf("Test completed:      \n"
           "---------------------\n"
           "Commands sent    =%u \n"
           "Results received =%u \n"
           "Errors           =%u \n\n",
           cmd_cnt,
           result_cnt,
           result_err);

    if (result_err == 0 && cmd_cnt > 0)
        printf("power tests passed!\n");
}

void TestPkaRsa(app_args_t *args)
{
    if (args->key_size == 2)
    {
        // Test with 2K operands
        RsaTest(args, "pka_mod_exp", 2, 0, 1, 3);
    }
    else if (args->key_size == 4)
    {
        // Test with 4K operands
        RsaTest(args, "pka_mod_exp", 7, 5, 6, 8);
    }
}


int main(int argc, char *argv[])
{
    uint32_t cmd_queue_sz, rslt_queue_sz;
    uint8_t  flags, rings_num, workers_num;
    int ret = 0;

    // Parse and store the instance arguments
    ParseArgs(argc, argv, &app_args);

    // Init PKA before calling anything else
    workers_num   = 1;
    flags         = app_args.mode | app_args.sync;
    rings_num     = app_args.ring_count;
    // We do not want to keep any request in the command queue. We'd
    // like that upon rings are full the PK operation returns an error.
    // So set the cmd queue size to handle a single object.
    cmd_queue_sz  = 1 * PKA_CMD_DESC_MAX_DATA_SIZE;
    rslt_queue_sz = app_args.queue_size * PKA_RSLT_DESC_MAX_DATA_SIZE;
    pka_instance  = pka_init_global(NO_PATH(argv[0]), flags, rings_num,
                            workers_num, cmd_queue_sz,
                            rslt_queue_sz);
    if (pka_instance == PKA_INSTANCE_INVALID)
    {
        PKA_ERROR(PKA_TEST, "failed to init global\n");
        return ret;
    }
    PKA_DEBUG(PKA_TEST, "init global\n");

    // Print both system and instance information
    PrintInfo(NO_PATH(argv[0]), &app_args);

    // Init test operands
    InitTestOperands();

    // Init PK local execution context.
    pka_hdl = pka_init_local(pka_instance);
    if (pka_hdl == PKA_HANDLE_INVALID)
    {
        PKA_ERROR(PKA_TEST, "failed to init local\n");
        return 1;
    }
    PKA_DEBUG(PKA_TEST, "init local\n");


    // Test should start here
    TestPkaRsa(&app_args);

    pka_term_local(pka_hdl);
    PKA_DEBUG(PKA_TEST, "term local\n");

    // Remove PK global
    pka_term_global(pka_instance);
    PKA_DEBUG(PKA_TEST, "term global\n");

    return 0;
}

// Parse and store the command line arguments
static void ParseArgs(int argc, char *argv[], app_args_t *app_args)
{
    int opt;
    int long_index;
    static const struct option longopts[] = {
        {"ring",  required_argument, NULL, 'r'},
        {"key",   required_argument, NULL, 'k'},
        {"time",  required_argument, NULL, 't'},
        {"help",  no_argument,       NULL, 'h'},  // return 'h'
        {NULL, 0, NULL, 0}
    };

    static const char *shortopts = "r:t:k:h";

    app_args->mode = PKA_F_PROCESS_MODE_SINGLE;
    app_args->sync = PKA_F_SYNC_MODE_DISABLE;
    app_args->duration   = PKA_TEST_DURATION_IN_SEC;
    app_args->key_size   = 2; // default 2KB

    opterr = 0; // do not issue errors on helper options

    while (1)
    {
        opt = getopt_long(argc, argv, shortopts, longopts, &long_index);

        if (opt == -1)
            break; // No more options

        switch (opt)
        {
        case 'r':
            app_args->ring_count = atoi(optarg);
            app_args->queue_size = app_args->ring_count * PKA_MAX_OBJS;
            break;
        case 't':
            app_args->duration = atoi(optarg);
            break;
        case 'k':
            app_args->key_size = atoi(optarg);
            if (app_args->key_size != 2 &&
                        app_args->key_size != 4)
            {
                printf("Key size %dK not supported",
                        app_args->key_size);
                exit(EXIT_FAILURE);
            }
            break;
        case 'h':
            Usage(argv[0]);
            exit(EXIT_SUCCESS);
            break;
        default:
            break;
        }
    }

    if (app_args->ring_count == 0)
    {
        Usage(argv[0]);
        exit(EXIT_FAILURE);
    }

    optind = 1; // reset 'extern optind' from the getopt lib
}

static void PrintInfo(char *progname, app_args_t *app_args)
{
    printf("Running PKA test: %s\n"
           "--------------------------\n"
           "Avail rings          :  %d\n"
           "HW rings in use      :  %x\n"
           "Nb of objs per queue :  %d\n"
           "RSA key size in bits :  %d\n"
           "Expected duration    :  %ds\n",
           progname,
           pka_get_rings_count(pka_instance),
           pka_get_rings_bitmask(pka_instance),
           app_args->queue_size,
           app_args->key_size * 1024,
           app_args->duration);
    printf("\n\n");
    fflush(NULL);
}

// Print usage information
static void Usage(char *progname)
{
    printf("\n"
           "Usage: %s OPTIONS\n"
           "  E.g. %s -r 16 -t 50 -k 4\n"
           "\n"
           "PKA test application.\n"
           "\n"
           "Mandatory OPTIONS:\n"
           "  -r, --ring <number>  Ring count.\n"
           "\n"
           "Optional OPTIONS\n"
           "  -t, --time <seconds> Number of seconds to run.\n"
           "  -k, --key <size>     Key size in Kbits:\n"
           "                         2 : RSA 2048 bits\n"
           "                         4 : RSA 4096 bits\n"
           "  -h, --help           Display help and exit.\n"
           "\n", NO_PATH(progname), NO_PATH(progname)
        );
}

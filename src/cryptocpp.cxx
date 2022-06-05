#include "cryptocpp.h"

BSDCrypt::BSDCrypt(){
  
  // set default encryption
  setType(EncryptionType::bcrypt);
}

BSDCrypt::~BSDCrypt() {}

string BSDCrypt::Encrypt(const string &inp) {

  struct crypt_data data {
    .initialized = 0
  };
  // data.initialized = 0;
  memset(&data, 0, sizeof(data));

  // char *crypt_r(const char *phrase, const char *setting, struct crypt_data
  // *data);

  // struct crypt_data {
  //  char output[CRYPT_OUTPUT_SIZE];
  //  char setting[CRYPT_OUTPUT_SIZE];
  //  char phrase[CRYPT_MAX_PASSPHRASE_SIZE];
  //  char initialized;
  //};

  // char *
  //  crypt_gensalt_rn(const char * prefix, unsigned long count, const char
  //  *rbytes, int nrbytes, char * output, int output_size);




// hash based on the Blowfish block cipher, modified to have an extra-expensive key schedule.  Originally developed by Niels Provos and David Mazieres
//     for OpenBSD and also supported on recent versions of FreeBSD and NetBSD, on Solaris 10 and newer, and on several GNU/*/Linux distributions.
//
//     Prefix
//         "$2b$"
//
//     Hashed passphrase format
//         \$2[abxy]\$[0-9]{2}\$[./A-Za-z0-9]{53}
//
//     Maximum passphrase length
//         72 characters
//
//     Hash size
//         184 bits
//
//     Salt size
//         128 bits
//
//     CPU time cost parameter
//         4 to 31 (logarithmic)

}

bool BSDCrypt::Compare(const string &a, const string &b) {}

#include "cryptocpp.h"

BSDCrypt::BSDCrypt() { setType(EncryptionType::bcrypt); }

BSDCrypt::BSDCrypt(EncryptionType enc) { setType(enc); }

BSDCrypt::~BSDCrypt() {}

string BSDCrypt::Encrypt(const string &inp) { return e_->Encrypt(inp); }

void BSDCrypt::setType(EncryptionType type) {
  type_ = type;

  switch (type) {
  case EncryptionType::bcrypt:
    e_ = createBcrypt();
    break;
  default:
    throw std::runtime_error{"Encryption type is not supported"};
    break;
  }
}

bool BSDCrypt::Compare(const string &a, const string &b) { return false; }

unique_ptr<IEncrypt> BSDCrypt::createBcrypt() {
  return unique_ptr<IEncrypt>{new Bcrypt()};
}

string Bcrypt::Encrypt(const string &inp) {
  struct crypt_data data = {};
  // memset(&data,0,sizeof(data));
  
  char *setting =
      crypt_gensalt_rn(prefix().c_str(), static_cast<unsigned long>(cpuCost()),
                       NULL, 0, data.setting, CRYPT_OUTPUT_SIZE);

  if (setting == NULL) {
    throw runtime_error{"Encryption setting is null"};
  }

  char *out = crypt_rn(inp.c_str(), setting, &data, sizeof(data));
  if (out == NULL) {
    throw runtime_error{"Encryption Failed"};
  }

  return string(data.output, CRYPT_OUTPUT_SIZE);
}

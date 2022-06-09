#include "cryptocpp.h"
#include <iostream>

using namespace std;

BSDCrypt::BSDCrypt() { setType(EncryptionType::bcrypt); }

BSDCrypt::BSDCrypt(EncryptionType enc) { setType(enc); }

BSDCrypt::~BSDCrypt() {}

string BSDCrypt::encrypt(const string &inp) { return e_->encrypt(inp); }

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

bool BSDCrypt::compare(const string &encrypted_string,
                       const string &plain_text) {
  return e_->compare(encrypted_string, plain_text);
}

unique_ptr<IEncrypt> BSDCrypt::createBcrypt() {
  return unique_ptr<IEncrypt>{new Bcrypt()};
}

bool Bcrypt::compare(const std::string encrypted_string,
                     const std::string plain_text) {
  string enc;
  try {
    enc = encrypt(plain_text, encrypted_string);
  } catch (const std::exception &ec) {
    throw_with_nested(std::runtime_error{"Couldn't encrypt"});
  }

  return ((enc.length() == encrypted_string.length()) &&
          (enc == encrypted_string));
}

std::string BSDCrypt::encrypt(const std::string &inp, const std::string &salt) {
  return e_->encrypt(inp, salt);
}

std::string Bcrypt::encrypt(const std::string &inp, const std::string &salt) {
  struct crypt_data data = {};
  string out_ = "";
  if(salt.empty()){
    throw runtime_error{"Invalid salt"};}
  
  string new_salt = prefix() + to_string(cpuCost()) + "$" + salt;
  if (crypt_rn(inp.c_str(), new_salt.c_str(), &data, sizeof(data)) == NULL) {
    throw runtime_error{"Encryption Failed"};
  }
  try{
    out_ = string(data.output).erase(0, 7);
  }catch(const std::exception &ex){
    std::throw_with_nested(ex);
  }
  return out_;
}

string Bcrypt::encrypt(const string &inp) {
  struct crypt_data data = {};
  string out_ = "";

  char *setting =
      crypt_gensalt_rn(prefix().c_str(), static_cast<unsigned long>(cpuCost()),
                       NULL, 0, data.setting, CRYPT_OUTPUT_SIZE);

  if (setting == NULL) {
    throw runtime_error{"Encryption setting is null"};
  }

  if (crypt_rn(inp.c_str(), setting, &data, sizeof(data)) == NULL) {
    throw runtime_error{"Encryption Failed"};
  }

  try {
    out_ = string(data.output).erase(0, 7);
  } catch (const std::exception &ex) {
    std::throw_with_nested(ex);
  }
  return out_;
}

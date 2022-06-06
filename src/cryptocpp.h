#ifndef CRYPTOCPP_H_
#define CRYPTOCPP_H_
#include <crypt.h>
#include <cstring>
#include <memory>
using namespace std;

/**
 * Using BSD crypt for password hashing
 *
 */

class IEncrypt {
public:
  virtual ~IEncrypt() {}
  virtual string Encrypt(const string &) = 0;
};

class Bcrypt : public IEncrypt {
public:
  explicit Bcrypt() {}
  ~Bcrypt() {}

  inline const string name() const { return string("bcrypt"); }
  inline const string prefix() const { return string("$2b$"); }
  inline const int hashSize() const { return 184; }
  inline const int maxPassphraseLen() const { return 72; }
  inline const int saltSize() const { return 128; }
  inline const int cpuCost() const { return 12; /* 4 to 31 (logarithmic) */ };
  inline const string regexCheck() { return string("\\$2[abxy]\\$[0-9]{2}\\$[./A-Za-z0-9]{53}");}

  string Encrypt(const string &inp) override;
};

class IBSDCrypt {
public:
  virtual unique_ptr<IEncrypt> createBcrypt() = 0;
  virtual ~IBSDCrypt() {}
};

class BSDCrypt : public IBSDCrypt {

public:
  /**
   * A list of supported encryption types
   */
  enum class EncryptionType {
    yescrypt,
    gost_yescrypt,
    scrypt,
    bcrypt,
    sha512crypt,
    sha256crypt,
    sha1crypt,
    SunMD5,
    md5crypt,
    bsdicrypt,
    bigcrypt,
    descrypt,
    NT
  };

  BSDCrypt();
  BSDCrypt(EncryptionType enc);

  ~BSDCrypt();

  BSDCrypt(const BSDCrypt &) = delete;
  BSDCrypt &operator=(const BSDCrypt &) = delete;

  BSDCrypt(BSDCrypt &&) = delete;
  BSDCrypt &operator=(BSDCrypt &&) = delete;

  /**
   * Set an encryption type
   *
   * @param type encryption type
   */
  void setType(EncryptionType type);

  /**
   * Encrypt the input string
   *
   * @param inp input value
   * @return An encrypted string. If error occured this function throw an
   * exception.
   *
   */
  string Encrypt(const string &inp);

  /**
   * Compare encrpted string to plain text
   *
   * @param enc_a encrypted string
   * @param plain_b palin text
   * @return Return true if they are equals
   *
   */
  bool Compare(const string &enc_a, const string &plain_b);

  shared_ptr<IEncrypt> getInternalEncryption(){return e_;}

private:
  unique_ptr<IEncrypt> createBcrypt() override;
  EncryptionType type_;
  shared_ptr<IEncrypt> e_;
};

#endif

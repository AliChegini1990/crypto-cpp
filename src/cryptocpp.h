#ifndef _CRYPTOCPP_H_
#define _CRYPTOCPP_H_

#include <string>
#include <unordered_map>

/**
 * Using BSD crypt for password hashing
 *
 */

#include <crypt.h>

class BSDCrypt {

public:
  BSDCrypt();
  ~BSDCrypt();

  BSDCrypt(const BSDCrypt &) = delete;
  BSDCrypt &operator=(const BSDCrypt &) = delete;

  BSDCrypt(BSDCrypt &&) = delete;
  BSDCrypt &operator=(BSDCrypt &&) = delete;

  /**
   * A list of supported encryption types
   */
  enum class EncryptionType{
    yescrypt,
    gost-yescrypt,
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

  /**
   * Set an encryption type
   *
   * @param type encryption type
   */
  inline void setType(EncryptionType type) noexcept {type_ = type;}
  
  /**
   * Encrypt the input string
   * 
   * @param inp input value
   * @return An encrypted string. If error occured this function throw an exception.
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
  

  private:

   EncryptionType type_;

   unordered_map<string, EncryptionType> enc_text{
    {"$y$", EncryptionType::bcrypt}
   }
};


#endif

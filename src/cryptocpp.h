#ifndef _CRYPTOCPP_H_
#define _CRYPTOCPP_H_

#include <string>

/**
 * Using BSD crypt for password hashing
 *
 */

class BSDCrypt {

public:
  BSDCrypt();
  ~BSDCrypt();

  BSDCrypt(const BSDCrypt &) = delete;
  BSDCrypt &operator=(const BSDCrypt &) = delete;

  BSDCrypt(BSDCrypt &&) = delete;
  BSDCrypt &operator=(BSDCrypt &&) = delete;

  
  string Encrypt(const string &inp);
  
  
  bool Compare(const string &a, const string &b);

};

#endif

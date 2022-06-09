#include "cryptocpp.h"
#include <cassert>
#include <iostream>
#include <regex>
#include <stdexcept>

using namespace std;

class test_bcrypt_block_1 : public BSDCrypt {
public:

  test_bcrypt_block_1() {

    cout << "test1 is running" << endl;
    cout << "================" << endl;
    string input = "test1";

    try {

      BSDCrypt crypt(BSDCrypt::EncryptionType::bcrypt);
      cout << "input: " << input << endl;

      string out = crypt.encrypt(input);
      cout << "output: " << out << endl;

      // verify output
      auto &base = dynamic_cast<Bcrypt &>(*e_);
      std::regex re(base.regexCheck());
      string full_out = base.prefix() + to_string(base.cpuCost()) + "$" + out;

      if (!std::regex_match(full_out, re)) {
        cerr << "Encryption Failed: out put is not correct" << endl;
        throw runtime_error{"Regex is not match"};
      }

      if(!crypt.compare(out,"test1")){
         cerr << "Comparison Failed" << endl;
         throw runtime_error{"Comnparison Failed"};
      }

      if(crypt.compare(out,"")){
         cerr << "Comparison Failed" << endl;
         throw runtime_error{"Comnparison Failed with empty string"};
      }

      if(crypt.compare(out,"0000000000000000000000")){
         cerr << "Comparison Failed" << endl;
         throw runtime_error{"Comnparison Failed with invalid string"};
      }


      cout << "Successful" << endl;
      cout << "==========" << endl;

    } catch (const std::exception &ex) {
      cerr << "error: " << to_string(errno) << endl;
      cerr << "error msg: " << strerror(errno) << endl;
      cerr << ex.what() << endl;
      cerr << "Failed" << endl;
      cerr << "======" << endl;

      assert(1 == 0);
    }
  }
};

class test_bcrypt_block_2 : public BSDCrypt {
public:

  test_bcrypt_block_2() {

    cout << "test2 is running" << endl;
    cout << "================" << endl;
    string input = "";

    try {

      BSDCrypt crypt(BSDCrypt::EncryptionType::bcrypt);
      cout << "input: " << input << endl;

      string out = crypt.encrypt(input);
      cout << "output: " << out << endl;

      // verify output
      auto& base = dynamic_cast<Bcrypt &>(*e_);
      std::regex re(base.regexCheck());
      out = base.prefix() + to_string(base.cpuCost()) + "$" + out;

      if (!std::regex_match(out, re)) {
        cerr << "Encryption Failed: out put is not correct" << endl;
        throw runtime_error{"Regex is not match"};
      }
      cout << "Successful" << endl;
      cout << "==========" << endl;

    } catch (const std::exception &ex) {
      cerr << "error: " << to_string(errno) << endl;
      cerr << "error msg: " << strerror(errno) << endl;
      cerr << ex.what() << endl;
      cerr << "Failed" << endl;
      cerr << "======" << endl;

      assert(1 == 0);
    }
  }
};

int main() {
  test_bcrypt_block_1 t1;
  test_bcrypt_block_2 t2;
  return 0;
}

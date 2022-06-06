#include "cryptocpp.h"
#include <cassert>
#include <stdexcept>
#include <iostream>

using namespace std;

void test_bcrypt_block() {

  cout << "test1 is running" << endl;
  string input = "test1";
 
  try {

    BSDCrypt crypt(BSDCrypt::EncryptionType::bcrypt);
    cout << "input: " << input  << endl;
    
    string out = crypt.Encrypt(input);
    cout << "output: " << out  << endl;
  
    cout << "error: " << to_string(errno) << endl;
    cout << "error msg: " << strerror(errno) << endl;
   
  } catch (const std::exception &ex) {
    cerr << ex.what() << endl;
  }
}

int main() { 
  test_bcrypt_block();
  return 0; 
}

#include "cryptocpp.h"
#include <cassert>
#include <stdexcept>
#include <iostream>
#include <regex>
#include <cassert>

using namespace std;

void test_bcrypt_block_1() {

  cout << "test1 is running" << endl;
  cout << "================" << endl;
  string input = "test1";
 
  try {

    BSDCrypt crypt(BSDCrypt::EncryptionType::bcrypt);
    cout << "input: " << input  << endl;
    
    string out = crypt.Encrypt(input);
    cout << "output: " << out  << endl;
 
   //verify output
   auto bc_ = crypt.getInternalEncryption(); 
   auto base =  dynamic_cast<Bcrypt&>(*bc_);
   std::regex re(base.regexCheck());
   out = base.prefix() + to_string(base.cpuCost()) + "$" + out;
   cout << "setting + encoded string : " << out  << endl;

   if(!std::regex_match(out, re)){
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

    assert(1==0);
  }
}
void test_bcrypt_block_2() {

  cout << "test2 is running" << endl;
  cout << "================" << endl;
  string input = "";
 
  try {

    BSDCrypt crypt(BSDCrypt::EncryptionType::bcrypt);
    cout << "input: " << input  << endl;
    
    string out = crypt.Encrypt(input);
    cout << "output: " << out  << endl;
 
   //verify output
   auto bc_ = crypt.getInternalEncryption(); 
   auto base =  dynamic_cast<Bcrypt&>(*bc_);
   std::regex re(base.regexCheck());
   out = base.prefix() + to_string(base.cpuCost()) + "$" + out;
   cout << "setting + encoded string : " << out  << endl;

   if(!std::regex_match(out, re)){
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

    assert(1==0);
  }
}
int main() { 
  test_bcrypt_block_1();
  test_bcrypt_block_2();
  return 0; 
}

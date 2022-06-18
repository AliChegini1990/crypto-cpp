# Crypto-CPP
A C++ wrapper for encryption and decryption.

# Requirement

* GNU/Linux libcrypt library.
* cmake

# How to use

```c++
#include <iostream>
#include "cryptocpp.h"
using namespace std;

int main(){

  try {
    string input="";

    cout << "please enter input text: ";
    cin >> input; 
    
    BSDCrypt crypt(BSDCrypt::EncryptionType::bcrypt);
    string out = crypt.encrypt(input);
    cout << "output: " << out << endl;

    if(!crypt.compare(out,input)){
       cerr << "Comparison Failed" << endl;
       throw runtime_error{"Comnparison Failed"};
    }

  } catch (const std::exception &ex) {
    cerr << "error: " << to_string(errno) << endl;
    cerr << "error msg: " << strerror(errno) << endl;
    cerr << ex.what() << endl;
  }

  return 0;
}

```

# Build

```
mkdir build
cd build
cmake ..
make

```

# Test

After the library compiled successfuly you can run test file.

```
./test/test
```

# Note

* Supported methods
  * bcrypt

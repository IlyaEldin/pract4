#include <cryptopp/cryptlib.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>
#include <cryptopp/sha.h>
#include <vector>
#include <iostream>
#include <string>
#include <fstream>
using namespace std;
int main ()
{

    CryptoPP::SHA256 hash;

    cout <<"Name: " << hash.AlgorithmName() << endl;
    cout << "Diget size:" << hash.DigestSize() << endl;
    cout << "Block size:" << hash.BlockSize() << endl;
    fstream file;
    string path = "/home/ilya/hash.txt";
    string Message, file_contents, fc_message;
    file.open(path);
    if (!file.is_open()) {
        cout<<"Read error \n";
        return 1;
    } else {
        cout<<"Enter a message: ";
        getline(cin, fc_message);
        file<<fc_message;
    }
    file.close();
    file.open(path);
    if(!file.is_open()) {
        cout<<"Read error \n";
        return 1;
    }
    while(true) {
        getline(file,Message);
        if (file.fail()) 
            break;
        file_contents += Message;
    }
    cout << "File contents: " << file_contents << endl;
    vector<byte> digest (hash.DigestSize());

    hash.Update(reinterpret_cast<const byte*>(file_contents.data()),file_contents.size());
    hash.Final(digest.data());

    cout << "Digest HEX format: ";
    CryptoPP::StringSource(digest.data(),digest.size(),true, new CryptoPP::HexEncoder(new CryptoPP::FileSink(cout)));
    cout << endl;
    return 0;
}

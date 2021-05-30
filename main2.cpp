#include <cryptopp/cryptlib.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>
#include <cryptopp/sha.h>
#include <cryptopp/gost.h>
#include <cryptopp/pwdbased.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>
#include "cryptopp/modes.h"
#include <iostream>
#include <string>
#include <fstream>
using namespace std;
using namespace CryptoPP;

class AlgorithmGost
{
private:
    string filePath_in;
    string filePath_out;
    string filePath_Iv;
    string psw;
    string salt = "solurahelszxytrgvbcvbsewqe";
public:
    AlgorithmGost() = delete;
    AlgorithmGost(const string& filePath_in, const string& filePath_out, const string& pass);
    AlgorithmGost(const string& filePath_in, const string& filePath_out, const string& pass, const string & iv);
    void encodeGost (AlgorithmGost enc);
    void decodeGost (AlgorithmGost dec);
};

AlgorithmGost::AlgorithmGost(const string& filePath_in, const string& filePath_out, const string& pass)
{
    this->filePath_in = filePath_in;
    this->filePath_out = filePath_out;
    this->psw = pass;
}

AlgorithmGost::AlgorithmGost(const string& filePath_in, const string& filePath_out, const string& pass, const string & iv)
{
    this->filePath_in = filePath_in;
    this->filePath_out = filePath_out;
    this->psw = pass;
    this->filePath_Iv = iv;
}

void AlgorithmGost::encodeGost (AlgorithmGost enc)
{
    //Генерируем ключ
    SecByteBlock key(GOST::DEFAULT_KEYLENGTH);
    PKCS12_PBKDF<SHA512> pbkdf;
    pbkdf.DeriveKey(key.data(), key.size(), 0, (byte*)enc.psw.data(), enc.psw.size(), (byte*)salt.data(), salt.size(), 1024, 0.0f);

    //Генерируем вектор инициализации(IV)
    AutoSeededRandomPool prng;
    byte iv[GOST::BLOCKSIZE];
    prng.GenerateBlock(iv, sizeof(iv));
    //Записываем  вектор инициализации(IV) в файл (он понадобится при расшифровании)
    ofstream v_IV(string(enc.filePath_out + ".iv").c_str(), ios::out | ios::binary);
    v_IV.write((char*)iv, GOST::BLOCKSIZE);
    v_IV.close();

    cout << "Файл \"IV\" c вектором инициализации успешно создан.\nПуть: " << enc.filePath_out << ".iv" << endl;

    //Шифрование. Результат в файл
    CBC_Mode<GOST>::Encryption encr;
    encr.SetKeyWithIV(key, key.size(), iv);
    FileSource fs(enc.filePath_in.c_str(), true, new StreamTransformationFilter(encr, new FileSink(enc.filePath_out.c_str())));
    cout << "Шифрование прошло успешно.\nРезультат записан в файл, который находится по следующем пути:\n" << enc.filePath_out << endl;
}

void AlgorithmGost::decodeGost (AlgorithmGost dec)
{
    //Генерируем ключ (нужно использовать такой же пароль)
    SecByteBlock key(GOST::DEFAULT_KEYLENGTH);
    PKCS12_PBKDF<SHA512> pbkdf;
    pbkdf.DeriveKey(key.data(), key.size(), 0, (byte*)dec.psw.data(), psw.size(), (byte*)salt.data(), salt.size(), 1024, 0.0f);

    //Записываем вектор инициализации(IV) из файла, который формируется при шифровании
    byte iv[GOST::BLOCKSIZE];
    ifstream v_IV(dec.filePath_Iv.c_str(), ios::in | ios::binary);
    //Проверки файла с вектором инициализации(IV) на ошибки
    if (v_IV.good()) {
        v_IV.read(reinterpret_cast<char*>(&iv), GOST::BLOCKSIZE);
        v_IV.close();
    } else if (!v_IV.is_open()) {
        throw string ("Ошибка: Файл \"IV\" (с вектором инициализации) не открыт");
        v_IV.close();
    } else {
        throw string ("Ошибка: Файл \"IV\" (с вектором инициализации) некорректный");
        v_IV.close();
    }
    //Расшифрование
    CBC_Mode<GOST>::Decryption decr;
    decr.SetKeyWithIV(key, key.size(), iv);
    FileSource fs(dec.filePath_in.c_str(), true, new StreamTransformationFilter(decr, new FileSink(dec.filePath_out.c_str())));
    cout << "Расшифрование прошло успешно.\nРезультат записан в файл, который находится по следующем пути:\n" << dec.filePath_out << endl;
}

class AlgorithmAES
{
private:
    string filePath_in;
    string filePath_out;
    string psw;
    string filePath_Iv;
    string salt = "saltzemlirusskoi";
public:
    AlgorithmAES() = delete;
    AlgorithmAES(const string& filePath_in, const string& filePath_out, const string& Pass);
    AlgorithmAES(const string& filePath_in, const string& filePath_out, const string& Pass, const string & iv);
    void encodeAES (AlgorithmAES enc);
    void decodeAES (AlgorithmAES dec);
};
AlgorithmAES::AlgorithmAES(const string& filePath_in, const string& filePath_out, const string& Pass)
{
    this->filePath_in = filePath_in;
    this->filePath_out = filePath_out;
    this->psw = Pass;
}
AlgorithmAES::AlgorithmAES(const string& filePath_in, const string& filePath_out, const string& Pass, const string & iv)
{
    this->filePath_in = filePath_in;
    this->filePath_out = filePath_out;
    this->psw = Pass;
    this->filePath_Iv = iv;
}

void AlgorithmAES::encodeAES (AlgorithmAES enc)
{
    //Генерируем ключ
    SecByteBlock key(AES::DEFAULT_KEYLENGTH);
    PKCS12_PBKDF<SHA512> pbkdf;
    pbkdf.DeriveKey(key.data(), key.size(), 0, (byte*)enc.psw.data(), enc.psw.size(), (byte*)salt.data(), salt.size(), 1024, 0.0f);

    //Генерируем вектор инициализации(IV)
    AutoSeededRandomPool prng;
    byte iv[AES::BLOCKSIZE];
    prng.GenerateBlock(iv, sizeof(iv));

    //Записываем  вектор инициализации(IV) в файл (он понадобится при расшифровании)
    ofstream v_IV(string(enc.filePath_out + ".iv").c_str(), ios::out | ios::binary);
    v_IV.write((char*)iv, AES::BLOCKSIZE);
    v_IV.close();

    cout << "Файл \"IV\" c вектором инициализации успешно создан:\n " << enc.filePath_out << ".iv" << endl;

    //Шифрование. Результат в файл
    CBC_Mode<AES>::Encryption encr;
    encr.SetKeyWithIV(key, key.size(), iv);
    FileSource fs(enc.filePath_in.c_str(), true, new StreamTransformationFilter(encr, new FileSink(enc.filePath_out.c_str())));
    cout << "Шифрование прошло успешно.\nРезультат записан в файл:\n" << enc.filePath_out << endl;
}

void AlgorithmAES::decodeAES (AlgorithmAES dec)
{
    //Генерируем ключ (нужно использовать такой же пароль)
    SecByteBlock key(AES::DEFAULT_KEYLENGTH);
    PKCS12_PBKDF<SHA512> pbkdf;
    pbkdf.DeriveKey(key.data(), key.size(), 0, (byte*)dec.psw.data(), psw.size(), (byte*)salt.data(), salt.size(), 1024, 0.0f);

    //Записываем вектор инициализации(IV) из файла, который формируется при шифровании
    byte iv[AES::BLOCKSIZE];
    ifstream v_IV(dec.filePath_Iv.c_str(), ios::in | ios::binary);
    //Проверки файла с вектором инициализации(IV) на ошибки
    if (v_IV.good()) {
        v_IV.read(reinterpret_cast<char*>(&iv), AES::BLOCKSIZE);
        v_IV.close();
    } else if (!v_IV.is_open()) {
        throw string ("Ошибка:: Файл \"IV\" (с вектором инициализации) не найден");
        v_IV.close();
    } else {
        throw string ("Ошибка:: Файл \"IV\" (с вектором инициализации) некорректный");
        v_IV.close();
    }
    //Расшифрование
    CBC_Mode<AES>::Decryption decr;
    decr.SetKeyWithIV(key, key.size(), iv);
    FileSource fs(dec.filePath_in.c_str(), true, new StreamTransformationFilter(decr, new FileSink(dec.filePath_out.c_str())));
    cout << "Расшифрование прошло успешно.\nРезультат записан в файл:\n" << dec.filePath_out << endl;
}
int main ()
{
    bool isTrue = true;
    string mode;
    string f_in, f_out,f_iv,password;
    cout << "Добро пожаловать! \nЧтобы узнать режимы работы программы введите \"Help\"" << endl;
    do {
        cout << "Выбирете режим работы: ";
        cin >> mode;
        if (mode == "Help") {
            cout << "Справки о режимах работы программы:" << endl;
            cout << " EG - шифрование с использованием алгоритма \"GOST\"" << endl;
            cout << " DeG - расшифрование с использованием алгоритма \"GOST\"" << endl;
            cout << " EA - шифрование с использованием алгоритма \"AES\"" << endl;
            cout << " DeA - расшифрование с использованием алгоритма \"AES\"" << endl;
            cout << " Exit - для выхода из программы" << endl;
        }
        if (mode == "EG") {
            cout << "Укажите путь до файла: ";
            cin >> f_in;
            cout << "Укажите путь до файла, где будет сохраняться результат: ";
            cin >> f_out;
            cout << "Укажите пароль: ";
            cin >> password;
            try {
                AlgorithmGost enc(f_in,f_out,password);
                enc.encodeGost(enc);
            }  catch (const CryptoPP::Exception & ex) {
                cerr << ex.what() << endl;
            }
        }
        if (mode == "EA") {
            cout << "Укажите путь до файла: ";
            cin >> f_in;
            cout << "Укажите путь до файла, где будет сохраняться результат: ";
            cin >> f_out;
            cout << "Укажите пароль: ";
            cin >> password;
            try {
                AlgorithmAES enc(f_in,f_out,password);
                enc.encodeAES(enc);
            }  catch (const CryptoPP::Exception & ex) {
                cerr << ex.what() << endl;
            }
        }
        if (mode == "DeG") {
            cout << "Укажите путь до файла: ";
            cin >> f_in;
            cout << "Укажите путь до файла, где будет сохраняться результат: ";
            cin >> f_out;
            cout << "Укажите путь до файла, в котором находится вектор инициализации: ";
            cin >> f_iv;
            cout << "Укажите пароль: ";
            cin >> password;
            try {
                AlgorithmGost dec(f_in,f_out,password,f_iv);
                dec.decodeGost(dec);
            }  catch (const CryptoPP::Exception & ex) {
                cerr << ex.what() << endl;
            } catch (const string & error) {
                cerr << error << endl;
            }
        }
        if (mode == "DeA") {
            cout << "Укажите путь до файла: ";
            cin >> f_in;
            cout << "Укажите путь до файла, где будет сохраняться результат: ";
            cin >> f_out;
            cout << "Укажите путь до файла, в котором находится вектор инициализации: ";
            cin >> f_iv;
            cout << "Укажите пароль: ";
            cin >> password;
            try {
                AlgorithmAES dec(f_in,f_out, password, f_iv );
                dec.decodeAES(dec);
            } catch (const CryptoPP::Exception & ex) {
                cerr << ex.what() << endl;
            } catch (const string & error) {
                cerr << error << endl;
            }
        }
        if (mode == "Exit") {
            cout << "Завершение работы!" << endl;
            isTrue = false;
            break;
        }
    } while (isTrue != false);

    return 0;
}

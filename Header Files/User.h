#pragma once
#ifndef USER_H
#define USER_H
#define CROW_USE_ASIO

#include "crow.h"
#include <unordered_map>
#include <mutex>
#include <string>
#include <random>
#include <sstream>
#include <memory>
#include <iostream>
#include <fstream>
#include <filesystem>
using namespace std;
class User {
    private:
    string userName;
    string salt;
    size_t hashPassword;

    public:
    User(const string& , const string&);
    uint64_t getHashPassword();
    bool checkPassword(const string&) const;
    string generateSalt();
    string getSalt();
    static uint64_t hashPasswordWithSalt(const string& , const string&);
};
#endif



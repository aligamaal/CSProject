#pragma once
#ifndef AUTHMANAGER_H
#define AUTHMANAGER_H
#include "User.h"
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

class AuthManager {
    private:
    unordered_map<string , User> users;
    unordered_map<string , string> sessions;
    mutex data_mutex;
    string generateToken();

    public:
    bool registerUser(const string& , const string&);
    string loginUser(const string& , const string&);
    string* getUsernameFromToken(const string&);
};
#endif
#define CROW_USE_ASIO
#include "AuthManager.h"
#include "crow.h"
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

string AuthManager::generateToken(){
    stringstream ss;
        static random_device rd;
        static mt19937 gen(rd());
        static uniform_int_distribution<> dis(0, 15);
        for (int i = 0; i < 32; ++i)
            ss << hex << dis(gen);
        return ss.str();
}

bool AuthManager::registerUser(const string& username , const string& password){
    lock_guard<mutex> lock(data_mutex);
        if (users.count(username)) return false;
        users.emplace(username, User(username, password));
        return true;
}
string AuthManager::loginUser(const string& username , const string& password){
    lock_guard<mutex> lock(data_mutex);
        auto it = users.find(username);
        if (it == users.end() || !it->second.checkPassword(password))
            return "";
            const string& userSalt = it->second.getSalt();
     uint64_t computedHash = User::hashPasswordWithSalt(password,userSalt);
    
     cout << "Stored hash: " << it->second.getHashPassword() << endl;
     cout << "Computed hash: " << computedHash << endl;
     cout << "Match: " << (it->second.getHashPassword() == computedHash) << endl;
    
    if (!it->second.checkPassword(password))
        return "";

        string token = generateToken();
        sessions[token] = username;
        return token;
}
string* AuthManager::getUsernameFromToken(const string& token){
    lock_guard<mutex> lock(data_mutex);
        auto it = sessions.find(token);
        if (it != sessions.end()) {
            return &it->second;
        }
        return nullptr;
}

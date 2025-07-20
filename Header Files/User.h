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
#include <functional>
#include "AVLTree.h"
using namespace std;
class User {
private:
    string userName;
    string salt;
    size_t hashPassword;
    AVLTree<std::string> friendsTree;

public:
    AVLTree<std::string> friends;
    User();
    User(const string&, const string&);
    size_t getHashPassword();
    bool checkPassword(const string&) const;
    string generateSalt();
    string getSalt();
    static size_t hashPasswordWithSalt(const string&, const string&);
    void addFriend(const string& friendName);
    void removeFriend(const string& friendName);
    bool isFriendWith(const string& friendName);
    vector<string> getFriendsList() const;
};
#endif
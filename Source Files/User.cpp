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
#include <stdexcept>
#include "AVLTree.h"
#include "User.h"
#include "Post.h"
using namespace std;

User::User() {
    salt = "";
    userName = "";
    hashPassword = 0;
}

User::User(const string& uname, const string& password) : userName(uname) {
    salt = generateSalt();
    hashPassword = hashPasswordWithSalt(password, salt);
}

bool User::checkPassword(const string& password) const {
    return hashPassword == hashPasswordWithSalt(password, salt);
}

string User::generateSalt() {
    static random_device rd;
    static mt19937 gen(rd());
    static uniform_int_distribution<> dis(0, 15);
    stringstream ss;
    for (int i = 0; i < 16; ++i) {  // 16 character salt
        ss << hex << dis(gen);
    }
    return ss.str();
}

string User::getSalt() {
    return salt;
}

size_t User::hashPasswordWithSalt(const string& password, const string& salt) {
    return hash<string> {}(password + salt);
}

size_t User::getHashPassword() {
    return hashPassword;
}

void User::addFriend(const string& friendName) {
    friends.insert(friendName);
}

void User::removeFriend(const string& friendName) {
    friends.deleteNode(friendName);
}

bool User::isFriendWith(const string& friendName) {
    return friends.search(friendName);
}

vector<string> User::getFriendsList() const {
    return friends.inOrderTraversal();
}

void User::addPost(const std::string& content) {
    posts_.push_back(Post(content, userName));
}

const std::vector<Post>& User::getPosts() const {
    return posts_;
}

std::vector<Post>& User::getPostsMutable() {
    return posts_;
}

void User::deletePost(size_t index) {
    if (index >= posts_.size()) {
        throw std::out_of_range("Invalid post index");
    }
    posts_.erase(posts_.begin() + index);
}

void User::editPost(size_t index, const std::string& newContent) {
    if (index >= posts_.size()) {
        throw std::out_of_range("Invalid post index");
    }
    // Since Post class stores content as const, we need to replace the post
    posts_[index] = Post(newContent, userName);
}
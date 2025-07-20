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
#include "AVLTree.h"
#include "User.h"
using namespace std;
User::User(){
	salt = "";
	userName = "";
	hashPassword = 0;
}
User::User(const string& uname, const string& password) : userName(uname) {
	salt = generateSalt();
	hashPassword = hashPasswordWithSalt(password, salt);
	// Debug output for registration
	cout << "=== USER REGISTRATION DEBUG ===" << endl;
	cout << "Username: " << userName << endl;
	cout << "Original password: " << password << endl;
	cout << "Generated salt: " << salt << endl;
	cout << "Combined string: " << (password + salt) << endl;
	cout << "Final hash: " << hashPassword << endl;
	cout << "===============================" << endl;
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

<<<<<<< HEAD
	void User::addFriend(string friendName) {
		friends.insert(friendName);
	}


	void User::removeFriend(string friendName) {
		friends.deleteNode(friendName);
	}


	bool User::isFriendWith(string friendName) {
		return friends.search(friendName);
	}


	vector<string> User::getFriendsList() {
		return friends.inOrderTraversal();
	}
=======
User::User(const string& uname, const string& password) : userName(uname){
    salt = generateSalt();  
        hashPassword = hashPasswordWithSalt(password, salt); 
        // Debug output for registration
        cout << "=== USER REGISTRATION DEBUG ===" << endl;
        cout << "Username: " << userName << endl;
        cout << "Original password: " << password << endl;
        cout << "Generated salt: " << salt << endl;
        cout << "Combined string: " << (password + salt) << endl;
        cout << "Final hash: " << hashPassword << endl;
        cout << "===============================" << endl;
}
bool User::checkPassword(const string& password) const{
    return hashPassword == hashPasswordWithSalt(password, salt);
}
string User::generateSalt(){
    static random_device rd;
        static mt19937 gen(rd());
        static uniform_int_distribution<> dis(0, 15);
        stringstream ss;
        for (int i = 0; i < 16; ++i) {  // 16 character salt
            ss << hex << dis(gen);
        }
        return ss.str();
}
string User::getSalt(){
    return salt;
}
uint64_t User::hashPasswordWithSalt(const string& password, const string& salt){
    return hash<string>{}(password + salt);
}
uint64_t User::getHashPassword(){
    return hashPassword;
}
>>>>>>> ea73ec424d5d578ff3225c50c576b25177f6e6c5

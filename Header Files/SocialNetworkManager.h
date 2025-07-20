#pragma once
#ifndef SOCIALNETWORK_H
#define SOCIALNETWORK_H
#include "User.h"
#include <unordered_map>
#include <mutex>
#include <stdexcept>
#include <vector>
#include <algorithm>
using namespace std;

class SocialNetworkManager {
private:
    unordered_map<string, User> users;
    mutable mutex mtx;
    unordered_map<string, vector<string>> sentRequests;  
    unordered_map<string, vector<string>> receivedRequests; 

public:
    void registerUser(string username, string password);
    bool authenticateUser(string username,string password);

    void addFriendship(string user1, string user2);
    void removeFriendship(string user1,string user2);
    bool areFriends(string user1, string user2);

    vector<string> getFriends(string username);
    void removeUser(string username);

    void printAllUsers();

    void sendRequest(string sender, string receiver);
    void acceptRequest(string receiver, string sender);
    void rejectRequest(string receiver, string sender);
    void cancelRequest(string sender, string receiver);
    vector<string> getMutualFriends(string user1, string user2);
    vector<string> suggestFriends(string username);
};
#endif
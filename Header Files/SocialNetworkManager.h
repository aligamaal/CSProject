#ifndef SOCIALNETWORKMANAGER_H
#define SOCIALNETWORKMANAGER_H

#include <unordered_map>
#include <vector>
#include <string>
#include <mutex>
#include <iostream>
#include "User.h"
#include "crow.h"  // Add this for crow::json

using namespace std;

class SocialNetworkManager {
private:
    unordered_map<string, User> users;
    unordered_map<string, vector<string>> sentRequests;
    unordered_map<string, vector<string>> receivedRequests;
    mutex mtx;
    
    // Internal helper method
    bool areFriendsInternal(string user1, string user2);

public:
    void registerUser(string username, string password);
    bool authenticateUser(string username, const string password);
    void addFriendship(const string& user1,const string& user2);
    void removeFriendship(string user1, string user2);
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
    vector<string> getAllUsers();
    vector<string> getPendingRequests(string username);
    vector<string> getSentRequests(string username);
   std::pair<std::unordered_map<std::string, std::vector<std::string>>, 
          std::unordered_map<std::string, std::vector<std::string>>> getAllFriendRequests();  // Add this
};

#endif
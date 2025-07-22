#ifndef SOCIALNETWORKMANAGER_H
#define SOCIALNETWORKMANAGER_H

#include <unordered_map>
#include <vector>
#include <string>
#include <mutex>
#include <queue>
#include <utility>
#include "crow.h"
#include "User.h"
#include "Post.h"
#include "AVLTree.h"

class SocialNetworkManager {
private:
    std::unordered_map<std::string, User> users;
    std::mutex mtx;
    
    // Friend request tracking
    std::unordered_map<std::string, std::vector<std::string>> sentRequests;    // sender -> [receivers]
    std::unordered_map<std::string, std::vector<std::string>> receivedRequests; // receiver -> [senders]
    
    // AVL tree for efficient user search
    AVLTree<std::string> userSearchTree;
    
    // Internal helper method
    bool areFriendsInternal(std::string user1, std::string user2);
    
public:
    // User management
    void registerUser(std::string username, std::string password);
    bool authenticateUser(std::string username, const std::string password);
    void removeUser(std::string username);
    std::vector<std::string> getAllUsers();
    
    // Friendship management
    void addFriendship(const std::string& user1, const std::string& user2);
    void removeFriendship(std::string user1, std::string user2);
    bool areFriends(std::string user1, std::string user2);
    std::vector<std::string> getFriends(std::string username);
    
    // Friend requests
    void sendRequest(std::string sender, std::string receiver);
    void acceptRequest(std::string receiver, std::string sender);
    void rejectRequest(std::string receiver, std::string sender);
    void cancelRequest(std::string sender, std::string receiver);
    std::vector<std::string> getPendingRequests(std::string username);
    std::vector<std::string> getSentRequests(std::string username);
    
    // Friend suggestions and mutual friends
    std::vector<std::string> getMutualFriends(std::string user1, std::string user2);
    std::vector<std::string> suggestFriends(std::string username);
    
    // Search functionality
    std::vector<std::string> searchUsersByPrefix(const std::string& prefix, const std::string& currentUser = "");
    std::vector<std::string> searchFriendsByPrefix(const std::string& username, const std::string& prefix);
    
    // Posts functionality
    void addPost(const std::string& username, const std::string& content);
    std::vector<Post> getTimeline(const std::string& username);
    std::vector<Post> getUserPosts(const std::string& username);
    void deletePost(const std::string& username, size_t postIndex);
    void editPost(const std::string& username, size_t postIndex, const std::string& newContent);
    
    // Debug methods
    void printAllUsers();
    std::pair<std::unordered_map<std::string, std::vector<std::string>>, 
              std::unordered_map<std::string, std::vector<std::string>>> getAllFriendRequests();
    
    // AVL Tree debugging
    struct AVLTreeInfo {
        crow::json::wvalue treeStructure;
        int height;
        int nodeCount;
        bool isBalanced;
        std::string visualRepresentation;
    };
    
    AVLTreeInfo getUserAVLTreeInfo(const std::string& username);
    crow::json::wvalue convertTreeToJSON(AVLNode<std::string>* node);
};

#endif // SOCIALNETWORKMANAGER_H
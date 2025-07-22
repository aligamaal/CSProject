#include "SocialNetworkManager.h"
#include <algorithm>
#include <set>
#include <iostream>  // For debugging
#include <string>
#include <queue>     // For std::priority_queue
#include "AVLTree.h"
#include "User.h"
#include "Post.h"
#include <chrono>
#include <ctime>
using namespace std;

// SocialNetworkManager.cpp
void SocialNetworkManager::registerUser(string username, string password) {
    lock_guard<mutex> lock(mtx);
    if (users.find(username) != users.end()) {
        std::cout << "[DEBUG] User " << username << " already exists in social network\n";
        return; // Gracefully handle existing user
    }
    
    users.emplace(username, User(username, password));
    
    // Add to search tree for efficient prefix searching
    userSearchTree.insert(username);
    
    std::cout << "[DEBUG] User registered: " << username << endl;
    std::cout << "[DEBUG] User search tree now has " << userSearchTree.getSize() << " users" << endl;
}

bool SocialNetworkManager::authenticateUser(string username, const string password) {
    lock_guard<mutex> lock(mtx);
    auto it = users.find(username);
    if (it == users.end()) {
        std::cout << "[DEBUG] User " << username << " not found in social network" << endl;
        return false;
    }
    bool result = it->second.checkPassword(password);
    std::cout << "[DEBUG] Authentication for " << username << ": " << (result ? "success" : "failed") << endl;
    return result;
}

void SocialNetworkManager::addFriendship(const string& user1, const string& user2) {
    lock_guard<mutex> lock(mtx);
    auto it1 = users.find(user1);
    auto it2 = users.find(user2);

    if (it1 == users.end() || it2 == users.end()) {
        throw runtime_error("User not found");
    }

    if (it1->second.isFriendWith(user2)) {
        throw runtime_error("Users are already friends");
    }

    it1->second.addFriend(user2);
    it2->second.addFriend(user1);
    
    // Enhanced debug output
    std::cout << "\n[DEBUG] === Friendship Added ===" << endl;
    std::cout << "[DEBUG] Between: " << user1 << " and " << user2 << endl;
    
    // Show friends in alphabetical order for both users
    auto friends1 = it1->second.getFriendsList();
    std::cout << "[DEBUG] " << user1 << "'s friends (should be alphabetical): ";
    for (size_t i = 0; i < friends1.size(); i++) {
        std::cout << friends1[i];
        if (i < friends1.size() - 1) std::cout << ", ";
    }
    std::cout << endl;
    
    auto friends2 = it2->second.getFriendsList();
    std::cout << "[DEBUG] " << user2 << "'s friends (should be alphabetical): ";
    for (size_t i = 0; i < friends2.size(); i++) {
        std::cout << friends2[i];
        if (i < friends2.size() - 1) std::cout << ", ";
    }
    std::cout << endl;
    
    // Verify alphabetical order
    bool sorted1 = is_sorted(friends1.begin(), friends1.end());
    bool sorted2 = is_sorted(friends2.begin(), friends2.end());
    
    if (!sorted1) std::cout << "[WARNING] " << user1 << "'s friends are NOT sorted!" << endl;
    if (!sorted2) std::cout << "[WARNING] " << user2 << "'s friends are NOT sorted!" << endl;
    
    std::cout << "[DEBUG] ======================" << endl;
}

void SocialNetworkManager::removeFriendship(string user1, string user2) {
    lock_guard<mutex> lock(mtx);
    auto it1 = users.find(user1);
    auto it2 = users.find(user2);

    if (it1 != users.end()) it1->second.removeFriend(user2);
    if (it2 != users.end()) it2->second.removeFriend(user1);
}

bool SocialNetworkManager::areFriends(string user1, string user2) {
    lock_guard<mutex> lock(mtx);
    auto it = users.find(user1);
    return it != users.end() && it->second.isFriendWith(user2);
}

// Internal version without locking (to be called when mutex is already held)
bool SocialNetworkManager::areFriendsInternal(string user1, string user2) {
    auto it = users.find(user1);
    return it != users.end() && it->second.isFriendWith(user2);
}

vector<string> SocialNetworkManager::getFriends(string username) {
    lock_guard<mutex> lock(mtx);
    auto it = users.find(username);
    if (it != users.end()) {
        auto friends = it->second.getFriendsList();
        std::cout << "[DEBUG] Getting friends for " << username << ": " << friends.size() << " friends" << endl;
        return friends;
    }
    return vector<string>();
}

void SocialNetworkManager::removeUser(string username) {
    lock_guard<mutex> lock(mtx);
    auto userIt = users.find(username);
    if (userIt == users.end()) return;

    auto friends = userIt->second.getFriendsList();
    for (const auto& friendName : friends) {
        auto friendIt = users.find(friendName);
        if (friendIt != users.end()) {
            friendIt->second.removeFriend(username);
        }
    }

    // Also remove from pending requests
    sentRequests.erase(username);
    receivedRequests.erase(username);
    
    // Remove username from other users' request lists
    for (auto& pair : sentRequests) {
        auto& requests = pair.second;
        requests.erase(remove(requests.begin(), requests.end(), username), requests.end());
    }
    for (auto& pair : receivedRequests) {
        auto& requests = pair.second;
        requests.erase(remove(requests.begin(), requests.end(), username), requests.end());
    }
    userSearchTree.deleteNode(username);
    users.erase(username);
      std::cout << "[DEBUG] User removed: " << username << endl;
    std::cout << "[DEBUG] User search tree now has " << userSearchTree.getSize() << " users" << endl;
}
void SocialNetworkManager::printAllUsers() {
    lock_guard<mutex> lock(mtx);
    std::cout << "\n=== Registered Users ===" << endl;
    for (const auto& userEntry : users) {
        std::cout << "- " << userEntry.first;
        auto friends = userEntry.second.getFriendsList();
        if (!friends.empty()) {
            std::cout << " (Friends: ";
            for (const auto& f : friends) std::cout << f << " ";
            std::cout << ")";
        }
        std::cout << endl;
    }
    std::cout << "Total users: " << users.size() << endl;
    std::cout << "=======================" << endl;
}

void SocialNetworkManager::sendRequest(string sender, string receiver) {
    lock_guard<mutex> lock(mtx);
    
    // Debug
    std::cout << "[DEBUG] Send request from " << sender << " to " << receiver << endl;
    std::cout << "[DEBUG] Checking if users exist..." << endl;
    
    if (users.find(sender) == users.end()) {
        std::cout << "[DEBUG] Sender " << sender << " not found!" << endl;
        throw runtime_error("Sender not found");
    }
    if (users.find(receiver) == users.end()) {
        std::cout << "[DEBUG] Receiver " << receiver << " not found!" << endl;
        throw runtime_error("Receiver not found");
    }
    
    if (sender == receiver) {
        throw runtime_error("Cannot send friend request to yourself");
    }
    
    // Use internal version since we already have the lock
     auto userIt = users.find(sender);
    if (userIt != users.end() && userIt->second.isFriendWith(receiver)) {
        throw runtime_error("Users are already friends");
    }
    
    // Check if request already exists
    auto& sentList = sentRequests[sender];
    if (find(sentList.begin(), sentList.end(), receiver) != sentList.end()) {
        throw runtime_error("Friend request already sent");
    }

    // Check if receiver already sent a request to sender
    auto& receiverSentList = sentRequests[receiver];
    if (find(receiverSentList.begin(), receiverSentList.end(), sender) != receiverSentList.end()) {
        throw runtime_error("This user already sent you a friend request. Please accept it instead.");
    }
    sentRequests[sender].push_back(receiver);
    receivedRequests[receiver].push_back(sender);
    
    std::cout << "[DEBUG] Friend request sent successfully" << endl;
    std::cout << "[DEBUG] Sender " << sender << " now has " << sentRequests[sender].size() << " sent requests" << endl;
    std::cout << "[DEBUG] Receiver " << receiver << " now has " << receivedRequests[receiver].size() << " received requests" << endl;
}

void SocialNetworkManager::acceptRequest(string receiver, string sender) {
    lock_guard<mutex> lock(mtx);
    
    // Check if request exists
    auto& receiverList = receivedRequests[receiver];
    auto it = find(receiverList.begin(), receiverList.end(), sender);
    if (it == receiverList.end()) {
        throw runtime_error("No friend request found from this user");
    }
     // Add friendship without locking again
    auto it1 = users.find(sender);
    auto it2 = users.find(receiver);
    if (it1 != users.end() && it2 != users.end()) {
        it1->second.addFriend(receiver);
        it2->second.addFriend(sender);
        std::cout << "[DEBUG] Friendship added between " << sender << " and " << receiver << endl;
    }

    // Remove from request lists
    auto& senderList = sentRequests[sender];
    senderList.erase(remove(senderList.begin(), senderList.end(), receiver), senderList.end());
    receiverList.erase(remove(receiverList.begin(), receiverList.end(), sender), receiverList.end());
}

vector<string> SocialNetworkManager::getMutualFriends(string user1, string user2) {
    lock_guard<mutex> lock(mtx);
    
    if (users.find(user1) == users.end() || users.find(user2) == users.end()) {
        throw runtime_error("User not found");
    }
    
    auto& tree1 = users[user1].friends;
    auto& tree2 = users[user2].friends;

    // Get sorted friend lists using in-order traversal
    auto list1 = tree1.inOrderTraversal();
    auto list2 = tree2.inOrderTraversal();

    // Find intersection
    vector<string> mutual;
    set_intersection(
        list1.begin(), list1.end(),
        list2.begin(), list2.end(),
        back_inserter(mutual)
    );
    return mutual;
}

vector<string> SocialNetworkManager::suggestFriends(string username) {
    lock_guard<mutex> lock(mtx);
    
    if (users.find(username) == users.end()) {
        throw runtime_error("User not found");
    }
    
    unordered_map<string, int> candidateScores;

    // Get user's direct friends
    auto directFriends = users[username].getFriendsList();

    // Traverse 2nd-degree connections
    for (const auto& friendName : directFriends) {
        // Skip if friend doesn't exist in system
        if (users.find(friendName) == users.end()) continue;

        auto friendsOfFriend = users[friendName].getFriendsList();

        for (const auto& candidate : friendsOfFriend) {
            // Skip self and existing friends
            if (candidate == username || users[username].isFriendWith(candidate)) continue;

            candidateScores[candidate]++;
        }
    }

    // Convert to sorted vector by mutual count
    vector<pair<string, int>> ranked;
    for (const auto& entry : candidateScores) {
        ranked.push_back(entry);
    }

    // Sort in descending order by mutual count
    sort(ranked.begin(), ranked.end(),
        [](const pair<string, int>& a, const pair<string, int>& b) {
            return a.second > b.second;
        });

    vector<string> suggestions;
    for (const auto& entry : ranked) {
        suggestions.push_back(entry.first);
    }
    return suggestions;
}

void SocialNetworkManager::rejectRequest(string receiver, string sender) {
    lock_guard<mutex> lock(mtx);

    // Remove from receiver's received requests
    if (receivedRequests.find(receiver) != receivedRequests.end()) {
        auto& requests = receivedRequests[receiver];
        requests.erase(
            remove(requests.begin(), requests.end(), sender),
            requests.end()
        );
    }

    // Remove from sender's sent requests
    if (sentRequests.find(sender) != sentRequests.end()) {
        auto& requests = sentRequests[sender];
        requests.erase(
            remove(requests.begin(), requests.end(), receiver),
            requests.end()
        );
    }
}

void SocialNetworkManager::cancelRequest(string sender, string receiver) {
    lock_guard<mutex> lock(mtx);

    // Remove from sender's sent requests
    if (sentRequests.find(sender) != sentRequests.end()) {
        auto& requests = sentRequests[sender];
        requests.erase(
            remove(requests.begin(), requests.end(), receiver),
            requests.end()
        );
    }

    // Remove from receiver's received requests
    if (receivedRequests.find(receiver) != receivedRequests.end()) {
        auto& requests = receivedRequests[receiver];
        requests.erase(
            remove(requests.begin(), requests.end(), sender),
            requests.end()
        );
    }
}
// NEW BST-BASED SEARCH IMPLEMENTATION

vector<string> SocialNetworkManager::searchUsersByPrefix(const string& prefix, const string& currentUser) {
    lock_guard<mutex> lock(mtx);
    
    if (prefix.empty()) {
        return vector<string>(); // Return empty for empty prefix
    }
    
    // Use BST-based search on the user search tree
    vector<string> matchingUsers = userSearchTree.searchByPrefix(prefix);
    
    // Filter out current user if specified
    if (!currentUser.empty()) {
        matchingUsers.erase(
            remove(matchingUsers.begin(), matchingUsers.end(), currentUser),
            matchingUsers.end()
        );
    }
    
    std::cout << "[DEBUG] BST Search for prefix '" << prefix << "' found " 
         << matchingUsers.size() << " users" << endl;
    
    return matchingUsers;
}

vector<string> SocialNetworkManager::searchFriendsByPrefix(const string& username, const string& prefix) {
    lock_guard<mutex> lock(mtx);
    
    auto it = users.find(username);
    if (it == users.end()) {
        throw runtime_error("User not found: " + username);
    }
    
    if (prefix.empty()) {
        return vector<string>(); // Return empty for empty prefix
    }
    
    // Use BST-based search on the user's friends tree
    vector<string> matchingFriends = it->second.friends.searchByPrefix(prefix);
    
    std::cout << "[DEBUG] BST Search for friends of '" << username 
         << "' with prefix '" << prefix << "' found " 
         << matchingFriends.size() << " friends" << endl;
    
    return matchingFriends;
}

// Add this method to get all users (useful for debugging and search)
vector<string> SocialNetworkManager::getAllUsers() {
    lock_guard<mutex> lock(mtx);
    vector<string> allUsers;
    for (const auto& pair : users) {
        allUsers.push_back(pair.first);
    }
    return allUsers;
}

// Get pending friend requests (received)
vector<string> SocialNetworkManager::getPendingRequests(string username) {
    lock_guard<mutex> lock(mtx);
    if (receivedRequests.find(username) != receivedRequests.end()) {
        return receivedRequests[username];
    }
    return vector<string>();
}

// Get sent friend requests
vector<string> SocialNetworkManager::getSentRequests(string username) {
    lock_guard<mutex> lock(mtx);
    if (sentRequests.find(username) != sentRequests.end()) {
        return sentRequests[username];
    }
    return vector<string>();
}

// Debug method to get all friend requests
pair<unordered_map<string, vector<string>>, unordered_map<string, vector<string>>> 
SocialNetworkManager::getAllFriendRequests() {
    lock_guard<mutex> lock(mtx);
    return make_pair(sentRequests, receivedRequests);
}
SocialNetworkManager::AVLTreeInfo SocialNetworkManager::getUserAVLTreeInfo(const std::string& username) {
    lock_guard<mutex> lock(mtx);
    
    auto it = users.find(username);
    if (it == users.end()) {
        throw std::runtime_error("User not found: " + username);
    }
    
    AVLTreeInfo info;
    User& user = it->second;
    
    // Get the AVL tree from the user's friends list
    AVLTree<std::string>* friendsTree = user.getFriendsTree();
    
    if (!friendsTree) {
        info.height = 0;
        info.nodeCount = 0;
        info.isBalanced = true;
        info.visualRepresentation = "Empty tree";
        info.treeStructure = crow::json::wvalue();
        return info;
    }
    
    // Convert tree to JSON structure
    info.treeStructure = convertTreeToJSON(friendsTree->getRoot());
    info.height = friendsTree->getHeight();
    info.nodeCount = friendsTree->getSize();
    info.isBalanced = friendsTree->isBalanced();
    info.visualRepresentation = friendsTree->visualize();
    
    return info;
}

crow::json::wvalue SocialNetworkManager::convertTreeToJSON(AVLNode<string>* node) {
    crow::json::wvalue result;
    
    if (!node) {
        return result;
    }
    
    result["value"] = node->key;
    result["height"] = node->height;
    
    if (node->left) {
        result["left"] = convertTreeToJSON(node->left);
    } else {
        result["left"] = nullptr;
    }
    
    if (node->right) {
        result["right"] = convertTreeToJSON(node->right);
    } else {
        result["right"] = nullptr;
    }
    
    return result;
}
void SocialNetworkManager::addPost(const std::string& username, const std::string& content) {
    std::lock_guard<std::mutex> lock(mtx);
    auto it = users.find(username);
    if (it == users.end()) throw std::runtime_error("User not found");
    it->second.addPost(content);
}

std::vector<Post> SocialNetworkManager::getTimeline(const std::string& username) {
    std::lock_guard<std::mutex> lock(mtx);
    auto userIt = users.find(username);
    if (userIt == users.end()) throw std::runtime_error("User not found");
    
    // Get friends list
    std::vector<std::string> friends = userIt->second.getFriendsList();
    std::vector<const std::vector<Post>*> postLists;
    
    // Add current user's posts
    postLists.push_back(&(userIt->second.getPosts()));
    
    // Add friends' posts
    for (const auto& friendName : friends) {
        auto friendIt = users.find(friendName);
        if (friendIt != users.end()) {
            postLists.push_back(&(friendIt->second.getPosts()));
        }
    }

    // Priority queue for k-way merge (max-heap by timestamp)
    auto cmp = [](const std::pair<const Post*, int>& a, const std::pair<const Post*, int>& b) {
        return a.first->getTimestamp() < b.first->getTimestamp();
    };
    std::priority_queue<
        std::pair<const Post*, int>,
        std::vector<std::pair<const Post*, int>>,
        decltype(cmp)
    > pq(cmp);

    // Track current indices for each list
    std::vector<int> currentIndices(postLists.size());
    
    // Initialize heap with last element of each list (most recent)
    for (size_t i = 0; i < postLists.size(); i++) {
        if (!postLists[i]->empty()) {
            int lastIndex = postLists[i]->size() - 1;
            pq.push({&((*postLists[i])[lastIndex]), static_cast<int>(i)});
            currentIndices[i] = lastIndex;
        }
    }

    // Merge posts
    std::vector<Post> timeline;
    while (!pq.empty()) {
        auto topElement = pq.top();
        const Post* post = topElement.first;
        int listIdx = topElement.second;
        pq.pop();
        timeline.push_back(*post);
        
        // Move to next post in this list (going backwards since we want newest first)
        currentIndices[listIdx]--;
        if (currentIndices[listIdx] >= 0) {
            pq.push({&((*postLists[listIdx])[currentIndices[listIdx]]), listIdx});
        }
    }
    
    return timeline;
}

// Add these new methods to SocialNetworkManager class:

void SocialNetworkManager::deletePost(const std::string& username, size_t postIndex) {
    std::lock_guard<std::mutex> lock(mtx);
    auto it = users.find(username);
    if (it == users.end()) throw std::runtime_error("User not found");
    
    auto& posts = it->second.getPosts();
    if (postIndex >= posts.size()) {
        throw std::runtime_error("Invalid post index");
    }
    
    // Since we can't modify the const vector, we need to add a non-const getter in User class
    // For now, throw an error indicating this needs to be implemented
    throw std::runtime_error("Post deletion requires modification to User class");
}

std::vector<Post> SocialNetworkManager::getUserPosts(const std::string& username) {
    std::lock_guard<std::mutex> lock(mtx);
    auto it = users.find(username);
    if (it == users.end()) throw std::runtime_error("User not found");
    
    return it->second.getPosts();
}
void SocialNetworkManager::editPost(const std::string& username, size_t postIndex, const std::string& newContent) {
    std::lock_guard<std::mutex> lock(mtx);
    auto it = users.find(username);
    if (it == users.end()) throw std::runtime_error("User not found");
    
    it->second.editPost(postIndex, newContent);
    std::cout << "[DEBUG] Post edited by " << username << " at index " << postIndex << std::endl;
}

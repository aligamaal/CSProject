#include "SocialNetworkManager.h"
#include <algorithm>
#include <set>
#include <iostream>  // For debugging
#include <string>
#include "AVLTree.h"
#include "User.h"

// SocialNetworkManager.cpp
void SocialNetworkManager::registerUser(string username, string password) {
    lock_guard<mutex> lock(mtx);
    if (users.find(username) != users.end()) {
        cout << "[DEBUG] User " << username << " already exists in social network\n";
        return; // Gracefully handle existing user
    }
    users.emplace(username, User(username, password));
    cout << "[DEBUG] User registered: " << username << endl;
}

bool SocialNetworkManager::authenticateUser(string username, const string password) {
    lock_guard<mutex> lock(mtx);
    auto it = users.find(username);
    if (it == users.end()) {
        cout << "[DEBUG] User " << username << " not found in social network" << endl;
        return false;
    }
    bool result = it->second.checkPassword(password);
    cout << "[DEBUG] Authentication for " << username << ": " << (result ? "success" : "failed") << endl;
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
    cout << "\n[DEBUG] === Friendship Added ===" << endl;
    cout << "[DEBUG] Between: " << user1 << " and " << user2 << endl;
    
    // Show friends in alphabetical order for both users
    auto friends1 = it1->second.getFriendsList();
    cout << "[DEBUG] " << user1 << "'s friends (should be alphabetical): ";
    for (size_t i = 0; i < friends1.size(); i++) {
        cout << friends1[i];
        if (i < friends1.size() - 1) cout << ", ";
    }
    cout << endl;
    
    auto friends2 = it2->second.getFriendsList();
    cout << "[DEBUG] " << user2 << "'s friends (should be alphabetical): ";
    for (size_t i = 0; i < friends2.size(); i++) {
        cout << friends2[i];
        if (i < friends2.size() - 1) cout << ", ";
    }
    cout << endl;
    
    // Verify alphabetical order
    bool sorted1 = is_sorted(friends1.begin(), friends1.end());
    bool sorted2 = is_sorted(friends2.begin(), friends2.end());
    
    if (!sorted1) cout << "[WARNING] " << user1 << "'s friends are NOT sorted!" << endl;
    if (!sorted2) cout << "[WARNING] " << user2 << "'s friends are NOT sorted!" << endl;
    
    cout << "[DEBUG] ======================" << endl;
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
        cout << "[DEBUG] Getting friends for " << username << ": " << friends.size() << " friends" << endl;
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

    users.erase(username);
}

void SocialNetworkManager::printAllUsers() {
    lock_guard<mutex> lock(mtx);
    cout << "\n=== Registered Users ===" << endl;
    for (const auto& userEntry : users) {
        cout << "- " << userEntry.first;
        auto friends = userEntry.second.getFriendsList();
        if (!friends.empty()) {
            cout << " (Friends: ";
            for (const auto& f : friends) cout << f << " ";
            cout << ")";
        }
        cout << endl;
    }
    cout << "Total users: " << users.size() << endl;
    cout << "=======================" << endl;
}

void SocialNetworkManager::sendRequest(string sender, string receiver) {
    lock_guard<mutex> lock(mtx);
    
    // Debug
    cout << "[DEBUG] Send request from " << sender << " to " << receiver << endl;
    cout << "[DEBUG] Checking if users exist..." << endl;
    
    if (users.find(sender) == users.end()) {
        cout << "[DEBUG] Sender " << sender << " not found!" << endl;
        throw runtime_error("Sender not found");
    }
    if (users.find(receiver) == users.end()) {
        cout << "[DEBUG] Receiver " << receiver << " not found!" << endl;
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
    
    cout << "[DEBUG] Friend request sent successfully" << endl;
    cout << "[DEBUG] Sender " << sender << " now has " << sentRequests[sender].size() << " sent requests" << endl;
    cout << "[DEBUG] Receiver " << receiver << " now has " << receivedRequests[receiver].size() << " received requests" << endl;
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
        cout << "[DEBUG] Friendship added between " << sender << " and " << receiver << endl;
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
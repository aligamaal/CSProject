#include "SocialNetworkManager.h"

void SocialNetworkManager::registerUser(string username, string password) {
    lock_guard<mutex> lock(mtx);
    if (users.find(username) != users.end()) {
        throw runtime_error("Username already exists");
    }
    users.emplace(username, User(username, password));
}

bool SocialNetworkManager::authenticateUser(string username, const string password) {
    lock_guard<mutex> lock(mtx);
    auto it = users.find(username);
    return it != users.end() && it->second.checkPassword(password);
}

void SocialNetworkManager::addFriendship(string user1, string user2) {
    lock_guard<mutex> lock(mtx);
    auto it1 = users.find(user1);
    auto it2 = users.find(user2);

    if (it1 == users.end() || it2 == users.end()) {
        throw runtime_error("User not found");
    }

    it1->second.addFriend(user2);
    it2->second.addFriend(user1);
}

void SocialNetworkManager::removeFriendship(string user1,string user2) {
    lock_guard<mutex> lock(mtx);
    auto it1 = users.find(user1);
    auto it2 = users.find(user2);

    if (it1 != users.end()) it1->second.removeFriend(user2);
    if (it2 != users.end()) it2->second.removeFriend(user1);
}

bool SocialNetworkManager::areFriends(string user1,string user2) {
    lock_guard<mutex> lock(mtx);
    auto it = users.find(user1);
    return it != users.end() && it->second.isFriendWith(user2);
}

vector<string> SocialNetworkManager::getFriends(string username){
    lock_guard<mutex> lock(mtx);
    auto it = users.find(username);
    return it != users.end() ? it->second.getFriendsList() : vector<string>();
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

    users.erase(username);
}

void SocialNetworkManager::printAllUsers() {
    lock_guard<mutex> lock(mtx);
    cout << "\n=== Registered Users ===";
    for (auto userEntry : users) {
        cout << "\n- " << userEntry.first;
        auto friends = userEntry.second.getFriendsList();
        if (!friends.empty()) {
            cout << " (Friends: ";
            for (auto f : friends) cout << f << " ";
            cout << ")";
        }
    }
    cout << "\n=======================\n";
}

    void SocialNetworkManager::sendRequest(string sender, string receiver){
        lock_guard<mutex> lock(mtx);
        if (users.find(sender) == users.end() || users.find(receiver) == users.end()) return;

        sentRequests[sender].push_back(receiver);
        receivedRequests[receiver].push_back(sender);
    }

    void SocialNetworkManager::acceptRequest(string receiver,string sender) {
        lock_guard<mutex> lock(mtx);
        
        addFriendship(sender, receiver);

    
        auto& senderList = sentRequests[sender];
        senderList.erase(remove(senderList.begin(), senderList.end(), receiver), senderList.end());

        auto& receiverList = receivedRequests[receiver];
        receiverList.erase(remove(receiverList.begin(), receiverList.end(), sender), receiverList.end());
    }

    vector<string> SocialNetworkManager::getMutualFriends(string user1, string user2)
    {
        lock_guard<mutex> lock(mtx);
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
                if (candidate == username ||
                    users[username].isFriendWith(candidate)) continue;

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
                return a.second > b.second;  // is for > for descending order
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

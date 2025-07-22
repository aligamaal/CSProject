// Add these includes at the top of Main.cpp
#define CROW_USE_ASIO
#include "crow.h"
#include "User.h"
#include "CORSMiddleware.h"
#include "AuthManager.h"
#include "utils.h"
#include "AVLTree.h"
#include "SocialNetworkManager.h"
#include <unordered_map>
#include <mutex>
#include <string>
#include <random>
#include <sstream>
#include <memory>
#include <iostream>
#include <fstream>
#include <filesystem>
#include <chrono>      // For time measurement
#include <thread>      // For sleep_for
#include <ctime>       // For time functions
#include <iomanip>     // For time formatting
#include <algorithm>   // For min function

using namespace std;

int main()
{   
    crow::App<CORSMiddleware> app;

    auto auth = std::make_shared<AuthManager>();
    auto socialNetwork = std::make_shared<SocialNetworkManager>();

    // Serve HTML file for root endpoint
    CROW_ROUTE(app, "/")([] {
        try {
            ifstream file("login.html");
            if (!file) {
                return crow::response(404, "login.html not found");
            }
            
            string content((istreambuf_iterator<char>(file)), 
                       istreambuf_iterator<char>());
            
            crow::response res(content);
            res.set_header("Content-Type", "text/html");
            
            // Relax CSP for development
            res.set_header("Content-Security-Policy", "default-src * 'unsafe-inline' 'unsafe-eval'; style-src * 'unsafe-inline'; img-src * data:; font-src *;");
            
            return res;
        } catch (const exception& e) {
            return crow::response(500, string("Error loading HTML file: ") + e.what());
        }
    });

    // Signup endpoint with JSON error responses
    // Main.cpp - Signup endpoint
CROW_ROUTE(app, "/api/signup").methods("POST"_method, "OPTIONS"_method)
([auth, socialNetwork](const crow::request& req) {
    crow::response res;
    res.set_header("Content-Type", "application/json");
    
    // Handle CORS preflight
    if (req.method == "OPTIONS"_method) {
        res.add_header("Access-Control-Allow-Methods", "POST, OPTIONS");
        res.add_header("Access-Control-Allow-Headers", "Content-Type");
        res.add_header("Access-Control-Allow-Origin", "*");
        return res;
    }

    auto body = crow::json::load(req.body);
    crow::json::wvalue result;
    
    if (!body) {
        res.code = 400;
        result["success"] = false;
        result["message"] = "Invalid JSON";
        res.write(result.dump());
        return res;
    }

    if (!body.has("username") || !body.has("password")) {
        res.code = 400;
        result["success"] = false;
        result["message"] = "Missing username or password";
        res.write(result.dump());
        return res;
    }

    try {
        std::string username = body["username"].s();
        std::string password = body["password"].s();
        bool success = auth->registerUser(username, password);

        if (success) {
            // FIX: Gracefully handle social network registration
            try {
                // This won't throw anymore for existing users
                socialNetwork->registerUser(username, password);
            } catch (const std::exception& e) {
                // Log but don't fail signup
                std::cout << "[INFO] Social network registration: " << e.what() 
                          << " (user was still created in auth system)" << std::endl;
            }
            
            string token = auth->loginUser(username, password);
            
            result["success"] = true;
            result["username"] = username;
            result["avatar"] = "https://via.placeholder.com/150/1DB954/FFFFFF?text=" + username.substr(0, 1);
            result["token"] = token;
            res.code = 200;
        } else {
            result["success"] = false;
            result["message"] = "Username already exists";
            res.code = 409;
        }
    } catch (const std::exception& e) {
        res.code = 500;
        result["success"] = false;
        result["message"] = "Internal server error";
        // Log the actual error for debugging
        std::cerr << "[ERROR] Signup exception: " << e.what() << std::endl;
    }

    res.add_header("Access-Control-Allow-Origin", "*");
    res.write(result.dump());
    return res;
});
// Add this endpoint to your main.cpp file, after the other routes but before app.port(18080).multithreaded().run();

// Debug endpoint for AVL tree visualization
// Add this complete endpoint to your main.cpp file, before app.port(18080).multithreaded().run();

// Debug endpoint for AVL tree visualization
CROW_ROUTE(app, "/api/debug/avl-tree/<string>").methods("GET"_method)
([auth, socialNetwork](const crow::request& req, std::string username) {
    crow::response res;
    res.set_header("Content-Type", "application/json");
    
    // Optional: Add authentication check
    std::string token = req.get_header_value("Authorization");
    std::string* currentUser = auth->getUsernameFromToken(token);
    
    if (!currentUser) {
        res.code = 401;
        crow::json::wvalue result;
        result["success"] = false;
        result["message"] = "Unauthorized";
        res.write(result.dump());
        return res;
    }
    
    crow::json::wvalue result;
    
    try {
        auto treeInfo = socialNetwork->getUserAVLTreeInfo(username);
        
        result["success"] = true;
        result["username"] = username;
        result["tree"] = move(treeInfo.treeStructure); // No std::move needed here
        result["height"] = treeInfo.height;
        result["count"] = treeInfo.nodeCount;
        result["isBalanced"] = treeInfo.isBalanced;
        result["visual"] = treeInfo.visualRepresentation; // No std::move needed here
        
        // Add the friends list for verification
        auto friends = socialNetwork->getFriends(username);
        crow::json::wvalue friendsArray;
        for (size_t i = 0; i < friends.size(); ++i) {
            friendsArray[static_cast<int>(i)] = friends[i];
        }
        result["friendsList"] = move(friendsArray); // No std::move needed
        
        res.code = 200;
    } catch (const std::exception& e) {
        res.code = 500;
        result["success"] = false;
        result["message"] = std::string("Error getting AVL tree info: ") + e.what();
    }
    
    res.add_header("Access-Control-Allow-Origin", "*");
    res.write(result.dump());
    return res;
});

CROW_ROUTE(app, "/api/debug/all-avl-trees").methods("GET"_method)
([auth, socialNetwork](const crow::request& req) {
    crow::response res;
    res.set_header("Content-Type", "application/json");
    
    // Optional: Add authentication check
    std::string token = req.get_header_value("Authorization");
    std::string* currentUser = auth->getUsernameFromToken(token);
    
    if (!currentUser) {
        res.code = 401;
        crow::json::wvalue result;
        result["success"] = false;
        result["message"] = "Unauthorized";
        res.write(result.dump());
        return res;
    }
    
    crow::json::wvalue result;
    
    try {
        auto allUsers = socialNetwork->getAllUsers();
        crow::json::wvalue usersTreeInfo;
        
        for (size_t i = 0; i < allUsers.size(); ++i) {
            try {
                auto treeInfo = socialNetwork->getUserAVLTreeInfo(allUsers[i]);
                crow::json::wvalue userTree;
                userTree["username"] = allUsers[i];
                userTree["friendCount"] = treeInfo.nodeCount;
                userTree["treeHeight"] = treeInfo.height;
                userTree["isBalanced"] = treeInfo.isBalanced;
                usersTreeInfo[static_cast<int>(i)] = move(userTree); // Cast to int
            } catch (const std::exception& e) {
                crow::json::wvalue userTree;
                userTree["username"] = allUsers[i];
                userTree["error"] = e.what();
                usersTreeInfo[static_cast<int>(i)] = move(userTree); // Cast to int
            }
        }
        
        result["success"] = true;
        result["users"] = move(usersTreeInfo); // No std::move needed
        result["totalUsers"] = static_cast<int>(allUsers.size());
        res.code = 200;
    } catch (const std::exception& e) {
        res.code = 500;
        result["success"] = false;
        result["message"] = std::string("Error getting AVL trees info: ") + e.what();
    }
    
    res.add_header("Access-Control-Allow-Origin", "*");
    res.write(result.dump());
    return res;
});

    // Login endpoint
    CROW_ROUTE(app, "/api/login").methods("POST"_method, "OPTIONS"_method)
    ([auth, socialNetwork](const crow::request& req) {
        crow::response res;
        res.set_header("Content-Type", "application/json");

        // Handle CORS preflight
        if (req.method == "OPTIONS"_method) {
            res.add_header("Access-Control-Allow-Methods", "POST, OPTIONS");
            res.add_header("Access-Control-Allow-Headers", "Content-Type");
            res.add_header("Access-Control-Allow-Origin", "*");
            return res;
        }

        auto body = crow::json::load(req.body);
        crow::json::wvalue result;

        if (!body) {
            res.code = 400;
            result["success"] = false;
            result["message"] = "Bad Request";
            res.write(result.dump());
            return res;
        }

        try {
            std::string username = body["username"].s();
            std::string password = body["password"].s();
            
            // Try to login first
            string token = auth->loginUser(username, password);

            if (!token.empty()) {
                // If login successful, ensure user exists in social network
                try {
                    if (!socialNetwork->authenticateUser(username, password)) {
                        // User doesn't exist in social network, add them
                        socialNetwork->registerUser(username, password);
                    }
                } catch (const std::exception& e) {
                    // If user already exists, that's fine
                    std::cout << "[DEBUG] Social network sync: " << e.what() << std::endl;
                }
                
                result["success"] = true;
                result["username"] = username;
                result["avatar"] = "https://via.placeholder.com/150/1DB954/FFFFFF?text=" + username.substr(0, 1);
                result["token"] = token;
                res.code = 200;
            } else {
                result["success"] = false;
                result["message"] = "Invalid username or password";
                res.code = 401;
            }
        } catch (const std::exception& e) {
            std::cout << "[ERROR] Login exception: " << e.what() << std::endl;
            res.code = 500;
            result["success"] = false;
            result["message"] = string("Internal server error: ") + e.what();
        }

        res.add_header("Access-Control-Allow-Origin", "*");
        res.write(result.dump());
        return res;
    });

    // Get all users endpoint (for searching)
    CROW_ROUTE(app, "/api/users").methods("GET"_method, "OPTIONS"_method)
    ([auth, socialNetwork](const crow::request& req) {
        crow::response res;
        res.set_header("Content-Type", "application/json");
        
        // Handle CORS preflight
        if (req.method == "OPTIONS"_method) {
            res.add_header("Access-Control-Allow-Methods", "GET, OPTIONS");
            res.add_header("Access-Control-Allow-Headers", "Authorization");
            res.add_header("Access-Control-Allow-Origin", "*");
            return res;
        }
        
        string token = req.get_header_value("Authorization");
        string* currentUser = auth->getUsernameFromToken(token);
        
        if (!currentUser) {
            res.code = 401;
            crow::json::wvalue result;
            result["success"] = false;
            result["message"] = "Unauthorized";
            res.write(result.dump());
            return res;
        }
        
        crow::json::wvalue result;
        
        try {
            auto allUsers = socialNetwork->getAllUsers();
            result["success"] = true;
            crow::json::wvalue usersArray;
            int index = 0;
            for (const auto& user : allUsers) {
                if (user != *currentUser) {  // Don't include current user
                    crow::json::wvalue userObj;
                    userObj["username"] = user;
                    userObj["avatar"] = "https://via.placeholder.com/150/1DB954/FFFFFF?text=" + user.substr(0, 1);
                    
                    // Check if already friends
                    if (socialNetwork->areFriends(*currentUser, user)) {
                        userObj["status"] = "friend";
                    } else {
                        userObj["status"] = "not_friend";
                    }
                    
                    usersArray[index++] = std::move(userObj);
                }
            }
            result["users"] = std::move(usersArray);
            result["count"] = index;
            res.code = 200;
        } catch (const std::exception& e) {
            res.code = 500;
            result["success"] = false;
            result["message"] = e.what();
        }
        
        res.add_header("Access-Control-Allow-Origin", "*");
        res.write(result.dump());
        return res;
    });

    // Search users by prefix
    // NEW ENDPOINT: Search friends by prefix using BST
CROW_ROUTE(app, "/api/friends/search/<string>").methods("GET"_method)
([auth, socialNetwork](const crow::request& req, std::string prefix) {
    crow::response res;
    res.set_header("Content-Type", "application/json");
    
    std::string token = req.get_header_value("Authorization");
    std::string* currentUser = auth->getUsernameFromToken(token);
    
    if (!currentUser) {
        res.code = 401;
        crow::json::wvalue result;
        result["success"] = false;
        result["message"] = "Unauthorized";
        res.write(result.dump());
        return res;
    }
    
    crow::json::wvalue result;
    
    try {
        // Use BST-based search on user's friends
        auto matchingFriends = socialNetwork->searchFriendsByPrefix(*currentUser, prefix);
        
        result["success"] = true;
        crow::json::wvalue friendsArray;
        
        for (size_t i = 0; i < matchingFriends.size(); ++i) {
            crow::json::wvalue friendObj;
            friendObj["username"] = matchingFriends[i];
            friendObj["avatar"] = "https://via.placeholder.com/150/1DB954/FFFFFF?text=" + matchingFriends[i].substr(0, 1);
            friendsArray[static_cast<int>(i)] = move(friendObj); // Cast to int
        }
        
        result["friends"] = move(friendsArray); // No std::move needed
        result["count"] = static_cast<int>(matchingFriends.size());
        result["searchMethod"] = "BST-based"; // Indicator that BST search was used
        res.code = 200;
        
        std::cout << "[DEBUG] BST friends search for '" << prefix << "' returned " 
                  << matchingFriends.size() << " results" << std::endl;
        
    } catch (const std::exception& e) {
        res.code = 500;
        result["success"] = false;
        result["message"] = e.what();
        std::cout << "[ERROR] BST friends search error: " << e.what() << std::endl;
    }
    
    res.add_header("Access-Control-Allow-Origin", "*");
    res.write(result.dump());
    return res;
});
CROW_ROUTE(app, "/api/debug/search-performance/<string>").methods("GET"_method)
([auth, socialNetwork](const crow::request& req, std::string prefix) {
    crow::response res;
    res.set_header("Content-Type", "application/json");
    
    std::string token = req.get_header_value("Authorization");
    std::string* currentUser = auth->getUsernameFromToken(token);
    
    if (!currentUser) {
        res.code = 401;
        crow::json::wvalue result;
        result["success"] = false;
        result["message"] = "Unauthorized";
        res.write(result.dump());
        return res;
    }
    
    crow::json::wvalue result;
    
    try {
        auto start = std::chrono::high_resolution_clock::now();
        
        // BST-based search
        auto bstResults = socialNetwork->searchUsersByPrefix(prefix, *currentUser);
        
        auto end = std::chrono::high_resolution_clock::now();
        auto bstDuration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        
        result["success"] = true;
        result["prefix"] = prefix;
        result["bstResultCount"] = static_cast<int>(bstResults.size());
        result["bstSearchTime_microseconds"] = static_cast<int>(bstDuration.count());
        result["searchMethod"] = "AVL Tree BST-based search";
        
        // Include first few results for verification
        crow::json::wvalue resultsArray;
        int maxResults = std::min(5, static_cast<int>(bstResults.size()));
        for (int i = 0; i < maxResults; ++i) {
            resultsArray[i] = bstResults[i];
        }
        result["sampleResults"] = move(resultsArray); // No std::move needed
        
        res.code = 200;
        
        std::cout << "[DEBUG] BST search performance for '" << prefix << "':" << std::endl;
        std::cout << "  - Results: " << bstResults.size() << std::endl;
        std::cout << "  - Time: " << bstDuration.count() << " microseconds" << std::endl;
        
    } catch (const std::exception& e) {
        res.code = 500;
        result["success"] = false;
        result["message"] = e.what();
    }
    
    res.add_header("Access-Control-Allow-Origin", "*");
    res.write(result.dump());
    return res;
});

    // Debug endpoint to print all users
    CROW_ROUTE(app, "/api/debug/users").methods("GET"_method)
    ([socialNetwork](const crow::request&) {
        crow::response res;
        res.set_header("Content-Type", "application/json");
        
        // Print to console
        socialNetwork->printAllUsers();
        
        // Also return as JSON
        crow::json::wvalue result;
        try {
            auto allUsers = socialNetwork->getAllUsers();
            result["success"] = true;
            crow::json::wvalue usersArray;
            for (size_t i = 0; i < allUsers.size(); ++i) {
                usersArray[i] = allUsers[i];
            }
            result["users"] = std::move(usersArray);
            result["count"] = allUsers.size();
            res.code = 200;
        } catch (const std::exception& e) {
            res.code = 500;
            result["success"] = false;
            result["message"] = e.what();
        }
        
        res.add_header("Access-Control-Allow-Origin", "*");
        res.write(result.dump());
        return res;
    });

    // Send friend request
    CROW_ROUTE(app, "/api/friend-request/send").methods("POST"_method)
    ([auth, socialNetwork](const crow::request& req) {
        crow::response res;
        res.set_header("Content-Type", "application/json");
        
        string token = req.get_header_value("Authorization");
        string* sender = auth->getUsernameFromToken(token);
        
        if (!sender) {
            res.code = 401;
            crow::json::wvalue result;
            result["success"] = false;
            result["message"] = "Unauthorized";
            res.write(result.dump());
            return res;
        }
        
        auto body = crow::json::load(req.body);
        crow::json::wvalue result;
        
        if (!body || !body.has("receiver")) {
            res.code = 400;
            result["success"] = false;
            result["message"] = "Missing receiver";
            res.write(result.dump());
            return res;
        }
        
        try {
            string receiver = body["receiver"].s();
            socialNetwork->sendRequest(*sender, receiver);
            result["success"] = true;
            result["message"] = "Friend request sent";
            res.code = 200;
        } catch (const std::exception& e) {
            res.code = 500;
            result["success"] = false;
            result["message"] = e.what();
        }
        
        res.add_header("Access-Control-Allow-Origin", "*");
        res.write(result.dump());
        return res;
    });

    // Accept friend request
    CROW_ROUTE(app, "/api/friend-request/accept").methods("POST"_method)
    ([auth, socialNetwork](const crow::request& req) {
        crow::response res;
        res.set_header("Content-Type", "application/json");
        
        string token = req.get_header_value("Authorization");
        string* receiver = auth->getUsernameFromToken(token);
        
        if (!receiver) {
            res.code = 401;
            crow::json::wvalue result;
            result["success"] = false;
            result["message"] = "Unauthorized";
            res.write(result.dump());
            return res;
        }
        
        auto body = crow::json::load(req.body);
        crow::json::wvalue result;
        
        if (!body || !body.has("sender")) {
            res.code = 400;
            result["success"] = false;
            result["message"] = "Missing sender";
            res.write(result.dump());
            return res;
        }
        
        try {
            string sender = body["sender"].s();
            socialNetwork->acceptRequest(*receiver, sender);
            result["success"] = true;
            result["message"] = "Friend request accepted";
            res.code = 200;
        } catch (const std::exception& e) {
            res.code = 500;
            result["success"] = false;
            result["message"] = e.what();
        }
        
        res.add_header("Access-Control-Allow-Origin", "*");
        res.write(result.dump());
        return res;
    });

    // Reject friend request
    CROW_ROUTE(app, "/api/friend-request/reject").methods("POST"_method)
    ([auth, socialNetwork](const crow::request& req) {
        crow::response res;
        res.set_header("Content-Type", "application/json");
        
        string token = req.get_header_value("Authorization");
        string* receiver = auth->getUsernameFromToken(token);
        
        if (!receiver) {
            res.code = 401;
            crow::json::wvalue result;
            result["success"] = false;
            result["message"] = "Unauthorized";
            res.write(result.dump());
            return res;
        }
        
        auto body = crow::json::load(req.body);
        crow::json::wvalue result;
        
        if (!body || !body.has("sender")) {
            res.code = 400;
            result["success"] = false;
            result["message"] = "Missing sender";
            res.write(result.dump());
            return res;
        }
        
        try {
            string sender = body["sender"].s();
            socialNetwork->rejectRequest(*receiver, sender);
            result["success"] = true;
            result["message"] = "Friend request rejected";
            res.code = 200;
        } catch (const std::exception& e) {
            res.code = 500;
            result["success"] = false;
            result["message"] = e.what();
        }
        
        res.add_header("Access-Control-Allow-Origin", "*");
        res.write(result.dump());
        return res;
    });

    // Get friends list
    CROW_ROUTE(app, "/api/friends").methods("GET"_method)
    ([auth, socialNetwork](const crow::request& req) {
        crow::response res;
        res.set_header("Content-Type", "application/json");
        
        string token = req.get_header_value("Authorization");
        string* username = auth->getUsernameFromToken(token);
        
        if (!username) {
            res.code = 401;
            crow::json::wvalue result;
            result["success"] = false;
            result["message"] = "Unauthorized";
            res.write(result.dump());
            return res;
        }
        
        crow::json::wvalue result;
        
        try {
            auto friends = socialNetwork->getFriends(*username);
            result["success"] = true;
            crow::json::wvalue friendsArray;
            for (size_t i = 0; i < friends.size(); ++i) {
                friendsArray[i] = friends[i];
            }
            result["friends"] = std::move(friendsArray);
            res.code = 200;
        } catch (const std::exception& e) {
            res.code = 500;
            result["success"] = false;
            result["message"] = e.what();
        }
        
        res.add_header("Access-Control-Allow-Origin", "*");
        res.write(result.dump());
        return res;
    });

    // Remove friend
    CROW_ROUTE(app, "/api/friends/remove").methods("POST"_method)
    ([auth, socialNetwork](const crow::request& req) {
        crow::response res;
        res.set_header("Content-Type", "application/json");
        
        string token = req.get_header_value("Authorization");
        string* user1 = auth->getUsernameFromToken(token);
        
        if (!user1) {
            res.code = 401;
            crow::json::wvalue result;
            result["success"] = false;
            result["message"] = "Unauthorized";
            res.write(result.dump());
            return res;
        }
        
        auto body = crow::json::load(req.body);
        crow::json::wvalue result;
        
        if (!body || !body.has("friend")) {
            res.code = 400;
            result["success"] = false;
            result["message"] = "Missing friend username";
            res.write(result.dump());
            return res;
        }
        
        try {
            string user2 = body["friend"].s();
            socialNetwork->removeFriendship(*user1, user2);
            result["success"] = true;
            result["message"] = "Friend removed";
            res.code = 200;
        } catch (const std::exception& e) {
            res.code = 500;
            result["success"] = false;
            result["message"] = e.what();
        }
        
        res.add_header("Access-Control-Allow-Origin", "*");
        res.write(result.dump());
        return res;
    });

    // Get mutual friends
    CROW_ROUTE(app, "/api/friends/mutual/<string>").methods("GET"_method)
    ([auth, socialNetwork](const crow::request& req, string otherUser) {
        crow::response res;
        res.set_header("Content-Type", "application/json");
        
        string token = req.get_header_value("Authorization");
        string* currentUser = auth->getUsernameFromToken(token);
        
        if (!currentUser) {
            res.code = 401;
            crow::json::wvalue result;
            result["success"] = false;
            result["message"] = "Unauthorized";
            res.write(result.dump());
            return res;
        }
        
        crow::json::wvalue result;
        
        try {
            auto mutualFriends = socialNetwork->getMutualFriends(*currentUser, otherUser);
            result["success"] = true;
            crow::json::wvalue mutualArray;
            for (size_t i = 0; i < mutualFriends.size(); ++i) {
                mutualArray[i] = mutualFriends[i];
            }
            result["mutualFriends"] = std::move(mutualArray);
            res.code = 200;
        } catch (const std::exception& e) {
            res.code = 500;
            result["success"] = false;
            result["message"] = e.what();
        }
        
        res.add_header("Access-Control-Allow-Origin", "*");
        res.write(result.dump());
        return res;
    });

    // Get pending friend requests (received)
    CROW_ROUTE(app, "/api/friend-requests/pending").methods("GET"_method)
    ([auth, socialNetwork](const crow::request& req) {
        crow::response res;
        res.set_header("Content-Type", "application/json");
        
        string token = req.get_header_value("Authorization");
        string* username = auth->getUsernameFromToken(token);
        
        if (!username) {
            res.code = 401;
            crow::json::wvalue result;
            result["success"] = false;
            result["message"] = "Unauthorized";
            res.write(result.dump());
            return res;
        }
        
        crow::json::wvalue result;
        
        try {
            auto pendingRequests = socialNetwork->getPendingRequests(*username);
            result["success"] = true;
            crow::json::wvalue requestsArray;
            for (size_t i = 0; i < pendingRequests.size(); ++i) {
                crow::json::wvalue requestObj;
                requestObj["username"] = pendingRequests[i];
                requestObj["avatar"] = "https://via.placeholder.com/150/1DB954/FFFFFF?text=" + pendingRequests[i].substr(0, 1);
                requestsArray[i] = std::move(requestObj);
            }
            result["requests"] = std::move(requestsArray);
            result["count"] = pendingRequests.size();
            res.code = 200;
        } catch (const std::exception& e) {
            res.code = 500;
            result["success"] = false;
            result["message"] = e.what();
        }
        
        res.add_header("Access-Control-Allow-Origin", "*");
        res.write(result.dump());
        return res;
    });

    // Get sent friend requests
    CROW_ROUTE(app, "/api/friend-requests/sent").methods("GET"_method)
    ([auth, socialNetwork](const crow::request& req) {
        crow::response res;
        res.set_header("Content-Type", "application/json");
        
        string token = req.get_header_value("Authorization");
        string* username = auth->getUsernameFromToken(token);
        
        if (!username) {
            res.code = 401;
            crow::json::wvalue result;
            result["success"] = false;
            result["message"] = "Unauthorized";
            res.write(result.dump());
            return res;
        }
        
        crow::json::wvalue result;
        
        try {
            auto sentRequests = socialNetwork->getSentRequests(*username);
            result["success"] = true;
            crow::json::wvalue requestsArray;
            for (size_t i = 0; i < sentRequests.size(); ++i) {
                requestsArray[i] = sentRequests[i];
            }
            result["requests"] = std::move(requestsArray);
            result["count"] = sentRequests.size();
            res.code = 200;
        } catch (const std::exception& e) {
            res.code = 500;
            result["success"] = false;
            result["message"] = e.what();
        }
        
        res.add_header("Access-Control-Allow-Origin", "*");
        res.write(result.dump());
        return res;
    });

    // Get friend suggestions
    CROW_ROUTE(app, "/api/friends/suggestions").methods("GET"_method)
([auth, socialNetwork](const crow::request& req) {
    crow::response res;
    res.set_header("Content-Type", "application/json");
    
    string token = req.get_header_value("Authorization");
    string* username = auth->getUsernameFromToken(token);
    
    if (!username) {
        res.code = 401;
        crow::json::wvalue result;
        result["success"] = false;
        result["message"] = "Unauthorized";
        res.write(result.dump());
        return res;
    }
    
    crow::json::wvalue result;
    
    try {
        // Get the basic suggestions (already sorted by mutual count)
        auto suggestions = socialNetwork->suggestFriends(*username);
        
        result["success"] = true;
        crow::json::wvalue suggestionsArray;
        
        // Limit to top 3 and get mutual friend counts for each
        int maxSuggestions = std::min(3, (int)suggestions.size());
        
        for (int i = 0; i < maxSuggestions; ++i) {
            try {
                // Get mutual friends between current user and suggestion
                auto mutualFriends = socialNetwork->getMutualFriends(*username, suggestions[i]);
                
                crow::json::wvalue suggestionObj;
                suggestionObj["username"] = suggestions[i];
                suggestionObj["avatar"] = "https://via.placeholder.com/150/1DB954/FFFFFF?text=" + suggestions[i].substr(0, 1);
                suggestionObj["mutualCount"] = (int)mutualFriends.size();
                
                // Include the actual mutual friends list
                crow::json::wvalue mutualArray;
                for (size_t j = 0; j < mutualFriends.size(); ++j) {
                    mutualArray[j] = mutualFriends[j];
                }
                suggestionObj["mutualFriends"] = std::move(mutualArray);
                
                suggestionsArray[i] = std::move(suggestionObj);
            } catch (const std::exception& e) {
                // If there's an error getting mutual friends, still include the suggestion with 0 count
                crow::json::wvalue suggestionObj;
                suggestionObj["username"] = suggestions[i];
                suggestionObj["avatar"] = "https://via.placeholder.com/150/1DB954/FFFFFF?text=" + suggestions[i].substr(0, 1);
                suggestionObj["mutualCount"] = 0;
                suggestionObj["mutualFriends"] = crow::json::wvalue();
                
                suggestionsArray[i] = std::move(suggestionObj);
            }
        }
        
        result["suggestions"] = std::move(suggestionsArray);
        result["count"] = maxSuggestions;
        res.code = 200;
    } catch (const std::exception& e) {
        res.code = 500;
        result["success"] = false;
        result["message"] = e.what();
    }
    
    res.add_header("Access-Control-Allow-Origin", "*");
    res.write(result.dump());
    return res;
});
// Add these endpoints to your Main.cpp file before app.port(18080).multithreaded().run();

// Create a new post
CROW_ROUTE(app, "/api/posts").methods("POST"_method)
([auth, socialNetwork](const crow::request& req) {
    crow::response res;
    res.set_header("Content-Type", "application/json");
    
    string token = req.get_header_value("Authorization");
    string* username = auth->getUsernameFromToken(token);
    
    if (!username) {
        res.code = 401;
        crow::json::wvalue result;
        result["success"] = false;
        result["message"] = "Unauthorized";
        res.write(result.dump());
        return res;
    }
    
    auto body = crow::json::load(req.body);
    crow::json::wvalue result;
    
    if (!body || !body.has("content")) {
        res.code = 400;
        result["success"] = false;
        result["message"] = "Missing post content";
        res.write(result.dump());
        return res;
    }
    
    try {
        string content = body["content"].s();
        
        // Validate content
        if (content.empty()) {
            res.code = 400;
            result["success"] = false;
            result["message"] = "Post content cannot be empty";
            res.write(result.dump());
            return res;
        }
        
        if (content.length() > 500) { // Limit post length
            res.code = 400;
            result["success"] = false;
            result["message"] = "Post content too long (max 500 characters)";
            res.write(result.dump());
            return res;
        }
        
        socialNetwork->addPost(*username, content);
        
        result["success"] = true;
        result["message"] = "Post created successfully";
        res.code = 201;
        
        std::cout << "[DEBUG] New post created by " << *username << ": " << content << std::endl;
        
    } catch (const std::exception& e) {
        res.code = 500;
        result["success"] = false;
        result["message"] = string("Error creating post: ") + e.what();
    }
    
    res.add_header("Access-Control-Allow-Origin", "*");
    res.write(result.dump());
    return res;
});
// Add this endpoint to your Main.cpp file, after the other search endpoints but before app.port(18080).multithreaded().run();

// Search all users by prefix (BST-based)
CROW_ROUTE(app, "/api/users/search/<string>").methods("GET"_method)
([auth, socialNetwork](const crow::request& req, std::string prefix) {
    crow::response res;
    res.set_header("Content-Type", "application/json");
    
    std::string token = req.get_header_value("Authorization");
    std::string* currentUser = auth->getUsernameFromToken(token);
    
    if (!currentUser) {
        res.code = 401;
        crow::json::wvalue result;
        result["success"] = false;
        result["message"] = "Unauthorized";
        res.write(result.dump());
        return res;
    }
    
    crow::json::wvalue result;
    
    try {
        // Use BST-based search to find users
        auto matchingUsers = socialNetwork->searchUsersByPrefix(prefix, *currentUser);
        
        result["success"] = true;
        crow::json::wvalue usersArray;
        
        // Convert to the format expected by frontend
        for (size_t i = 0; i < matchingUsers.size(); ++i) {
            crow::json::wvalue userObj;
            userObj["username"] = matchingUsers[i];
            userObj["avatar"] = "https://via.placeholder.com/150/1DB954/FFFFFF?text=" + 
                                matchingUsers[i].substr(0, 1);
            
            // Check relationship status
            if (socialNetwork->areFriends(*currentUser, matchingUsers[i])) {
                userObj["status"] = "friend";
            } else {
                userObj["status"] = "not_friend";
            }
            
            usersArray[static_cast<int>(i)] = std::move(userObj);
        }
        
        result["users"] = std::move(usersArray);
        result["count"] = static_cast<int>(matchingUsers.size());
        result["searchMethod"] = "BST-based";
        res.code = 200;
        
        std::cout << "[DEBUG] User search for '" << prefix << "' returned " 
                  << matchingUsers.size() << " results" << std::endl;
        
    } catch (const std::exception& e) {
        res.code = 500;
        result["success"] = false;
        result["message"] = std::string("Search error: ") + e.what();
        std::cout << "[ERROR] User search error: " << e.what() << std::endl;
    }
    
    res.add_header("Access-Control-Allow-Origin", "*");
    res.write(result.dump());
    return res;
});

// Get timeline (user's posts + friends' posts)
CROW_ROUTE(app, "/api/timeline").methods("GET"_method)
([auth, socialNetwork](const crow::request& req) {
    crow::response res;
    res.set_header("Content-Type", "application/json");
    
    string token = req.get_header_value("Authorization");
    string* username = auth->getUsernameFromToken(token);
    
    if (!username) {
        res.code = 401;
        crow::json::wvalue result;
        result["success"] = false;
        result["message"] = "Unauthorized";
        res.write(result.dump());
        return res;
    }
    
    crow::json::wvalue result;
    
    try {
        auto timeline = socialNetwork->getTimeline(*username);
        
        result["success"] = true;
        crow::json::wvalue postsArray;
        
        // Convert posts to JSON (newest first - already sorted by k-way merge)
        for (size_t i = 0; i < timeline.size(); ++i) {
            crow::json::wvalue postObj;
            postObj["content"] = timeline[i].getContent();
            postObj["author"] = timeline[i].getAuthor();
            postObj["timestamp"] = static_cast<int64_t>(timeline[i].getTimestamp());
            
            // Convert timestamp to readable format
            char timeBuffer[100];
            std::time_t timestamp = timeline[i].getTimestamp();
            std::strftime(timeBuffer, sizeof(timeBuffer), "%Y-%m-%d %H:%M:%S", std::localtime(&timestamp));
            postObj["dateTime"] = std::string(timeBuffer);
            
            // Add author avatar
            postObj["authorAvatar"] = "https://via.placeholder.com/150/1DB954/FFFFFF?text=" + 
                                      timeline[i].getAuthor().substr(0, 1);
            
            // Check if this is user's own post
            postObj["isOwnPost"] = (timeline[i].getAuthor() == *username);
            
            postsArray[i] = std::move(postObj);
        }
        
        result["posts"] = std::move(postsArray);
        result["count"] = timeline.size();
        res.code = 200;
        
        std::cout << "[DEBUG] Timeline requested by " << *username << ", returned " 
                  << timeline.size() << " posts" << std::endl;
        
    } catch (const std::exception& e) {
        res.code = 500;
        result["success"] = false;
        result["message"] = string("Error fetching timeline: ") + e.what();
    }
    
    res.add_header("Access-Control-Allow-Origin", "*");
    res.write(result.dump());
    return res;
});

// Get only user's own posts
CROW_ROUTE(app, "/api/posts/<string>").methods("GET"_method)
([auth, socialNetwork](const crow::request& req, string targetUsername) {
    crow::response res;
    res.set_header("Content-Type", "application/json");
    
    string token = req.get_header_value("Authorization");
    string* currentUser = auth->getUsernameFromToken(token);
    
    if (!currentUser) {
        res.code = 401;
        crow::json::wvalue result;
        result["success"] = false;
        result["message"] = "Unauthorized";
        res.write(result.dump());
        return res;
    }
    
    crow::json::wvalue result;
    
    try {
        auto posts = socialNetwork->getUserPosts(targetUsername);
        
        result["success"] = true;
        crow::json::wvalue postsArray;
        
        // Return posts in reverse order (newest first)
        for (int i = posts.size() - 1; i >= 0; --i) {
            crow::json::wvalue postObj;
            postObj["content"] = posts[i].getContent();
            postObj["author"] = posts[i].getAuthor();
            postObj["timestamp"] = static_cast<int64_t>(posts[i].getTimestamp());
            postObj["index"] = i; // Include index for potential deletion
            
            // Convert timestamp to readable format
            char timeBuffer[100];
            std::time_t timestamp = posts[i].getTimestamp();
            std::strftime(timeBuffer, sizeof(timeBuffer), "%Y-%m-%d %H:%M:%S", std::localtime(&timestamp));
            postObj["dateTime"] = std::string(timeBuffer);
            
            postsArray[posts.size() - 1 - i] = std::move(postObj);
        }
        
        result["posts"] = std::move(postsArray);
        result["count"] = posts.size();
        result["username"] = targetUsername;
        res.code = 200;
        
    } catch (const std::exception& e) {
        res.code = 500;
        result["success"] = false;
        result["message"] = string("Error fetching posts: ") + e.what();
    }
    
    res.add_header("Access-Control-Allow-Origin", "*");
    res.write(result.dump());
    return res;
});

// Debug endpoint to test timeline generation efficiency
CROW_ROUTE(app, "/api/debug/timeline-performance").methods("GET"_method)
([auth, socialNetwork](const crow::request& req) {
    crow::response res;
    res.set_header("Content-Type", "application/json");
    
    string token = req.get_header_value("Authorization");
    string* username = auth->getUsernameFromToken(token);
    
    if (!username) {
        res.code = 401;
        crow::json::wvalue result;
        result["success"] = false;
        result["message"] = "Unauthorized";
        res.write(result.dump());
        return res;
    }
    
    crow::json::wvalue result;
    
    try {
        auto start = std::chrono::high_resolution_clock::now();
        
        // Get timeline
        auto timeline = socialNetwork->getTimeline(*username);
        
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        
        // Get friend count for context
        auto friends = socialNetwork->getFriends(*username);
        
        result["success"] = true;
        result["username"] = *username;
        result["friendCount"] = friends.size();
        result["totalPosts"] = timeline.size();
        result["timelineFetchTime_microseconds"] = (int)duration.count();
        result["algorithm"] = "k-way merge with priority queue";
        
        // Calculate average posts per user
        if (!friends.empty()) {
            result["averagePostsPerFriend"] = (double)timeline.size() / (friends.size() + 1);
        }
        
        res.code = 200;
        
        std::cout << "[DEBUG] Timeline performance for " << *username << ":" << std::endl;
        std::cout << "  - Friends: " << friends.size() << std::endl;
        std::cout << "  - Total posts: " << timeline.size() << std::endl;
        std::cout << "  - Fetch time: " << duration.count() << " microseconds" << std::endl;
        
    } catch (const std::exception& e) {
        res.code = 500;
        result["success"] = false;
        result["message"] = string("Error testing timeline performance: ") + e.what();
    }
    
    res.add_header("Access-Control-Allow-Origin", "*");
    res.write(result.dump());
    return res;
});

// Optional: Endpoint to delete a post (requires User class modification)
CROW_ROUTE(app, "/api/posts/<int>").methods("DELETE"_method)
([auth, socialNetwork](const crow::request& req, int postIndex) {
    crow::response res;
    res.set_header("Content-Type", "application/json");
    
    string token = req.get_header_value("Authorization");
    string* username = auth->getUsernameFromToken(token);
    
    if (!username) {
        res.code = 401;
        crow::json::wvalue result;
        result["success"] = false;
        result["message"] = "Unauthorized";
        res.write(result.dump());
        return res;
    }
    
    crow::json::wvalue result;
    
    try {
        // Note: This requires modification to User class to support post deletion
        result["success"] = false;
        result["message"] = "Post deletion not yet implemented - requires User class modification";
        res.code = 501; // Not Implemented
        
        // When implemented, uncomment:
        // socialNetwork->deletePost(*username, postIndex);
        // result["success"] = true;
        // result["message"] = "Post deleted successfully";
        // res.code = 200;
        
    } catch (const std::exception& e) {
        res.code = 500;
        result["success"] = false;
        result["message"] = string("Error deleting post: ") + e.what();
    }
    
    res.add_header("Access-Control-Allow-Origin", "*");
    res.write(result.dump());
    return res;
});
CROW_ROUTE(app, "/api/posts/<int>").methods("PUT"_method)
([auth, socialNetwork](const crow::request& req, int postIndex) {
    crow::response res;
    res.set_header("Content-Type", "application/json");
    
    string token = req.get_header_value("Authorization");
    string* username = auth->getUsernameFromToken(token);
    
    if (!username) {
        res.code = 401;
        crow::json::wvalue result;
        result["success"] = false;
        result["message"] = "Unauthorized";
        res.write(result.dump());
        return res;
    }
    
    auto body = crow::json::load(req.body);
    crow::json::wvalue result;
    
    if (!body || !body.has("content")) {
        res.code = 400;
        result["success"] = false;
        result["message"] = "Missing new content";
        res.write(result.dump());
        return res;
    }
    
    try {
        string newContent = body["content"].s();
        
        if (newContent.empty()) {
            res.code = 400;
            result["success"] = false;
            result["message"] = "Post content cannot be empty";
            res.write(result.dump());
            return res;
        }
        
        if (newContent.length() > 500) {
            res.code = 400;
            result["success"] = false;
            result["message"] = "Post content too long (max 500 characters)";
            res.write(result.dump());
            return res;
        }
        
        socialNetwork->editPost(*username, postIndex, newContent);
        
        result["success"] = true;
        result["message"] = "Post updated successfully";
        res.code = 200;
        
    } catch (const std::exception& e) {
        res.code = 500;
        result["success"] = false;
        result["message"] = string("Error editing post: ") + e.what();
    }
    
    res.add_header("Access-Control-Allow-Origin", "*");
    res.write(result.dump());
    return res;
});

// Create bulk posts (for testing timeline performance)
CROW_ROUTE(app, "/api/debug/bulk-posts").methods("POST"_method)
([auth, socialNetwork](const crow::request& req) {
    crow::response res;
    res.set_header("Content-Type", "application/json");
    
    string token = req.get_header_value("Authorization");
    string* username = auth->getUsernameFromToken(token);
    
    if (!username) {
        res.code = 401;
        crow::json::wvalue result;
        result["success"] = false;
        result["message"] = "Unauthorized";
        res.write(result.dump());
        return res;
    }
    
    auto body = crow::json::load(req.body);
    crow::json::wvalue result;
    
    if (!body || !body.has("count")) {
        res.code = 400;
        result["success"] = false;
        result["message"] = "Missing count parameter";
        res.write(result.dump());
        return res;
    }
    
    try {
        int count = body["count"].i();
        
        if (count <= 0 || count > 100) {
            res.code = 400;
            result["success"] = false;
            result["message"] = "Count must be between 1 and 100";
            res.write(result.dump());
            return res;
        }
        
        // Create multiple posts for testing
        for (int i = 0; i < count; ++i) {
            std::string content = "Test post #" + std::to_string(i + 1) + 
                                " from " + *username + " at " + 
                                std::to_string(std::time(nullptr));
            socialNetwork->addPost(*username, content);
            
            // Small delay to ensure different timestamps
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        
        result["success"] = true;
        result["message"] = "Created " + std::to_string(count) + " test posts";
        result["count"] = count;
        res.code = 201;
        
    } catch (const std::exception& e) {
        res.code = 500;
        result["success"] = false;
        result["message"] = string("Error creating bulk posts: ") + e.what();
    }
    
    res.add_header("Access-Control-Allow-Origin", "*");
    res.write(result.dump());
    return res;
});


    // Dashboard endpoint
    CROW_ROUTE(app, "/dashboard").methods("GET"_method, "OPTIONS"_method)
    ([auth](const crow::request& req) {
        crow::response res;
        
        // Handle CORS preflight
        if (req.method == "OPTIONS"_method) {
            res.add_header("Access-Control-Allow-Methods", "GET, OPTIONS");
            res.add_header("Access-Control-Allow-Headers", "Authorization");
            res.add_header("Access-Control-Allow-Origin", "*");
            return res;
        }

        try {
            string token = req.get_header_value("Authorization");
            
            if (token.empty()) {
                res.code = 401;
                res.set_header("WWW-Authenticate", "Bearer");
                res.write("Unauthorized: Missing Authorization header");
                return res;
            }

            string* username = auth->getUsernameFromToken(token);
            if (username != nullptr) {
                res.code = 200;
                res.set_header("Content-Type", "text/plain");
                res.add_header("Access-Control-Allow-Origin", "*");
                res.write("Welcome, " + *username + "!");
            } else {
                res.code = 401;
                res.set_header("WWW-Authenticate", "Bearer");
                res.write("Unauthorized: Invalid token");
            }
        } catch (const std::exception& e) {
            res.code = 500;
            res.write("Internal server error");
        }

        return res;
    });
    // Cancel friend request
// Cancel friend request
CROW_ROUTE(app, "/api/friend-request/cancel").methods("POST"_method)
([auth, socialNetwork](const crow::request& req) {
    crow::response res;
    res.set_header("Content-Type", "application/json");
    
    string token = req.get_header_value("Authorization");
    string* sender = auth->getUsernameFromToken(token);
    
    if (!sender) {
        res.code = 401;
        crow::json::wvalue result;
        result["success"] = false;
        result["message"] = "Unauthorized";
        res.write(result.dump());
        return res;
    }
    
    auto body = crow::json::load(req.body);
    crow::json::wvalue result;
    
    if (!body || !body.has("receiver")) {
        res.code = 400;
        result["success"] = false;
        result["message"] = "Missing receiver";
        res.write(result.dump());
        return res;
    }
    
    try {
        string receiver = body["receiver"].s();
        socialNetwork->cancelRequest(*sender, receiver);
        result["success"] = true;
        result["message"] = "Friend request canceled";
        res.code = 200;
    } catch (const std::exception& e) {
        res.code = 500;
        result["success"] = false;
        result["message"] = e.what();
    }
    
    res.add_header("Access-Control-Allow-Origin", "*");
    res.write(result.dump());
    return res;
});
// Debug endpoint to check friend requests state
// Debug endpoint to check friend requests state
CROW_ROUTE(app, "/api/debug/friend-requests").methods("GET"_method)
([socialNetwork](const crow::request&) {
    crow::response res;
    res.set_header("Content-Type", "application/json");
    
    crow::json::wvalue result;
    try {
        auto allRequests = socialNetwork->getAllFriendRequests();
        
        // Convert sent requests to JSON
        crow::json::wvalue sent;
        int i = 0;
        for (const auto& pair : allRequests.first) {
            sent[i]["sender"] = pair.first;
            crow::json::wvalue receivers;
            for (size_t j = 0; j < pair.second.size(); j++) {
                receivers[j] = pair.second[j];
            }
            sent[i]["receivers"] = std::move(receivers);
            i++;
        }
        
        // Convert received requests to JSON
        crow::json::wvalue received;
        i = 0;
        for (const auto& pair : allRequests.second) {
            received[i]["receiver"] = pair.first;
            crow::json::wvalue senders;
            for (size_t j = 0; j < pair.second.size(); j++) {
                senders[j] = pair.second[j];
            }
            received[i]["senders"] = std::move(senders);
            i++;
        }
        
        result["success"] = true;
        result["sentRequests"] = std::move(sent);
        result["receivedRequests"] = std::move(received);
        res.code = 200;
    } catch (const std::exception& e) {
        res.code = 500;
        result["success"] = false;
        result["message"] = e.what();
    }
    
    res.add_header("Access-Control-Allow-Origin", "*");
    res.write(result.dump());
    return res;
});

    // Static file serving for assets
    CROW_ROUTE(app, "/<string>")
    ([](const crow::request& req, string filename) {
        // Prevent directory traversal
        if (filename.find("..") != string::npos) {
            return crow::response(403, "Forbidden");
        }

        // Default to index.html for frontend routes
        if (filename.find('.') == string::npos) {
            filename = "login.html";
        }

        try {
            ifstream file(filename, ios::binary);
            if (!file) {
                return crow::response(404, "File not found: " + filename);
            }

            string content((istreambuf_iterator<char>(file)), 
                       istreambuf_iterator<char>());
            
            crow::response res(content);
            res.set_header("Content-Type", getMimeType(filename));
            res.set_header("Cache-Control", "public, max-age=3600");
            
            // Security headers
            res.set_header("X-Content-Type-Options", "nosniff");
            
            // Relax CSP for development
            if (filename.find(".html") != string::npos) {
                res.set_header("Content-Security-Policy", "default-src * 'unsafe-inline' 'unsafe-eval'; style-src * 'unsafe-inline'; img-src * data:; font-src *;");
            }
            
            return res;
        } catch (const exception& e) {
            return crow::response(500, string("Error loading file: ") + e.what());
        }
    });
    

    app.port(18080).multithreaded().run();
}
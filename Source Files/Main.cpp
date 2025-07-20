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
                // Also register in social network
                socialNetwork->registerUser(username, password);
                
                result["success"] = true;
                result["username"] = username;
                result["avatar"] = "https://via.placeholder.com/150/1DB954/FFFFFF?text=" + username.substr(0, 1);
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
        }

        res.add_header("Access-Control-Allow-Origin", "*");
        res.write(result.dump());
        return res;
    });

    // Login endpoint
    CROW_ROUTE(app, "/api/login").methods("POST"_method, "OPTIONS"_method)
    ([auth](const crow::request& req) {
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
            string token = auth->loginUser(username, password);

            if (!token.empty()) {
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
            res.code = 500;
            result["success"] = false;
            result["message"] = "Internal server error";
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
            auto suggestions = socialNetwork->suggestFriends(*username);
            result["success"] = true;
            crow::json::wvalue suggestionsArray;
            for (size_t i = 0; i < suggestions.size(); ++i) {
                suggestionsArray[i] = suggestions[i];
            }
            result["suggestions"] = std::move(suggestionsArray);
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

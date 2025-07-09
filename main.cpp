#define CROW_USE_ASIO
#include "crow_all.h"
#include <unordered_map>
#include <mutex>
#include <string>
#include <random>
#include <sstream>
#include <memory>
#include <iostream>
#include <fstream>
#include <filesystem>

using namespace std;
namespace fs = std::filesystem;

struct User {
    string username;
    size_t hashedPassword;

    User(const string& uname, const string& password)
        : username(uname), hashedPassword(hashPassword(password)) {}

    static size_t hashPassword(const string& password) {
        return hash<string>{}(password);
    }

    bool checkPassword(const string& password) const {
        return hashedPassword == hashPassword(password);
    }
};

class AuthManager {
private:
    unordered_map<string, User> users;
    unordered_map<string, string> sessions;
    mutex data_mutex;

    string generateToken() {
        stringstream ss;
        static random_device rd;
        static mt19937 gen(rd());
        static uniform_int_distribution<> dis(0, 15);
        for (int i = 0; i < 32; ++i)
            ss << hex << dis(gen);
        return ss.str();
    }

public:
    bool registerUser(const string& username, const string& password) {
        lock_guard<mutex> lock(data_mutex);
        if (users.count(username)) return false;
        users.emplace(username, User(username, password));
        return true;
    }

    string loginUser(const string& username, const string& password) {
        lock_guard<mutex> lock(data_mutex);
        auto it = users.find(username);
        if (it == users.end() || !it->second.checkPassword(password))
            return "";

        string token = generateToken();
        sessions[token] = username;
        return token;
    }

    string* getUsernameFromToken(const string& token) {
        lock_guard<mutex> lock(data_mutex);
        auto it = sessions.find(token);
        if (it != sessions.end()) {
            return &it->second;
        }
        return nullptr;
    }
};

// Enhanced CORS Middleware
struct CORSMiddleware {
    struct context {};

    void before_handle(crow::request& req, crow::response& res, context& /*ctx*/) {
        // Set CORS headers
        res.set_header("Access-Control-Allow-Origin", "*");
        res.set_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        res.set_header("Access-Control-Allow-Headers", "Content-Type, Authorization");
        res.set_header("Access-Control-Allow-Credentials", "true");

        // Handle preflight request
        if (req.method == "OPTIONS"_method) {
            res.code = 200;
            res.end();
            return;
        }
    }

    void after_handle(crow::request& /*req*/, crow::response& /*res*/, context& /*ctx*/) {}
};

string getMimeType(const string& filename) {
    if (filename.find(".html") != string::npos) return "text/html";
    if (filename.find(".css") != string::npos) return "text/css";
    if (filename.find(".js") != string::npos) return "application/javascript";
    if (filename.find(".png") != string::npos) return "image/png";
    if (filename.find(".jpg") != string::npos || filename.find(".jpeg") != string::npos) return "image/jpeg";
    if (filename.find(".gif") != string::npos) return "image/gif";
    if (filename.find(".svg") != string::npos) return "image/svg+xml";
    if (filename.find(".woff") != string::npos) return "font/woff";
    if (filename.find(".woff2") != string::npos) return "font/woff2";
    if (filename.find(".ttf") != string::npos) return "font/ttf";
    if (filename.find(".ico") != string::npos) return "image/x-icon";
    return "text/plain";
}

int main()
{
    crow::App<CORSMiddleware> app;

    auto auth = std::make_shared<AuthManager>();

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
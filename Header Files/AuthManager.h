#ifndef AUTHMANAGER_H
#define AUTHMANAGER_H

#include <string>
#include <unordered_map>
#include <mutex>
#include "User.h"

class AuthManager {
private:
    std::unordered_map<std::string, User> users;
    std::unordered_map<std::string, std::string> sessions;  // token -> username
    std::mutex data_mutex;
    
    std::string generateToken();
    
public:
    bool registerUser(const std::string& username, const std::string& password);
    std::string loginUser(const std::string& username, const std::string& password);
    std::string* getUsernameFromToken(const std::string& token);
};

#endif // AUTHMANAGER_H
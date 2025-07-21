#pragma once
#include <string>
#include <chrono>

class Post {
private:
    std::string content;
    std::string author;
    std::chrono::system_clock::time_point timestamp;
    std::string id; // Unique identifier for the post

public:
    Post(const std::string& content, const std::string& author);
    
    // Getters
    std::string getContent() const;
    std::string getAuthor() const;
    std::string getId() const;
    std::string getTimestamp() const;
    long getTimestampRaw() const; // For sorting
    
    // For JSON serialization
    crow::json::wvalue toJson() const;
};

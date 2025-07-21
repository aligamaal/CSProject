#include "Post.h"
#include "crow.h"
#include <sstream>
#include <iomanip>

Post::Post(const std::string& content, const std::string& author) 
    : content(content), author(author), timestamp(std::chrono::system_clock::now()) {
    // Generate unique ID
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<> dis(0, 15);
    
    std::stringstream ss;
    for(int i = 0; i < 32; ++i) {
        ss << std::hex << dis(gen);
    }
    id = ss.str();
}

std::string Post::getContent() const { return content; }
std::string Post::getAuthor() const { return author; }
std::string Post::getId() const { return id; }

std::string Post::getTimestamp() const {
    auto in_time_t = std::chrono::system_clock::to_time_t(timestamp);
    std::stringstream ss;
    ss << std::put_time(std::localtime(&in_time_t), "%Y-%m-%d %H:%M:%S");
    return ss.str();
}

long Post::getTimestampRaw() const {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        timestamp.time_since_epoch()).count();
}

crow::json::wvalue Post::toJson() const {
    crow::json::wvalue json;
    json["id"] = id;
    json["content"] = content;
    json["author"] = author;
    json["timestamp"] = getTimestamp();
    json["timestamp_raw"] = getTimestampRaw();
    return json;
}

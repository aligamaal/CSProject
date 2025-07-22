#ifndef POST_H
#define POST_H

#include <string>
#include <ctime>

class Post {
private:
    std::string content_;
    std::string author_;
    std::time_t timestamp_;
    
public:
    Post(const std::string& content, const std::string& author);
    
    std::string getContent() const;
    std::string getAuthor() const;
    std::time_t getTimestamp() const;
};

#endif // POST_H
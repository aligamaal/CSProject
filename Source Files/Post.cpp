#include "Post.h"

Post::Post(const std::string& content, const std::string& author)
    : content_(content), author_(author), timestamp_(std::time(nullptr)) {}

std::string Post::getContent() const { return content_; }
std::string Post::getAuthor() const { return author_; }
std::time_t Post::getTimestamp() const { return timestamp_; }
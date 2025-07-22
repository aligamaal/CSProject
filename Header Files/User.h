#ifndef USER_H
#define USER_H

#include <string>
#include <vector>
#include "AVLTree.h"
#include "Post.h"

class User {
private:
    std::string userName;
    std::string salt;
    size_t hashPassword;
    std::vector<Post> posts_;
    
    // Static methods for password handling
    static std::string generateSalt();
    static size_t hashPasswordWithSalt(const std::string& password, const std::string& salt);
    
public:
    AVLTree<std::string> friends;  // Made public for direct access
    
    User();
    User(const std::string& uname, const std::string& password);
    
    // Password methods
    bool checkPassword(const std::string& password) const;
    std::string getSalt();
    size_t getHashPassword();
    
    // Friend management
    void addFriend(const std::string& friendName);
    void removeFriend(const std::string& friendName);
    bool isFriendWith(const std::string& friendName);
    std::vector<std::string> getFriendsList() const;
    AVLTree<std::string>* getFriendsTree() { return &friends; }
    
    // Post management
    void addPost(const std::string& content);
    const std::vector<Post>& getPosts() const;
    std::vector<Post>& getPostsMutable();
    void deletePost(size_t index);
    void editPost(size_t index, const std::string& newContent);
};

#endif // USER_H
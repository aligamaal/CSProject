#ifndef AVLTREE_H
#define AVLTREE_H

#include <vector>
#include <string>

template <typename T>
struct AVLNode {
    T key;
    AVLNode* left;
    AVLNode* right;
    int height;
    
    AVLNode(T k) : key(k), left(nullptr), right(nullptr), height(1) {}
};

template <typename T>
class AVLTree {
private:
    AVLNode<T>* root;
    
    int height(AVLNode<T>* node) const;
    int balanceFactor(AVLNode<T>* node) const;
    void updateHeight(AVLNode<T>* node);
    
    AVLNode<T>* rightRotate(AVLNode<T>* y);
    AVLNode<T>* leftRotate(AVLNode<T>* x);
    AVLNode<T>* leftRightRotate(AVLNode<T>* z);
    AVLNode<T>* rightLeftRotate(AVLNode<T>* z);
    
    AVLNode<T>* insertRecursive(AVLNode<T>* node, T key);
    AVLNode<T>* deleteRecursive(AVLNode<T>* node, T key);
    AVLNode<T>* minValueNode(AVLNode<T>* node);
    
    void inOrderRecursive(AVLNode<T>* node, std::vector<T>& result) const;
    void destroyTree(AVLNode<T>* node);
    
    // New helper methods for BST search
    bool hasPrefix(const T& str, const std::string& prefix) const;
    void searchByPrefixRecursive(AVLNode<T>* node, const std::string& prefix, std::vector<T>& result) const;
    
    // Helper methods for debugging
    int getSizeRecursive(AVLNode<T>* node) const;
    bool isBalancedRecursive(AVLNode<T>* node) const;
    std::string visualizeRecursive(AVLNode<T>* node, std::string prefix, bool isLeft) const;
    
public:
    AVLTree();
    ~AVLTree();
    
    void insert(T key);
    void deleteNode(T key);
    bool search(T key);
    std::vector<T> inOrderTraversal() const;
    std::vector<T> levelOrderTraversal();
    
    // BST-based prefix search
    std::vector<T> searchByPrefix(const std::string& prefix) const;
    
    // Getters for debugging
    AVLNode<T>* getRoot() const { return root; }
    int getHeight() const { return height(root); }
    int getSize() const;
    bool isBalanced() const;
    std::string visualize() const;
};

#endif // AVLTREE_H
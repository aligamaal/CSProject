#pragma once
#ifndef AVLTREE_H
#define AVLTREE_H
#include <vector>
#include <algorithm> // For std::max
#include <cmath>     // For std::abs
#include <string>
#include <sstream>  
using namespace std;

template<typename T>
struct AVLNode{
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

    void destroyTree(AVLNode<T>* node);
    int height(AVLNode<T>* node);
    AVLNode<T>* rightRotate(AVLNode<T>* y);
    AVLNode<T>* leftRotate(AVLNode<T>* x);
    AVLNode<T>* leftRightRotate(AVLNode<T>* z);
    AVLNode<T>* rightLeftRotate(AVLNode<T>* z);
    int balanceFactor(AVLNode<T>* node);
    void updateHeight(AVLNode<T>* node);
    AVLNode<T>* insertRecursive(AVLNode<T>* node, T key);
    AVLNode<T>* deleteRecursive(AVLNode<T>* node, T key);
    AVLNode<T>* minValueNode(AVLNode<T>* node);
    void inOrderRecursive(AVLNode<T>* node, vector<T>& result) const;
    
    int getSizeRecursive(AVLNode<T>* node){
        if (!node) return 0;
        return 1 + getSizeRecursive(node->left) + getSizeRecursive(node->right);
    }
    
    bool isBalancedRecursive(AVLNode<T>* node) {
        if (!node) return true;
        
        int bf = balanceFactor(node);
        if (abs(bf) > 1) return false;
        
        return isBalancedRecursive(node->left) && isBalancedRecursive(node->right);
    }
    
    void visualizeRecursive(AVLNode<T>* node, std::string& result, std::string prefix, bool isLeft) {
        if (!node) return;
        
        if (node->right) {
            visualizeRecursive(node->right, result, prefix + (isLeft ? "│   " : "    "), false);
        }
        
        ostringstream oss;
        oss << node->key;
        result += prefix + (isLeft ? "└── " : "┌── ") + oss.str() + 
               " (h:" + to_string(node->height) + ")\n";
        
        if (node->left) {
            visualizeRecursive(node->left, result, prefix + (isLeft ? "    " : "│   "), true);
        }
    }

public:
    AVLTree();
    ~AVLTree();

    void insert(T key);
    void deleteNode(T key);
    bool search(T key);
    vector<T> inOrderTraversal() const;
    vector<T> levelOrderTraversal();
    AVLNode<T>* getRoot() { return root; }
    
    int getHeight() { 
        return root ? root->height : 0; 
    }
    
    int getSize() {
        return getSizeRecursive(root);
    }
    
    bool isBalanced() {
        return isBalancedRecursive(root);
    }
    
    // Visual representation of the tree
    string visualize() {
        if (!root) return "Empty tree";
        std::string result;
        visualizeRecursive(root, result, "", true);
        return result;
    }
};

#endif
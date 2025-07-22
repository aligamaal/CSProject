#include "AVLTree.h"
#include <iostream>
#include <algorithm>
#include <queue>
#include <vector>
#include <string>
#include <cctype>
using namespace std;

template <typename T>
AVLTree<T>::AVLTree() : root(nullptr) {}

template <typename T>
void AVLTree<T>::destroyTree(AVLNode<T>* node) {
    if (node) {
        destroyTree(node->left);
        destroyTree(node->right);
        delete node;
    }
}

template <typename T>
AVLTree<T>::~AVLTree() {
    destroyTree(root);
}

template <typename T>
int AVLTree<T>::height(AVLNode<T>* node) const {
    return node ? node->height : 0;
}

template <typename T>
AVLNode<T>* AVLTree<T>::rightRotate(AVLNode<T>* y) {
    AVLNode<T>* x = y->left;
    AVLNode<T>* T2 = x->right;

    x->right = y;
    y->left = T2;

    updateHeight(y);
    updateHeight(x);

    return x;
}

template <typename T> 
AVLNode<T>* AVLTree<T>::leftRotate(AVLNode<T>* x) {
    AVLNode<T>* y = x->right;
    AVLNode<T>* T2 = y->left;

    y->left = x;
    x->right = T2;

    updateHeight(x);
    updateHeight(y);

    return y;
}

template <typename T>
AVLNode<T>* AVLTree<T>::leftRightRotate(AVLNode<T>* z) {
    z->left = leftRotate(z->left);
    return rightRotate(z);
}

template <typename T>
AVLNode<T>* AVLTree<T>::rightLeftRotate(AVLNode<T>* z) {
    z->right = rightRotate(z->right);
    return leftRotate(z);
}

template <typename T>
int AVLTree<T>::balanceFactor(AVLNode<T>* node) const {
    return node ? height(node->left) - height(node->right) : 0;
}

template <typename T>
void AVLTree<T>::updateHeight(AVLNode<T>* node) {
    if (node) {
        node->height = 1 + max(height(node->left), height(node->right));
    }
}

template <typename T>
void AVLTree<T>::insert(T key) {
    root = insertRecursive(root, key);
}

template <typename T>
AVLNode<T>* AVLTree<T>::insertRecursive(AVLNode<T>* node, T key) {
    if (!node) return new AVLNode<T>(key);

    if (key < node->key)
        node->left = insertRecursive(node->left, key);
    else if (key > node->key)
        node->right = insertRecursive(node->right, key);
    else
        return node;

    updateHeight(node);
    int bf = balanceFactor(node);

    if (bf > 1) {
        if (key < node->left->key)
            return rightRotate(node);
        else
            return leftRightRotate(node);
    }

    if (bf < -1) {
        if (key > node->right->key)
            return leftRotate(node);
        else
            return rightLeftRotate(node);
    }

    return node;
}

template <typename T>
void AVLTree<T>::deleteNode(T key) {
    root = deleteRecursive(root, key);
}

template <typename T>
AVLNode<T>* AVLTree<T>::deleteRecursive(AVLNode<T>* node, T key) {
    if (!node) return nullptr;

    if (key < node->key) {
        node->left = deleteRecursive(node->left, key);
    }
    else if (key > node->key) {
        node->right = deleteRecursive(node->right, key);
    }
    else {
        if (!node->left || !node->right) {
            AVLNode<T>* temp = node->left ? node->left : node->right;
            if (!temp) {
                delete node;
                return nullptr;
            }
            else {
                delete node;
                return temp;
            }
        }
        else {
            AVLNode<T>* successor = minValueNode(node->right);
            node->key = successor->key;
            node->right = deleteRecursive(node->right, successor->key);
        }
    }

    updateHeight(node);
    int bf = balanceFactor(node);

    if (bf > 1) {
        if (balanceFactor(node->left) >= 0)
            return rightRotate(node);
        else
            return leftRightRotate(node);
    }

    if (bf < -1) {
        if (balanceFactor(node->right) <= 0)
            return leftRotate(node);
        else
            return rightLeftRotate(node);
    }

    return node;
}

template <typename T>
AVLNode<T>* AVLTree<T>::minValueNode(AVLNode<T>* node) {
    AVLNode<T>* current = node;
    while (current && current->left)
        current = current->left;
    return current;
}

template <typename T>
vector<T> AVLTree<T>::inOrderTraversal() const {
    vector<T> result;
    inOrderRecursive(root, result);
    return result;
}

template <typename T>
void AVLTree<T>::inOrderRecursive(AVLNode<T>* node, vector<T>& result) const {
    if (!node) return;
    inOrderRecursive(node->left, result);
    result.push_back(node->key);
    inOrderRecursive(node->right, result);
}

template <typename T>
vector<T> AVLTree<T>::levelOrderTraversal() {
    vector<T> result;
    if (!root) return result;

    queue<AVLNode<T>*> q;
    q.push(root);

    while (!q.empty()) {
        AVLNode<T>* current = q.front();
        q.pop();
        result.push_back(current->key);

        if (current->left) q.push(current->left);
        if (current->right) q.push(current->right);
    }
    return result;
}

template <typename T>
bool AVLTree<T>::search(T key) {
    AVLNode<T>* current = root;
    while (current) {
        if (key == current->key) return true;
        current = (key < current->key) ? current->left : current->right;
    }
    return false;
}

// NEW BST-BASED PREFIX SEARCH IMPLEMENTATION
template <typename T>
bool AVLTree<T>::hasPrefix(const T& str, const string& prefix) const {
    if (prefix.empty()) return true;
    if (str.length() < prefix.length()) return false;
    
    // Convert both to lowercase for case-insensitive comparison
    string lowerStr = str;
    string lowerPrefix = prefix;
    transform(lowerStr.begin(), lowerStr.end(), lowerStr.begin(), ::tolower);
    transform(lowerPrefix.begin(), lowerPrefix.end(), lowerPrefix.begin(), ::tolower);
    
    return lowerStr.substr(0, prefix.length()) == lowerPrefix;
}

template <typename T>
void AVLTree<T>::searchByPrefixRecursive(AVLNode<T>* node, const string& prefix, vector<T>& result) const {
    if (!node) return;
    
    // Convert prefix to lowercase for comparison
    string lowerPrefix = prefix;
    transform(lowerPrefix.begin(), lowerPrefix.end(), lowerPrefix.begin(), ::tolower);
    
    // Convert current node key to lowercase for comparison
    string lowerKey = node->key;
    transform(lowerKey.begin(), lowerKey.end(), lowerKey.begin(), ::tolower);
    
    // BST Property: If current node's key is lexicographically smaller than prefix,
    // all nodes in left subtree will also be smaller, so we only need to search right
    if (lowerKey < lowerPrefix) {
        searchByPrefixRecursive(node->right, prefix, result);
    }
    // BST Property: If current node's key starts with a character greater than 
    // the last character of prefix + 1, then all nodes in right subtree will also
    // be greater, so we only need to search left
    else if (!lowerPrefix.empty() && lowerKey.length() > 0 && 
             lowerKey[0] > lowerPrefix[0] + ('z' - 'a')) {
        searchByPrefixRecursive(node->left, prefix, result);
    }
    // Otherwise, we need to check both subtrees
    else {
        // Search left subtree
        searchByPrefixRecursive(node->left, prefix, result);
        
        // Check current node
        if (hasPrefix(node->key, prefix)) {
            result.push_back(node->key);
        }
        
        // Search right subtree
        searchByPrefixRecursive(node->right, prefix, result);
    }
}

template <typename T>
vector<T> AVLTree<T>::searchByPrefix(const string& prefix) const {
    vector<T> result;
    searchByPrefixRecursive(root, prefix, result);
    
    // Sort the result to maintain consistent ordering
    sort(result.begin(), result.end());
    return result;
}

// Additional utility methods for debugging
template <typename T>
int AVLTree<T>::getSize() const {
    return getSizeRecursive(root);
}

template <typename T>
int AVLTree<T>::getSizeRecursive(AVLNode<T>* node) const {
    if (!node) return 0;
    return 1 + getSizeRecursive(node->left) + getSizeRecursive(node->right);
}

template <typename T>
bool AVLTree<T>::isBalanced() const {
    return isBalancedRecursive(root);
}

template <typename T>
bool AVLTree<T>::isBalancedRecursive(AVLNode<T>* node) const {
    if (!node) return true;
    
    int bf = balanceFactor(node);
    return (abs(bf) <= 1) && 
           isBalancedRecursive(node->left) && 
           isBalancedRecursive(node->right);
}

template <typename T>
string AVLTree<T>::visualize() const {
    if (!root) return "Empty tree";
    return visualizeRecursive(root, "", true);
}

template <typename T>
string AVLTree<T>::visualizeRecursive(AVLNode<T>* node, string prefix, bool isLeft) const {
    if (!node) return "";
    
    string result = "";
    
    if (node->right) {
        result += visualizeRecursive(node->right, prefix + (isLeft ? "│   " : "    "), false);
    }
    
    result += prefix + (isLeft ? "└── " : "┌── ") + node->key + " (h:" + to_string(node->height) + ")\n";
    
    if (node->left) {
        result += visualizeRecursive(node->left, prefix + (isLeft ? "    " : "│   "), true);
    }
    
    return result;
}



// Explicit template instantiation for string type
template class AVLTree<string>;
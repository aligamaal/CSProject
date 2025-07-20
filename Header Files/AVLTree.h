#pragma once
#ifndef AVLTREE_H
#define AVLTREE_H
#include <vector>
using namespace std;

template <typename T>
class AVLTree {
private:
    struct Node {
        T key;
        Node* left;
        Node* right;
        int height;
        Node(T k) : key(k), left(nullptr), right(nullptr), height(1) {}
    };

    Node* root;


    void destroyTree(Node* node);
    int height(Node* node);
    Node* rightRotate(Node* y);
    Node* leftRotate(Node* x);
    Node* leftRightRotate(Node* z);
    Node* rightLeftRotate(Node* z);
    int balanceFactor(Node* node);
    void updateHeight(Node* node);
    Node* insertRecursive(Node* node, T key);
    Node* deleteRecursive(Node* node, T key);
    Node* minValueNode(Node* node);
    void inOrderRecursive(Node* node, vector<T>& result) const;

public:
    AVLTree();
    ~AVLTree();


    void insert(T key);
    void deleteNode(T key);
    bool search(T key);
    vector<T> inOrderTraversal() const;
    vector<T> levelOrderTraversal();
};
#endif
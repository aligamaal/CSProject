#include "AVLTree.h"
#include <iostream>
#include <algorithm>
#include <queue>
#include <vector>
#include <string>
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
int AVLTree<T>::height(AVLNode<T>* node) {
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
int AVLTree<T>::balanceFactor(AVLNode<T>* node) {
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
		// Node found - handle 3 cases
		if (!node->left || !node->right) {
			// Node has 0 or 1 child
			AVLNode<T>* temp = node->left ? node->left : node->right;
			if (!temp) {
				// No children
				delete node;
				return nullptr;
			}
			else {
				// One child: bypass node
				delete node;  // Delete current node
				return temp;  // Replace with child
			}
		}
		else {
			// Node has 2 children
			AVLNode<T>* successor = minValueNode(node->right);
			node->key = successor->key;  // Copy successor's data
			node->right = deleteRecursive(node->right, successor->key);
		}
	}

	// Update height and balance
	updateHeight(node);
	int bf = balanceFactor(node);

	// Left Heavy
	if (bf > 1) {
		if (balanceFactor(node->left) >= 0)
			return rightRotate(node);
		else
			return leftRightRotate(node);
	}

	// Right Heavy
	if (bf < -1) {
		if (balanceFactor(node->right) <= 0)
			return leftRotate(node);
		else
			return rightLeftRotate(node);
	}

	return node;
}

// Find minimum value node
template <typename T>
AVLNode<T>* AVLTree<T>::minValueNode(AVLNode<T>* node) {
	AVLNode<T>* current = node;
	while (current && current->left)
		current = current->left;
	return current;
}

// Traversals
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

// Search
template <typename T>
bool AVLTree<T>::search(T key) {
	AVLNode<T>* current = root;
	while (current) {
		if (key == current->key) return true;
		current = (key < current->key) ? current->left : current->right;
	}
	return false;
}

// Explicit template instantiation for string type
template class AVLTree<string>;
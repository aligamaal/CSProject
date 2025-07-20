#include "AVLTree.h"
#include <iostream>
#include <algorithm>
#include <queue>
#include <vector>
using namespace std;


template <typename T>
AVLTree<T>::AVLTree() : root(nullptr) {}


template <typename T>
void AVLTree<T>::destroyTree(Node* node) {
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
int AVLTree<T>::height(Node* node) {
	return node ? node->height : 0;
}


template <typename T>
typename AVLTree<T>::Node* AVLTree<T>::rightRotate(Node* y) {
	Node* x = y->left;
	Node* T2 = x->right;

	x->right = y;
	y->left = T2;

	updateHeight(y);
	updateHeight(x);

	return x;
}

template <typename T>
typename AVLTree<T>::Node* AVLTree<T>::leftRotate(Node* x) {
	Node* y = x->right;
	Node* T2 = y->left;

	y->left = x;
	x->right = T2;

	updateHeight(x);
	updateHeight(y);

	return y;
}

template <typename T>
typename AVLTree<T>::Node* AVLTree<T>::leftRightRotate(Node* z) {
	z->left = leftRotate(z->left);
	return rightRotate(z);
}

template <typename T>
typename AVLTree<T>::Node* AVLTree<T>::rightLeftRotate(Node* z) {
	z->right = rightRotate(z->right);
	return leftRotate(z);
}


template <typename T>
int AVLTree<T>::balanceFactor(Node* node) {
	return node ? height(node->left) - height(node->right) : 0;
}


template <typename T>
void AVLTree<T>::updateHeight(Node* node) {
	if (node) {
		node->height = 1 + max(height(node->left), height(node->right));
	}
}


template <typename T>
void AVLTree<T>::insert(T key) {
	root = insertRecursive(root, key);
}

template <typename T>
typename AVLTree<T>::Node* AVLTree<T>::insertRecursive(Node* node, T key) {
	if (!node) return new Node(key);

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
typename AVLTree<T>::Node* AVLTree<T>::deleteRecursive(Node* node, T key) {
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
			Node* temp = node->left ? node->left : node->right;
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
			Node* successor = minValueNode(node->right);
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
typename AVLTree<T>::Node* AVLTree<T>::minValueNode(Node* node) {
	Node* current = node;
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
void AVLTree<T>::inOrderRecursive(Node* node, vector<T>& result) const {
	if (!node) return;
	inOrderRecursive(node->left, result);
	result.push_back(node->key);
	inOrderRecursive(node->right, result);
}

template <typename T>
	vector<T> AVLTree<T>::levelOrderTraversal() {
		vector<T> result;
	if (!root) return result;

	queue<Node*> q;
	q.push(root);

	while (!q.empty()) {
		Node* current = q.front();
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
	Node* current = root;
	while (current) {
		if (key == current->key) return true;
		current = (key < current->key) ? current->left : current->right;
	}
	return false;
}

// Explicit template instantiation for string type
template class AVLTree<string>;
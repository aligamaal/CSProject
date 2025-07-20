#pragma once
#ifndef UTILS_H
#define UTILS_H

#define CROW_USE_ASIO
#include "crow.h"
#include "USER.H"
#include <unordered_map>
#include <mutex>
#include <string>
#include <random>
#include <sstream>
#include <memory>
#include <iostream>
#include <fstream>
#include <filesystem>
using namespace std;

string getMimeType(const string&);
#endif

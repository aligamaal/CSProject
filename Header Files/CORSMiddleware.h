#pragma once
#ifndef CORSMIDDLEWARE_H
#define CORSMIDDLEWARE_H

#include "crow.h"
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

struct CORSMiddleware {
    struct context{};

    void before_handle(crow::request& , crow::response& , context&);
    void after_handle(crow::request& , crow::response& , context&);
};

#endif

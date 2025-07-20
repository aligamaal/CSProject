#include "CORSMiddleware.h"
#define CROW_USE_ASIO
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

void CORSMiddleware::before_handle(crow::request& req, crow::response& res, context&){
    // Set CORS headers
        res.set_header("Access-Control-Allow-Origin", "*");
        res.set_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        res.set_header("Access-Control-Allow-Headers", "Content-Type, Authorization");
        res.set_header("Access-Control-Allow-Credentials", "true");

        // Handle preflight request
        if (req.method == "OPTIONS"_method) {
            res.code = 200;
            res.end();
            return;
        }
}
void CORSMiddleware::after_handle(crow::request& /*req*/, crow::response& /*res*/, context&){}

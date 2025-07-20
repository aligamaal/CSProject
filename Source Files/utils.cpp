#include "utils.h"
#define CROW_USE_ASIO
#include "crow.h"
#include "User.H"
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

string getMimeType(const string& filename) {
    if (filename.find(".html") != string::npos) return "text/html";
    if (filename.find(".css") != string::npos) return "text/css";
    if (filename.find(".js") != string::npos) return "application/javascript";
    if (filename.find(".png") != string::npos) return "image/png";
    if (filename.find(".jpg") != string::npos || filename.find(".jpeg") != string::npos) return "image/jpeg";
    if (filename.find(".gif") != string::npos) return "image/gif";
    if (filename.find(".svg") != string::npos) return "image/svg+xml";
    if (filename.find(".woff") != string::npos) return "font/woff";
    if (filename.find(".woff2") != string::npos) return "font/woff2";
    if (filename.find(".ttf") != string::npos) return "font/ttf";
    if (filename.find(".ico") != string::npos) return "image/x-icon";
    return "text/plain";
}

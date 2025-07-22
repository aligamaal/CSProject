#ifndef CORSMIDDLEWARE_H
#define CORSMIDDLEWARE_H

#include "crow.h"

struct CORSMiddleware {
    struct context {};
    
    void before_handle(crow::request& req, crow::response& res, context& ctx);
    void after_handle(crow::request& req, crow::response& res, context& ctx);
};

#endif // CORSMIDDLEWARE_H
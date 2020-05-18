#pragma once

#include <string>
#include <vector>

#include "options.h"
#include "data.h"

class AuthRepository
{
public:
    virtual ~AuthRepository() {}

    virtual bool init(const PluginOptions /*options*/) { return true; }
    virtual void cleanup() {}

    virtual bool get_user(const std::string &username, User &user) = 0;
    virtual void get_acl_rules(std::vector<AclRule> &rules) = 0;
};
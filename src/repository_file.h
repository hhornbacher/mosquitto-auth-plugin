#pragma once

#include <map>

#include "repository.h"

class FileAuthRepository : public AuthRepository
{
public:
    virtual bool init(const PluginOptions options);

    virtual bool get_user(const std::string &username, User &user);
    virtual void get_acl_rules(std::vector<AclRule> &rules);

protected:
    void split_string(std::string input, std::vector<std::string> &output, char delimiter);

    bool load_users();
    bool load_acl_rules();

private:
    std::string m_base_path;

    std::map<std::string, User> m_users;
    std::vector<AclRule> m_acl_rules;
};
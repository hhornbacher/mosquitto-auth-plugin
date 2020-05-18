#include "repository_file.h"

#include <map>
#include <fstream>
#include <sstream>

#include <mosquitto.h>

extern "C"
{
#include <mosquitto_broker.h>
}

bool FileAuthRepository::init(const PluginOptions options)
{
    m_base_path = options.get("repo_path");
    if (m_base_path == "")
    {
        mosquitto_log_printf(MOSQ_LOG_ERR, "File repo path not configured!");
        return false;
    }

    if (!load_users())
    {
        mosquitto_log_printf(MOSQ_LOG_ERR, "Unable to load users from file!");
        return false;
    }

    if (!load_acl_rules())
    {
        mosquitto_log_printf(MOSQ_LOG_ERR, "Unable to load ACL rules from file!");
        return false;
    }

    return true;
}

bool FileAuthRepository::get_user(const std::string &username, User &user)
{
    if (m_users.find(username) != m_users.end())
    {
        user = m_users[username];
        return true;
    }
    return false;
}

void FileAuthRepository::get_acl_rules(std::vector<AclRule> &rules)
{
    AclRule rule;
    rule.access = AclAccess::Read | AclAccess::Write | AclAccess::Subscribe;
    rule.group = "controller";
    rule.topic = "controller/test";
    rules.push_back(rule);
    rule.access = AclAccess::Read | AclAccess::Write | AclAccess::Subscribe;
    rule.group = "device";
    rule.topic = "device/test";
    rules.push_back(rule);
}

void FileAuthRepository::split_string(std::string input, std::vector<std::string> &output, char delimiter)
{
    std::istringstream stringStream(input);
    std::string field;
    while (std::getline(stringStream, field, delimiter))
    {
        output.push_back(field);
    }
}

bool FileAuthRepository::load_users()
{
    std::ifstream usersFile(m_base_path + "/users.txt", std::ifstream::in);

    std::string line;
    while (std::getline(usersFile, line))
    {
        if (line == "")
            continue;

        User user;

        std::vector<std::string> fields;

        split_string(line, fields, ';');

        if (fields.size() != 3)
        {
            mosquitto_log_printf(MOSQ_LOG_ERR, "Cannot parse line: %s", line.c_str());
            mosquitto_log_printf(MOSQ_LOG_ERR, "Wrong field count: %d != 3", fields.size());
            return false;
        }

        user.name = fields[0];
        user.password_hash = fields[1];
        split_string(fields[2], user.groups, ',');

        m_users[user.name] = user;
    }
    return true;
}

bool FileAuthRepository::load_acl_rules()
{
    std::ifstream aclFile(m_base_path + "/acl.txt", std::ifstream::in);

    std::string line;
    while (std::getline(aclFile, line))
    {
        if (line == "")
            continue;

        AclRule acl_rule;

        std::vector<std::string> fields;

        split_string(line, fields, ';');

        if (fields.size() != 3)
        {
            mosquitto_log_printf(MOSQ_LOG_ERR, "Cannot parse line: %s", line.c_str());
            mosquitto_log_printf(MOSQ_LOG_ERR, "Wrong field count: %d != 3", fields.size());
            return false;
        }

        acl_rule.group = fields[0];
        acl_rule.topic = fields[1];
        acl_rule.access = AclAccess::None;
        std::vector<std::string> access_flags;
        split_string(fields[2], access_flags, ',');
        for (auto a : access_flags)
        {
            if (a == "READ")
            {
                acl_rule.access |= AclAccess::Read;
            }
            else if (a == "WRITE")
            {
                acl_rule.access |= AclAccess::Write;
            }
            else if (a == "SUBSCRIBE")
            {
                acl_rule.access |= AclAccess::Subscribe;
            }
        }

        m_acl_rules.push_back(acl_rule);
    }
    return true;
}
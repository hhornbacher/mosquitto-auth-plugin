#pragma once

#include <map>
#include <string>
#include <memory>

extern "C"
{
#include <mosquitto_plugin.h>
}

#include "repository.h"

class MosquittoAuthPlugin
{
public:
    using Options = std::map<std::string, std::string>;

    MosquittoAuthPlugin(std::unique_ptr<AuthRepository> repo) : repo(std::move(repo)) {}

    int security_init(const Options opts, const bool reload);
    int security_cleanup(const Options opts, const bool reload);
    int acl_check(int access, mosquitto *client, const mosquitto_acl_msg *msg);
    int unpwd_check(mosquitto *client, const char *username, const char *password);

private:
    std::unique_ptr<AuthRepository> repo;
};
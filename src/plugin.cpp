#include "plugin.h"

#include <cstdio>
#include <algorithm>

#include <libscrypt.h>

#include <mosquitto.h>

extern "C"
{
#include <mosquitto_broker.h>
}

int MosquittoAuthPlugin::security_init(const PluginOptions opts, const bool reload)
{
    mosquitto_log_printf(MOSQ_LOG_DEBUG, "security_init");
    mosquitto_log_printf(MOSQ_LOG_DEBUG, "  Options:");
    for (auto opt : opts)
    {
        mosquitto_log_printf(MOSQ_LOG_DEBUG, "    %s=%s", opt.first.c_str(), opt.second.c_str());
    }
    mosquitto_log_printf(MOSQ_LOG_DEBUG, "  Reload: %d", reload);
    if (!m_repo->init(opts))
    {
        return MOSQ_ERR_NOT_SUPPORTED;
    }

    return MOSQ_ERR_SUCCESS;
}
int MosquittoAuthPlugin::security_cleanup(const PluginOptions opts, const bool reload)
{
    mosquitto_log_printf(MOSQ_LOG_DEBUG, "security_cleanup");
    mosquitto_log_printf(MOSQ_LOG_DEBUG, "  Options:");
    for (auto opt : opts)
    {
        mosquitto_log_printf(MOSQ_LOG_DEBUG, "    %s=%s", opt.first.c_str(), opt.second.c_str());
    }
    mosquitto_log_printf(MOSQ_LOG_DEBUG, "  Reload: %d", reload);
    m_repo->cleanup();
    return MOSQ_ERR_SUCCESS;
}
int MosquittoAuthPlugin::acl_check(int access, mosquitto *client, const mosquitto_acl_msg *msg)
{
    mosquitto_log_printf(MOSQ_LOG_DEBUG, "acl_check");
    mosquitto_log_printf(MOSQ_LOG_DEBUG, "  Access: %d", access);
    mosquitto_log_printf(MOSQ_LOG_DEBUG, "  Address: %s", mosquitto_client_address(client));
    mosquitto_log_printf(MOSQ_LOG_DEBUG, "  ID: %s", mosquitto_client_id(client));
    mosquitto_log_printf(MOSQ_LOG_DEBUG, "  Username: %s", mosquitto_client_username(client));
    mosquitto_log_printf(MOSQ_LOG_DEBUG, "  Topic: %s", msg->topic);

    std::string username = mosquitto_client_username(client);

    User user;
    if (m_repo->get_user(username, user))
    {
        std::vector<AclRule> rules;
        m_repo->get_acl_rules(rules);

        for (auto rule : rules)
        {
            if (msg->topic == rule.topic)
            {
                if (
                    (access == MOSQ_ACL_SUBSCRIBE && rule.access & AclAccess::Subscribe) ||
                    (access == MOSQ_ACL_READ && rule.access & AclAccess::Read) ||
                    (access == MOSQ_ACL_WRITE && rule.access & AclAccess::Write))
                {
                    if (std::find(user.groups.begin(), user.groups.end(), rule.group) != user.groups.end())
                    {
                        mosquitto_log_printf(MOSQ_LOG_DEBUG, "ACL success for user: %s", user.name.c_str());
                        return MOSQ_ERR_SUCCESS;
                    }
                    mosquitto_log_printf(MOSQ_LOG_WARNING, "ACL failed for user: %s G", user.name.c_str());
                    return MOSQ_ERR_ACL_DENIED;
                }
            }
        }
        mosquitto_log_printf(MOSQ_LOG_WARNING, "ACL failed for user: %s R", user.name.c_str());
        return MOSQ_ERR_ACL_DENIED;
    }
    mosquitto_log_printf(MOSQ_LOG_WARNING, "ACL Unknown user: %s", username);
    return MOSQ_ERR_ACL_DENIED;
}
int MosquittoAuthPlugin::unpwd_check(mosquitto *client, const char *username, const char *password)
{
    mosquitto_log_printf(MOSQ_LOG_DEBUG, "unpwd_check");
    mosquitto_log_printf(MOSQ_LOG_DEBUG, "  Address: %s", mosquitto_client_address(client));
    mosquitto_log_printf(MOSQ_LOG_DEBUG, "  ID: %s", mosquitto_client_id(client));
    mosquitto_log_printf(MOSQ_LOG_DEBUG, "  Username: %s", username);
    mosquitto_log_printf(MOSQ_LOG_DEBUG, "  Password: %s", password);

    User user;
    if (m_repo->get_user(username, user))
    {
        if (libscrypt_check(&user.password_hash[0], password))
        {
            mosquitto_log_printf(MOSQ_LOG_DEBUG, "User authorized: %s", user.name.c_str());
            return MOSQ_ERR_SUCCESS;
        }
        mosquitto_log_printf(MOSQ_LOG_WARNING, "User NOT authorized: %s", user.name.c_str());
        return MOSQ_ERR_AUTH;
    }
    mosquitto_log_printf(MOSQ_LOG_WARNING, "Unknown user: %s", username);
    return MOSQ_ERR_AUTH;
}
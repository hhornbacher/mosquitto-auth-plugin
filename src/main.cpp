#include <cstring>

#include <mosquitto.h>

#include "plugin.h"
#include "options.h"
#include "repository_file.h"

extern "C"
{
#include <mosquitto_broker.h>
#include <mosquitto_plugin.h>

    int mosquitto_auth_plugin_version(void)
    {
        return MOSQ_AUTH_PLUGIN_VERSION;
    }

    int mosquitto_auth_plugin_init(void **user_data, struct mosquitto_opt *opts, int opt_count)
    {
        mosquitto_log_printf(MOSQ_LOG_DEBUG, "Initialize auth plugin");
        PluginOptions options;
        options.load_mosquitto_opts(opts, opt_count);

        auto repo_backend = options.get("repo_backend", "file");

        std::unique_ptr<AuthRepository> repo;
        if (repo_backend == "file")
        {
            repo = std::make_unique<FileAuthRepository>();
        }
        else
        {
            mosquitto_log_printf(MOSQ_LOG_ERR, "You need to configure a supported repository backend: %s not available", repo_backend.c_str());
            return MOSQ_ERR_NOT_SUPPORTED;
        }

        *user_data = (void *)new MosquittoAuthPlugin(
            std::move(repo));
        return MOSQ_ERR_SUCCESS;
    }

    int mosquitto_auth_plugin_cleanup(void *user_data, struct mosquitto_opt * /*opts*/, int /*opt_count*/)
    {
        mosquitto_log_printf(MOSQ_LOG_DEBUG, "Cleanup auth plugin");
        if (user_data != NULL)
        {
            auto plugin = static_cast<MosquittoAuthPlugin *>(user_data);
            delete plugin;
        }
        return MOSQ_ERR_SUCCESS;
    }

    int mosquitto_auth_security_init(void *user_data, struct mosquitto_opt *opts, int opt_count, bool reload)
    {
        auto plugin = static_cast<MosquittoAuthPlugin *>(user_data);
        PluginOptions options;
        options.load_mosquitto_opts(opts, opt_count);
        return plugin->security_init(options, reload);
    }

    int mosquitto_auth_security_cleanup(void *user_data, struct mosquitto_opt *opts, int opt_count, bool reload)
    {
        auto plugin = static_cast<MosquittoAuthPlugin *>(user_data);
        PluginOptions options;
        options.load_mosquitto_opts(opts, opt_count);
        return plugin->security_cleanup(options, reload);
    }

    int mosquitto_auth_acl_check(void *user_data, int access, struct mosquitto *client, const struct mosquitto_acl_msg *msg)
    {
        auto plugin = static_cast<MosquittoAuthPlugin *>(user_data);
        return plugin->acl_check(access, client, msg);
    }

    int mosquitto_auth_unpwd_check(void *user_data, struct mosquitto *client, const char *username, const char *password)
    {
        auto plugin = static_cast<MosquittoAuthPlugin *>(user_data);
        return plugin->unpwd_check(client, username, password);
    }
}
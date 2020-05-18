#include "options.h"

extern "C"
{
#include <mosquitto_plugin.h>
}

void PluginOptions::load_mosquitto_opts(struct mosquitto_opt *opts, int opt_count)
{
    for (int i = 0; i < opt_count; ++i)
    {
        (*this)[opts[i].key] = opts[i].value;
    }
}

std::string PluginOptions::get(const std::string key, const std::string default_value) const
{
    if (find(key) != end())
    {
        return at(key);
    }
    return default_value;
}
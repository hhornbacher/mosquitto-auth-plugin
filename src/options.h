#pragma once

#include <map>
#include <string>

struct mosquitto_opt;

class PluginOptions : public std::map<std::string, std::string>
{
public:
    void load_mosquitto_opts(mosquitto_opt *opts, int opt_count);
    std::string get(std::string key, const std::string default_value = "") const;
};
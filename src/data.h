#pragma once

#include <string>
#include <vector>
#include <type_traits>

enum AclAccess : uint8_t
{
    None = 0x00,
    Read = 0x01,
    Write = 0x02,
    Subscribe = 0x04
};

inline AclAccess operator|(AclAccess lhs, AclAccess rhs)
{
    using T = std::underlying_type_t<AclAccess>;
    return static_cast<AclAccess>(static_cast<T>(lhs) | static_cast<T>(rhs));
}

inline AclAccess &operator|=(AclAccess &lhs, AclAccess rhs)
{
    lhs = lhs | rhs;
    return lhs;
}

struct User
{
    std::string name;
    std::string password_hash;
    std::vector<std::string> groups;
};

struct AclRule
{
    std::string topic;
    std::string group;
    AclAccess access;
};
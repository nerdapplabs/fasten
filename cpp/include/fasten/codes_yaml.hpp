// fasten/codes_yaml.hpp — catalog YAML loader (P1-11 C++).
//
// Optional, opt-in header. fasten.hpp itself stays free of yaml-cpp;
// only adopters who #include this header pay the dep.
//
//   // Cmake / build system: link yaml-cpp
//   #include "fasten.hpp"
//   #include "fasten/codes_yaml.hpp"
//
//   fasten::codes::load("fleet.codes.yaml");   // throws on error
//   fasten::codes::reload();                    // atomic + fault-tolerant
//
// Reload semantics match Python / Go / JS / Rust:
// - Atomic: parse + validate fully into a fresh map; only swap if
//   everything succeeds.
// - Fault-tolerant: any error during reload (parse, invalid severity,
//   missing field) leaves the previous catalog active and throws.
// - NOT additive: codes removed from the yaml become unknown after the
//   swap. Programmatic register_codes() entries survive reload.
#pragma once

#include "../fasten.hpp"

#include <yaml-cpp/yaml.h>

#include <fstream>
#include <mutex>
#include <set>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>

namespace fasten {
namespace codes {
namespace detail_yaml {

inline std::mutex& yaml_mu() { static std::mutex m; return m; }
inline std::vector<std::string>& loaded_paths() {
    static std::vector<std::string> v; return v;
}
inline std::set<std::string>& yaml_codes() {
    static std::set<std::string> s; return s;
}

inline bool is_upper_snake(const std::string& s) {
    if (s.empty() || !(s[0] >= 'A' && s[0] <= 'Z')) return false;
    for (size_t i = 1; i < s.size(); ++i) {
        char c = s[i];
        if (!((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_'))
            return false;
    }
    return true;
}

inline Sev parse_severity(const std::string& s) {
    if (s.empty() || s == "info") return Sev::Info;
    if (s == "debug")    return Sev::Debug;
    if (s == "warn")     return Sev::Warn;
    if (s == "error")    return Sev::Error;
    if (s == "critical") return Sev::Critical;
    throw AuditCatalogError(
        "severity='" + s + "' is not one of {debug,info,warn,error,critical}");
}

inline Retention parse_retention(const std::string& s) {
    if (s.empty() || s == "medium") return Retention::Medium;
    if (s == "short") return Retention::Short;
    if (s == "long")  return Retention::Long;
    throw AuditCatalogError(
        "retention_class='" + s + "' is not one of {short,medium,long}");
}

// Parse + validate every yaml file into a fresh map. Throws on first error;
// caller's live registry is untouched until this returns successfully.
inline std::unordered_map<std::string, Meta> build_from_paths(
    const std::vector<std::string>& paths)
{
    std::unordered_map<std::string, Meta> fresh;

    for (const auto& path : paths) {
        std::ifstream in(path);
        if (!in) {
            throw AuditCatalogError("fasten: reading " + path + ": cannot open");
        }
        std::stringstream ss;
        ss << in.rdbuf();
        const std::string text = ss.str();

        YAML::Node doc;
        try {
            doc = YAML::Load(text);
        } catch (const YAML::Exception& e) {
            throw AuditCatalogError(
                "fasten: parsing " + path + ": " + e.what());
        }
        if (!doc.IsMap()) {
            throw AuditCatalogError(
                "fasten: " + path + " — top-level must be a mapping");
        }

        const auto file_domain = doc["domain"].as<std::string>("");
        if (file_domain.empty()) {
            throw AuditCatalogError(
                "fasten: " + path + " — top-level 'domain' is required");
        }
        const auto file_emitter = doc["emitter"].as<std::string>("");

        const auto codes_node = doc["codes"];
        if (codes_node && !codes_node.IsMap()) {
            throw AuditCatalogError(
                "fasten: " + path + " — 'codes' must be a mapping");
        }

        for (const auto& kv : codes_node) {
            const auto code = kv.first.as<std::string>();
            if (!is_upper_snake(code)) {
                throw AuditCatalogError(
                    "fasten: " + path + ":" + code +
                    " — code key must be UPPER_SNAKE_CASE");
            }
            if (fresh.count(code)) {
                throw AuditCatalogError(
                    "fasten: " + path + ":" + code + " — duplicate code in yaml");
            }
            const auto& raw = kv.second;
            if (!raw.IsMap()) {
                throw AuditCatalogError(
                    "fasten: " + path + ":" + code + " — entry must be a mapping");
            }

            const auto code_domain = raw["domain"].as<std::string>("");
            if (!code_domain.empty() && code_domain != file_domain) {
                throw AuditCatalogError(
                    "fasten: " + path + ":" + code +
                    " — domain='" + code_domain +
                    "' disagrees with file-level domain='" + file_domain + "'");
            }
            Meta meta;
            try {
                meta.id              = code;
                meta.domain          = file_domain;
                meta.category        = raw["category"].as<std::string>("");
                meta.action          = raw["action"].as<std::string>("");
                meta.severity        = parse_severity(raw["severity"].as<std::string>(""));
                meta.description     = raw["description"].as<std::string>("");
                meta.emitter         = raw["emitter"].as<std::string>(file_emitter);
                meta.retention_class = parse_retention(raw["retention_class"].as<std::string>(""));
                meta.high_volume     = raw["high_volume"].as<bool>(false);
                meta.pii_in_detail   = raw["pii_in_detail"].as<bool>(false);
            } catch (const AuditCatalogError& e) {
                throw AuditCatalogError(
                    "fasten: " + path + ":" + code + " — " + std::string(e.what()).substr(8));
            }

            fresh.emplace(code, std::move(meta));
        }
    }
    return fresh;
}

}  // namespace detail_yaml

// Initial load — throws on error (startup-safe). Subsequent reload() calls
// re-read all paths previously passed to load.
inline void load(const std::string& path) {
    std::lock_guard<std::mutex> ylk(detail_yaml::yaml_mu());
    auto fresh = detail_yaml::build_from_paths({path});

    auto& g = ::fasten::detail_::globals();
    std::lock_guard<std::mutex> rlk(g.reg_mu);

    auto& yc = detail_yaml::yaml_codes();
    for (const auto& kv : fresh) {
        if (g.registry.count(kv.first) && !yc.count(kv.first)) {
            throw AuditCatalogError(
                "fasten.load: " + path + ":" + kv.first +
                " — duplicate code (already registered programmatically)");
        }
    }
    for (auto& kv : fresh) {
        g.registry[kv.first] = std::move(kv.second);
        yc.insert(kv.first);
    }

    auto& paths = detail_yaml::loaded_paths();
    if (std::find(paths.begin(), paths.end(), path) == paths.end()) {
        paths.push_back(path);
    }
}

// Re-read every previously-loaded path and atomically swap.
//
// Atomic + fault-tolerant: parse + validate fully into a fresh map;
// any error throws and the previous catalog stays active.
// Reload is NOT additive — codes removed from yaml become unknown.
// Programmatic register_codes() codes survive reload.
inline void reload() {
    std::vector<std::string> paths_snapshot;
    {
        std::lock_guard<std::mutex> ylk(detail_yaml::yaml_mu());
        paths_snapshot = detail_yaml::loaded_paths();
    }
    if (paths_snapshot.empty()) return;

    auto fresh = detail_yaml::build_from_paths(paths_snapshot);

    std::lock_guard<std::mutex> ylk(detail_yaml::yaml_mu());
    auto& g = ::fasten::detail_::globals();
    std::lock_guard<std::mutex> rlk(g.reg_mu);

    auto& yc = detail_yaml::yaml_codes();
    // Drop entries that came from yaml in the previous load.
    for (const auto& code : yc) {
        g.registry.erase(code);
    }
    yc.clear();
    // Insert fresh yaml-derived entries.
    for (auto& kv : fresh) {
        yc.insert(kv.first);
        g.registry[kv.first] = std::move(kv.second);
    }
}

}  // namespace codes
}  // namespace fasten

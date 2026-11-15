// Every case in spec/redact-conformance.json, run through the fasten_redact()
// C ABI directly. The cases are read from the spec file (FASTEN_SPEC_DIR is
// set by CMake), so a new case there is run here without a copy.

#include "fasten.hpp"

#include <cstdlib>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

namespace {

std::string redact(const std::string& name, const std::string& json) {
    char* out  = nullptr;
    char* err  = nullptr;
    int32_t rc = fasten_redact(json.c_str(), &out, &err);
    if (rc != 0) {
        std::cerr << "FAIL [" << name << "] fasten_redact error: "
                  << (err ? err : "?") << "\n";
        fasten_store_free_str(err);
        std::exit(1);
    }
    std::string got(out ? out : "");
    fasten_store_free_str(out);
    return got;
}

// The JSON value that starts at s[i] (after whitespace): a string, or an
// object or array with balanced brackets. Leaves i just past it.
std::string json_value(const std::string& s, std::size_t& i) {
    while (i < s.size() && (s[i] == ' ' || s[i] == '\n' || s[i] == '\t' || s[i] == '\r')) ++i;
    const std::size_t start = i;
    int  depth     = 0;
    bool in_string = false;
    for (; i < s.size(); ++i) {
        const char c = s[i];
        if (in_string) {
            if (c == '\\') ++i;
            else if (c == '"') {
                in_string = false;
                if (depth == 0) { ++i; break; }
            }
        } else if (c == '"') {
            in_string = true;
        } else if (c == '{' || c == '[') {
            ++depth;
        } else if (c == '}' || c == ']') {
            if (--depth == 0) { ++i; break; }
        }
    }
    return s.substr(start, i - start);
}

// The value of the next `"key":` at or after `from`; npos-safe.
bool next_field(const std::string& s, const std::string& key, std::size_t& from,
                std::string& value) {
    const std::string needle = "\"" + key + "\":";
    const std::size_t at = s.find(needle, from);
    if (at == std::string::npos) return false;
    std::size_t i = at + needle.size();
    value = json_value(s, i);
    from = i;
    return true;
}

int run_all() {
    const std::string path = std::string(FASTEN_SPEC_DIR) + "/redact-conformance.json";
    std::ifstream f(path);
    if (!f) {
        std::cerr << "FAIL: cannot open " << path << "\n";
        std::exit(1);
    }
    std::stringstream buf;
    buf << f.rdbuf();
    const std::string spec = buf.str();

    std::size_t pos = spec.find("\"cases\":");
    if (pos == std::string::npos) {
        std::cerr << "FAIL: no cases in " << path << "\n";
        std::exit(1);
    }
    int n = 0;
    std::string name, input, expected;
    while (next_field(spec, "name", pos, name) &&
           next_field(spec, "input", pos, input) &&
           next_field(spec, "expected", pos, expected)) {
        // The expected value goes through redact() too: it is already
        // redacted, so that only puts it in the core's key order and
        // escaping.
        const std::string got  = redact(name, input);
        const std::string want = redact(name, expected);
        if (got != want) {
            std::cerr << "FAIL [" << name << "]\n"
                      << "  got:  " << got  << "\n"
                      << "  want: " << want << "\n";
            std::exit(1);
        }
        std::cout << "ok  " << name << "\n";
        ++n;
    }
    return n;
}

}  // namespace

int main() {
    const int n = run_all();
    // Guards against a parse that silently finds few cases.
    if (n < 100) {
        std::cerr << "FAIL: only " << n << " cases read from the spec file\n";
        return 1;
    }
    std::cout << "\nALL redact-conformance TESTS PASSED (" << n << " cases)\n";
    return 0;
}

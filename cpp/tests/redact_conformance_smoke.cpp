// Every case in spec/redact-conformance.json, run through the fasten_redact()
// C ABI directly. The cases are read from the spec file (FASTEN_SPEC_DIR is
// set by CMake), so a new case there is run here without a copy.

#include "fasten.hpp"

#include <cstdlib>
#include <fstream>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

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

// One JSON value in a canonical form: no whitespace, object keys sorted,
// strings decoded and written back with only `"`, `\\` and control
// characters escaped. Numbers, true, false and null are kept as written.
// Comparing two canonical forms checks the values, not their spelling.
class Canonical {
public:
    explicit Canonical(const std::string& s) : s_(s) {}

    std::string value() {
        ws();
        if (i_ >= s_.size()) fail("unexpected end");
        const char c = s_[i_];
        if (c == '{') return object();
        if (c == '[') return array();
        if (c == '"') return quote(string());
        const std::size_t start = i_;
        while (i_ < s_.size() && std::string(",]} \t\r\n").find(s_[i_]) == std::string::npos) ++i_;
        return s_.substr(start, i_ - start);
    }

private:
    const std::string& s_;
    std::size_t i_ = 0;

    [[noreturn]] void fail(const char* why) {
        std::cerr << "FAIL: bad JSON in the spec (" << why << ") at " << i_ << "\n";
        std::exit(1);
    }
    void ws() {
        while (i_ < s_.size() && std::string(" \t\r\n").find(s_[i_]) != std::string::npos) ++i_;
    }
    void expect(char c) {
        ws();
        if (i_ >= s_.size() || s_[i_] != c) fail("unexpected character");
        ++i_;
    }
    std::string object() {
        expect('{');
        std::map<std::string, std::string> fields;
        ws();
        if (s_[i_] == '}') { ++i_; return "{}"; }
        for (;;) {
            ws();
            std::string key = string();
            expect(':');
            fields[key] = value();
            ws();
            if (s_[i_] == ',') { ++i_; continue; }
            expect('}');
            break;
        }
        std::string out = "{";
        for (const auto& f : fields) {
            if (out.size() > 1) out += ',';
            out += quote(f.first) + ':' + f.second;
        }
        return out + '}';
    }
    std::string array() {
        expect('[');
        std::vector<std::string> items;
        ws();
        if (s_[i_] == ']') { ++i_; return "[]"; }
        for (;;) {
            items.push_back(value());
            ws();
            if (s_[i_] == ',') { ++i_; continue; }
            expect(']');
            break;
        }
        std::string out = "[";
        for (std::size_t k = 0; k < items.size(); ++k) out += (k ? "," : "") + items[k];
        return out + ']';
    }
    unsigned hex4() {
        if (i_ + 4 > s_.size()) fail("short \\u escape");
        const unsigned v = static_cast<unsigned>(std::stoul(s_.substr(i_, 4), nullptr, 16));
        i_ += 4;
        return v;
    }
    static void utf8(std::string& out, unsigned cp) {
        if (cp < 0x80) {
            out += static_cast<char>(cp);
        } else if (cp < 0x800) {
            out += static_cast<char>(0xC0 | (cp >> 6));
            out += static_cast<char>(0x80 | (cp & 0x3F));
        } else if (cp < 0x10000) {
            out += static_cast<char>(0xE0 | (cp >> 12));
            out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
            out += static_cast<char>(0x80 | (cp & 0x3F));
        } else {
            out += static_cast<char>(0xF0 | (cp >> 18));
            out += static_cast<char>(0x80 | ((cp >> 12) & 0x3F));
            out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
            out += static_cast<char>(0x80 | (cp & 0x3F));
        }
    }
    // The decoded bytes of the string that starts at s_[i_].
    std::string string() {
        expect('"');
        std::string out;
        while (i_ < s_.size() && s_[i_] != '"') {
            char c = s_[i_++];
            if (c != '\\') { out += c; continue; }
            if (i_ >= s_.size()) fail("short escape");
            c = s_[i_++];
            switch (c) {
                case 'n': out += '\n'; break;
                case 't': out += '\t'; break;
                case 'r': out += '\r'; break;
                case 'b': out += '\b'; break;
                case 'f': out += '\f'; break;
                case 'u': {
                    unsigned cp = hex4();
                    if (cp >= 0xD800 && cp < 0xDC00 && i_ + 6 <= s_.size() &&
                        s_[i_] == '\\' && s_[i_ + 1] == 'u') {
                        i_ += 2;
                        cp = 0x10000 + ((cp - 0xD800) << 10) + (hex4() - 0xDC00);
                    }
                    utf8(out, cp);
                    break;
                }
                default: out += c;  // " \\ /
            }
        }
        expect('"');
        return out;
    }
    static std::string quote(const std::string& raw) {
        static const char* hex = "0123456789abcdef";
        std::string out = "\"";
        for (unsigned char c : raw) {
            if (c == '"' || c == '\\') { out += '\\'; out += static_cast<char>(c); }
            else if (c < 0x20) { out += "\\u00"; out += hex[c >> 4]; out += hex[c & 0xF]; }
            else out += static_cast<char>(c);
        }
        return out + '"';
    }
};

std::string canonical(const std::string& json) { return Canonical(json).value(); }

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
        // Both sides in canonical form, so key order and escaping don't
        // matter. The expected value is not redacted: a case the core
        // starts masking by mistake fails here.
        const std::string got  = canonical(redact(name, input));
        const std::string want = canonical(expected);
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

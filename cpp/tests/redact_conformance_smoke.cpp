// Redact conformance smoke — mirrors every case in spec/redact-conformance.json.
//
// Calls fasten_redact() (C ABI → Rust canonical impl) directly so the test is
// independent of any C++ wrapper layer.  Cases are hardcoded to avoid a JSON-parse
// dependency; they are kept manually in sync with the spec file.
//
// Build: wired via CMakeLists -DFASTEN_BUILD_TESTS=ON (see redact_conformance_smoke target).

#include "fasten.hpp"

#include <cassert>
#include <cstring>
#include <iostream>
#include <string>

namespace {

void ok_or_die(const std::string& name,
               const std::string& in_json,
               const std::string& want_json)
{
    char* out  = nullptr;
    char* err  = nullptr;
    int32_t rc = fasten_redact(in_json.c_str(), &out, &err);
    if (rc != 0) {
        std::cerr << "FAIL [" << name << "] fasten_redact error: "
                  << (err ? err : "?") << "\n";
        fasten_store_free_str(err);
        std::exit(1);
    }
    std::string got(out ? out : "");
    fasten_store_free_str(out);
    if (got != want_json) {
        std::cerr << "FAIL [" << name << "]\n"
                  << "  got:  " << got      << "\n"
                  << "  want: " << want_json << "\n";
        std::exit(1);
    }
    std::cout << "ok  " << name << "\n";
}

// All cases mirror spec/redact-conformance.json exactly.
void run_all() {
    // ── key_pattern ──────────────────────────────────────────────────────────
    ok_or_die("key_password",
        R"({"password":"hunter2"})",
        R"({"password":"***"})");
    ok_or_die("key_passwd",
        R"({"passwd":"hunter2"})",
        R"({"passwd":"***"})");
    ok_or_die("key_api_key_underscore",
        R"({"api_key":"abc123"})",
        R"({"api_key":"***"})");
    ok_or_die("key_api_key_dash",
        R"({"api-key":"abc123"})",
        R"({"api-key":"***"})");
    ok_or_die("key_apikey_no_separator",
        R"({"apikey":"abc123"})",
        R"({"apikey":"***"})");
    ok_or_die("key_token",
        R"({"token":"tok-abc"})",
        R"({"token":"***"})");
    ok_or_die("key_secret",
        R"({"secret":"s3cr3t"})",
        R"({"secret":"***"})");
    ok_or_die("key_authorization",
        R"({"authorization":"Bearer xxx"})",
        R"({"authorization":"***"})");
    ok_or_die("key_bearer",
        R"({"bearer":"xxx"})",
        R"({"bearer":"***"})");
    ok_or_die("key_m2m_key_underscore",
        R"({"m2m_key":"xxx"})",
        R"({"m2m_key":"***"})");
    ok_or_die("key_private_key",
        R"({"private_key":"xxx"})",
        R"({"private_key":"***"})");
    ok_or_die("key_access_key",
        R"({"access_key":"xxx"})",
        R"({"access_key":"***"})");
    ok_or_die("key_session_id",
        R"({"session_id":"xxx"})",
        R"({"session_id":"***"})");
    ok_or_die("key_cookie",
        R"({"cookie":"xxx"})",
        R"({"cookie":"***"})");
    ok_or_die("key_credential",
        R"({"credential":"xxx"})",
        R"({"credential":"***"})");
    ok_or_die("key_substring_customer_token",
        R"({"customer_token":"tok-abc"})",
        R"({"customer_token":"***"})");
    ok_or_die("key_substring_user_password",
        R"({"user_password":"pw"})",
        R"({"user_password":"***"})");
    ok_or_die("key_substring_oauth_bearer_token",
        R"({"oauth_bearer_token":"tok-deep"})",
        R"({"oauth_bearer_token":"***"})");
    ok_or_die("key_case_insensitive_upper",
        R"({"API_KEY":"x"})",
        R"({"API_KEY":"***"})");
    ok_or_die("key_case_insensitive_mixed",
        R"({"Password":"x"})",
        R"({"Password":"***"})");

    // ── safe ─────────────────────────────────────────────────────────────────
    ok_or_die("safe_user_id",
        R"({"user_id":"u-42"})",
        R"({"user_id":"u-42"})");
    ok_or_die("safe_email",
        R"({"email":"alice@example.com"})",
        R"({"email":"alice@example.com"})");
    ok_or_die("safe_number",
        R"({"count":42})",
        R"({"count":42})");

    // ── value_shape ───────────────────────────────────────────────────────────
    ok_or_die("value_jwt",
        R"({"note":"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1LTQyIn0.abc123def456ghi789"})",
        R"({"note":"***JWT***"})");
    ok_or_die("value_pem_rsa",
        "{\"note\":\"-----BEGIN RSA PRIVATE KEY-----\\nMIIEpAIBAAKCAQEA...\"}",
        R"({"note":"***PRIVATE_KEY***"})");
    ok_or_die("value_pem_ec",
        "{\"note\":\"-----BEGIN EC PRIVATE KEY-----\\nMHQCAQEEIBkg...\"}",
        R"({"note":"***PRIVATE_KEY***"})");
    ok_or_die("value_pem_openssh",
        "{\"note\":\"-----BEGIN OPENSSH PRIVATE KEY-----\\nb3BlbnNzaC...\"}",
        R"({"note":"***PRIVATE_KEY***"})");
    ok_or_die("value_pem_generic",
        "{\"note\":\"-----BEGIN PRIVATE KEY-----\\nMIIEvQIBAD...\"}",
        R"({"note":"***PRIVATE_KEY***"})");
    ok_or_die("value_aws_akia",
        R"({"note":"AKIAIOSFODNN7EXAMPLE"})",
        R"({"note":"***AWS_KEY***"})");
    ok_or_die("value_aws_asia",
        R"({"note":"ASIAIOSFODNN7EXAMPLE"})",
        R"({"note":"***AWS_KEY***"})");
    ok_or_die("value_aws_as_substring",
        R"({"note":"key=AKIAIOSFODNN7EXAMPLE"})",
        R"({"note":"***AWS_KEY***"})");
    ok_or_die("value_gh_ghp",
        R"({"note":"ghp_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"})",
        R"({"note":"***GH_TOKEN***"})");
    ok_or_die("value_gh_ghs",
        R"({"note":"ghs_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"})",
        R"({"note":"***GH_TOKEN***"})");
    ok_or_die("value_gh_gho",
        R"({"note":"gho_CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"})",
        R"({"note":"***GH_TOKEN***"})");
    // Stripe: key constructed at runtime — the literal sk_live_<24+ chars> triggers
    // GitHub push-protection false-positive even in test files.
    {
        std::string key = std::string("sk") + "_live_" + std::string(24, 'A');
        ok_or_die("value_stripe_live",
            "{\"note\":\"" + key + "\"}",
            R"({"note":"***STRIPE_KEY***"})");
    }
    ok_or_die("value_openai_legacy",
        R"({"note":"sk-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh"})",
        R"({"note":"***OPENAI_KEY***"})");
    ok_or_die("value_openai_proj",
        R"({"note":"sk-proj-ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdef"})",
        R"({"note":"***OPENAI_KEY***"})");
    ok_or_die("value_cc_luhn_valid_visa",
        R"({"note":"4111111111111111"})",
        R"({"note":"***CC***"})");
    ok_or_die("value_cc_luhn_valid_visa_test2",
        R"({"note":"4539578763621486"})",
        R"({"note":"***CC***"})");
    ok_or_die("value_cc_luhn_invalid",
        R"({"note":"4111111111111112"})",
        R"({"note":"4111111111111112"})");
    ok_or_die("value_order_number_not_cc",
        R"({"note":"1234567890123456"})",
        R"({"note":"1234567890123456"})");

    // ── priority ──────────────────────────────────────────────────────────────
    ok_or_die("priority_key_wins_over_jwt",
        R"({"api_key":"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1LTQyIn0.sig"})",
        R"({"api_key":"***"})");
    ok_or_die("priority_key_wins_over_aws",
        R"({"access_key":"AKIAIOSFODNN7EXAMPLE"})",
        R"({"access_key":"***"})");

    // ── nested ────────────────────────────────────────────────────────────────
    ok_or_die("nested_2level_key_pattern",
        R"({"user":{"password":"abc","name":"Alice"}})",
        R"({"user":{"name":"Alice","password":"***"}})");
    ok_or_die("nested_2level_value_shape",
        R"({"meta":{"note":"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1LTQyIn0.abc123def456ghi789"}})",
        R"({"meta":{"note":"***JWT***"}})");
    ok_or_die("nested_array_of_dicts",
        R"({"items":[{"api_key":"x"},{"name":"y"}]})",
        R"({"items":[{"api_key":"***"},{"name":"y"}]})");
    ok_or_die("mixed_safe_and_redacted_keys",
        R"({"email":"a@b.com","name":"Alice","token":"tok-abc"})",
        R"({"email":"a@b.com","name":"Alice","token":"***"})");
}

}  // namespace

int main() {
    run_all();
    std::cout << "\nALL redact-conformance TESTS PASSED\n";
    return 0;
}

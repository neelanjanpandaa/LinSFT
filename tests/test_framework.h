// Minimal self-registering test framework (no external dependencies).
#pragma once
#include <cstdio>
#include <functional>
#include <string>
#include <vector>

namespace tf {
struct Case { const char* name; std::function<void()> fn; };
inline std::vector<Case>& registry() { static std::vector<Case> r; return r; }
inline int& failures() { static int f = 0; return f; }
inline int& checks() { static int c = 0; return c; }
struct Reg { Reg(const char* n, std::function<void()> f) { registry().push_back({n, std::move(f)}); } };
inline int runAll(const char* suite) {
    int failedCases = 0;
    for (auto& c : registry()) {
        int before = failures();
        std::printf("[ RUN  ] %s.%s\n", suite, c.name);
        std::fflush(stdout);
        try { c.fn(); } catch (const std::exception& e) { std::printf("  uncaught exception: %s\n", e.what()); ++failures(); }
        bool ok = failures() == before;
        std::printf("[ %s ] %s.%s\n", ok ? " OK " : "FAIL", suite, c.name);
        if (!ok) ++failedCases;
    }
    std::printf("\n%zu test cases, %d checks, %d failed cases\n", registry().size(), checks(), failedCases);
    return failedCases == 0 ? 0 : 1;
}
}  // namespace tf

#define TEST(name) static void test_##name(); static tf::Reg reg_##name(#name, test_##name); static void test_##name()
#define CHECK(cond) do { ++tf::checks(); if (!(cond)) { std::printf("  CHECK FAILED %s:%d: %s\n", __FILE__, __LINE__, #cond); ++tf::failures(); } } while (0)
#define CHECK_EQ(a, b) do { ++tf::checks(); auto _a = (a); auto _b = (b); if (!(_a == _b)) { std::printf("  CHECK_EQ FAILED %s:%d: %s == %s\n", __FILE__, __LINE__, #a, #b); ++tf::failures(); } } while (0)

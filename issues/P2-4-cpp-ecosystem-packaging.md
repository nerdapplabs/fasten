# [P2-4] C++ ecosystem packaging (when C++ stabilises)

**Priority:** P2 · **Effort:** L · **Labels:** `priority/P2` `area/cpp` `area/distribution`

## What

Ship rivet C++ via the canonical industrial-Linux distribution channels — once the language graduates from "experimental" to "stable" (a v0.x → v0.y bump):

- **CMakeLists.txt** declaring an INTERFACE (header-only) library `rivet::rivet`. Compiler matrix: g++ ≥ 9, clang ≥ 11, MSVC ≥ 19.20. C++14 standard pinned.
- **Conan recipe** — `rivet/cpp/conanfile.py` or contribution to conan-center-index
- **vcpkg port** — contribution to `microsoft/vcpkg/ports/rivet`
- **Apt PPA** — `ppa:edgebits/rivet` packaging `librivet-dev` for Debian/Ubuntu industrial Linux deployments

**Also under this issue:** the `rivet/cpp/README.md` usage example beyond `connector.cpp` — show `find_package(rivet REQUIRED)` + `target_link_libraries(my_block PRIVATE rivet::rivet)` for typical industrial blocks.

## Why

modbus-cpp and similar industrial blocks live in C++ ecosystems that don't `pip install`. Meeting them where they are = wider adoption. Each ecosystem (Conan, vcpkg, apt) has its own gatekeeping and review timeline — Conan/vcpkg PRs take weeks. This is genuinely L-effort because of that ecosystem time, not because the work is hard.

## Acceptance

- [ ] CMakeLists.txt + README example merged
- [ ] `conan install rivet/<version>` works end-to-end
- [ ] `vcpkg install rivet` works end-to-end (PR merged into upstream vcpkg ports)
- [ ] `apt install librivet-dev` from the EdgeBits PPA installs headers + CMake config
- [ ] All three documented in `rivet/cpp/README.md`

## Related

- **Blocked by:** C++ language stability — promote out of "experimental" first (separate v0.x bump)
- **Sister:** the modbus-cpp connector is the immediate downstream consumer; its packaging coordinates with this issue

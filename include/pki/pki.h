// The command entry point (D1). Each consumer's binary calls it with its own consumer
// fixed (`xapiand pki ...`); kronuz-pki, the library's driver, takes --consumer.
#pragma once

#include <iosfwd>
#include <string>
#include <string_view>
#include <vector>

namespace pki {

enum class Consumer { unset, xapiand, detent };

std::string_view name(Consumer consumer) noexcept;

// Exit statuses: ok, a check that found something (D11), and a refusal or a usage error.
inline constexpr int exit_ok = 0;
inline constexpr int exit_found = 1;
inline constexpr int exit_refused = 2;

// ARGV[0] is the command's name as usage prints it; the subcommand follows. Applies
// harden_process() first. Returns an exit status.
int run(Consumer consumer, int argc, char** argv);
int run(Consumer consumer, const std::vector<std::string>& args, std::ostream& out, std::ostream& err);

std::string_view version() noexcept;

}  // namespace pki

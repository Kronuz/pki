#include "pki/pki.h"

#include <exception>
#include <iostream>
#include <optional>

#include <openssl/crypto.h>

#include "pki/expiry.h"
#include "pki/fingerprint.h"
#include "pki/pem.h"
#include "pki/refusal.h"
#include "pki/secret.h"

namespace pki {

std::string_view name(Consumer consumer) noexcept {
	switch (consumer) {
		case Consumer::unset: return "unset";
		case Consumer::xapiand: return "xapiand";
		case Consumer::detent: return "detent";
	}
	return "unknown";
}

std::string_view version() noexcept { return PKI_VERSION; }

namespace {

struct Context {
	Consumer consumer;
	std::string program;
	std::vector<std::string> args;  // after the subcommand
	std::ostream& out;
	std::ostream& err;
};

void usage(std::ostream& out, const std::string& program, Consumer consumer) {
	out << "usage: " << program << (consumer == Consumer::unset ? " [--consumer xapiand|detent]" : "") << " COMMAND ...\n"
		<< "\n"
		<< "  fingerprint FILE          the SPKI and DER SHA-256 of each certificate, request, or public key\n"
		<< "  check FILE [--within T]   each certificate's standing; exits 1 when one is expiring,\n"
		<< "                            expired, or not yet valid (T: 30d, 12h, 90m, 3600s)\n"
		<< "  version                   pki's version and OpenSSL's\n"
		<< "\n"
		<< "Exit status: 0 ok, 1 a check found something, 2 refused.\n";
}

[[noreturn]] void refuse_usage(const std::string& message) { throw Refusal(Reason::usage, message); }

int fingerprint(Context& context) {
	if (context.args.size() != 1) { refuse_usage("fingerprint takes one FILE"); }
	int index = 0;
	for (auto& object : read_public_objects(context.args[0])) {
		++index;
		switch (object.kind) {
			case PublicObject::Kind::certificate:
				context.out << "certificate " << index << "\n"
					<< "spki-sha256 " << hex(spki_sha256(object.certificate.get())) << "\n"
					<< "der-sha256 " << hex(der_sha256(object.certificate.get())) << "\n";
				break;
			case PublicObject::Kind::request:
				context.out << "request " << index << "\n"
					<< "spki-sha256 " << hex(spki_sha256(object.key.get())) << "\n";
				break;
			case PublicObject::Kind::public_key:
				context.out << "public-key " << index << "\n"
					<< "spki-sha256 " << hex(spki_sha256(object.key.get())) << "\n";
				break;
		}
	}
	return exit_ok;
}

int check(Context& context) {
	std::optional<std::string> file;
	std::optional<std::int64_t> within;
	for (std::size_t i = 0; i < context.args.size(); ++i) {
		const auto& arg = context.args[i];
		if (arg == "--within") {
			if (++i == context.args.size()) { refuse_usage("--within takes a duration, such as 30d"); }
			within = parse_duration(context.args[i]);
		} else if (arg.starts_with("--")) {
			refuse_usage("check does not take " + arg);
		} else if (file) {
			refuse_usage("check takes one FILE");
		} else {
			file = arg;
		}
	}
	if (!file) { refuse_usage("check takes one FILE"); }
	auto certificates = read_certificates(*file);
	std::int64_t at = now();
	bool found = false;
	int index = 0;
	for (const auto& certificate : certificates) {
		++index;
		Validity v = validity(certificate.get());
		Standing s = standing(v, at, within);
		found = found || s != Standing::valid;
		std::int64_t left = v.not_after - at;
		context.out << "certificate " << index << " " << name(s) << " not-before " << format_time(v.not_before)
			<< " not-after " << format_time(v.not_after);
		if (s == Standing::valid || s == Standing::expiring) {
			context.out << " (" << left / 86400 << " days left)";
		}
		context.out << "\n";
	}
	return found ? exit_found : exit_ok;
}

int dispatch(Context& context, const std::string& command) {
	if (command == "fingerprint") { return fingerprint(context); }
	if (command == "check") { return check(context); }
	if (command == "version") {
		context.out << "pki " << version() << "\n" << OpenSSL_version(OPENSSL_VERSION) << "\n";
		return exit_ok;
	}
	if (command == "help" || command == "--help" || command == "-h") {
		usage(context.out, context.program, context.consumer);
		return exit_ok;
	}
	refuse_usage("unknown command " + quoted(command) + "; run `" + context.program + " help`");
}

}  // namespace

int run(Consumer consumer, const std::vector<std::string>& args, std::ostream& out, std::ostream& err) {
	harden_process();
	std::string program = args.empty() ? std::string("pki") : args[0];
	try {
		std::size_t i = 1;
		if (consumer == Consumer::unset && i < args.size() && args[i] == "--consumer") {
			if (i + 1 == args.size()) { refuse_usage("--consumer takes xapiand or detent"); }
			const auto& value = args[i + 1];
			if (value == "xapiand") {
				consumer = Consumer::xapiand;
			} else if (value == "detent") {
				consumer = Consumer::detent;
			} else {
				refuse_usage("--consumer takes xapiand or detent, not " + quoted(value));
			}
			i += 2;
		}
		if (i == args.size()) {
			usage(err, program, consumer);
			return exit_refused;
		}
		Context context{consumer, program, {args.begin() + static_cast<std::ptrdiff_t>(i) + 1, args.end()}, out, err};
		return dispatch(context, args[i]);
	} catch (const Refusal& refusal) {
		err << program << ": refused (" << name(refusal.reason()) << "): " << refusal.what() << "\n";
		return exit_refused;
	} catch (const std::exception& error) {
		err << program << ": error: " << error.what() << "\n";
		return exit_refused;
	}
}

int run(Consumer consumer, int argc, char** argv) {
	std::vector<std::string> args(argv, argv + argc);
	return run(consumer, args, std::cout, std::cerr);
}

}  // namespace pki

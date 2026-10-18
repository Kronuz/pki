// kronuz-pki: the library's driver and example. A consumer's binary calls pki::run the
// same way, with its own consumer fixed and no --consumer.
#include "pki/pki.h"

int main(int argc, char** argv) { return pki::run(pki::Consumer::unset, argc, argv); }

# Fails when BINARY holds the name of a test hook: release builds never read them.
file(STRINGS "${BINARY}" hooks REGEX "PKI_TEST_[A-Z_]+")
if(hooks)
	message(FATAL_ERROR "${BINARY} carries test hooks: ${hooks}")
endif()
message(STATUS "${BINARY}: no test hooks")

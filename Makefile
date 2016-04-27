# SRC = lib/*.js

# BIN = iojs

# ifeq ($(findstring io.js, $(shell which node)),)
# 	BIN = node
# endif
#
# ifeq (node, $(BIN))
# 	FLAGS = --harmony
# endif

REQUIRED = --require test/environment

TESTS = test/**/**/*.test.js

test:
	node $(FLAGS) \
		./node_modules/.bin/_mocha \
		$(REQUIRED) \
		$(TESTS)

test-cov:
	node $(FLAGS) \
		./node_modules/.bin/istanbul cover \
		./node_modules/.bin/_mocha \
		$(REQUIRED) \
		$(TESTS)

test-travis:
	node $(FLAGS) \
		./node_modules/.bin/istanbul cover \
		./node_modules/.bin/_mocha \
		--report lcovonly \
		$(REQUIRED) \
		$(TESTS)

.PHONY: test

NODE_VERSION = $(wordlist 1,1,$(subst ., ,$(subst v, ,$(shell node -v))))


ifeq ($(shell echo ${NODE_VERSION}\<6 | bc), 1)
	FLAGS = --harmony_destructuring
endif

REQUIRED = --require test/environment
EXCLUDE = -x **/adapters/**

TESTS = test/**/**/*.test.js test/**/*.test.js

test:
	node $(FLAGS) \
		./node_modules/.bin/_mocha \
		$(REQUIRED) \
		$(TESTS)

coverage:
	node $(FLAGS) \
		./node_modules/.bin/istanbul cover \
		./node_modules/.bin/_mocha \
		$(REQUIRED) \
		$(EXCLUDE) \
		$(TESTS)

test-travis:
	node $(FLAGS) \
		./node_modules/.bin/istanbul cover \
		./node_modules/.bin/_mocha \
		--report lcovonly \
		$(REQUIRED) \
		$(EXCLUDE) \
		$(TESTS)

.PHONY: test coverage

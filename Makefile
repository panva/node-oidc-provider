NODE_VERSION = $(wordlist 1,1,$(subst ., ,$(subst v, ,$(shell node -v))))

ifeq ($(shell echo ${NODE_VERSION}\<6 | bc), 1)
	FLAGS = --harmony_destructuring
endif

EXCLUDE = -x **/adapters/**/*.js
TESTS = test/**/**/*.test.js test/**/*.test.js

test:
	node $(FLAGS) \
		./test/run.js \
		$(TESTS)

coverage:
	node $(FLAGS) \
		./node_modules/.bin/istanbul cover \
		./test/run.js \
		$(EXCLUDE) \
		$(TESTS)

test-travis:
	node $(FLAGS) \
		./node_modules/.bin/istanbul cover \
		./test/run.js \
		--report lcovonly \
		$(EXCLUDE) \
		$(TESTS)

.PHONY: test coverage

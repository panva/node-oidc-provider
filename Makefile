NODE_VERSION = $(wordlist 1,1,$(subst ., ,$(subst v, ,$(shell node -v))))

ifeq ($(shell echo ${NODE_VERSION}\<8 | bc), 1)
	FLAGS = --harmony_async_await
endif

EXCLUDE = -x **/adapters/**/*.js
TESTS = test/**/**/*.test.js test/**/*.test.js

test:
	node $(FLAGS) \
		./test/run.js \
		$(TESTS)

.PHONY: test

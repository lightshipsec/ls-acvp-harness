CC=gcc
DEBUG=-g -DDEBUG 
ifeq ($(BUILD), release)
DEBUG=
endif
ifeq ($(BUILD), trace)
DEBUG=-g -DDEBUG -DTRACE
endif

OSSL ?= openssl
ifeq ($(strip $(cJSON)),)
	JSON := cJSON
else
	JSON := $(cJSON)
endif

CFLAGS=-c -Wall $(DEBUG) -std=c99 -D_GNU_SOURCE -I$(OSSL)/include -I$(JSON) -fstack-protector-all 
SOURCES=$(wildcard *.c)
LDFLAGS=-L$(OSSL) -L$(JSON)
LIBS=-l:libcrypto.a -l:libcjson.a -ldl -lpthread
OBJS=$(SOURCES:%.c=%.o)
DEPS=$(wildcard $(OBJS:%=%.d))
EXECUTABLE=acvpt

STRIP_FLAGS=
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
	STRIP_FLAGS += --strip-all
endif

ifeq (,$(wildcard ./openssl/include))
	$(error Could not locate openssl headers, check that the openssl source folder is symlinked)
endif

all: $(SOURCES) $(JSON)/libcjson.a $(EXECUTABLE)

debug:
	make "BUILD=debug"

$(EXECUTABLE): $(OBJS)
	$(CC) $(LDFLAGS) $(OBJS) -o $@ $(LIBS)
ifeq ($(BUILD), release)
	strip $(STRIP_FLAGS) $(EXECUTABLE)
endif

ifndef cJSON
cJSON/libcjson.a:
	(cd cJSON && make)
endif

%.o: %.c
	$(CC) $(CFLAGS) -MD -MP -MF "$@.d" -o $@ -c $<


include $(DEPS)

clean:
	rm -f $(OBJS) $(DEPS) $(EXECUTABLE)

veryclean: clean
ifndef cJSON
	(cd cJSON && make clean)
else
	@echo -n ""
endif

program_NAME := tcptest
program_C_SRCS := $(wildcard *.c)
program_CXX_SRCS := $(wildcard *.cpp)
program_C_OBJS := ${program_C_SRCS:.c=.o}
program_CXX_OBJS := ${program_CXX_SRCS:.cpp=.o}
program_OBJS := $(program_C_OBJS) $(program_CXX_OBJS)
program_INCLUDE_DIRS := /glt/tools/libpcap-1.1.1/include
program_LIBRARY_DIRS := /glt/tools/libpcap-1.1.1/lib
program_LIBRARIES := pcap

CPPFLAGS += $(foreach includedir,$(program_INCLUDE_DIRS),-I$(includedir))
LDFLAGS += $(foreach librarydir,$(program_LIBRARY_DIRS),-L$(librarydir))
LDFLAGS += $(foreach library,$(program_LIBRARIES),-l$(library))

.PHONY: all clean distclean

all: $(program_NAME)

$(program_NAME): $(program_OBJS)
    $(LINK.cc) $(program_OBJS) -o $(program_NAME)

clean:
    @- $(RM) $(program_NAME)
    @- $(RM) $(program_OBJS)

distclean: clean

define OBJECT_DEPENDS_ON_CORRESPONDING_HEADER
    $(1) : ${1:.o=.h}
endef

$(foreach object_file,$(program_OBJS),$(eval $(call OBJECT_DEPENDS_ON_CORRESPONDING_HEADER,$(object_file))))
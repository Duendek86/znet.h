
all: get_dependencies

get_dependencies:
	@echo "Using wget to add dependencies..."
	wget -q "https://raw.githubusercontent.com/z-libs/zstr.h/main/zstr.h"       -O "zstr.h"
	wget -q "https://raw.githubusercontent.com/z-libs/zfile.h/main/zfile.h"     -O "zfile.h"
	wget -q "https://raw.githubusercontent.com/z-libs/zthread.h/main/zthread.h" -O "zthread.h"

clean:
	@echo "Removing dependencies..."
	@rm zstr.h zfile.h zthread.h zhttpd 

.PHONY: get_dependencies clean

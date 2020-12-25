XLATIR_PATH=~/src/gpu/xir
XIR_TOOLS_PATH=~/src/gpu/semantics-compiler/exec_semantics

all:

build/ebpf_xir.py: ebpf.py
	$(XLATIR_PATH)/bin/xirconvert.py --xm $< -o $@

build:
	mkdir build

build/ebpf.c: build/ebpf_xir.py
	$(XIR_TOOLS_PATH)/xir2x.py --noptx $< c $@

build/ebpf.smt2: build/ebpf_xir.py
	$(XIR_TOOLS_PATH)/xir2x.py --noptx $< smt2 $@

.PHONEY: clean

clean:
	rm -rf build

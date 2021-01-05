XLATIR_PATH=~/src/gpu/xir
XIR_TOOLS_PATH=$(XLATIR_PATH)/bin

all: build build/ebpf_xir.py build/ebpf.c build/ebpf.smt2

build/ebpf_xir.py: ebpf.py
	$(XLATIR_PATH)/bin/xirconvert.py --xm $< -o $@

build:
	mkdir build

build/ebpf.c: build/ebpf_xir.py xirstdlib.pyi
	$(XIR_TOOLS_PATH)/xir2x.py -i -lxirstdlib.pyi -lebpflib.pyi --noptx $< c $@

build/ebpf.smt2: build/ebpf_xir.py
	$(XIR_TOOLS_PATH)/xir2x.py -i -lxirstdlib.pyi -lebpflib.pyi --noptx $< smt2 $@

.PHONEY: clean

clean:
	rm -rf build

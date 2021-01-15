all: build build/ebpf_xir.py build/ebpf.c build/ebpf.smt2

build/ebpf_xir.py: ebpf.py
	xirconvert.py --xm $< -o $@

build:
	mkdir -p build

build/ebpf.c: build/ebpf_xir.py
	xir2x.py -i -lxirbuiltin.pyi -lebpflib.pyi --noptx $< c $@

build/ebpf.smt2: build/ebpf_xir.py
	xir2x.py -i -lxirbuiltin.pyi -lebpflib.pyi --noptx $< smt2 $@

.PHONEY: clean

clean:
	rm -rf build

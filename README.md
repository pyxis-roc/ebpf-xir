This is an old variant of eBPF encoded in XIR and intended as a
demonstration.

After making sure `xlatir` is installed, run `make`.

The resulting `build` directory will contain the C and SMTLIB-v2
versions of the semantics. Note, due to missing function definitions,
neither of them will accepted by an SMT solver or by a C compiler.

The code in this repository is placed in the public domain.


# QSYM sources used by SymCC

This directory is vendored source code tracked directly by the SymCC repository.
A normal `git clone` includes it; no submodule initialization is needed.

Upstream repository: https://github.com/eurecom-s3/qsym.git
Upstream branch: `symcc`
Imported commit: `300300e8f417e057f918eb8fd696290aec3e1a69`

The import preserves the upstream `qsym/pintool` source files without changes,
including its code generators and third-party license notices. The Pin license
symlink is replaced by the original license text so it does not depend on the
omitted SDK directory. The QSYM license
is in `LICENSE`; the LLVM, xxHash, libdft, and Pin helper licenses remain in
`qsym/pintool/third_party`.

SymCC builds the required files through `../CMakeLists.txt`, using its own
`../pin.H` compatibility header. Do not build this directory as a standalone
QSYM/Pin installation. The standalone Python tools, Pin SDK, and nested Z3
submodule are not included. Z3 remains an external dependency selected through
the existing `Z3_DIR` or `Z3_TRUST_SYSTEM_VERSION` CMake options.

Future changes to these sources can be committed directly to the SymCC
repository. When importing an upstream update, record its commit here and
preserve the applicable copyright and license notices.

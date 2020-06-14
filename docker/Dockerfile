FROM rust:1.44.0-buster

RUN cargo install wasm-pack

# Install dependencies / tools
RUN apt update && \
  apt install -y \
  cmake \
  gcc-multilib \
  g++-multilib \
  make \
  rsync && \
  \
  wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key | apt-key add - && \
  echo "deb http://apt.llvm.org/buster/ llvm-toolchain-buster-9 main\n\
  deb-src http://apt.llvm.org/buster/ llvm-toolchain-buster-9 main" \
  >> /etc/apt/sources.list.d/llvm.list && \
  \
  apt update && \
  apt install -y -t \
  llvm-toolchain-buster-9 \
  clang-tools-9 \
  clang-9 \
  clang++-9 && \
  \
  ln -s $(which clang-9) $(dirname $(which clang-9))/clang && \
  ln -s $(which clang++-9) $(dirname $(which clang++-9))/clang++

# Clone repos for needed tools
RUN git clone --depth=1 \
  --branch version_93 \
  https://github.com/WebAssembly/binaryen && \
  cd /binaryen && \
  cmake . && \
  make

# Clone repos for needed tools
RUN git clone --depth=1 \
  --branch 1.0.16 \
  --recursive https://github.com/WebAssembly/wabt && \
  cd /wabt && \
  make

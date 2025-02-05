FROM debian:stable AS builder

ENV BUILDKIT_INLINE_CACHE=1

RUN apt-get update && apt-get install -y \
    git \
    build-essential \
    scons \
    pkg-config \
    libx11-dev \
    libxcursor-dev \
    libxinerama-dev \
    libgl1-mesa-dev \
    libglu1-mesa-dev \
    libasound2-dev \
    libpulse-dev \
    libudev-dev \
    libxi-dev \
    libxrandr-dev \
    libwayland-dev && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /godot

RUN git clone --depth=1 --branch=oss-fuzz https://github.com/wheatear-dev/godot.git .

RUN --mount=type=cache,target=/root/.scons \
    --mount=type=cache,target=/ccache \
    scons platform=linuxbsd target=editor -j$(nproc) use_ccache=yes


FROM debian:stable

COPY --from=builder /godot/bin/godot.linuxbsd.editor.x86_64 /usr/local/bin/godot

CMD ["godot"]

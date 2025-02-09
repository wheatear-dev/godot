# syntax=docker.io/docker/dockerfile:1.7-labs
FROM debian:stable AS builder

ENV BUILDKIT_INLINE_CACHE=1

RUN apt-get update && apt-get install -y \
    git \
    build-essential \
    clang \
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

COPY --exclude=.git --exclude=*.o . .

RUN --mount=type=cache,target=/root/.scons \
    --mount=type=cache,target=/ccache \
    scons platform=linuxbsd use_llvm=yes target=editor fuzz=yes -j$(nproc) use_ccache=yes


FROM debian:stable

COPY --from=builder /godot/bin/godot.linuxbsd.editor.fuzz.x86_64 /usr/local/bin/godot

CMD ["godot"]

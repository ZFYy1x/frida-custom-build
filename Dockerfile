FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV ANDROID_NDK_ROOT=/opt/android-ndk-r29
ENV JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64
ENV PATH=$PATH:/opt/android-ndk-r29/toolchains/llvm/prebuilt/linux-x86_64/bin:$JAVA_HOME/bin

# 基础工具 + 构建依赖
RUN apt-get update && apt-get install -y --no-install-recommends \
    git curl wget ca-certificates \
    build-essential ninja-build pkg-config \
    python3 python3-pip python3-venv \
    openjdk-17-jdk \
    xz-utils unzip zip \
    libglib2.0-dev libssl-dev libcapstone-dev \
    liblzfse-dev libminizip-dev libdwarf-dev libusrsctp-dev \
    libnice-dev libbpf-dev libsoup-3.0-dev \
    libjson-glib-dev libgirepository1.0-dev \
    && rm -rf /var/lib/apt/lists/*

# 安装 Node.js 22（rusda 官方要求）
RUN curl -fsSL https://deb.nodesource.com/setup_22.x | bash - && \
    apt-get install -y --no-install-recommends nodejs && \
    npm install -g npm@latest && \
    rm -rf /var/lib/apt/lists/*

# 安装 lief（二进制层 patch 需要）
RUN pip3 install --no-cache-dir lief

# 安装 Android NDK r29（17.15.0 / 17.14.1 对应 r29）
RUN mkdir -p /opt && cd /opt && \
    wget -q https://dl.google.com/android/repository/android-ndk-r29-linux.zip && \
    unzip -q android-ndk-r29-linux.zip && \
    rm android-ndk-r29-linux.zip && \
    mv android-ndk-r29 ${ANDROID_NDK_ROOT}

# 预装 Vala 0.58（Frida 17.15.0 需要）
RUN apt-get update && apt-get install -y --no-install-recommends \
    valac \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /work

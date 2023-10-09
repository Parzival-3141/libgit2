const std = @import("std");

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const lib = b.addStaticLibrary(std.Build.StaticLibraryOptions{
        .name = "git2",
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });

    lib.addIncludePath(.{ .path = "src/libgit2" });
    lib.addIncludePath(.{ .path = "src/util" });
    lib.addIncludePath(.{ .path = "include" });

    // TODO: maybe do -DLIBGIT2_NO_FEATURES_H and replace with flags?
    // Is configHeader slower?
    const features = b.addConfigHeader(
        .{ .style = .{ .cmake = .{ .path = "src/util/git2_features.h.in" } } },
        .{},
    );

    // SelectHTTPSBackend.cmake
    const HTTPS_Options = enum {
        auto_detect,
        secure_transport,
        openssl,
        openssl_dynamic,
        mbedTLS,
        schannel,
        winhttp,
    };
    const https_backend = b.option(HTTPS_Options, "https-backend", "");
    if (https_backend) |h| {
        switch (h) {
            .auto_detect => {
                // lib.linkSystemLibrary2();
                // lib.checkObject()
                // TODO: try to find which libraries are installed on the host
                @panic("auto_detect Unimplemented\n");
            },
            .secure_transport => {
                if (!target.isDarwin())
                    @panic("HTTPS SecureTransport backend only available on Darwin\n");

                lib.linkFramework("Security");
                lib.linkFramework("CoreFoundation");
                features.addValues(.{ .GIT_SECURE_TRANSPORT = 1 });
                @panic("Todo: Security headers\n");
            },
            .openssl => {
                if (target.isFreeBSD())
                    lib.linkSystemLibrary("ssl")
                else
                    lib.linkSystemLibrary("openssl");
                features.addValues(.{ .GIT_OPENSSL = 1 });
                @panic("Todo: include openssl headers\n");
            },
            .openssl_dynamic => {
                features.addValues(.{ .GIT_SHA1_OPENSSL = 1 });
                features.addValues(.{ .GIT_SHA1_OPENSSL_DYNAMIC = 1 });
                @panic("Todo: list(APPEND LIBGIT2_SYSTEM_LIBS dl)");
            },
            .mbedTLS => {
                features.addValues(.{ .GIT_MBEDTLS = 1 });
                @panic("mbedTLS Unimplemented\n");
            },
            .schannel => {
                lib.linkSystemLibrary("rpcrt4");
                lib.linkSystemLibrary("crypt32");
                lib.linkSystemLibrary("ole32");
                features.addValues(.{ .GIT_SCHANNEL = 1 });
            },
            .winhttp => {
                // Since MinGW does not come with headers or an import library for winhttp,
                // we have to include a private header and generate our own import library
                // if (target.toTarget().isMinGW()) {
                //     @panic("Todo: build and link deps/winhttp\n");
                // } else {
                lib.linkSystemLibrary("winhttp");
                // }

                lib.linkSystemLibrary("rpcrt4");
                lib.linkSystemLibrary("crypt32");
                lib.linkSystemLibrary("ole32");
                features.addValues(.{ .GIT_WINHTTP = 1 });
            },
        }

        features.addValues(.{ .GIT_HTTPS = 1 });
    } else {
        features.addValues(.{ .GIT_HTTPS = 0 });
    }

    // SelectHashes.cmake
    // TODO: try compressing the sha stuff into one codepath
    const SHA1_Options = enum {
        collision_detection,
        openssl,
        openssl_dynamic,
        common_crypto,
        mbedTLS,
        win32,
        /// Checks the HTTPS flag to determine backend
        https,
    };
    const sha1_backend = blk: {
        var sha = b.option(
            SHA1_Options,
            "sha1-backend",
            "Passing 'https' will check '-Dhttps-backend' flag to determine backend (default: collision_detection)",
        ) orelse .collision_detection;

        if (sha == .https) {
            sha = if (https_backend) |https|
                switch (https) {
                    .auto_detect => @panic("Unimplemented\n"),
                    .secure_transport => .common_crypto,
                    .schannel, .winhttp => .win32,
                    .openssl => .openssl,
                    .openssl_dynamic => .openssl_dynamic,
                    .mbedTLS => .mbedTLS,
                }
            else
                .collision_detection;
        }

        break :blk sha;
    };

    switch (sha1_backend) {
        .collision_detection => {
            features.addValues(.{ .GIT_SHA1_COLLISIONDETECT = 1 });
        },
        .openssl => {
            if (target.isFreeBSD())
                lib.linkSystemLibrary("ssl")
            else
                lib.linkSystemLibrary("openssl");
            features.addValues(.{ .GIT_SHA1_OPENSSL = 1 });
        },
        .openssl_dynamic => {
            features.addValues(.{ .GIT_SHA1_OPENSSL = 1 });
            features.addValues(.{ .GIT_SHA1_OPENSSL_DYNAMIC = 1 });
            @panic("Todo: list(APPEND LIBGIT2_SYSTEM_LIBS dl)");
        },
        .common_crypto => {
            features.addValues(.{ .GIT_SHA1_COMMON_CRYPTO = 1 });
        },
        .mbedTLS => {
            features.addValues(.{ .GIT_SHA1_MBEDTLS = 1 });
            @panic("Todo: mbedTLS\n");
        },
        .win32 => {
            features.addValues(.{ .GIT_SHA1_WIN32 = 1 });
        },
        .https => unreachable,
    }

    const SHA256_Options = enum {
        builtin,
        openssl,
        openssl_dynamic,
        common_crypto,
        mbedTLS,
        win32,
        /// Checks the HTTPS flag to determine backend
        https,
    };
    // const sha256_backend = b.option(SHA256_Options, "sha256-backend", "") orelse .builtin;
    const sha256_backend = blk: {
        var sha = b.option(
            SHA256_Options,
            "sha256-backend",
            "Passing 'https' will check '-Dhttps-backend' flag to determine backend (default: builtin)",
        ) orelse .builtin;

        if (sha == .https) {
            sha = if (https_backend) |https|
                switch (https) {
                    .auto_detect => @panic("Unimplemented\n"),
                    .secure_transport => .common_crypto,
                    .schannel, .winhttp => .win32,
                    .openssl => .openssl,
                    .openssl_dynamic => .openssl_dynamic,
                    .mbedTLS => .mbedTLS,
                }
            else
                @panic("https-backend flag missing\n");
        }

        break :blk sha;
    };

    switch (sha256_backend) {
        .builtin => {
            features.addValues(.{ .GIT_SHA256_BUILTIN = 1 });
        },
        .openssl => {
            if (target.isFreeBSD())
                lib.linkSystemLibrary("ssl")
            else
                lib.linkSystemLibrary("openssl");
            features.addValues(.{ .GIT_SHA256_OPENSSL = 1 });
        },
        .openssl_dynamic => {
            features.addValues(.{ .GIT_SHA256_OPENSSL = 1 });
            features.addValues(.{ .GIT_SHA256_OPENSSL_DYNAMIC = 1 });
            @panic("Todo: list(APPEND LIBGIT2_SYSTEM_LIBS dl)");
        },
        .common_crypto => {
            features.addValues(.{ .GIT_SHA256_COMMON_CRYPTO = 1 });
        },
        .mbedTLS => {
            features.addValues(.{ .GIT_SHA256_MBEDTLS = 1 });
            @panic("Todo: mbedTLS\n");
        },
        .win32 => {
            features.addValues(.{ .GIT_SHA256_WIN32 = 1 });
        },
        .https => unreachable,
    }

    // src/CMakeLists.txt
    switch (target.toTarget().ptrBitWidth()) {
        32 => features.addValues(.{ .GIT_ARCH_32 = 1 }),
        64 => features.addValues(.{ .GIT_ARCH_64 = 1 }),
        else => |size| std.debug.panic("Unsupported architecture ({d}bit)", .{size}),
    }

    var flags = std.ArrayList([]const u8).init(b.allocator);
    defer flags.deinit();

    switch (target.getOsTag()) {
        .windows => {
            features.addValues(.{ .GIT_IO_WSAPOLL = 1 });

            lib.linkSystemLibrary("ws2_32");
            lib.linkSystemLibrary("secur32");

            lib.addWin32ResourceFile(.{ .file = .{ .path = "src/libgit2/git2.rc" } });
        },
        .solaris => {
            lib.linkSystemLibrary("socket");
            lib.linkSystemLibrary("nsl");
        },
        .haiku => {
            lib.linkSystemLibrary("gnu");
            lib.linkSystemLibrary("network");
        },
        else => {},
    }

    lib.addConfigHeader(features);
    lib.addCSourceFiles(&libgit_sources, flags.items);

    lib.installHeadersDirectory("include", "git2");
    b.installArtifact(lib);
}

const libgit_sources = [_][]const u8{
    "src/libgit2/annotated_commit.c",
    "src/libgit2/apply.c",
    "src/libgit2/attr.c",
    "src/libgit2/attr_file.c",
    "src/libgit2/attrcache.c",
    "src/libgit2/blame.c",
    "src/libgit2/blame_git.c",
    "src/libgit2/blob.c",
    "src/libgit2/branch.c",
    "src/libgit2/buf.c",
    "src/libgit2/cache.c",
    "src/libgit2/checkout.c",
    "src/libgit2/cherrypick.c",
    "src/libgit2/clone.c",
    "src/libgit2/commit.c",
    "src/libgit2/commit_graph.c",
    "src/libgit2/commit_list.c",
    "src/libgit2/config.c",
    "src/libgit2/config_cache.c",
    "src/libgit2/config_file.c",
    "src/libgit2/config_list.c",
    "src/libgit2/config_mem.c",
    "src/libgit2/config_parse.c",
    "src/libgit2/config_snapshot.c",
    "src/libgit2/crlf.c",
    "src/libgit2/delta.c",
    "src/libgit2/describe.c",
    "src/libgit2/diff.c",
    "src/libgit2/diff_driver.c",
    "src/libgit2/diff_file.c",
    "src/libgit2/diff_generate.c",
    "src/libgit2/diff_parse.c",
    "src/libgit2/diff_print.c",
    "src/libgit2/diff_stats.c",
    "src/libgit2/diff_tform.c",
    "src/libgit2/diff_xdiff.c",
    "src/libgit2/email.c",
    "src/libgit2/fetch.c",
    "src/libgit2/fetchhead.c",
    "src/libgit2/filter.c",
    "src/libgit2/grafts.c",
    "src/libgit2/graph.c",
    "src/libgit2/hashsig.c",
    "src/libgit2/ident.c",
    "src/libgit2/idxmap.c",
    "src/libgit2/ignore.c",
    "src/libgit2/index.c",
    "src/libgit2/indexer.c",
    "src/libgit2/iterator.c",
    "src/libgit2/libgit2.c",
    "src/libgit2/mailmap.c",
    "src/libgit2/merge.c",
    "src/libgit2/merge_driver.c",
    "src/libgit2/merge_file.c",
    "src/libgit2/message.c",
    "src/libgit2/midx.c",
    "src/libgit2/mwindow.c",
    "src/libgit2/notes.c",
    "src/libgit2/object.c",
    "src/libgit2/object_api.c",
    "src/libgit2/odb.c",
    "src/libgit2/odb_loose.c",
    "src/libgit2/odb_mempack.c",
    "src/libgit2/odb_pack.c",
    "src/libgit2/offmap.c",
    "src/libgit2/oid.c",
    "src/libgit2/oidarray.c",
    "src/libgit2/oidmap.c",
    "src/libgit2/pack-objects.c",
    "src/libgit2/pack.c",
    "src/libgit2/parse.c",
    "src/libgit2/patch.c",
    "src/libgit2/patch_generate.c",
    "src/libgit2/patch_parse.c",
    "src/libgit2/path.c",
    "src/libgit2/pathspec.c",
    "src/libgit2/proxy.c",
    "src/libgit2/push.c",
    "src/libgit2/reader.c",
    "src/libgit2/rebase.c",
    "src/libgit2/refdb.c",
    "src/libgit2/refdb_fs.c",
    "src/libgit2/reflog.c",
    "src/libgit2/refs.c",
    "src/libgit2/refspec.c",
    "src/libgit2/remote.c",
    "src/libgit2/repository.c",
    "src/libgit2/reset.c",
    "src/libgit2/revert.c",
    "src/libgit2/revparse.c",
    "src/libgit2/revwalk.c",
    "src/libgit2/signature.c",
    "src/libgit2/stash.c",
    "src/libgit2/status.c",
    "src/libgit2/strarray.c",
    "src/libgit2/streams/mbedtls.c",
    "src/libgit2/streams/openssl.c",
    "src/libgit2/streams/openssl_dynamic.c",
    "src/libgit2/streams/openssl_legacy.c",
    "src/libgit2/streams/registry.c",
    "src/libgit2/streams/schannel.c",
    "src/libgit2/streams/socket.c",
    "src/libgit2/streams/stransport.c",
    "src/libgit2/streams/tls.c",
    "src/libgit2/submodule.c",
    "src/libgit2/sysdir.c",
    "src/libgit2/tag.c",
    "src/libgit2/trace.c",
    "src/libgit2/trailer.c",
    "src/libgit2/transaction.c",
    "src/libgit2/transport.c",
    "src/libgit2/transports/auth.c",
    "src/libgit2/transports/auth_gssapi.c",
    "src/libgit2/transports/auth_ntlmclient.c",
    "src/libgit2/transports/auth_sspi.c",
    "src/libgit2/transports/credential.c",
    "src/libgit2/transports/credential_helpers.c",
    "src/libgit2/transports/git.c",
    "src/libgit2/transports/http.c",
    "src/libgit2/transports/httpclient.c",
    "src/libgit2/transports/local.c",
    "src/libgit2/transports/smart.c",
    "src/libgit2/transports/smart_pkt.c",
    "src/libgit2/transports/smart_protocol.c",
    "src/libgit2/transports/ssh.c",
    "src/libgit2/transports/ssh_exec.c",
    "src/libgit2/transports/ssh_libssh2.c",
    "src/libgit2/transports/winhttp.c",
    "src/libgit2/tree-cache.c",
    "src/libgit2/tree.c",
    "src/libgit2/worktree.c",
};

const util_sources = [_][]const u8{
    "src/util/alloc.c",
    "src/util/allocators/failalloc.c",
    "src/util/allocators/stdalloc.c",
    "src/util/allocators/win32_leakcheck.c",
    "src/util/date.c",
    "src/util/errors.c",
    "src/util/filebuf.c",
    "src/util/fs_path.c",
    "src/util/futils.c",
    "src/util/hash/builtin.c",
    "src/util/hash/collisiondetect.c",
    "src/util/hash/common_crypto.c",
    "src/util/hash/mbedtls.c",
    "src/util/hash/openssl.c",
    "src/util/hash/rfc6234/sha224-256.c",
    "src/util/hash/sha1dc/sha1.c",
    "src/util/hash/sha1dc/ubc_check.c",
    "src/util/hash/win32.c",
    "src/util/hash.c",
    "src/util/net.c",
    "src/util/pool.c",
    "src/util/posix.c",
    "src/util/pqueue.c",
    "src/util/rand.c",
    "src/util/regexp.c",
    "src/util/runtime.c",
    "src/util/sortedcache.c",
    "src/util/str.c",
    "src/util/strlist.c",
    "src/util/strmap.c",
    "src/util/thread.c",
    "src/util/tsort.c",
    "src/util/utf8.c",
    "src/util/util.c",
    "src/util/varint.c",
    "src/util/vector.c",
    "src/util/wildmatch.c",
    "src/util/zstream.c",
};

const util_win32_sources = [_][]const u8{
    "src/util/win32/dir.c",
    "src/util/win32/error.c",
    "src/util/win32/map.c",
    "src/util/win32/path_w32.c",
    "src/util/win32/posix_w32.c",
    "src/util/win32/precompiled.c",
    "src/util/win32/process.c",
    "src/util/win32/thread.c",
    "src/util/win32/utf-conv.c",
    "src/util/win32/w32_buffer.c",
    "src/util/win32/w32_leakcheck.c",
    "src/util/win32/w32_util.c",
};

const util_unix_sources = [_][]const u8{
    "src/util/unix/map.c",
    "src/util/unix/process.c",
    "src/util/unix/realpath.c",
};

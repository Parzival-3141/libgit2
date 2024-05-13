const std = @import("std");

pub fn build(b: *std.Build) !void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const lib = b.addStaticLibrary(.{
        .name = "git2",
        .target = target,
        .optimize = optimize,
        .link_libc = true,
    });

    // @Todo: maybe do -DLIBGIT2_NO_FEATURES_H and replace with flags?
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
                if (!target.result.isDarwin())
                    @panic("HTTPS SecureTransport backend only available on Darwin\n");

                lib.linkFramework("Security");
                lib.linkFramework("CoreFoundation");
                features.addValues(.{ .GIT_SECURE_TRANSPORT = 1 });
                @panic("Todo: Security headers\n");
            },
            .openssl => {
                if (target.result.isBSD())
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
            lib.addCSourceFiles(.{
                .files = &util_hash_collision_detection_sources,
                .flags = &.{
                    "-DSHA1DC_NO_STANDARD_INCLUDES=1",
                    "-DSHA1DC_CUSTOM_INCLUDE_SHA1_C=\"git2_util.h\"",
                    "-DSHA1DC_CUSTOM_INCLUDE_UBC_CHECK_C=\"git2_util.h\"",
                },
            });
            features.addValues(.{ .GIT_SHA1_COLLISIONDETECT = 1 });
        },
        .openssl => {
            if (target.result.isBSD())
                lib.linkSystemLibrary("ssl")
            else
                lib.linkSystemLibrary("openssl");

            // TODO: this is probably an option for openssl itself...
            lib.addCSourceFiles(.{ .files = &util_hash_openssl_sources, .flags = &.{"-DOPENSSL_API_COMPAT=0x10100000L"} });
            features.addValues(.{ .GIT_SHA1_OPENSSL = 1 });
        },
        .openssl_dynamic => {
            // TODO: this is probably an option for openssl itself...
            lib.addCSourceFiles(.{ .files = &util_hash_openssl_sources, .flags = &.{"-DOPENSSL_API_COMPAT=0x10100000L"} });

            features.addValues(.{ .GIT_SHA1_OPENSSL = 1 });
            features.addValues(.{ .GIT_SHA1_OPENSSL_DYNAMIC = 1 });
            @panic("Todo: list(APPEND LIBGIT2_SYSTEM_LIBS dl)");
        },
        .common_crypto => {
            lib.addCSourceFiles(.{ .files = &util_hash_common_crypto_sources });
            features.addValues(.{ .GIT_SHA1_COMMON_CRYPTO = 1 });
        },
        .mbedTLS => {
            lib.addCSourceFiles(.{ .files = &util_hash_mbedTLS_sources });
            features.addValues(.{ .GIT_SHA1_MBEDTLS = 1 });
            @panic("Todo: mbedTLS\n");
        },
        .win32 => {
            lib.addCSourceFiles(.{ .files = &util_hash_win32_sources });
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
            lib.addCSourceFiles(.{ .files = &util_hash_builtin_sources });
            features.addValues(.{ .GIT_SHA256_BUILTIN = 1 });
        },
        .openssl => {
            if (target.result.isBSD())
                lib.linkSystemLibrary("ssl")
            else
                lib.linkSystemLibrary("openssl");
            // TODO: this is probably an option for openssl itself...
            lib.addCSourceFiles(.{ .files = &util_hash_openssl_sources, .flags = &.{"-DOPENSSL_API_COMPAT=0x10100000L"} });
            features.addValues(.{ .GIT_SHA256_OPENSSL = 1 });
        },
        .openssl_dynamic => {
            // TODO: this is probably an option for openssl itself...
            lib.addCSourceFiles(.{ .files = &util_hash_openssl_sources, .flags = &.{"-DOPENSSL_API_COMPAT=0x10100000L"} });

            features.addValues(.{ .GIT_SHA256_OPENSSL = 1 });
            features.addValues(.{ .GIT_SHA256_OPENSSL_DYNAMIC = 1 });
            @panic("Todo: list(APPEND LIBGIT2_SYSTEM_LIBS dl)");
        },
        .common_crypto => {
            lib.addCSourceFiles(.{ .files = &util_hash_common_crypto_sources });
            features.addValues(.{ .GIT_SHA256_COMMON_CRYPTO = 1 });
        },
        .mbedTLS => {
            lib.addCSourceFiles(.{ .files = &util_hash_mbedTLS_sources });
            features.addValues(.{ .GIT_SHA256_MBEDTLS = 1 });
            @panic("Todo: mbedTLS\n");
        },
        .win32 => {
            lib.addCSourceFiles(.{ .files = &util_hash_win32_sources });
            features.addValues(.{ .GIT_SHA256_WIN32 = 1 });
        },
        .https => unreachable,
    }

    // SelectZlib.cmake
    // TODO: Not bothering to build chromium's zlib right now
    if (b.option(bool, "bundle-zlib", "Build the bundled version of zlib instead of linking the system one") orelse false) {
        const zlib = b.addStaticLibrary(.{
            .name = "zlib",
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        });
        zlib.addIncludePath(.{ .path = "deps/zlib" });
        zlib.addCSourceFiles(.{
            .files = &zlib_sources,
            .flags = &.{ "-Wno-implicit-fallthrough", "-DNO_VIZ", "-DSTDC", "-DNO_GZIP" },
        });

        lib.addIncludePath(.{ .path = "deps/zlib" });
        lib.linkLibrary(zlib);
    } else {
        lib.linkSystemLibrary("zlib");
    }

    // SelectRegex.cmake
    // TODO: if unspecified, try using recomp_l, then pcre, then builtin
    const RegexOptions = enum { builtin, pcre, pcre2, regcomp, regcomp_l };
    const regex_backend = b.option(RegexOptions, "regex-backend", "Regular expression backend. (default: builtin)") orelse .builtin;
    switch (regex_backend) {
        .pcre => {
            lib.linkSystemLibrary("libpcre");
            features.addValues(.{ .GIT_REGEX_PCRE = 1 });
            @panic("Todo: include pcre headers\n");
        },
        .pcre2 => {
            lib.linkSystemLibrary("libpcre2-8");
            features.addValues(.{ .GIT_REGEX_PCRE2 = 1 });
            @panic("Todo: pcre2\n");
        },
        .regcomp => {
            // lib.linkSystemLibrary("regcomp"); // it's included in libc?
            features.addValues(.{ .GIT_REGEX_REGCOMP = 1 });
        },
        .regcomp_l => {
            // lib.linkSystemLibrary("regcomp_l"); // it's included in libc?
            features.addValues(.{ .GIT_REGEX_REGCOMP_L = 1 });
        },
        .builtin => {
            // deps/pcre/CMakeLists.txt
            // deps/pcre/config.h.in
            const pcre = b.addStaticLibrary(.{
                .name = "pcre",
                .target = target,
                .optimize = optimize,
                .link_libc = true,
            });
            pcre.addIncludePath(.{ .path = "deps/pcre" });

            // This doesn't really deserve it's own option,
            // so you can change it here if you'd like.
            const newline: enum { lf, cr, crlf, any, anycrlf } = .lf;
            const DNEWLINE = "-DNEWLINE=" ++ switch (newline) {
                .lf => "10",
                .cr => "13",
                .crlf => "3338",
                .any => "-1",
                .anycrlf => "-2",
            };

            pcre.addCSourceFiles(.{
                .files = &pcre_sources,
                .flags = &.{
                    "-Wno-unused-function",
                    "-Wno-implicit-fallthrough",
                    "-DSUPPORT_PCRE8=1",
                    "-DLINK_SIZE=2",
                    "-DPARENS_NEST_LIMIT=250",
                    "-DMATCH_LIMIT=10000000",
                    "-DMATCH_LIMIT_RECURSION=MATCH_LIMIT",
                    DNEWLINE,
                    "-DNO_RECURSE=1",
                    "-DPOSIX_MALLOC_THRESHOLD=10",
                    "-DBSR_ANYCRLF=0",
                    "-DMAX_NAME_SIZE=32",
                    "-DMAX_NAME_COUNT=10000",
                    // TODO: deps/prce has a config.h.in, but just passing these
                    // as flags seems fine?
                    // "-DHAVE_CONFIG_H",
                },
            });

            lib.addIncludePath(.{ .path = "deps/pcre" });
            lib.linkLibrary(pcre);
            features.addValues(.{ .GIT_REGEX_BUILTIN = 1 });
        },
    }

    // SelectXdiff.cmake
    const xdiff_impl = b.option(enum { system, builtin }, "xdiff", "Specifies the xdiff implementation (default: builtin)") orelse .builtin;
    switch (xdiff_impl) {
        .system => @panic("external/system xdiff is not yet supported\n"),
        .builtin => {
            // Bundled xdiff dependency relies on libgit2 headers & utils, so we
            // just add the source files directly instead of making a static lib step.

            // the xdiff dependency is not (yet) warning-free, disable warnings
            // as errors for the xdiff sources until we've sorted them out
            lib.addCSourceFiles(.{ .files = &xdiff_sources, .flags = &.{ "-Wno-sign-compare", "-Wno-unused-parameter" } });
            lib.addIncludePath(.{ .path = "deps/xdiff" });
        },
    }

    // SelectHTTPParser.cmake
    const http_parser_impl = b.option(enum { system, builtin }, "http-parser", "Specifies the HTTP Parser implementation (default: builtin)") orelse .builtin;
    switch (http_parser_impl) {
        .system => {
            lib.linkSystemLibrary("http_parser");
            @panic("Todo: include system http_parser headers\n");
        },
        .builtin => {
            // deps/http_parser/CMakeLists.txt
            const http_parser = b.addStaticLibrary(.{
                .name = "http_parser",
                .target = target,
                .optimize = optimize,
                .link_libc = true,
            });
            http_parser.addIncludePath(.{ .path = "deps/http-parser" });
            http_parser.addCSourceFile(.{
                .file = .{ .path = "deps/http-parser/http_parser.c" },
                .flags = &.{"-Wimplicit-fallthrough"},
            });

            lib.addIncludePath(.{ .path = "deps/http-parser" });
            lib.linkLibrary(http_parser);
        },
    }

    // src/CMakeLists.txt
    switch (target.result.ptrBitWidth()) {
        32 => features.addValues(.{ .GIT_ARCH_32 = 1 }),
        64 => features.addValues(.{ .GIT_ARCH_64 = 1 }),
        else => |size| std.debug.panic("Unsupported architecture ({d}bit)", .{size}),
    }

    var flags = std.ArrayList([]const u8).init(b.allocator);
    defer flags.deinit();

    switch (target.result.os.tag) {
        .windows => {
            // Ensure that MinGW provides the correct header files.
            // try flags.appendSlice(&.{ "-DWIN32", "-D_WIN32_WINNT=0x0600" });

            features.addValues(.{ .GIT_IO_WSAPOLL = 1 });

            lib.linkSystemLibrary("ws2_32");
            lib.linkSystemLibrary("secur32");

            lib.addWin32ResourceFile(.{ .file = .{ .path = "src/libgit2/git2.rc" } });

            lib.addCSourceFiles(.{ .files = &util_win32_sources, .flags = flags.items });
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

    if (target.result.os.tag != .windows) {
        lib.addCSourceFiles(.{ .files = &util_unix_sources, .flags = flags.items });

        // if (libc supports poll.h:poll()) set(GIT_IO_POLL, 1)
        // if (libc supports sys/select.h:select()) set(GIT_IO_SELECT, 1)
        // @Todo: This'll do for now, as we're unconditionally linking libc above,
        // but should double check this for non-standard libc's.
        features.addValues(.{ .GIT_IO_POLL = 1 });
        features.addValues(.{ .GIT_IO_SELECT = 1 });
    }

    if (b.option(
        bool,
        "multi-threaded",
        "Use threads for parallel processing when possible (default: true)",
    ) orelse true) {
        if (target.result.os.tag != .windows) {
            // @Todo: this code just seems wrong?
            // if(NOT WIN32)
            //     find_package(Threads REQUIRED)
            //     list(APPEND LIBGIT2_SYSTEM_LIBS ${CMAKE_THREAD_LIBS_INIT})
            //     list(APPEND LIBGIT2_PC_LIBS ${CMAKE_THREAD_LIBS_INIT})
            // endif()

            // lib.linkSystemLibrary("pthreads");
        }

        features.addValues(.{ .GIT_THREADS = 1 });
    }

    // lib.force_pic = true;
    // if (target.toTarget().isMinGW()) {
    //     lib.defineCMacro("__USE_MINGW_ANSI_STDIO", null);
    // }

    lib.addIncludePath(.{ .path = "src/libgit2" });
    lib.addIncludePath(.{ .path = "src/util" });
    lib.addIncludePath(.{ .path = "include" });

    lib.addConfigHeader(features);
    lib.addCSourceFiles(.{ .files = &util_sources, .flags = flags.items });
    lib.addCSourceFiles(.{ .files = &libgit_sources, .flags = flags.items });

    lib.installHeadersDirectory(.{ .path = "include" }, "git2", .{});
    b.installArtifact(lib);

    const cli_step = b.step("cli", "Build the command-line interface");
    {
        const cli = b.addExecutable(.{
            .name = "git2_cli",
            .target = target,
            .optimize = optimize,
            .link_libc = true,
        });

        cli.addIncludePath(.{ .path = "include" });
        cli.addIncludePath(.{ .path = "src/util" });
        cli.addIncludePath(.{ .path = "src/cli" });

        if (target.result.os.tag == .windows)
            cli.addCSourceFiles(.{ .files = &cli_win32_sources })
        else
            cli.addCSourceFiles(.{ .files = &cli_unix_sources });

        cli.linkLibrary(lib);
        cli.addConfigHeader(features);
        cli.addCSourceFiles(.{ .files = &cli_sources });

        cli_step.dependOn(&b.addInstallArtifact(cli, .{}).step);
    }
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

const util_hash_collision_detection_sources = [_][]const u8{
    "src/util/hash/collisiondetect.c",
    "src/util/hash/sha1dc/sha1.c",
    "src/util/hash/sha1dc/ubc_check.c",
};
const util_hash_openssl_sources = [_][]const u8{
    "src/util/hash/openssl.c",
};
const util_hash_common_crypto_sources = [_][]const u8{
    "src/util/hash/common_crypto.c",
};
const util_hash_mbedTLS_sources = [_][]const u8{
    "src/util/hash/mbedtls.c",
};
const util_hash_win32_sources = [_][]const u8{
    "src/util/hash/win32.c",
};
const util_hash_builtin_sources = [_][]const u8{
    "src/util/hash/builtin.c",
    "src/util/hash/rfc6234/sha224-256.c",
};

const util_win32_sources = [_][]const u8{
    "src/util/win32/dir.c",
    "src/util/win32/error.c",
    "src/util/win32/map.c",
    "src/util/win32/path_w32.c",
    "src/util/win32/posix_w32.c",
    // "src/util/win32/precompiled.c",
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

const zlib_sources = [_][]const u8{
    "deps/zlib/adler32.c",
    "deps/zlib/crc32.c",
    "deps/zlib/deflate.c",
    "deps/zlib/infback.c",
    "deps/zlib/inffast.c",
    "deps/zlib/inflate.c",
    "deps/zlib/inftrees.c",
    "deps/zlib/trees.c",
    "deps/zlib/zutil.c",
};

const pcre_sources = [_][]const u8{
    "deps/pcre/pcre_byte_order.c",
    "deps/pcre/pcre_chartables.c",
    "deps/pcre/pcre_compile.c",
    "deps/pcre/pcre_config.c",
    "deps/pcre/pcre_dfa_exec.c",
    "deps/pcre/pcre_exec.c",
    "deps/pcre/pcre_fullinfo.c",
    "deps/pcre/pcre_get.c",
    "deps/pcre/pcre_globals.c",
    "deps/pcre/pcre_jit_compile.c",
    "deps/pcre/pcre_maketables.c",
    "deps/pcre/pcre_newline.c",
    "deps/pcre/pcre_ord2utf8.c",
    "deps/pcre/pcre_printint.c",
    "deps/pcre/pcre_refcount.c",
    "deps/pcre/pcre_string_utils.c",
    "deps/pcre/pcre_study.c",
    "deps/pcre/pcre_tables.c",
    "deps/pcre/pcre_ucd.c",
    "deps/pcre/pcre_valid_utf8.c",
    "deps/pcre/pcre_version.c",
    "deps/pcre/pcre_xclass.c",
    "deps/pcre/pcreposix.c",
};

const xdiff_sources = [_][]const u8{
    "deps/xdiff/xdiffi.c",
    "deps/xdiff/xemit.c",
    "deps/xdiff/xhistogram.c",
    "deps/xdiff/xmerge.c",
    "deps/xdiff/xpatience.c",
    "deps/xdiff/xprepare.c",
    "deps/xdiff/xutils.c",
};

const cli_sources = [_][]const u8{
    "src/cli/cmd.c",
    "src/cli/cmd_cat_file.c",
    "src/cli/cmd_clone.c",
    "src/cli/cmd_config.c",
    "src/cli/cmd_hash_object.c",
    "src/cli/cmd_help.c",
    "src/cli/cmd_index_pack.c",
    "src/cli/common.c",
    "src/cli/main.c",
    "src/cli/opt.c",
    "src/cli/opt_usage.c",
    "src/cli/progress.c",
};

const cli_win32_sources = [_][]const u8{
    // "src/cli/win32/precompiled.c",
    "src/cli/win32/sighandler.c",
};

const cli_unix_sources = [_][]const u8{
    "src/cli/unix/sighandler.c",
};

const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const with_benchmark: bool = b.option(bool, "with-benchmark", "Compile benchmark") orelse false;
    const optimize = b.standardOptimizeOption(.{ .preferred_optimize_mode = .ReleaseFast });
    const version = std.SemanticVersion.parse("0.4.5") catch unreachable;
    const linkage = b.option(std.builtin.LinkMode, "link-mode", "Link mode") orelse .static;

    const lib = b.addLibrary(.{
        .name = "aegis",
        .version = version,
        .linkage = linkage,
        .root_module = b.createModule(.{
            .target = target,
            .optimize = optimize,
            .strip = true,
        }),
    });

    lib.linkLibC();

    const lib_options = b.addOptions();

    const favor_performance: bool = b.option(bool, "favor-performance", "Favor performance over side channel mitigations") orelse false;
    lib_options.addOption(bool, "favor_performance", favor_performance);
    if (favor_performance) {
        lib.root_module.addCMacro("FAVOR_PERFORMANCE", "1");
    }

    lib_options.addOption(bool, "benchmark", with_benchmark);

    lib.addIncludePath(b.path("src/include"));

    const source_files = &.{
        "src/aegis128l/aegis128l_aesni.c",
        "src/aegis128l/aegis128l_altivec.c",
        "src/aegis128l/aegis128l_neon_aes.c",
        "src/aegis128l/aegis128l_neon_sha3.c",
        "src/aegis128l/aegis128l_soft.c",
        "src/aegis128l/aegis128l.c",

        "src/aegis128x2/aegis128x2_aesni.c",
        "src/aegis128x2/aegis128x2_altivec.c",
        "src/aegis128x2/aegis128x2_avx2.c",
        "src/aegis128x2/aegis128x2_neon_aes.c",
        "src/aegis128x2/aegis128x2_soft.c",
        "src/aegis128x2/aegis128x2.c",

        "src/aegis128x4/aegis128x4_aesni.c",
        "src/aegis128x4/aegis128x4_altivec.c",
        "src/aegis128x4/aegis128x4_avx2.c",
        "src/aegis128x4/aegis128x4_avx512.c",
        "src/aegis128x4/aegis128x4_neon_aes.c",
        "src/aegis128x4/aegis128x4_soft.c",
        "src/aegis128x4/aegis128x4.c",

        "src/aegis256/aegis256_aesni.c",
        "src/aegis256/aegis256_altivec.c",
        "src/aegis256/aegis256_neon_aes.c",
        "src/aegis256/aegis256_soft.c",
        "src/aegis256/aegis256.c",

        "src/aegis256x2/aegis256x2_aesni.c",
        "src/aegis256x2/aegis256x2_altivec.c",
        "src/aegis256x2/aegis256x2_avx2.c",
        "src/aegis256x2/aegis256x2_neon_aes.c",
        "src/aegis256x2/aegis256x2_soft.c",
        "src/aegis256x2/aegis256x2.c",

        "src/aegis256x4/aegis256x4_aesni.c",
        "src/aegis256x4/aegis256x4_altivec.c",
        "src/aegis256x4/aegis256x4_avx2.c",
        "src/aegis256x4/aegis256x4_avx512.c",
        "src/aegis256x4/aegis256x4_neon_aes.c",
        "src/aegis256x4/aegis256x4_soft.c",
        "src/aegis256x4/aegis256x4.c",

        "src/common/common.c",
        "src/common/cpu.c",
        "src/common/softaes.c",
    };

    lib.addCSourceFiles(.{ .files = source_files });

    // This declares intent for the executable to be installed into the
    // standard location when the user invokes the "install" step (the default
    // step when running `zig build`).
    b.installArtifact(lib);

    b.installDirectory(.{
        .install_dir = .header,
        .install_subdir = "",
        .source_dir = b.path("src/include"),
    });

    // Creates a step for unit testing. This only builds the test executable
    // but does not run it.
    const main_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/test/main.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });

    main_tests.addIncludePath(b.path("src/include"));
    main_tests.linkLibrary(lib);

    const run_main_tests = b.addRunArtifact(main_tests);

    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&run_main_tests.step);

    if (with_benchmark) {
        const benchmark = b.addExecutable(.{
            .name = "benchmark",
            .root_module = b.createModule(.{
                .root_source_file = b.path("src/test/benchmark.zig"),
                .target = target,
                .optimize = optimize,
            }),
        });
        benchmark.addIncludePath(b.path("src/include"));
        benchmark.linkLibrary(lib);
        b.installArtifact(benchmark);
    }
}

const aegis = @cImport(@cInclude("aegis.h"));
const std = @import("std");
const testing = std.testing;

var io_source = std.Random.IoSource{ .io = testing.io };
const random = io_source.interface();

const MemoryFile = struct {
    data: std.ArrayListUnmanaged(u8),
    allocator: std.mem.Allocator,

    fn init(allocator: std.mem.Allocator) MemoryFile {
        return .{
            .data = .{},
            .allocator = allocator,
        };
    }

    fn deinit(self: *MemoryFile) void {
        self.data.deinit(self.allocator);
    }

    fn read_at(user: ?*anyopaque, buf: [*c]u8, len: usize, off: u64) callconv(.c) c_int {
        const self: *MemoryFile = @ptrCast(@alignCast(user));
        const offset = @as(usize, @intCast(off));
        if (offset + len > self.data.items.len) {
            return -1;
        }
        @memcpy(buf[0..len], self.data.items[offset .. offset + len]);
        return 0;
    }

    fn write_at(user: ?*anyopaque, buf: [*c]const u8, len: usize, off: u64) callconv(.c) c_int {
        const self: *MemoryFile = @ptrCast(@alignCast(user));
        const offset = @as(usize, @intCast(off));
        const end = offset + len;
        if (end > self.data.items.len) {
            return -1;
        }
        @memcpy(self.data.items[offset..end], buf[0..len]);
        return 0;
    }

    fn get_size(user: ?*anyopaque, size: [*c]u64) callconv(.c) c_int {
        const self: *MemoryFile = @ptrCast(@alignCast(user));
        size[0] = @intCast(self.data.items.len);
        return 0;
    }

    fn set_size(user: ?*anyopaque, size: u64) callconv(.c) c_int {
        const self: *MemoryFile = @ptrCast(@alignCast(user));
        const new_size = @as(usize, @intCast(size));
        self.data.resize(self.allocator, new_size) catch return -1;
        return 0;
    }

    fn sync(_: ?*anyopaque) callconv(.c) c_int {
        return 0;
    }

    fn io(self: *MemoryFile) aegis.aegis_raf_io {
        return .{
            .user = self,
            .read_at = read_at,
            .write_at = write_at,
            .get_size = get_size,
            .set_size = set_size,
            .sync = sync,
        };
    }
};

fn os_random(_: ?*anyopaque, out: [*c]u8, len: usize) callconv(.c) c_int {
    random.bytes(out[0..len]);
    return 0;
}

fn rng() aegis.aegis_raf_rng {
    return .{
        .user = null,
        .random = os_random,
    };
}

const FailingRng = struct {
    calls_until_fail: usize,
    call_count: usize = 0,

    fn failingRandom(user: ?*anyopaque, out: [*c]u8, len: usize) callconv(.c) c_int {
        const self: *FailingRng = @ptrCast(@alignCast(user));
        self.call_count += 1;
        if (self.call_count > self.calls_until_fail) {
            return -1;
        }
        io_source.interface().bytes(out[0..len]);
        return 0;
    }

    fn interface(self: *FailingRng) aegis.aegis_raf_rng {
        return .{
            .user = self,
            .random = failingRandom,
        };
    }
};

test "aegis128l_raf - create and basic write/read" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    var file = MemoryFile.init(testing.allocator);
    defer file.deinit();

    var key: [aegis.aegis128l_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    var scratch_buf: [aegis.AEGIS128L_RAF_SCRATCH_SIZE(4096)]u8 align(aegis.AEGIS_RAF_SCRATCH_ALIGN) = undefined;
    const scratch = aegis.aegis_raf_scratch{
        .buf = &scratch_buf,
        .len = scratch_buf.len,
    };

    const cfg = aegis.aegis_raf_config{
        .chunk_size = 4096,
        .flags = aegis.AEGIS_RAF_CREATE,
        .scratch = &scratch,
    };

    var ctx: aegis.aegis128l_raf_ctx align(32) = undefined;

    var ret = aegis.aegis128l_raf_create(&ctx, &file.io(), &rng(), &cfg, &key);
    try testing.expectEqual(ret, 0);

    var size: u64 = undefined;
    ret = aegis.aegis128l_raf_get_size(&ctx, &size);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(size, 0);

    const test_data = "Hello, AEGIS RAF!";
    var bytes_written: usize = undefined;
    ret = aegis.aegis128l_raf_write(&ctx, &bytes_written, test_data.ptr, test_data.len, 0);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(bytes_written, test_data.len);

    ret = aegis.aegis128l_raf_get_size(&ctx, &size);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(size, test_data.len);

    var read_buf: [64]u8 = undefined;
    var bytes_read: usize = undefined;
    ret = aegis.aegis128l_raf_read(&ctx, &read_buf, &bytes_read, test_data.len, 0);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(bytes_read, test_data.len);
    try testing.expectEqualSlices(u8, test_data, read_buf[0..bytes_read]);

    aegis.aegis128l_raf_close(&ctx);
}

test "aegis128l_raf - open existing file" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    var file = MemoryFile.init(testing.allocator);
    defer file.deinit();

    var key: [aegis.aegis128l_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    var scratch_buf: [aegis.AEGIS128L_RAF_SCRATCH_SIZE(4096)]u8 align(aegis.AEGIS_RAF_SCRATCH_ALIGN) = undefined;
    const scratch = aegis.aegis_raf_scratch{
        .buf = &scratch_buf,
        .len = scratch_buf.len,
    };

    const cfg = aegis.aegis_raf_config{
        .chunk_size = 4096,
        .flags = aegis.AEGIS_RAF_CREATE,
        .scratch = &scratch,
    };

    var ctx: aegis.aegis128l_raf_ctx align(32) = undefined;

    var ret = aegis.aegis128l_raf_create(&ctx, &file.io(), &rng(), &cfg, &key);
    try testing.expectEqual(ret, 0);

    const test_data = "Test data for re-open";
    var bytes_written: usize = undefined;
    ret = aegis.aegis128l_raf_write(&ctx, &bytes_written, test_data.ptr, test_data.len, 0);
    try testing.expectEqual(ret, 0);

    aegis.aegis128l_raf_close(&ctx);

    const open_cfg = aegis.aegis_raf_config{
        .chunk_size = 0,
        .flags = 0,
        .scratch = &scratch,
    };

    ret = aegis.aegis128l_raf_open(&ctx, &file.io(), &rng(), &open_cfg, &key);
    try testing.expectEqual(ret, 0);

    var size: u64 = undefined;
    ret = aegis.aegis128l_raf_get_size(&ctx, &size);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(size, test_data.len);

    var read_buf: [64]u8 = undefined;
    var bytes_read: usize = undefined;
    ret = aegis.aegis128l_raf_read(&ctx, &read_buf, &bytes_read, test_data.len, 0);
    try testing.expectEqual(ret, 0);
    try testing.expectEqualSlices(u8, test_data, read_buf[0..bytes_read]);

    aegis.aegis128l_raf_close(&ctx);
}

test "aegis128l_raf - random access write" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    var file = MemoryFile.init(testing.allocator);
    defer file.deinit();

    var key: [aegis.aegis128l_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    var scratch_buf: [aegis.AEGIS128L_RAF_SCRATCH_SIZE(1024)]u8 align(aegis.AEGIS_RAF_SCRATCH_ALIGN) = undefined;
    const scratch = aegis.aegis_raf_scratch{
        .buf = &scratch_buf,
        .len = scratch_buf.len,
    };

    const cfg = aegis.aegis_raf_config{
        .chunk_size = 1024,
        .flags = aegis.AEGIS_RAF_CREATE,
        .scratch = &scratch,
    };

    var ctx: aegis.aegis128l_raf_ctx align(32) = undefined;

    var ret = aegis.aegis128l_raf_create(&ctx, &file.io(), &rng(), &cfg, &key);
    try testing.expectEqual(ret, 0);

    const data1 = "First block";
    const data2 = "Second block at offset 2048";
    var bytes_written: usize = undefined;

    ret = aegis.aegis128l_raf_write(&ctx, &bytes_written, data1.ptr, data1.len, 0);
    try testing.expectEqual(ret, 0);

    ret = aegis.aegis128l_raf_write(&ctx, &bytes_written, data2.ptr, data2.len, 2048);
    try testing.expectEqual(ret, 0);

    var size: u64 = undefined;
    ret = aegis.aegis128l_raf_get_size(&ctx, &size);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(size, 2048 + data2.len);

    var read_buf1: [32]u8 = undefined;
    var bytes_read: usize = undefined;
    ret = aegis.aegis128l_raf_read(&ctx, &read_buf1, &bytes_read, data1.len, 0);
    try testing.expectEqual(ret, 0);
    try testing.expectEqualSlices(u8, data1, read_buf1[0..bytes_read]);

    var read_buf2: [64]u8 = undefined;
    ret = aegis.aegis128l_raf_read(&ctx, &read_buf2, &bytes_read, data2.len, 2048);
    try testing.expectEqual(ret, 0);
    try testing.expectEqualSlices(u8, data2, read_buf2[0..bytes_read]);

    var zeros: [100]u8 = undefined;
    ret = aegis.aegis128l_raf_read(&ctx, &zeros, &bytes_read, 100, 100);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(bytes_read, 100);
    for (zeros[0..bytes_read]) |b| {
        try testing.expectEqual(b, 0);
    }

    aegis.aegis128l_raf_close(&ctx);
}

test "aegis128l_raf - truncate" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    var file = MemoryFile.init(testing.allocator);
    defer file.deinit();

    var key: [aegis.aegis128l_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    var scratch_buf: [aegis.AEGIS128L_RAF_SCRATCH_SIZE(1024)]u8 align(aegis.AEGIS_RAF_SCRATCH_ALIGN) = undefined;
    const scratch = aegis.aegis_raf_scratch{
        .buf = &scratch_buf,
        .len = scratch_buf.len,
    };

    const cfg = aegis.aegis_raf_config{
        .chunk_size = 1024,
        .flags = aegis.AEGIS_RAF_CREATE,
        .scratch = &scratch,
    };

    var ctx: aegis.aegis128l_raf_ctx align(32) = undefined;

    var ret = aegis.aegis128l_raf_create(&ctx, &file.io(), &rng(), &cfg, &key);
    try testing.expectEqual(ret, 0);

    var data: [2048]u8 = undefined;
    random.bytes(&data);
    var bytes_written: usize = undefined;
    ret = aegis.aegis128l_raf_write(&ctx, &bytes_written, &data, data.len, 0);
    try testing.expectEqual(ret, 0);

    ret = aegis.aegis128l_raf_truncate(&ctx, 500);
    try testing.expectEqual(ret, 0);

    var size: u64 = undefined;
    ret = aegis.aegis128l_raf_get_size(&ctx, &size);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(size, 500);

    var read_buf: [500]u8 = undefined;
    var bytes_read: usize = undefined;
    ret = aegis.aegis128l_raf_read(&ctx, &read_buf, &bytes_read, 500, 0);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(bytes_read, 500);
    try testing.expectEqualSlices(u8, data[0..500], read_buf[0..500]);

    aegis.aegis128l_raf_close(&ctx);
}

test "aegis128l_raf - cross-chunk operations" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    var file = MemoryFile.init(testing.allocator);
    defer file.deinit();

    var key: [aegis.aegis128l_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    const chunk_size: usize = 1024;
    var scratch_buf: [aegis.AEGIS128L_RAF_SCRATCH_SIZE(chunk_size)]u8 align(aegis.AEGIS_RAF_SCRATCH_ALIGN) = undefined;
    const scratch = aegis.aegis_raf_scratch{
        .buf = &scratch_buf,
        .len = scratch_buf.len,
    };

    const cfg = aegis.aegis_raf_config{
        .chunk_size = @intCast(chunk_size),
        .flags = aegis.AEGIS_RAF_CREATE,
        .scratch = &scratch,
    };

    var ctx: aegis.aegis128l_raf_ctx align(32) = undefined;

    var ret = aegis.aegis128l_raf_create(&ctx, &file.io(), &rng(), &cfg, &key);
    try testing.expectEqual(ret, 0);

    var data: [2000]u8 = undefined;
    for (&data, 0..) |*b, i| {
        b.* = @truncate(i);
    }

    var bytes_written: usize = undefined;
    ret = aegis.aegis128l_raf_write(&ctx, &bytes_written, &data, data.len, chunk_size - 500);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(bytes_written, data.len);

    var read_buf: [2000]u8 = undefined;
    var bytes_read: usize = undefined;
    ret = aegis.aegis128l_raf_read(&ctx, &read_buf, &bytes_read, data.len, chunk_size - 500);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(bytes_read, data.len);
    try testing.expectEqualSlices(u8, &data, read_buf[0..bytes_read]);

    aegis.aegis128l_raf_close(&ctx);
}

test "aegis128l_raf - header tampering detection" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    var file = MemoryFile.init(testing.allocator);
    defer file.deinit();

    var key: [aegis.aegis128l_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    var scratch_buf: [aegis.AEGIS128L_RAF_SCRATCH_SIZE(4096)]u8 align(aegis.AEGIS_RAF_SCRATCH_ALIGN) = undefined;
    const scratch = aegis.aegis_raf_scratch{
        .buf = &scratch_buf,
        .len = scratch_buf.len,
    };

    const cfg = aegis.aegis_raf_config{
        .chunk_size = 4096,
        .flags = aegis.AEGIS_RAF_CREATE,
        .scratch = &scratch,
    };

    var ctx: aegis.aegis128l_raf_ctx align(32) = undefined;

    var ret = aegis.aegis128l_raf_create(&ctx, &file.io(), &rng(), &cfg, &key);
    try testing.expectEqual(ret, 0);

    const test_data = "Test data";
    var bytes_written: usize = undefined;
    ret = aegis.aegis128l_raf_write(&ctx, &bytes_written, test_data.ptr, test_data.len, 0);
    try testing.expectEqual(ret, 0);

    aegis.aegis128l_raf_close(&ctx);

    file.data.items[20] ^= 0x01;

    const open_cfg = aegis.aegis_raf_config{
        .chunk_size = 0,
        .flags = 0,
        .scratch = &scratch,
    };

    ret = aegis.aegis128l_raf_open(&ctx, &file.io(), &rng(), &open_cfg, &key);
    try testing.expect(ret != 0);
}

test "aegis128l_raf - chunk tampering detection" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    var file = MemoryFile.init(testing.allocator);
    defer file.deinit();

    var key: [aegis.aegis128l_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    var scratch_buf: [aegis.AEGIS128L_RAF_SCRATCH_SIZE(1024)]u8 align(aegis.AEGIS_RAF_SCRATCH_ALIGN) = undefined;
    const scratch = aegis.aegis_raf_scratch{
        .buf = &scratch_buf,
        .len = scratch_buf.len,
    };

    const cfg = aegis.aegis_raf_config{
        .chunk_size = 1024,
        .flags = aegis.AEGIS_RAF_CREATE,
        .scratch = &scratch,
    };

    var ctx: aegis.aegis128l_raf_ctx align(32) = undefined;

    var ret = aegis.aegis128l_raf_create(&ctx, &file.io(), &rng(), &cfg, &key);
    try testing.expectEqual(ret, 0);

    var data: [1024]u8 = undefined;
    random.bytes(&data);
    var bytes_written: usize = undefined;
    ret = aegis.aegis128l_raf_write(&ctx, &bytes_written, &data, data.len, 0);
    try testing.expectEqual(ret, 0);

    aegis.aegis128l_raf_close(&ctx);

    const chunk_offset = aegis.AEGIS_RAF_HEADER_SIZE + aegis.aegis128l_NPUBBYTES + 512;
    file.data.items[chunk_offset] ^= 0x01;

    const open_cfg = aegis.aegis_raf_config{
        .chunk_size = 0,
        .flags = 0,
        .scratch = &scratch,
    };

    ret = aegis.aegis128l_raf_open(&ctx, &file.io(), &rng(), &open_cfg, &key);
    try testing.expectEqual(ret, 0);

    var read_buf: [1024]u8 = undefined;
    var bytes_read: usize = undefined;
    ret = aegis.aegis128l_raf_read(&ctx, &read_buf, &bytes_read, 1024, 0);
    try testing.expect(ret != 0);

    aegis.aegis128l_raf_close(&ctx);
}

test "aegis128l_raf - wrong key detection" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    var file = MemoryFile.init(testing.allocator);
    defer file.deinit();

    var key1: [aegis.aegis128l_KEYBYTES]u8 = undefined;
    var key2: [aegis.aegis128l_KEYBYTES]u8 = undefined;
    random.bytes(&key1);
    random.bytes(&key2);

    var scratch_buf: [aegis.AEGIS128L_RAF_SCRATCH_SIZE(4096)]u8 align(aegis.AEGIS_RAF_SCRATCH_ALIGN) = undefined;
    const scratch = aegis.aegis_raf_scratch{
        .buf = &scratch_buf,
        .len = scratch_buf.len,
    };

    const cfg = aegis.aegis_raf_config{
        .chunk_size = 4096,
        .flags = aegis.AEGIS_RAF_CREATE,
        .scratch = &scratch,
    };

    var ctx: aegis.aegis128l_raf_ctx align(32) = undefined;

    var ret = aegis.aegis128l_raf_create(&ctx, &file.io(), &rng(), &cfg, &key1);
    try testing.expectEqual(ret, 0);

    const test_data = "Secret data";
    var bytes_written: usize = undefined;
    ret = aegis.aegis128l_raf_write(&ctx, &bytes_written, test_data.ptr, test_data.len, 0);
    try testing.expectEqual(ret, 0);

    aegis.aegis128l_raf_close(&ctx);

    const open_cfg = aegis.aegis_raf_config{
        .chunk_size = 0,
        .flags = 0,
        .scratch = &scratch,
    };

    ret = aegis.aegis128l_raf_open(&ctx, &file.io(), &rng(), &open_cfg, &key2);
    try testing.expect(ret != 0);
}

test "aegis256_raf - basic operations" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    var file = MemoryFile.init(testing.allocator);
    defer file.deinit();

    var key: [aegis.aegis256_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    var scratch_buf: [aegis.AEGIS256_RAF_SCRATCH_SIZE(4096)]u8 align(aegis.AEGIS_RAF_SCRATCH_ALIGN) = undefined;
    const scratch = aegis.aegis_raf_scratch{
        .buf = &scratch_buf,
        .len = scratch_buf.len,
    };

    const cfg = aegis.aegis_raf_config{
        .chunk_size = 4096,
        .flags = aegis.AEGIS_RAF_CREATE,
        .scratch = &scratch,
    };

    var ctx: aegis.aegis256_raf_ctx = undefined;

    var ret = aegis.aegis256_raf_create(&ctx, &file.io(), &rng(), &cfg, &key);
    try testing.expectEqual(ret, 0);

    const test_data = "AEGIS-256 RAF test data";
    var bytes_written: usize = undefined;
    ret = aegis.aegis256_raf_write(&ctx, &bytes_written, test_data.ptr, test_data.len, 0);
    try testing.expectEqual(ret, 0);

    aegis.aegis256_raf_close(&ctx);

    const open_cfg = aegis.aegis_raf_config{
        .chunk_size = 0,
        .flags = 0,
        .scratch = &scratch,
    };

    ret = aegis.aegis256_raf_open(&ctx, &file.io(), &rng(), &open_cfg, &key);
    try testing.expectEqual(ret, 0);

    var read_buf: [64]u8 = undefined;
    var bytes_read: usize = undefined;
    ret = aegis.aegis256_raf_read(&ctx, &read_buf, &bytes_read, test_data.len, 0);
    try testing.expectEqual(ret, 0);
    try testing.expectEqualSlices(u8, test_data, read_buf[0..bytes_read]);

    aegis.aegis256_raf_close(&ctx);
}

test "aegis_raf - algorithm mismatch detection" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    var file = MemoryFile.init(testing.allocator);
    defer file.deinit();

    var key128: [aegis.aegis128l_KEYBYTES]u8 = undefined;
    var key256: [aegis.aegis256_KEYBYTES]u8 = undefined;
    random.bytes(&key128);
    @memcpy(key256[0..16], &key128);
    @memcpy(key256[16..32], &key128);

    var scratch128_buf: [aegis.AEGIS128L_RAF_SCRATCH_SIZE(4096)]u8 align(aegis.AEGIS_RAF_SCRATCH_ALIGN) = undefined;
    const scratch128 = aegis.aegis_raf_scratch{
        .buf = &scratch128_buf,
        .len = scratch128_buf.len,
    };

    const cfg = aegis.aegis_raf_config{
        .chunk_size = 4096,
        .flags = aegis.AEGIS_RAF_CREATE,
        .scratch = &scratch128,
    };

    var ctx128: aegis.aegis128l_raf_ctx align(32) = undefined;

    var ret = aegis.aegis128l_raf_create(&ctx128, &file.io(), &rng(), &cfg, &key128);
    try testing.expectEqual(ret, 0);

    const test_data = "Test";
    var bytes_written: usize = undefined;
    ret = aegis.aegis128l_raf_write(&ctx128, &bytes_written, test_data.ptr, test_data.len, 0);
    try testing.expectEqual(ret, 0);

    aegis.aegis128l_raf_close(&ctx128);

    var scratch256_buf: [aegis.AEGIS256_RAF_SCRATCH_SIZE(4096)]u8 align(aegis.AEGIS_RAF_SCRATCH_ALIGN) = undefined;
    const scratch256 = aegis.aegis_raf_scratch{
        .buf = &scratch256_buf,
        .len = scratch256_buf.len,
    };

    const open_cfg = aegis.aegis_raf_config{
        .chunk_size = 0,
        .flags = 0,
        .scratch = &scratch256,
    };

    var ctx256: aegis.aegis256_raf_ctx = undefined;
    ret = aegis.aegis256_raf_open(&ctx256, &file.io(), &rng(), &open_cfg, &key256);
    try testing.expect(ret != 0);
}

test "aegis128l_raf - EOF behavior" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    var file = MemoryFile.init(testing.allocator);
    defer file.deinit();

    var key: [aegis.aegis128l_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    var scratch_buf: [aegis.AEGIS128L_RAF_SCRATCH_SIZE(4096)]u8 align(aegis.AEGIS_RAF_SCRATCH_ALIGN) = undefined;
    const scratch = aegis.aegis_raf_scratch{
        .buf = &scratch_buf,
        .len = scratch_buf.len,
    };

    const cfg = aegis.aegis_raf_config{
        .chunk_size = 4096,
        .flags = aegis.AEGIS_RAF_CREATE,
        .scratch = &scratch,
    };

    var ctx: aegis.aegis128l_raf_ctx align(32) = undefined;

    var ret = aegis.aegis128l_raf_create(&ctx, &file.io(), &rng(), &cfg, &key);
    try testing.expectEqual(ret, 0);

    const test_data = "Short data";
    var bytes_written: usize = undefined;
    ret = aegis.aegis128l_raf_write(&ctx, &bytes_written, test_data.ptr, test_data.len, 0);
    try testing.expectEqual(ret, 0);

    var read_buf: [100]u8 = undefined;
    var bytes_read: usize = undefined;

    ret = aegis.aegis128l_raf_read(&ctx, &read_buf, &bytes_read, 100, 100);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(bytes_read, 0);

    ret = aegis.aegis128l_raf_read(&ctx, &read_buf, &bytes_read, 100, 0);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(bytes_read, test_data.len);

    aegis.aegis128l_raf_close(&ctx);
}

test "aegis128l_raf - empty file" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    var file = MemoryFile.init(testing.allocator);
    defer file.deinit();

    var key: [aegis.aegis128l_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    var scratch_buf: [aegis.AEGIS128L_RAF_SCRATCH_SIZE(4096)]u8 align(aegis.AEGIS_RAF_SCRATCH_ALIGN) = undefined;
    const scratch = aegis.aegis_raf_scratch{
        .buf = &scratch_buf,
        .len = scratch_buf.len,
    };

    const cfg = aegis.aegis_raf_config{
        .chunk_size = 4096,
        .flags = aegis.AEGIS_RAF_CREATE,
        .scratch = &scratch,
    };

    var ctx: aegis.aegis128l_raf_ctx align(32) = undefined;

    var ret = aegis.aegis128l_raf_create(&ctx, &file.io(), &rng(), &cfg, &key);
    try testing.expectEqual(ret, 0);

    var size: u64 = undefined;
    ret = aegis.aegis128l_raf_get_size(&ctx, &size);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(size, 0);

    var read_buf: [100]u8 = undefined;
    var bytes_read: usize = undefined;
    ret = aegis.aegis128l_raf_read(&ctx, &read_buf, &bytes_read, 100, 0);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(bytes_read, 0);

    aegis.aegis128l_raf_close(&ctx);

    const open_cfg = aegis.aegis_raf_config{
        .chunk_size = 0,
        .flags = 0,
        .scratch = &scratch,
    };

    ret = aegis.aegis128l_raf_open(&ctx, &file.io(), &rng(), &open_cfg, &key);
    try testing.expectEqual(ret, 0);

    ret = aegis.aegis128l_raf_get_size(&ctx, &size);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(size, 0);

    aegis.aegis128l_raf_close(&ctx);
}

test "aegis128l_raf - create flags semantics" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    var file = MemoryFile.init(testing.allocator);
    defer file.deinit();

    var key: [aegis.aegis128l_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    var ctx: aegis.aegis128l_raf_ctx align(32) = undefined;

    var scratch_buf: [aegis.AEGIS128L_RAF_SCRATCH_SIZE(4096)]u8 align(aegis.AEGIS_RAF_SCRATCH_ALIGN) = undefined;
    const scratch = aegis.aegis_raf_scratch{
        .buf = &scratch_buf,
        .len = scratch_buf.len,
    };

    const cfg_create_only = aegis.aegis_raf_config{
        .chunk_size = 4096,
        .flags = aegis.AEGIS_RAF_CREATE,
        .scratch = &scratch,
    };

    var ret = aegis.aegis128l_raf_create(&ctx, &file.io(), &rng(), &cfg_create_only, &key);
    try testing.expectEqual(ret, 0);

    const test_data = "Test data";
    var bytes_written: usize = undefined;
    ret = aegis.aegis128l_raf_write(&ctx, &bytes_written, test_data.ptr, test_data.len, 0);
    try testing.expectEqual(ret, 0);

    aegis.aegis128l_raf_close(&ctx);

    ret = aegis.aegis128l_raf_create(&ctx, &file.io(), &rng(), &cfg_create_only, &key);
    try testing.expect(ret != 0);

    const cfg_truncate = aegis.aegis_raf_config{
        .chunk_size = 4096,
        .flags = aegis.AEGIS_RAF_CREATE | aegis.AEGIS_RAF_TRUNCATE,
        .scratch = &scratch,
    };

    ret = aegis.aegis128l_raf_create(&ctx, &file.io(), &rng(), &cfg_truncate, &key);
    try testing.expectEqual(ret, 0);

    var size: u64 = undefined;
    ret = aegis.aegis128l_raf_get_size(&ctx, &size);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(size, 0);

    aegis.aegis128l_raf_close(&ctx);
}

test "aegis128l_raf - create without CREATE flag fails on empty file" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    var file = MemoryFile.init(testing.allocator);
    defer file.deinit();

    var key: [aegis.aegis128l_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    var scratch_buf: [aegis.AEGIS128L_RAF_SCRATCH_SIZE(4096)]u8 align(aegis.AEGIS_RAF_SCRATCH_ALIGN) = undefined;
    const scratch = aegis.aegis_raf_scratch{
        .buf = &scratch_buf,
        .len = scratch_buf.len,
    };

    const cfg_no_create = aegis.aegis_raf_config{
        .chunk_size = 4096,
        .flags = 0,
        .scratch = &scratch,
    };

    var ctx: aegis.aegis128l_raf_ctx align(32) = undefined;
    const ret = aegis.aegis128l_raf_create(&ctx, &file.io(), &rng(), &cfg_no_create, &key);
    try testing.expect(ret != 0);
}

test "aegis128l_raf - truncate grow within same chunk" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    var file = MemoryFile.init(testing.allocator);
    defer file.deinit();

    var key: [aegis.aegis128l_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    var scratch_buf: [aegis.AEGIS128L_RAF_SCRATCH_SIZE(1024)]u8 align(aegis.AEGIS_RAF_SCRATCH_ALIGN) = undefined;
    const scratch = aegis.aegis_raf_scratch{
        .buf = &scratch_buf,
        .len = scratch_buf.len,
    };

    const cfg = aegis.aegis_raf_config{
        .chunk_size = 1024,
        .flags = aegis.AEGIS_RAF_CREATE,
        .scratch = &scratch,
    };

    var ctx: aegis.aegis128l_raf_ctx align(32) = undefined;

    var ret = aegis.aegis128l_raf_create(&ctx, &file.io(), &rng(), &cfg, &key);
    try testing.expectEqual(ret, 0);

    const test_data = "Hello, grow test!";
    var bytes_written: usize = undefined;
    ret = aegis.aegis128l_raf_write(&ctx, &bytes_written, test_data.ptr, test_data.len, 0);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(bytes_written, test_data.len);

    ret = aegis.aegis128l_raf_truncate(&ctx, 800);
    try testing.expectEqual(ret, 0);

    var size: u64 = undefined;
    ret = aegis.aegis128l_raf_get_size(&ctx, &size);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(size, 800);

    var read_buf: [64]u8 = undefined;
    var bytes_read: usize = undefined;
    ret = aegis.aegis128l_raf_read(&ctx, &read_buf, &bytes_read, test_data.len, 0);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(bytes_read, test_data.len);
    try testing.expectEqualSlices(u8, test_data, read_buf[0..bytes_read]);

    var zeros: [100]u8 = undefined;
    ret = aegis.aegis128l_raf_read(&ctx, &zeros, &bytes_read, 100, test_data.len);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(bytes_read, 100);
    for (zeros[0..bytes_read]) |b| {
        try testing.expectEqual(b, 0);
    }

    aegis.aegis128l_raf_close(&ctx);
}

test "aegis128l_raf - truncate grow across chunk boundaries" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    var file = MemoryFile.init(testing.allocator);
    defer file.deinit();

    var key: [aegis.aegis128l_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    const chunk_size: usize = 1024;
    var scratch_buf: [aegis.AEGIS128L_RAF_SCRATCH_SIZE(chunk_size)]u8 align(aegis.AEGIS_RAF_SCRATCH_ALIGN) = undefined;
    const scratch = aegis.aegis_raf_scratch{
        .buf = &scratch_buf,
        .len = scratch_buf.len,
    };

    const cfg = aegis.aegis_raf_config{
        .chunk_size = @intCast(chunk_size),
        .flags = aegis.AEGIS_RAF_CREATE,
        .scratch = &scratch,
    };

    var ctx: aegis.aegis128l_raf_ctx align(32) = undefined;

    var ret = aegis.aegis128l_raf_create(&ctx, &file.io(), &rng(), &cfg, &key);
    try testing.expectEqual(ret, 0);

    var data: [1500]u8 = undefined;
    for (&data, 0..) |*b, i| {
        b.* = @truncate(i);
    }

    var bytes_written: usize = undefined;
    ret = aegis.aegis128l_raf_write(&ctx, &bytes_written, &data, data.len, 0);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(bytes_written, data.len);

    ret = aegis.aegis128l_raf_truncate(&ctx, 3500);
    try testing.expectEqual(ret, 0);

    var size: u64 = undefined;
    ret = aegis.aegis128l_raf_get_size(&ctx, &size);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(size, 3500);

    var read_buf: [1500]u8 = undefined;
    var bytes_read: usize = undefined;
    ret = aegis.aegis128l_raf_read(&ctx, &read_buf, &bytes_read, data.len, 0);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(bytes_read, data.len);
    try testing.expectEqualSlices(u8, &data, read_buf[0..bytes_read]);

    var zeros: [500]u8 = undefined;
    ret = aegis.aegis128l_raf_read(&ctx, &zeros, &bytes_read, 500, 2500);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(bytes_read, 500);
    for (zeros[0..bytes_read]) |b| {
        try testing.expectEqual(b, 0);
    }

    aegis.aegis128l_raf_close(&ctx);

    const open_cfg = aegis.aegis_raf_config{
        .chunk_size = 0,
        .flags = 0,
        .scratch = &scratch,
    };

    ret = aegis.aegis128l_raf_open(&ctx, &file.io(), &rng(), &open_cfg, &key);
    try testing.expectEqual(ret, 0);

    ret = aegis.aegis128l_raf_get_size(&ctx, &size);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(size, 3500);

    ret = aegis.aegis128l_raf_read(&ctx, &read_buf, &bytes_read, data.len, 0);
    try testing.expectEqual(ret, 0);
    try testing.expectEqualSlices(u8, &data, read_buf[0..bytes_read]);

    ret = aegis.aegis128l_raf_read(&ctx, &zeros, &bytes_read, 500, 3000);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(bytes_read, 500);
    for (zeros[0..bytes_read]) |b| {
        try testing.expectEqual(b, 0);
    }

    aegis.aegis128l_raf_close(&ctx);
}

test "aegis128l_raf - shrink then grow within same chunk" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    var file = MemoryFile.init(testing.allocator);
    defer file.deinit();

    var key: [aegis.aegis128l_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    const chunk_size: usize = 1024;
    var scratch_buf: [aegis.AEGIS128L_RAF_SCRATCH_SIZE(chunk_size)]u8 align(aegis.AEGIS_RAF_SCRATCH_ALIGN) = undefined;
    const scratch = aegis.aegis_raf_scratch{
        .buf = &scratch_buf,
        .len = scratch_buf.len,
    };

    const cfg = aegis.aegis_raf_config{
        .chunk_size = @intCast(chunk_size),
        .flags = aegis.AEGIS_RAF_CREATE,
        .scratch = &scratch,
    };

    var ctx: aegis.aegis128l_raf_ctx align(32) = undefined;

    var ret = aegis.aegis128l_raf_create(&ctx, &file.io(), &rng(), &cfg, &key);
    try testing.expectEqual(ret, 0);

    var data: [800]u8 = undefined;
    for (&data, 0..) |*b, i| {
        b.* = @truncate(i ^ 0xAB);
    }

    var bytes_written: usize = undefined;
    ret = aegis.aegis128l_raf_write(&ctx, &bytes_written, &data, data.len, 0);
    try testing.expectEqual(ret, 0);

    ret = aegis.aegis128l_raf_truncate(&ctx, 500);
    try testing.expectEqual(ret, 0);

    ret = aegis.aegis128l_raf_truncate(&ctx, 700);
    try testing.expectEqual(ret, 0);

    var size: u64 = undefined;
    ret = aegis.aegis128l_raf_get_size(&ctx, &size);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(size, 700);

    var read_buf: [500]u8 = undefined;
    var bytes_read: usize = undefined;
    ret = aegis.aegis128l_raf_read(&ctx, &read_buf, &bytes_read, 500, 0);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(bytes_read, 500);
    try testing.expectEqualSlices(u8, data[0..500], read_buf[0..500]);

    var grown_region: [200]u8 = undefined;
    ret = aegis.aegis128l_raf_read(&ctx, &grown_region, &bytes_read, 200, 500);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(bytes_read, 200);
    for (grown_region[0..bytes_read]) |b| {
        try testing.expectEqual(b, 0);
    }

    aegis.aegis128l_raf_close(&ctx);
}

test "aegis128l_raf - shrink then grow across chunk boundaries" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    var file = MemoryFile.init(testing.allocator);
    defer file.deinit();

    var key: [aegis.aegis128l_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    const chunk_size: usize = 1024;
    var scratch_buf: [aegis.AEGIS128L_RAF_SCRATCH_SIZE(chunk_size)]u8 align(aegis.AEGIS_RAF_SCRATCH_ALIGN) = undefined;
    const scratch = aegis.aegis_raf_scratch{
        .buf = &scratch_buf,
        .len = scratch_buf.len,
    };

    const cfg = aegis.aegis_raf_config{
        .chunk_size = @intCast(chunk_size),
        .flags = aegis.AEGIS_RAF_CREATE,
        .scratch = &scratch,
    };

    var ctx: aegis.aegis128l_raf_ctx align(32) = undefined;

    var ret = aegis.aegis128l_raf_create(&ctx, &file.io(), &rng(), &cfg, &key);
    try testing.expectEqual(ret, 0);

    var data: [2000]u8 = undefined;
    for (&data, 0..) |*b, i| {
        b.* = @truncate(i ^ 0xCD);
    }

    var bytes_written: usize = undefined;
    ret = aegis.aegis128l_raf_write(&ctx, &bytes_written, &data, data.len, 0);
    try testing.expectEqual(ret, 0);

    ret = aegis.aegis128l_raf_truncate(&ctx, 1500);
    try testing.expectEqual(ret, 0);

    ret = aegis.aegis128l_raf_truncate(&ctx, 3000);
    try testing.expectEqual(ret, 0);

    var size: u64 = undefined;
    ret = aegis.aegis128l_raf_get_size(&ctx, &size);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(size, 3000);

    var read_buf: [1500]u8 = undefined;
    var bytes_read: usize = undefined;
    ret = aegis.aegis128l_raf_read(&ctx, &read_buf, &bytes_read, 1500, 0);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(bytes_read, 1500);
    try testing.expectEqualSlices(u8, data[0..1500], read_buf[0..1500]);

    var tail_of_old_chunk: [chunk_size - 476]u8 = undefined;
    ret = aegis.aegis128l_raf_read(&ctx, &tail_of_old_chunk, &bytes_read, tail_of_old_chunk.len, 1500);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(bytes_read, tail_of_old_chunk.len);
    for (tail_of_old_chunk[0..bytes_read]) |b| {
        try testing.expectEqual(b, 0);
    }

    var new_chunks: [1000]u8 = undefined;
    ret = aegis.aegis128l_raf_read(&ctx, &new_chunks, &bytes_read, 1000, 2000);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(bytes_read, 1000);
    for (new_chunks[0..bytes_read]) |b| {
        try testing.expectEqual(b, 0);
    }

    aegis.aegis128l_raf_close(&ctx);
}

test "aegis128l_raf - RNG failure during truncate grow" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    var file = MemoryFile.init(testing.allocator);
    defer file.deinit();

    var key: [aegis.aegis128l_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    const chunk_size: usize = 1024;
    var scratch_buf: [aegis.AEGIS128L_RAF_SCRATCH_SIZE(chunk_size)]u8 align(aegis.AEGIS_RAF_SCRATCH_ALIGN) = undefined;
    const scratch = aegis.aegis_raf_scratch{
        .buf = &scratch_buf,
        .len = scratch_buf.len,
    };

    const cfg = aegis.aegis_raf_config{
        .chunk_size = @intCast(chunk_size),
        .flags = aegis.AEGIS_RAF_CREATE,
        .scratch = &scratch,
    };

    var ctx: aegis.aegis128l_raf_ctx align(32) = undefined;

    var failing_rng = FailingRng{ .calls_until_fail = 2 };

    var ret = aegis.aegis128l_raf_create(&ctx, &file.io(), &failing_rng.interface(), &cfg, &key);
    try testing.expectEqual(ret, 0);

    const test_data = "Initial data";
    var bytes_written: usize = undefined;
    ret = aegis.aegis128l_raf_write(&ctx, &bytes_written, test_data.ptr, test_data.len, 0);
    try testing.expectEqual(ret, 0);

    var size_before: u64 = undefined;
    ret = aegis.aegis128l_raf_get_size(&ctx, &size_before);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(size_before, test_data.len);

    ret = aegis.aegis128l_raf_truncate(&ctx, 5000);
    try testing.expect(ret != 0);

    var size_after: u64 = undefined;
    ret = aegis.aegis128l_raf_get_size(&ctx, &size_after);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(size_after, test_data.len);

    aegis.aegis128l_raf_close(&ctx);

    const open_cfg = aegis.aegis_raf_config{
        .chunk_size = 0,
        .flags = 0,
        .scratch = &scratch,
    };

    ret = aegis.aegis128l_raf_open(&ctx, &file.io(), &rng(), &open_cfg, &key);
    try testing.expectEqual(ret, 0);

    var read_buf: [32]u8 = undefined;
    var bytes_read: usize = undefined;
    ret = aegis.aegis128l_raf_read(&ctx, &read_buf, &bytes_read, test_data.len, 0);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(bytes_read, test_data.len);
    try testing.expectEqualSlices(u8, test_data, read_buf[0..bytes_read]);

    aegis.aegis128l_raf_close(&ctx);
}

test "aegis128l_raf - null scratch rejected" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    var file = MemoryFile.init(testing.allocator);
    defer file.deinit();

    var key: [aegis.aegis128l_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    const cfg_no_scratch = aegis.aegis_raf_config{
        .chunk_size = 4096,
        .flags = aegis.AEGIS_RAF_CREATE,
        .scratch = null,
    };

    var ctx: aegis.aegis128l_raf_ctx align(32) = undefined;

    const ret = aegis.aegis128l_raf_create(&ctx, &file.io(), &rng(), &cfg_no_scratch, &key);
    try testing.expect(ret != 0);
    try testing.expectEqual(std.c._errno().*, @intFromEnum(std.c.E.INVAL));
}

test "aegis128l_raf - undersized scratch rejected" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    var file = MemoryFile.init(testing.allocator);
    defer file.deinit();

    var key: [aegis.aegis128l_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    var small_scratch_buf: [64]u8 align(aegis.AEGIS_RAF_SCRATCH_ALIGN) = undefined;
    const small_scratch = aegis.aegis_raf_scratch{
        .buf = &small_scratch_buf,
        .len = small_scratch_buf.len,
    };

    const cfg = aegis.aegis_raf_config{
        .chunk_size = 4096,
        .flags = aegis.AEGIS_RAF_CREATE,
        .scratch = &small_scratch,
    };

    var ctx: aegis.aegis128l_raf_ctx align(32) = undefined;

    const ret = aegis.aegis128l_raf_create(&ctx, &file.io(), &rng(), &cfg, &key);
    try testing.expect(ret != 0);
    try testing.expectEqual(std.c._errno().*, @intFromEnum(std.c.E.INVAL));
}

test "aegis128l_raf - misaligned scratch rejected" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    var file = MemoryFile.init(testing.allocator);
    defer file.deinit();

    var key: [aegis.aegis128l_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    var scratch_buf: [aegis.AEGIS128L_RAF_SCRATCH_SIZE(4096) + 64]u8 align(aegis.AEGIS_RAF_SCRATCH_ALIGN) = undefined;
    const misaligned_scratch = aegis.aegis_raf_scratch{
        .buf = scratch_buf[1..].ptr,
        .len = aegis.AEGIS128L_RAF_SCRATCH_SIZE(4096),
    };

    const cfg = aegis.aegis_raf_config{
        .chunk_size = 4096,
        .flags = aegis.AEGIS_RAF_CREATE,
        .scratch = &misaligned_scratch,
    };

    var ctx: aegis.aegis128l_raf_ctx align(32) = undefined;

    const ret = aegis.aegis128l_raf_create(&ctx, &file.io(), &rng(), &cfg, &key);
    try testing.expect(ret != 0);
    try testing.expectEqual(std.c._errno().*, @intFromEnum(std.c.E.INVAL));
}

test "aegis_raf_probe - basic functionality" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    var file = MemoryFile.init(testing.allocator);
    defer file.deinit();

    var key: [aegis.aegis128l_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    var scratch_buf: [aegis.AEGIS128L_RAF_SCRATCH_SIZE(4096)]u8 align(aegis.AEGIS_RAF_SCRATCH_ALIGN) = undefined;
    const scratch = aegis.aegis_raf_scratch{
        .buf = &scratch_buf,
        .len = scratch_buf.len,
    };

    const cfg = aegis.aegis_raf_config{
        .chunk_size = 4096,
        .flags = aegis.AEGIS_RAF_CREATE,
        .scratch = &scratch,
    };

    var ctx: aegis.aegis128l_raf_ctx align(32) = undefined;

    var ret = aegis.aegis128l_raf_create(&ctx, &file.io(), &rng(), &cfg, &key);
    try testing.expectEqual(ret, 0);

    const test_data = "Probe test data";
    var bytes_written: usize = undefined;
    ret = aegis.aegis128l_raf_write(&ctx, &bytes_written, test_data.ptr, test_data.len, 0);
    try testing.expectEqual(ret, 0);

    aegis.aegis128l_raf_close(&ctx);

    var info: aegis.aegis_raf_info = undefined;
    ret = aegis.aegis_raf_probe(&file.io(), &info);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(info.alg_id, aegis.AEGIS_RAF_ALG_128L);
    try testing.expectEqual(info.chunk_size, 4096);
    try testing.expectEqual(info.file_size, test_data.len);
}

test "aegis256_raf_probe - basic functionality" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    var file = MemoryFile.init(testing.allocator);
    defer file.deinit();

    var key: [aegis.aegis256_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    var scratch_buf: [aegis.AEGIS256_RAF_SCRATCH_SIZE(2048)]u8 align(aegis.AEGIS_RAF_SCRATCH_ALIGN) = undefined;
    const scratch = aegis.aegis_raf_scratch{
        .buf = &scratch_buf,
        .len = scratch_buf.len,
    };

    const cfg = aegis.aegis_raf_config{
        .chunk_size = 2048,
        .flags = aegis.AEGIS_RAF_CREATE,
        .scratch = &scratch,
    };

    var ctx: aegis.aegis256_raf_ctx = undefined;

    var ret = aegis.aegis256_raf_create(&ctx, &file.io(), &rng(), &cfg, &key);
    try testing.expectEqual(ret, 0);

    const test_data = "AEGIS-256 probe test";
    var bytes_written: usize = undefined;
    ret = aegis.aegis256_raf_write(&ctx, &bytes_written, test_data.ptr, test_data.len, 0);
    try testing.expectEqual(ret, 0);

    aegis.aegis256_raf_close(&ctx);

    var info: aegis.aegis_raf_info = undefined;
    ret = aegis.aegis_raf_probe(&file.io(), &info);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(info.alg_id, aegis.AEGIS_RAF_ALG_256);
    try testing.expectEqual(info.chunk_size, 2048);
    try testing.expectEqual(info.file_size, test_data.len);
}

test "aegis128l_raf_scratch_size - runtime helper matches macro" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    const chunk_sizes = [_]u32{ 1024, 2048, 4096, 8192, 16384, 32768, 65536 };

    for (chunk_sizes) |chunk_size| {
        const macro_size = aegis.AEGIS128L_RAF_SCRATCH_SIZE(chunk_size);
        const runtime_size = aegis.aegis128l_raf_scratch_size(chunk_size);
        try testing.expectEqual(macro_size, runtime_size);
    }

    try testing.expectEqual(aegis.aegis_raf_scratch_align(), aegis.AEGIS_RAF_SCRATCH_ALIGN);
}

test "aegis256_raf_scratch_size - runtime helper matches macro" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    const chunk_sizes = [_]u32{ 1024, 2048, 4096, 8192 };

    for (chunk_sizes) |chunk_size| {
        const macro_size = aegis.AEGIS256_RAF_SCRATCH_SIZE(chunk_size);
        const runtime_size = aegis.aegis256_raf_scratch_size(chunk_size);
        try testing.expectEqual(macro_size, runtime_size);
    }
}

test "aegis128l_raf_scratch_validate - validates correctly" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    var scratch_buf: [aegis.AEGIS128L_RAF_SCRATCH_SIZE(4096)]u8 align(aegis.AEGIS_RAF_SCRATCH_ALIGN) = undefined;

    const valid_scratch = aegis.aegis_raf_scratch{
        .buf = &scratch_buf,
        .len = scratch_buf.len,
    };
    try testing.expectEqual(aegis.aegis128l_raf_scratch_validate(&valid_scratch, 4096), 0);

    const undersized_scratch = aegis.aegis_raf_scratch{
        .buf = &scratch_buf,
        .len = 64,
    };
    try testing.expect(aegis.aegis128l_raf_scratch_validate(&undersized_scratch, 4096) != 0);

    try testing.expect(aegis.aegis128l_raf_scratch_validate(null, 4096) != 0);
}

test "aegis128l_raf - partial overwrite preserves trailing data" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    var file = MemoryFile.init(testing.allocator);
    defer file.deinit();

    var key: [aegis.aegis128l_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    var scratch_buf: [aegis.AEGIS128L_RAF_SCRATCH_SIZE(4096)]u8 align(aegis.AEGIS_RAF_SCRATCH_ALIGN) = undefined;
    const scratch = aegis.aegis_raf_scratch{
        .buf = &scratch_buf,
        .len = scratch_buf.len,
    };

    const cfg = aegis.aegis_raf_config{
        .chunk_size = 4096,
        .flags = aegis.AEGIS_RAF_CREATE,
        .scratch = &scratch,
    };

    var ctx: aegis.aegis128l_raf_ctx align(32) = undefined;

    var ret = aegis.aegis128l_raf_create(&ctx, &file.io(), &rng(), &cfg, &key);
    try testing.expectEqual(ret, 0);

    const initial_data = "AAAABBBB";
    var bytes_written: usize = undefined;
    ret = aegis.aegis128l_raf_write(&ctx, &bytes_written, initial_data.ptr, initial_data.len, 0);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(bytes_written, initial_data.len);

    var size: u64 = undefined;
    ret = aegis.aegis128l_raf_get_size(&ctx, &size);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(size, 8);

    const overwrite_data = "XX";
    ret = aegis.aegis128l_raf_write(&ctx, &bytes_written, overwrite_data.ptr, overwrite_data.len, 4);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(bytes_written, overwrite_data.len);

    ret = aegis.aegis128l_raf_get_size(&ctx, &size);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(size, 8);

    var read_buf: [8]u8 = undefined;
    var bytes_read: usize = undefined;
    ret = aegis.aegis128l_raf_read(&ctx, &read_buf, &bytes_read, 8, 0);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(bytes_read, 8);
    try testing.expectEqualSlices(u8, "AAAAXXBB", &read_buf);

    aegis.aegis128l_raf_close(&ctx);
}

test "aegis128l_raf - partial overwrite preserves leading data" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    var file = MemoryFile.init(testing.allocator);
    defer file.deinit();

    var key: [aegis.aegis128l_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    var scratch_buf: [aegis.AEGIS128L_RAF_SCRATCH_SIZE(4096)]u8 align(aegis.AEGIS_RAF_SCRATCH_ALIGN) = undefined;
    const scratch = aegis.aegis_raf_scratch{
        .buf = &scratch_buf,
        .len = scratch_buf.len,
    };

    const cfg = aegis.aegis_raf_config{
        .chunk_size = 4096,
        .flags = aegis.AEGIS_RAF_CREATE,
        .scratch = &scratch,
    };

    var ctx: aegis.aegis128l_raf_ctx align(32) = undefined;

    var ret = aegis.aegis128l_raf_create(&ctx, &file.io(), &rng(), &cfg, &key);
    try testing.expectEqual(ret, 0);

    const initial_data = "AAAABBBB";
    var bytes_written: usize = undefined;
    ret = aegis.aegis128l_raf_write(&ctx, &bytes_written, initial_data.ptr, initial_data.len, 0);
    try testing.expectEqual(ret, 0);

    var size: u64 = undefined;
    ret = aegis.aegis128l_raf_get_size(&ctx, &size);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(size, 8);

    const overwrite_data = "XX";
    ret = aegis.aegis128l_raf_write(&ctx, &bytes_written, overwrite_data.ptr, overwrite_data.len, 0);
    try testing.expectEqual(ret, 0);

    ret = aegis.aegis128l_raf_get_size(&ctx, &size);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(size, 8);

    var read_buf: [8]u8 = undefined;
    var bytes_read: usize = undefined;
    ret = aegis.aegis128l_raf_read(&ctx, &read_buf, &bytes_read, 8, 0);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(bytes_read, 8);
    try testing.expectEqualSlices(u8, "XXAABBBB", &read_buf);

    aegis.aegis128l_raf_close(&ctx);
}

test "aegis128l_raf - multiple partial overwrites within chunk" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    var file = MemoryFile.init(testing.allocator);
    defer file.deinit();

    var key: [aegis.aegis128l_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    var scratch_buf: [aegis.AEGIS128L_RAF_SCRATCH_SIZE(4096)]u8 align(aegis.AEGIS_RAF_SCRATCH_ALIGN) = undefined;
    const scratch = aegis.aegis_raf_scratch{
        .buf = &scratch_buf,
        .len = scratch_buf.len,
    };

    const cfg = aegis.aegis_raf_config{
        .chunk_size = 4096,
        .flags = aegis.AEGIS_RAF_CREATE,
        .scratch = &scratch,
    };

    var ctx: aegis.aegis128l_raf_ctx align(32) = undefined;

    var ret = aegis.aegis128l_raf_create(&ctx, &file.io(), &rng(), &cfg, &key);
    try testing.expectEqual(ret, 0);

    var initial_data: [1000]u8 = undefined;
    for (&initial_data, 0..) |*b, i| {
        b.* = @truncate(i);
    }
    var bytes_written: usize = undefined;
    ret = aegis.aegis128l_raf_write(&ctx, &bytes_written, &initial_data, initial_data.len, 0);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(bytes_written, 1000);

    var size: u64 = undefined;
    ret = aegis.aegis128l_raf_get_size(&ctx, &size);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(size, 1000);

    const patch1 = "XXXXXXXXXX";
    ret = aegis.aegis128l_raf_write(&ctx, &bytes_written, patch1.ptr, patch1.len, 100);
    try testing.expectEqual(ret, 0);

    const patch2 = "YYYYYYYYYY";
    ret = aegis.aegis128l_raf_write(&ctx, &bytes_written, patch2.ptr, patch2.len, 500);
    try testing.expectEqual(ret, 0);

    ret = aegis.aegis128l_raf_get_size(&ctx, &size);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(size, 1000);

    var read_buf: [1000]u8 = undefined;
    var bytes_read: usize = undefined;
    ret = aegis.aegis128l_raf_read(&ctx, &read_buf, &bytes_read, 1000, 0);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(bytes_read, 1000);

    try testing.expectEqualSlices(u8, initial_data[0..100], read_buf[0..100]);
    try testing.expectEqualSlices(u8, patch1, read_buf[100..110]);
    try testing.expectEqualSlices(u8, initial_data[110..500], read_buf[110..500]);
    try testing.expectEqualSlices(u8, patch2, read_buf[500..510]);
    try testing.expectEqualSlices(u8, initial_data[510..1000], read_buf[510..1000]);

    aegis.aegis128l_raf_close(&ctx);
}

test "aegis128l_raf - cross-chunk partial write preserves existing data" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    var file = MemoryFile.init(testing.allocator);
    defer file.deinit();

    var key: [aegis.aegis128l_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    const chunk_size: usize = 1024;
    var scratch_buf: [aegis.AEGIS128L_RAF_SCRATCH_SIZE(chunk_size)]u8 align(aegis.AEGIS_RAF_SCRATCH_ALIGN) = undefined;
    const scratch = aegis.aegis_raf_scratch{
        .buf = &scratch_buf,
        .len = scratch_buf.len,
    };

    const cfg = aegis.aegis_raf_config{
        .chunk_size = @intCast(chunk_size),
        .flags = aegis.AEGIS_RAF_CREATE,
        .scratch = &scratch,
    };

    var ctx: aegis.aegis128l_raf_ctx align(32) = undefined;

    var ret = aegis.aegis128l_raf_create(&ctx, &file.io(), &rng(), &cfg, &key);
    try testing.expectEqual(ret, 0);

    var initial_data: [2000]u8 = undefined;
    for (&initial_data, 0..) |*b, i| {
        b.* = @truncate(i ^ 0x5A);
    }
    var bytes_written: usize = undefined;
    ret = aegis.aegis128l_raf_write(&ctx, &bytes_written, &initial_data, initial_data.len, 0);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(bytes_written, 2000);

    var size: u64 = undefined;
    ret = aegis.aegis128l_raf_get_size(&ctx, &size);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(size, 2000);

    var patch: [100]u8 = undefined;
    @memset(&patch, 0xFF);
    ret = aegis.aegis128l_raf_write(&ctx, &bytes_written, &patch, patch.len, 1000);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(bytes_written, 100);

    ret = aegis.aegis128l_raf_get_size(&ctx, &size);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(size, 2000);

    var read_buf: [2000]u8 = undefined;
    var bytes_read: usize = undefined;
    ret = aegis.aegis128l_raf_read(&ctx, &read_buf, &bytes_read, 2000, 0);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(bytes_read, 2000);

    try testing.expectEqualSlices(u8, initial_data[0..1000], read_buf[0..1000]);
    try testing.expectEqualSlices(u8, &patch, read_buf[1000..1100]);
    try testing.expectEqualSlices(u8, initial_data[1100..2000], read_buf[1100..2000]);

    aegis.aegis128l_raf_close(&ctx);
}

const MERKLE_HASH_LEN: usize = 16;

fn xorHashLeaf(
    _: ?*anyopaque,
    out: [*c]u8,
    out_len: usize,
    chunk: [*c]const u8,
    chunk_len: usize,
    chunk_idx: u64,
) callconv(.c) c_int {
    _ = out_len;
    @memset(out[0..MERKLE_HASH_LEN], 0);
    out[0] = 0x01;
    out[1] = @truncate(chunk_idx);
    out[2] = @truncate(chunk_len);
    out[3] = @truncate(chunk_len >> 8);
    for (chunk[0..chunk_len], 0..) |b, i| {
        out[4 + (i % 8)] ^= b +% @as(u8, @truncate(i));
    }
    return 0;
}

fn xorHashParent(
    _: ?*anyopaque,
    out: [*c]u8,
    out_len: usize,
    left: [*c]const u8,
    right: [*c]const u8,
    level: u32,
    node_idx: u64,
) callconv(.c) c_int {
    _ = out_len;
    @memset(out[0..MERKLE_HASH_LEN], 0);
    out[0] = 0x02;
    out[1] = @truncate(level);
    out[2] = @truncate(node_idx);
    for (0..MERKLE_HASH_LEN) |i| {
        out[i] ^= left[i] ^ right[i];
    }
    return 0;
}

fn xorHashEmpty(
    _: ?*anyopaque,
    out: [*c]u8,
    out_len: usize,
    level: u32,
    node_idx: u64,
) callconv(.c) c_int {
    _ = out_len;
    @memset(out[0..MERKLE_HASH_LEN], 0);
    out[0] = 0x00;
    out[1] = @truncate(level);
    out[2] = @truncate(node_idx);
    return 0;
}

fn variableHashLeaf(
    _: ?*anyopaque,
    out: [*c]u8,
    out_len: usize,
    chunk: [*c]const u8,
    chunk_len: usize,
    chunk_idx: u64,
) callconv(.c) c_int {
    if (out_len == 0) {
        return -1;
    }
    @memset(out[0..out_len], 0);
    out[0] = 0x31;
    if (out_len > 1) {
        out[1] = @truncate(chunk_idx);
    }
    if (out_len > 2) {
        out[2] = @truncate(chunk_len);
    }
    for (chunk[0..chunk_len], 0..) |b, i| {
        out[i % out_len] ^= b +% @as(u8, @truncate(i));
    }
    return 0;
}

fn variableHashParent(
    _: ?*anyopaque,
    out: [*c]u8,
    out_len: usize,
    left: [*c]const u8,
    right: [*c]const u8,
    level: u32,
    node_idx: u64,
) callconv(.c) c_int {
    if (out_len == 0) {
        return -1;
    }
    for (0..out_len) |i| {
        out[i] = left[i] ^ right[i] ^ @as(u8, @truncate(level)) ^ @as(u8, @truncate(node_idx)) ^
            @as(u8, @truncate(i));
    }
    return 0;
}

fn variableHashEmpty(
    _: ?*anyopaque,
    out: [*c]u8,
    out_len: usize,
    level: u32,
    node_idx: u64,
) callconv(.c) c_int {
    if (out_len == 0) {
        return -1;
    }
    for (0..out_len) |i| {
        out[i] = 0xA5 ^ @as(u8, @truncate(level)) ^ @as(u8, @truncate(node_idx)) ^
            @as(u8, @truncate(i));
    }
    return 0;
}

fn xorHashCommitment(
    _: ?*anyopaque,
    out: [*c]u8,
    out_len: usize,
    structural_root: [*c]const u8,
    ctx: [*c]const u8,
    ctx_len: usize,
    file_size: u64,
) callconv(.c) c_int {
    _ = out_len;
    @memcpy(out[0..MERKLE_HASH_LEN], structural_root[0..MERKLE_HASH_LEN]);
    const fs_bytes: [8]u8 = @bitCast(std.mem.nativeToLittle(u64, file_size));
    for (0..@min(MERKLE_HASH_LEN, 8)) |i| {
        out[i] ^= fs_bytes[i];
    }
    if (ctx != null) {
        for (0..@min(MERKLE_HASH_LEN, ctx_len)) |i| {
            out[i] ^= ctx[i];
        }
    }
    return 0;
}

fn variableHashCommitment(
    _: ?*anyopaque,
    out: [*c]u8,
    out_len: usize,
    structural_root: [*c]const u8,
    ctx: [*c]const u8,
    ctx_len: usize,
    file_size: u64,
) callconv(.c) c_int {
    if (out_len == 0) {
        return -1;
    }
    @memcpy(out[0..out_len], structural_root[0..out_len]);
    const fs_bytes: [8]u8 = @bitCast(std.mem.nativeToLittle(u64, file_size));
    for (0..@min(out_len, 8)) |i| {
        out[i] ^= fs_bytes[i];
    }
    if (ctx != null) {
        for (0..@min(out_len, ctx_len)) |i| {
            out[i] ^= ctx[i];
        }
    }
    return 0;
}

test "aegis_raf_merkle - buffer_size" {
    var cfg = aegis.aegis_raf_merkle_config{
        .buf = null,
        .len = 0,
        .hash_len = 16,
        .max_chunks = 0,
        .user = null,
        .hash_leaf = null,
        .hash_parent = null,
        .hash_empty = null,
        .hash_commitment = null,
    };

    try testing.expectEqual(aegis.aegis_raf_merkle_buffer_size(&cfg), 0);

    cfg.max_chunks = 1;
    try testing.expectEqual(aegis.aegis_raf_merkle_buffer_size(&cfg), 16);

    cfg.max_chunks = 2;
    try testing.expectEqual(aegis.aegis_raf_merkle_buffer_size(&cfg), 48);

    cfg.max_chunks = 4;
    try testing.expectEqual(aegis.aegis_raf_merkle_buffer_size(&cfg), 112);
}

test "aegis_raf_merkle - null hash_commitment rejected by config_validate" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    var file = MemoryFile.init(testing.allocator);
    defer file.deinit();

    var key: [aegis.aegis128l_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    var merkle_buf: [256]u8 = undefined;
    @memset(&merkle_buf, 0);

    const merkle_cfg = aegis.aegis_raf_merkle_config{
        .buf = &merkle_buf,
        .len = merkle_buf.len,
        .hash_len = MERKLE_HASH_LEN,
        .max_chunks = 4,
        .user = null,
        .hash_leaf = xorHashLeaf,
        .hash_parent = xorHashParent,
        .hash_empty = xorHashEmpty,
        .hash_commitment = null,
    };

    var scratch_buf: [aegis.AEGIS128L_RAF_SCRATCH_SIZE(1024)]u8 align(aegis.AEGIS_RAF_SCRATCH_ALIGN) = undefined;
    const scratch = aegis.aegis_raf_scratch{
        .buf = &scratch_buf,
        .len = scratch_buf.len,
    };

    const cfg = aegis.aegis_raf_config{
        .chunk_size = 1024,
        .flags = aegis.AEGIS_RAF_CREATE,
        .scratch = &scratch,
        .merkle = &merkle_cfg,
    };

    var ctx: aegis.aegis128l_raf_ctx align(32) = undefined;
    try testing.expectEqual(aegis.aegis128l_raf_create(&ctx, &file.io(), &rng(), &cfg, &key), -1);
}

test "aegis128l_raf_merkle - root changes on write" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    var file = MemoryFile.init(testing.allocator);
    defer file.deinit();

    var key: [aegis.aegis128l_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    const max_chunks: u64 = 8;
    var merkle_buf: [256]u8 = undefined;
    @memset(&merkle_buf, 0);

    var merkle_cfg = aegis.aegis_raf_merkle_config{
        .buf = &merkle_buf,
        .len = merkle_buf.len,
        .hash_len = MERKLE_HASH_LEN,
        .max_chunks = max_chunks,
        .user = null,
        .hash_leaf = xorHashLeaf,
        .hash_parent = xorHashParent,
        .hash_empty = xorHashEmpty,
        .hash_commitment = xorHashCommitment,
    };

    const merkle_buf_size = aegis.aegis_raf_merkle_buffer_size(&merkle_cfg);
    try testing.expect(merkle_buf_size <= merkle_buf.len);

    var scratch_buf: [aegis.AEGIS128L_RAF_SCRATCH_SIZE(1024)]u8 align(aegis.AEGIS_RAF_SCRATCH_ALIGN) = undefined;
    const scratch = aegis.aegis_raf_scratch{
        .buf = &scratch_buf,
        .len = scratch_buf.len,
    };

    const cfg = aegis.aegis_raf_config{
        .chunk_size = 1024,
        .flags = aegis.AEGIS_RAF_CREATE,
        .scratch = &scratch,
        .merkle = &merkle_cfg,
    };

    var ctx: aegis.aegis128l_raf_ctx align(32) = undefined;

    var ret = aegis.aegis128l_raf_create(&ctx, &file.io(), &rng(), &cfg, &key);
    try testing.expectEqual(ret, 0);

    var root0: [MERKLE_HASH_LEN]u8 = undefined;
    try testing.expectEqual(aegis.aegis128l_raf_merkle_commitment(&ctx, &root0, MERKLE_HASH_LEN), 0);

    var root_before: [MERKLE_HASH_LEN]u8 = undefined;
    @memcpy(&root_before, &root0);

    const test_data = "Hello, Merkle!";
    var bytes_written: usize = undefined;
    ret = aegis.aegis128l_raf_write(&ctx, &bytes_written, test_data.ptr, test_data.len, 0);
    try testing.expectEqual(ret, 0);

    var root1: [MERKLE_HASH_LEN]u8 = undefined;
    try testing.expectEqual(aegis.aegis128l_raf_merkle_commitment(&ctx, &root1, MERKLE_HASH_LEN), 0);

    try testing.expect(!std.mem.eql(u8, &root_before, &root1));

    var root_after_write: [MERKLE_HASH_LEN]u8 = undefined;
    @memcpy(&root_after_write, &root1);

    const more_data = "More data here";
    ret = aegis.aegis128l_raf_write(&ctx, &bytes_written, more_data.ptr, more_data.len, 2048);
    try testing.expectEqual(ret, 0);

    var root2: [MERKLE_HASH_LEN]u8 = undefined;
    try testing.expectEqual(aegis.aegis128l_raf_merkle_commitment(&ctx, &root2, MERKLE_HASH_LEN), 0);
    try testing.expect(!std.mem.eql(u8, &root_after_write, &root2));

    aegis.aegis128l_raf_close(&ctx);
}

test "aegis128l_raf_merkle - rebuild matches incremental" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    var file = MemoryFile.init(testing.allocator);
    defer file.deinit();

    var key: [aegis.aegis128l_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    const max_chunks: u64 = 4;
    var merkle_buf1: [256]u8 = undefined;
    var merkle_buf2: [256]u8 = undefined;
    @memset(&merkle_buf1, 0);
    @memset(&merkle_buf2, 0);

    var merkle_cfg1 = aegis.aegis_raf_merkle_config{
        .buf = &merkle_buf1,
        .len = merkle_buf1.len,
        .hash_len = MERKLE_HASH_LEN,
        .max_chunks = max_chunks,
        .user = null,
        .hash_leaf = xorHashLeaf,
        .hash_parent = xorHashParent,
        .hash_empty = xorHashEmpty,
        .hash_commitment = xorHashCommitment,
    };

    const merkle_buf_size = aegis.aegis_raf_merkle_buffer_size(&merkle_cfg1);
    try testing.expect(merkle_buf_size <= merkle_buf1.len);

    var merkle_cfg2 = aegis.aegis_raf_merkle_config{
        .buf = &merkle_buf2,
        .len = merkle_buf2.len,
        .hash_len = MERKLE_HASH_LEN,
        .max_chunks = max_chunks,
        .user = null,
        .hash_leaf = xorHashLeaf,
        .hash_parent = xorHashParent,
        .hash_empty = xorHashEmpty,
        .hash_commitment = xorHashCommitment,
    };

    var scratch_buf: [aegis.AEGIS128L_RAF_SCRATCH_SIZE(1024)]u8 align(aegis.AEGIS_RAF_SCRATCH_ALIGN) = undefined;
    const scratch = aegis.aegis_raf_scratch{
        .buf = &scratch_buf,
        .len = scratch_buf.len,
    };

    const cfg1 = aegis.aegis_raf_config{
        .chunk_size = 1024,
        .flags = aegis.AEGIS_RAF_CREATE,
        .scratch = &scratch,
        .merkle = &merkle_cfg1,
    };

    var ctx: aegis.aegis128l_raf_ctx align(32) = undefined;

    var ret = aegis.aegis128l_raf_create(&ctx, &file.io(), &rng(), &cfg1, &key);
    try testing.expectEqual(ret, 0);

    var data: [2500]u8 = undefined;
    for (&data, 0..) |*b, i| {
        b.* = @truncate(i ^ 0xAB);
    }

    var bytes_written: usize = undefined;
    ret = aegis.aegis128l_raf_write(&ctx, &bytes_written, &data, data.len, 0);
    try testing.expectEqual(ret, 0);

    var incremental_root: [MERKLE_HASH_LEN]u8 = undefined;
    try testing.expectEqual(aegis.aegis128l_raf_merkle_commitment(&ctx, &incremental_root, MERKLE_HASH_LEN), 0);

    aegis.aegis128l_raf_close(&ctx);

    const cfg2 = aegis.aegis_raf_config{
        .chunk_size = 0,
        .flags = 0,
        .scratch = &scratch,
        .merkle = &merkle_cfg2,
    };

    ret = aegis.aegis128l_raf_open(&ctx, &file.io(), &rng(), &cfg2, &key);
    try testing.expectEqual(ret, 0);

    ret = aegis.aegis128l_raf_merkle_rebuild(&ctx);
    try testing.expectEqual(ret, 0);

    var rebuilt_root: [MERKLE_HASH_LEN]u8 = undefined;
    try testing.expectEqual(aegis.aegis128l_raf_merkle_commitment(&ctx, &rebuilt_root, MERKLE_HASH_LEN), 0);

    try testing.expectEqualSlices(u8, &incremental_root, &rebuilt_root);

    aegis.aegis128l_raf_close(&ctx);
}

test "aegis128l_raf_merkle - truncate shrink clears leaves" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    var file = MemoryFile.init(testing.allocator);
    defer file.deinit();

    var key: [aegis.aegis128l_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    const max_chunks: u64 = 8;
    var merkle_buf: [256]u8 = undefined;
    @memset(&merkle_buf, 0);

    const merkle_cfg = aegis.aegis_raf_merkle_config{
        .buf = &merkle_buf,
        .len = merkle_buf.len,
        .hash_len = MERKLE_HASH_LEN,
        .max_chunks = max_chunks,
        .user = null,
        .hash_leaf = xorHashLeaf,
        .hash_parent = xorHashParent,
        .hash_empty = xorHashEmpty,
        .hash_commitment = xorHashCommitment,
    };

    var scratch_buf: [aegis.AEGIS128L_RAF_SCRATCH_SIZE(1024)]u8 align(aegis.AEGIS_RAF_SCRATCH_ALIGN) = undefined;
    const scratch = aegis.aegis_raf_scratch{
        .buf = &scratch_buf,
        .len = scratch_buf.len,
    };

    const cfg = aegis.aegis_raf_config{
        .chunk_size = 1024,
        .flags = aegis.AEGIS_RAF_CREATE,
        .scratch = &scratch,
        .merkle = &merkle_cfg,
    };

    var ctx: aegis.aegis128l_raf_ctx align(32) = undefined;

    var ret = aegis.aegis128l_raf_create(&ctx, &file.io(), &rng(), &cfg, &key);
    try testing.expectEqual(ret, 0);

    var data: [3000]u8 = undefined;
    for (&data, 0..) |*b, i| {
        b.* = @truncate(i);
    }

    var bytes_written: usize = undefined;
    ret = aegis.aegis128l_raf_write(&ctx, &bytes_written, &data, data.len, 0);
    try testing.expectEqual(ret, 0);

    var root_before_truncate: [MERKLE_HASH_LEN]u8 = undefined;
    try testing.expectEqual(aegis.aegis128l_raf_merkle_commitment(&ctx, &root_before_truncate, MERKLE_HASH_LEN), 0);

    ret = aegis.aegis128l_raf_truncate(&ctx, 500);
    try testing.expectEqual(ret, 0);

    var root_after_truncate: [MERKLE_HASH_LEN]u8 = undefined;
    try testing.expectEqual(aegis.aegis128l_raf_merkle_commitment(&ctx, &root_after_truncate, MERKLE_HASH_LEN), 0);

    try testing.expect(!std.mem.eql(u8, &root_before_truncate, &root_after_truncate));

    aegis.aegis128l_raf_close(&ctx);
}

test "aegis128l_raf_merkle - truncate within same chunk count rehashes" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    var file = MemoryFile.init(testing.allocator);
    defer file.deinit();

    var key: [aegis.aegis128l_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    const max_chunks: u64 = 8;
    var merkle_buf: [256]u8 = undefined;
    @memset(&merkle_buf, 0);

    const merkle_cfg = aegis.aegis_raf_merkle_config{
        .buf = &merkle_buf,
        .len = merkle_buf.len,
        .hash_len = MERKLE_HASH_LEN,
        .max_chunks = max_chunks,
        .user = null,
        .hash_leaf = xorHashLeaf,
        .hash_parent = xorHashParent,
        .hash_empty = xorHashEmpty,
        .hash_commitment = xorHashCommitment,
    };

    var scratch_buf: [aegis.AEGIS128L_RAF_SCRATCH_SIZE(1024)]u8 align(aegis.AEGIS_RAF_SCRATCH_ALIGN) = undefined;
    const scratch = aegis.aegis_raf_scratch{
        .buf = &scratch_buf,
        .len = scratch_buf.len,
    };

    const cfg = aegis.aegis_raf_config{
        .chunk_size = 1024,
        .flags = aegis.AEGIS_RAF_CREATE,
        .scratch = &scratch,
        .merkle = &merkle_cfg,
    };

    var ctx: aegis.aegis128l_raf_ctx align(32) = undefined;

    var ret = aegis.aegis128l_raf_create(&ctx, &file.io(), &rng(), &cfg, &key);
    try testing.expectEqual(ret, 0);

    var data: [1500]u8 = undefined;
    for (&data, 0..) |*b, i| {
        b.* = @truncate(i);
    }

    var bytes_written: usize = undefined;
    ret = aegis.aegis128l_raf_write(&ctx, &bytes_written, &data, data.len, 0);
    try testing.expectEqual(ret, 0);

    var root_before_truncate: [MERKLE_HASH_LEN]u8 = undefined;
    try testing.expectEqual(aegis.aegis128l_raf_merkle_commitment(&ctx, &root_before_truncate, MERKLE_HASH_LEN), 0);

    ret = aegis.aegis128l_raf_truncate(&ctx, 1200);
    try testing.expectEqual(ret, 0);

    var root_after_truncate: [MERKLE_HASH_LEN]u8 = undefined;
    try testing.expectEqual(aegis.aegis128l_raf_merkle_commitment(&ctx, &root_after_truncate, MERKLE_HASH_LEN), 0);

    try testing.expect(!std.mem.eql(u8, &root_before_truncate, &root_after_truncate));

    ret = aegis.aegis128l_raf_merkle_verify(&ctx, null);
    try testing.expectEqual(ret, 0);

    aegis.aegis128l_raf_close(&ctx);
}

test "aegis128l_raf_merkle - max_chunks exceeded fails" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    var file = MemoryFile.init(testing.allocator);
    defer file.deinit();

    var key: [aegis.aegis128l_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    const max_chunks: u64 = 2;
    var merkle_buf: [256]u8 = undefined;
    @memset(&merkle_buf, 0);

    const merkle_cfg = aegis.aegis_raf_merkle_config{
        .buf = &merkle_buf,
        .len = merkle_buf.len,
        .hash_len = MERKLE_HASH_LEN,
        .max_chunks = max_chunks,
        .user = null,
        .hash_leaf = xorHashLeaf,
        .hash_parent = xorHashParent,
        .hash_empty = xorHashEmpty,
        .hash_commitment = xorHashCommitment,
    };

    var scratch_buf: [aegis.AEGIS128L_RAF_SCRATCH_SIZE(1024)]u8 align(aegis.AEGIS_RAF_SCRATCH_ALIGN) = undefined;
    const scratch = aegis.aegis_raf_scratch{
        .buf = &scratch_buf,
        .len = scratch_buf.len,
    };

    const cfg = aegis.aegis_raf_config{
        .chunk_size = 1024,
        .flags = aegis.AEGIS_RAF_CREATE,
        .scratch = &scratch,
        .merkle = &merkle_cfg,
    };

    var ctx: aegis.aegis128l_raf_ctx align(32) = undefined;

    var ret = aegis.aegis128l_raf_create(&ctx, &file.io(), &rng(), &cfg, &key);
    try testing.expectEqual(ret, 0);

    const small_data = "Small data";
    var bytes_written: usize = undefined;
    ret = aegis.aegis128l_raf_write(&ctx, &bytes_written, small_data.ptr, small_data.len, 0);
    try testing.expectEqual(ret, 0);

    var large_data: [3000]u8 = undefined;
    @memset(&large_data, 0xAA);
    ret = aegis.aegis128l_raf_write(&ctx, &bytes_written, &large_data, large_data.len, 0);
    try testing.expect(ret != 0);
    try testing.expectEqual(std.c._errno().*, @intFromEnum(std.c.E.OVERFLOW));

    aegis.aegis128l_raf_close(&ctx);
}

test "aegis128l_raf_merkle - partial overwrite updates root" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    var file = MemoryFile.init(testing.allocator);
    defer file.deinit();

    var key: [aegis.aegis128l_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    const max_chunks: u64 = 4;
    var merkle_buf: [256]u8 = undefined;
    @memset(&merkle_buf, 0);

    const merkle_cfg = aegis.aegis_raf_merkle_config{
        .buf = &merkle_buf,
        .len = merkle_buf.len,
        .hash_len = MERKLE_HASH_LEN,
        .max_chunks = max_chunks,
        .user = null,
        .hash_leaf = xorHashLeaf,
        .hash_parent = xorHashParent,
        .hash_empty = xorHashEmpty,
        .hash_commitment = xorHashCommitment,
    };

    var scratch_buf: [aegis.AEGIS128L_RAF_SCRATCH_SIZE(1024)]u8 align(aegis.AEGIS_RAF_SCRATCH_ALIGN) = undefined;
    const scratch = aegis.aegis_raf_scratch{
        .buf = &scratch_buf,
        .len = scratch_buf.len,
    };

    const cfg = aegis.aegis_raf_config{
        .chunk_size = 1024,
        .flags = aegis.AEGIS_RAF_CREATE,
        .scratch = &scratch,
        .merkle = &merkle_cfg,
    };

    var ctx: aegis.aegis128l_raf_ctx align(32) = undefined;

    var ret = aegis.aegis128l_raf_create(&ctx, &file.io(), &rng(), &cfg, &key);
    try testing.expectEqual(ret, 0);

    var data: [1500]u8 = undefined;
    @memset(&data, 0x00);
    var bytes_written: usize = undefined;
    ret = aegis.aegis128l_raf_write(&ctx, &bytes_written, &data, data.len, 0);
    try testing.expectEqual(ret, 0);

    var root_before: [MERKLE_HASH_LEN]u8 = undefined;
    try testing.expectEqual(aegis.aegis128l_raf_merkle_commitment(&ctx, &root_before, MERKLE_HASH_LEN), 0);

    var patch: [11]u8 = undefined;
    @memset(&patch, 0xFF);
    ret = aegis.aegis128l_raf_write(&ctx, &bytes_written, &patch, patch.len, 100);
    try testing.expectEqual(ret, 0);

    var root_after: [MERKLE_HASH_LEN]u8 = undefined;
    try testing.expectEqual(aegis.aegis128l_raf_merkle_commitment(&ctx, &root_after, MERKLE_HASH_LEN), 0);

    try testing.expect(!std.mem.eql(u8, &root_before, &root_after));

    aegis.aegis128l_raf_close(&ctx);
}

test "aegis128l_raf_merkle - verify succeeds after rebuild" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    var file = MemoryFile.init(testing.allocator);
    defer file.deinit();

    var key: [aegis.aegis128l_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    const max_chunks: u64 = 8;
    var merkle_buf: [256]u8 = undefined;
    @memset(&merkle_buf, 0);

    const merkle_cfg = aegis.aegis_raf_merkle_config{
        .buf = &merkle_buf,
        .len = merkle_buf.len,
        .hash_len = MERKLE_HASH_LEN,
        .max_chunks = max_chunks,
        .user = null,
        .hash_leaf = xorHashLeaf,
        .hash_parent = xorHashParent,
        .hash_empty = xorHashEmpty,
        .hash_commitment = xorHashCommitment,
    };

    var scratch align(64) = [_]u8{0} ** 4096;
    const scratch_buf = aegis.aegis_raf_scratch{
        .buf = &scratch,
        .len = scratch.len,
    };

    const cfg = aegis.aegis_raf_config{
        .chunk_size = aegis.AEGIS_RAF_CHUNK_MIN,
        .flags = aegis.AEGIS_RAF_CREATE,
        .scratch = &scratch_buf,
        .merkle = &merkle_cfg,
    };

    var ctx: aegis.aegis128l_raf_ctx align(32) = undefined;

    var ret = aegis.aegis128l_raf_create(&ctx, &file.io(), &rng(), &cfg, &key);
    try testing.expectEqual(ret, 0);

    const test_data = "Test data for verification";
    var bytes_written: usize = undefined;
    ret = aegis.aegis128l_raf_write(&ctx, &bytes_written, test_data, test_data.len, 0);
    try testing.expectEqual(ret, 0);

    ret = aegis.aegis128l_raf_merkle_verify(&ctx, null);
    try testing.expectEqual(ret, 0);

    aegis.aegis128l_raf_close(&ctx);

    var merkle_buf2: [256]u8 = undefined;
    @memset(&merkle_buf2, 0);

    const merkle_cfg2 = aegis.aegis_raf_merkle_config{
        .buf = &merkle_buf2,
        .len = merkle_buf2.len,
        .hash_len = MERKLE_HASH_LEN,
        .max_chunks = max_chunks,
        .user = null,
        .hash_leaf = xorHashLeaf,
        .hash_parent = xorHashParent,
        .hash_empty = xorHashEmpty,
        .hash_commitment = xorHashCommitment,
    };

    const cfg2 = aegis.aegis_raf_config{
        .chunk_size = aegis.AEGIS_RAF_CHUNK_MIN,
        .flags = 0,
        .scratch = &scratch_buf,
        .merkle = &merkle_cfg2,
    };

    var ctx2: aegis.aegis128l_raf_ctx align(32) = undefined;
    ret = aegis.aegis128l_raf_open(&ctx2, &file.io(), &rng(), &cfg2, &key);
    try testing.expectEqual(ret, 0);

    ret = aegis.aegis128l_raf_merkle_rebuild(&ctx2);
    try testing.expectEqual(ret, 0);

    ret = aegis.aegis128l_raf_merkle_verify(&ctx2, null);
    try testing.expectEqual(ret, 0);

    try testing.expect(std.mem.eql(u8, &merkle_buf, &merkle_buf2));

    aegis.aegis128l_raf_close(&ctx2);
}

test "aegis128l_raf_merkle - verify detects corruption" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    var file = MemoryFile.init(testing.allocator);
    defer file.deinit();

    var key: [aegis.aegis128l_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    const max_chunks: u64 = 8;
    var merkle_buf: [256]u8 = undefined;
    @memset(&merkle_buf, 0);

    const merkle_cfg = aegis.aegis_raf_merkle_config{
        .buf = &merkle_buf,
        .len = merkle_buf.len,
        .hash_len = MERKLE_HASH_LEN,
        .max_chunks = max_chunks,
        .user = null,
        .hash_leaf = xorHashLeaf,
        .hash_parent = xorHashParent,
        .hash_empty = xorHashEmpty,
        .hash_commitment = xorHashCommitment,
    };

    var scratch align(64) = [_]u8{0} ** 4096;
    const scratch_buf = aegis.aegis_raf_scratch{
        .buf = &scratch,
        .len = scratch.len,
    };

    const cfg = aegis.aegis_raf_config{
        .chunk_size = aegis.AEGIS_RAF_CHUNK_MIN,
        .flags = aegis.AEGIS_RAF_CREATE,
        .scratch = &scratch_buf,
        .merkle = &merkle_cfg,
    };

    var ctx: aegis.aegis128l_raf_ctx align(32) = undefined;

    var ret = aegis.aegis128l_raf_create(&ctx, &file.io(), &rng(), &cfg, &key);
    try testing.expectEqual(ret, 0);

    const test_data = "Test data for verification";
    var bytes_written: usize = undefined;
    ret = aegis.aegis128l_raf_write(&ctx, &bytes_written, test_data, test_data.len, 0);
    try testing.expectEqual(ret, 0);

    var saved_merkle: [256]u8 = undefined;
    @memcpy(&saved_merkle, &merkle_buf);

    aegis.aegis128l_raf_close(&ctx);

    var ctx2: aegis.aegis128l_raf_ctx align(32) = undefined;

    const cfg2 = aegis.aegis_raf_config{
        .chunk_size = aegis.AEGIS_RAF_CHUNK_MIN,
        .flags = aegis.AEGIS_RAF_CREATE | aegis.AEGIS_RAF_TRUNCATE,
        .scratch = &scratch_buf,
        .merkle = &merkle_cfg,
    };

    ret = aegis.aegis128l_raf_create(&ctx2, &file.io(), &rng(), &cfg2, &key);
    try testing.expectEqual(ret, 0);

    const different_data = "Different content!!!!!!!!";
    ret = aegis.aegis128l_raf_write(&ctx2, &bytes_written, different_data, different_data.len, 0);
    try testing.expectEqual(ret, 0);

    @memcpy(&merkle_buf, &saved_merkle);

    var corrupted_chunk: u64 = undefined;
    ret = aegis.aegis128l_raf_merkle_verify(&ctx2, &corrupted_chunk);
    try testing.expect(ret != 0);
    try testing.expectEqual(corrupted_chunk, 0);

    aegis.aegis128l_raf_close(&ctx2);
}

test "aegis_raf_merkle - buffer_size edge cases" {
    var cfg = aegis.aegis_raf_merkle_config{
        .buf = null,
        .len = 0,
        .hash_len = 0,
        .max_chunks = 10,
        .user = null,
        .hash_leaf = null,
        .hash_parent = null,
        .hash_empty = null,
        .hash_commitment = null,
    };
    try testing.expectEqual(aegis.aegis_raf_merkle_buffer_size(&cfg), 0);

    cfg.hash_len = 32;
    cfg.max_chunks = 1;
    try testing.expectEqual(aegis.aegis_raf_merkle_buffer_size(&cfg), 32); // 1 node
    cfg.max_chunks = 2;
    try testing.expectEqual(aegis.aegis_raf_merkle_buffer_size(&cfg), 96); // 2 + 1 = 3 nodes
    cfg.max_chunks = 3;
    try testing.expectEqual(aegis.aegis_raf_merkle_buffer_size(&cfg), 192); // 3 + 2 + 1 = 6 nodes
    cfg.max_chunks = 4;
    try testing.expectEqual(aegis.aegis_raf_merkle_buffer_size(&cfg), 224); // 4 + 2 + 1 = 7 nodes
    cfg.max_chunks = 5;
    try testing.expectEqual(aegis.aegis_raf_merkle_buffer_size(&cfg), 352); // 5 + 3 + 2 + 1 = 11 nodes
    cfg.max_chunks = 8;
    try testing.expectEqual(aegis.aegis_raf_merkle_buffer_size(&cfg), 480); // 8 + 4 + 2 + 1 = 15 nodes
    cfg.max_chunks = 16;
    try testing.expectEqual(aegis.aegis_raf_merkle_buffer_size(&cfg), 992); // 16 + 8 + 4 + 2 + 1 = 31 nodes
}

test "aegis128l_raf_merkle - single chunk tree" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    var file = MemoryFile.init(testing.allocator);
    defer file.deinit();

    var key: [aegis.aegis128l_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    const max_chunks: u64 = 1;
    var merkle_buf: [64]u8 = undefined;
    @memset(&merkle_buf, 0);

    const merkle_cfg = aegis.aegis_raf_merkle_config{
        .buf = &merkle_buf,
        .len = merkle_buf.len,
        .hash_len = MERKLE_HASH_LEN,
        .max_chunks = max_chunks,
        .user = null,
        .hash_leaf = xorHashLeaf,
        .hash_parent = xorHashParent,
        .hash_empty = xorHashEmpty,
        .hash_commitment = xorHashCommitment,
    };

    const merkle_buf_size = aegis.aegis_raf_merkle_buffer_size(&merkle_cfg);
    try testing.expectEqual(merkle_buf_size, MERKLE_HASH_LEN);

    var scratch_buf: [aegis.AEGIS128L_RAF_SCRATCH_SIZE(1024)]u8 align(aegis.AEGIS_RAF_SCRATCH_ALIGN) = undefined;
    const scratch = aegis.aegis_raf_scratch{
        .buf = &scratch_buf,
        .len = scratch_buf.len,
    };

    const cfg = aegis.aegis_raf_config{
        .chunk_size = 1024,
        .flags = aegis.AEGIS_RAF_CREATE,
        .scratch = &scratch,
        .merkle = &merkle_cfg,
    };

    var ctx: aegis.aegis128l_raf_ctx align(32) = undefined;

    var ret = aegis.aegis128l_raf_create(&ctx, &file.io(), &rng(), &cfg, &key);
    try testing.expectEqual(ret, 0);

    const test_data = "Single chunk test";
    var bytes_written: usize = undefined;
    ret = aegis.aegis128l_raf_write(&ctx, &bytes_written, test_data.ptr, test_data.len, 0);
    try testing.expectEqual(ret, 0);

    var root: [MERKLE_HASH_LEN]u8 = undefined;
    try testing.expectEqual(aegis.aegis128l_raf_merkle_commitment(&ctx, &root, MERKLE_HASH_LEN), 0);

    ret = aegis.aegis128l_raf_merkle_verify(&ctx, null);
    try testing.expectEqual(ret, 0);

    var large_data: [2000]u8 = undefined;
    @memset(&large_data, 0xAB);
    ret = aegis.aegis128l_raf_write(&ctx, &bytes_written, &large_data, large_data.len, 0);
    try testing.expect(ret != 0);

    aegis.aegis128l_raf_close(&ctx);
}

test "aegis128l_raf_merkle - empty file operations" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    var file = MemoryFile.init(testing.allocator);
    defer file.deinit();

    var key: [aegis.aegis128l_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    const max_chunks: u64 = 4;
    var merkle_buf: [256]u8 = undefined;
    @memset(&merkle_buf, 0);

    const merkle_cfg = aegis.aegis_raf_merkle_config{
        .buf = &merkle_buf,
        .len = merkle_buf.len,
        .hash_len = MERKLE_HASH_LEN,
        .max_chunks = max_chunks,
        .user = null,
        .hash_leaf = xorHashLeaf,
        .hash_parent = xorHashParent,
        .hash_empty = xorHashEmpty,
        .hash_commitment = xorHashCommitment,
    };

    var scratch_buf: [aegis.AEGIS128L_RAF_SCRATCH_SIZE(1024)]u8 align(aegis.AEGIS_RAF_SCRATCH_ALIGN) = undefined;
    const scratch = aegis.aegis_raf_scratch{
        .buf = &scratch_buf,
        .len = scratch_buf.len,
    };

    const cfg = aegis.aegis_raf_config{
        .chunk_size = 1024,
        .flags = aegis.AEGIS_RAF_CREATE,
        .scratch = &scratch,
        .merkle = &merkle_cfg,
    };

    var ctx: aegis.aegis128l_raf_ctx align(32) = undefined;

    var ret = aegis.aegis128l_raf_create(&ctx, &file.io(), &rng(), &cfg, &key);
    try testing.expectEqual(ret, 0);

    var empty_root: [MERKLE_HASH_LEN]u8 = undefined;
    try testing.expectEqual(aegis.aegis128l_raf_merkle_commitment(&ctx, &empty_root, MERKLE_HASH_LEN), 0);

    var empty_root_copy: [MERKLE_HASH_LEN]u8 = undefined;
    @memcpy(&empty_root_copy, &empty_root);

    ret = aegis.aegis128l_raf_merkle_verify(&ctx, null);
    try testing.expectEqual(ret, 0);

    const test_data = "Some data";
    var bytes_written: usize = undefined;
    ret = aegis.aegis128l_raf_write(&ctx, &bytes_written, test_data.ptr, test_data.len, 0);
    try testing.expectEqual(ret, 0);

    ret = aegis.aegis128l_raf_truncate(&ctx, 0);
    try testing.expectEqual(ret, 0);

    ret = aegis.aegis128l_raf_merkle_verify(&ctx, null);
    try testing.expectEqual(ret, 0);

    aegis.aegis128l_raf_close(&ctx);
}

test "aegis128l_raf_merkle - write spanning multiple chunks" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    var file = MemoryFile.init(testing.allocator);
    defer file.deinit();

    var key: [aegis.aegis128l_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    const max_chunks: u64 = 16;
    var merkle_buf: [1024]u8 = undefined;
    @memset(&merkle_buf, 0);

    const merkle_cfg = aegis.aegis_raf_merkle_config{
        .buf = &merkle_buf,
        .len = merkle_buf.len,
        .hash_len = MERKLE_HASH_LEN,
        .max_chunks = max_chunks,
        .user = null,
        .hash_leaf = xorHashLeaf,
        .hash_parent = xorHashParent,
        .hash_empty = xorHashEmpty,
        .hash_commitment = xorHashCommitment,
    };

    var scratch_buf: [aegis.AEGIS128L_RAF_SCRATCH_SIZE(1024)]u8 align(aegis.AEGIS_RAF_SCRATCH_ALIGN) = undefined;
    const scratch = aegis.aegis_raf_scratch{
        .buf = &scratch_buf,
        .len = scratch_buf.len,
    };

    const cfg = aegis.aegis_raf_config{
        .chunk_size = 1024,
        .flags = aegis.AEGIS_RAF_CREATE,
        .scratch = &scratch,
        .merkle = &merkle_cfg,
    };

    var ctx: aegis.aegis128l_raf_ctx align(32) = undefined;

    var ret = aegis.aegis128l_raf_create(&ctx, &file.io(), &rng(), &cfg, &key);
    try testing.expectEqual(ret, 0);

    var large_data: [5000]u8 = undefined;
    for (&large_data, 0..) |*b, i| {
        b.* = @truncate(i *% 17 +% 1);
    }

    var bytes_written: usize = undefined;
    ret = aegis.aegis128l_raf_write(&ctx, &bytes_written, &large_data, large_data.len, 0);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(bytes_written, large_data.len);

    var root1_copy: [MERKLE_HASH_LEN]u8 = undefined;
    try testing.expectEqual(aegis.aegis128l_raf_merkle_commitment(&ctx, &root1_copy, MERKLE_HASH_LEN), 0);

    ret = aegis.aegis128l_raf_merkle_verify(&ctx, null);
    try testing.expectEqual(ret, 0);

    aegis.aegis128l_raf_close(&ctx);

    var merkle_buf2: [1024]u8 = undefined;
    @memset(&merkle_buf2, 0);

    const merkle_cfg2 = aegis.aegis_raf_merkle_config{
        .buf = &merkle_buf2,
        .len = merkle_buf2.len,
        .hash_len = MERKLE_HASH_LEN,
        .max_chunks = max_chunks,
        .user = null,
        .hash_leaf = xorHashLeaf,
        .hash_parent = xorHashParent,
        .hash_empty = xorHashEmpty,
        .hash_commitment = xorHashCommitment,
    };

    const cfg2 = aegis.aegis_raf_config{
        .chunk_size = 0,
        .flags = 0,
        .scratch = &scratch,
        .merkle = &merkle_cfg2,
    };

    ret = aegis.aegis128l_raf_open(&ctx, &file.io(), &rng(), &cfg2, &key);
    try testing.expectEqual(ret, 0);

    ret = aegis.aegis128l_raf_merkle_rebuild(&ctx);
    try testing.expectEqual(ret, 0);

    var root2: [MERKLE_HASH_LEN]u8 = undefined;
    try testing.expectEqual(aegis.aegis128l_raf_merkle_commitment(&ctx, &root2, MERKLE_HASH_LEN), 0);
    try testing.expectEqualSlices(u8, &root1_copy, &root2);

    aegis.aegis128l_raf_close(&ctx);
}

test "aegis128l_raf_merkle - write at chunk boundary" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    var file = MemoryFile.init(testing.allocator);
    defer file.deinit();

    var key: [aegis.aegis128l_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    const max_chunks: u64 = 8;
    var merkle_buf: [256]u8 = undefined;
    @memset(&merkle_buf, 0);

    const merkle_cfg = aegis.aegis_raf_merkle_config{
        .buf = &merkle_buf,
        .len = merkle_buf.len,
        .hash_len = MERKLE_HASH_LEN,
        .max_chunks = max_chunks,
        .user = null,
        .hash_leaf = xorHashLeaf,
        .hash_parent = xorHashParent,
        .hash_empty = xorHashEmpty,
        .hash_commitment = xorHashCommitment,
    };

    var scratch_buf: [aegis.AEGIS128L_RAF_SCRATCH_SIZE(1024)]u8 align(aegis.AEGIS_RAF_SCRATCH_ALIGN) = undefined;
    const scratch = aegis.aegis_raf_scratch{
        .buf = &scratch_buf,
        .len = scratch_buf.len,
    };

    const cfg = aegis.aegis_raf_config{
        .chunk_size = 1024,
        .flags = aegis.AEGIS_RAF_CREATE,
        .scratch = &scratch,
        .merkle = &merkle_cfg,
    };

    var ctx: aegis.aegis128l_raf_ctx align(32) = undefined;

    var ret = aegis.aegis128l_raf_create(&ctx, &file.io(), &rng(), &cfg, &key);
    try testing.expectEqual(ret, 0);

    var chunk_data: [1024]u8 = undefined;
    @memset(&chunk_data, 0x11);
    var bytes_written: usize = undefined;
    ret = aegis.aegis128l_raf_write(&ctx, &bytes_written, &chunk_data, chunk_data.len, 0);
    try testing.expectEqual(ret, 0);

    var root_after_chunk0: [MERKLE_HASH_LEN]u8 = undefined;
    try testing.expectEqual(aegis.aegis128l_raf_merkle_commitment(&ctx, &root_after_chunk0, MERKLE_HASH_LEN), 0);

    @memset(&chunk_data, 0x22);
    ret = aegis.aegis128l_raf_write(&ctx, &bytes_written, &chunk_data, chunk_data.len, 1024);
    try testing.expectEqual(ret, 0);

    var root_after_chunk1: [MERKLE_HASH_LEN]u8 = undefined;
    try testing.expectEqual(aegis.aegis128l_raf_merkle_commitment(&ctx, &root_after_chunk1, MERKLE_HASH_LEN), 0);

    try testing.expect(!std.mem.eql(u8, &root_after_chunk0, &root_after_chunk1));

    @memset(&chunk_data, 0x33);
    ret = aegis.aegis128l_raf_write(&ctx, &bytes_written, &chunk_data, chunk_data.len, 1536);
    try testing.expectEqual(ret, 0);

    var root_after_spanning: [MERKLE_HASH_LEN]u8 = undefined;
    try testing.expectEqual(aegis.aegis128l_raf_merkle_commitment(&ctx, &root_after_spanning, MERKLE_HASH_LEN), 0);

    try testing.expect(!std.mem.eql(u8, &root_after_chunk1, &root_after_spanning));

    ret = aegis.aegis128l_raf_merkle_verify(&ctx, null);
    try testing.expectEqual(ret, 0);

    aegis.aegis128l_raf_close(&ctx);
}

test "aegis128l_raf_merkle - verify detects corruption in middle chunk" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    var file = MemoryFile.init(testing.allocator);
    defer file.deinit();

    var key: [aegis.aegis128l_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    const max_chunks: u64 = 8;
    var merkle_buf: [256]u8 = undefined;
    @memset(&merkle_buf, 0);

    var merkle_cfg = aegis.aegis_raf_merkle_config{
        .buf = &merkle_buf,
        .len = merkle_buf.len,
        .hash_len = MERKLE_HASH_LEN,
        .max_chunks = max_chunks,
        .user = null,
        .hash_leaf = xorHashLeaf,
        .hash_parent = xorHashParent,
        .hash_empty = xorHashEmpty,
        .hash_commitment = xorHashCommitment,
    };

    var scratch_buf: [aegis.AEGIS128L_RAF_SCRATCH_SIZE(1024)]u8 align(aegis.AEGIS_RAF_SCRATCH_ALIGN) = undefined;
    const scratch = aegis.aegis_raf_scratch{
        .buf = &scratch_buf,
        .len = scratch_buf.len,
    };

    const cfg = aegis.aegis_raf_config{
        .chunk_size = 1024,
        .flags = aegis.AEGIS_RAF_CREATE,
        .scratch = &scratch,
        .merkle = &merkle_cfg,
    };

    var ctx: aegis.aegis128l_raf_ctx align(32) = undefined;

    var ret = aegis.aegis128l_raf_create(&ctx, &file.io(), &rng(), &cfg, &key);
    try testing.expectEqual(ret, 0);

    var large_data: [4000]u8 = undefined;
    for (&large_data, 0..) |*b, i| {
        b.* = @truncate(i);
    }

    var bytes_written: usize = undefined;
    ret = aegis.aegis128l_raf_write(&ctx, &bytes_written, &large_data, large_data.len, 0);
    try testing.expectEqual(ret, 0);

    ret = aegis.aegis128l_raf_merkle_verify(&ctx, null);
    try testing.expectEqual(ret, 0);

    const leaf2_offset = 2 * MERKLE_HASH_LEN;
    merkle_buf[leaf2_offset] ^= 0xFF;
    merkle_buf[leaf2_offset + 1] ^= 0xFF;

    var corrupted_chunk: u64 = undefined;
    ret = aegis.aegis128l_raf_merkle_verify(&ctx, &corrupted_chunk);
    try testing.expect(ret != 0);
    try testing.expectEqual(corrupted_chunk, 2);

    aegis.aegis128l_raf_close(&ctx);
}

test "aegis128l_raf_merkle - verify detects corruption in last chunk" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    var file = MemoryFile.init(testing.allocator);
    defer file.deinit();

    var key: [aegis.aegis128l_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    const max_chunks: u64 = 8;
    var merkle_buf: [256]u8 = undefined;
    @memset(&merkle_buf, 0);

    var merkle_cfg = aegis.aegis_raf_merkle_config{
        .buf = &merkle_buf,
        .len = merkle_buf.len,
        .hash_len = MERKLE_HASH_LEN,
        .max_chunks = max_chunks,
        .user = null,
        .hash_leaf = xorHashLeaf,
        .hash_parent = xorHashParent,
        .hash_empty = xorHashEmpty,
        .hash_commitment = xorHashCommitment,
    };

    var scratch_buf: [aegis.AEGIS128L_RAF_SCRATCH_SIZE(1024)]u8 align(aegis.AEGIS_RAF_SCRATCH_ALIGN) = undefined;
    const scratch = aegis.aegis_raf_scratch{
        .buf = &scratch_buf,
        .len = scratch_buf.len,
    };

    const cfg = aegis.aegis_raf_config{
        .chunk_size = 1024,
        .flags = aegis.AEGIS_RAF_CREATE,
        .scratch = &scratch,
        .merkle = &merkle_cfg,
    };

    var ctx: aegis.aegis128l_raf_ctx align(32) = undefined;

    var ret = aegis.aegis128l_raf_create(&ctx, &file.io(), &rng(), &cfg, &key);
    try testing.expectEqual(ret, 0);

    var large_data: [2500]u8 = undefined;
    for (&large_data, 0..) |*b, i| {
        b.* = @truncate(i);
    }

    var bytes_written: usize = undefined;
    ret = aegis.aegis128l_raf_write(&ctx, &bytes_written, &large_data, large_data.len, 0);
    try testing.expectEqual(ret, 0);

    ret = aegis.aegis128l_raf_merkle_verify(&ctx, null);
    try testing.expectEqual(ret, 0);

    const leaf2_offset = 2 * MERKLE_HASH_LEN;
    merkle_buf[leaf2_offset] ^= 0xFF;

    var corrupted_chunk: u64 = undefined;
    ret = aegis.aegis128l_raf_merkle_verify(&ctx, &corrupted_chunk);
    try testing.expect(ret != 0);
    try testing.expectEqual(corrupted_chunk, 2);

    aegis.aegis128l_raf_close(&ctx);
}

test "aegis128l_raf_merkle - verify detects parent and root tampering" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    var file = MemoryFile.init(testing.allocator);
    defer file.deinit();

    var key: [aegis.aegis128l_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    const max_chunks: u64 = 8;
    var merkle_buf: [256]u8 = undefined;
    @memset(&merkle_buf, 0);

    var merkle_cfg = aegis.aegis_raf_merkle_config{
        .buf = &merkle_buf,
        .len = merkle_buf.len,
        .hash_len = MERKLE_HASH_LEN,
        .max_chunks = max_chunks,
        .user = null,
        .hash_leaf = xorHashLeaf,
        .hash_parent = xorHashParent,
        .hash_empty = xorHashEmpty,
        .hash_commitment = xorHashCommitment,
    };

    const merkle_tree_size = aegis.aegis_raf_merkle_buffer_size(&merkle_cfg);
    try testing.expect(merkle_tree_size <= merkle_buf.len);

    var scratch_buf: [aegis.AEGIS128L_RAF_SCRATCH_SIZE(1024)]u8 align(aegis.AEGIS_RAF_SCRATCH_ALIGN) = undefined;
    const scratch = aegis.aegis_raf_scratch{
        .buf = &scratch_buf,
        .len = scratch_buf.len,
    };

    const cfg = aegis.aegis_raf_config{
        .chunk_size = 1024,
        .flags = aegis.AEGIS_RAF_CREATE,
        .scratch = &scratch,
        .merkle = &merkle_cfg,
    };

    var ctx: aegis.aegis128l_raf_ctx align(32) = undefined;

    var ret = aegis.aegis128l_raf_create(&ctx, &file.io(), &rng(), &cfg, &key);
    try testing.expectEqual(ret, 0);

    var large_data: [3000]u8 = undefined;
    for (&large_data, 0..) |*b, i| {
        b.* = @truncate(i *% 13 +% 7);
    }

    var bytes_written: usize = undefined;
    ret = aegis.aegis128l_raf_write(&ctx, &bytes_written, &large_data, large_data.len, 0);
    try testing.expectEqual(ret, 0);

    ret = aegis.aegis128l_raf_merkle_verify(&ctx, null);
    try testing.expectEqual(ret, 0);

    const level1_offset = @as(usize, @intCast(max_chunks)) * MERKLE_HASH_LEN;
    merkle_buf[level1_offset + 1] ^= 0x5A;

    ret = aegis.aegis128l_raf_merkle_verify(&ctx, null);
    try testing.expect(ret != 0);

    merkle_buf[level1_offset + 1] ^= 0x5A;
    ret = aegis.aegis128l_raf_merkle_verify(&ctx, null);
    try testing.expectEqual(ret, 0);

    const root_offset = merkle_tree_size - MERKLE_HASH_LEN;
    merkle_buf[root_offset] ^= 0xA6;

    ret = aegis.aegis128l_raf_merkle_verify(&ctx, null);
    try testing.expect(ret != 0);

    aegis.aegis128l_raf_close(&ctx);
}

test "aegis128l_raf_merkle - odd tree supports max hash_len" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    var file = MemoryFile.init(testing.allocator);
    defer file.deinit();

    var key: [aegis.aegis128l_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    const max_hash_len: usize = aegis.AEGIS_RAF_MERKLE_HASH_MAX;
    const max_chunks: u64 = 3;
    var merkle_buf: [2048]u8 = undefined;
    @memset(&merkle_buf, 0);

    var merkle_cfg = aegis.aegis_raf_merkle_config{
        .buf = &merkle_buf,
        .len = merkle_buf.len,
        .hash_len = max_hash_len,
        .max_chunks = max_chunks,
        .user = null,
        .hash_leaf = variableHashLeaf,
        .hash_parent = variableHashParent,
        .hash_empty = variableHashEmpty,
        .hash_commitment = variableHashCommitment,
    };

    const merkle_tree_size = aegis.aegis_raf_merkle_buffer_size(&merkle_cfg);
    try testing.expect(merkle_tree_size <= merkle_buf.len);

    var scratch_buf: [aegis.AEGIS128L_RAF_SCRATCH_SIZE(1024)]u8 align(aegis.AEGIS_RAF_SCRATCH_ALIGN) = undefined;
    const scratch = aegis.aegis_raf_scratch{
        .buf = &scratch_buf,
        .len = scratch_buf.len,
    };

    const cfg = aegis.aegis_raf_config{
        .chunk_size = 1024,
        .flags = aegis.AEGIS_RAF_CREATE,
        .scratch = &scratch,
        .merkle = &merkle_cfg,
    };

    var ctx: aegis.aegis128l_raf_ctx align(32) = undefined;

    var ret = aegis.aegis128l_raf_create(&ctx, &file.io(), &rng(), &cfg, &key);
    try testing.expectEqual(ret, 0);

    var data: [1500]u8 = undefined;
    for (&data, 0..) |*b, i| {
        b.* = @truncate(i *% 11 +% 1);
    }

    var bytes_written: usize = undefined;
    ret = aegis.aegis128l_raf_write(&ctx, &bytes_written, &data, data.len, 0);
    try testing.expectEqual(ret, 0);

    ret = aegis.aegis128l_raf_merkle_verify(&ctx, null);
    try testing.expectEqual(ret, 0);

    aegis.aegis128l_raf_close(&ctx);
}

test "aegis128l_raf_merkle - hash_len above max is rejected" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    var file = MemoryFile.init(testing.allocator);
    defer file.deinit();

    var key: [aegis.aegis128l_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    const max_chunks: u64 = 3;
    var merkle_buf: [2048]u8 = undefined;
    @memset(&merkle_buf, 0);

    var merkle_cfg = aegis.aegis_raf_merkle_config{
        .buf = &merkle_buf,
        .len = merkle_buf.len,
        .hash_len = aegis.AEGIS_RAF_MERKLE_HASH_MAX + 1,
        .max_chunks = max_chunks,
        .user = null,
        .hash_leaf = variableHashLeaf,
        .hash_parent = variableHashParent,
        .hash_empty = variableHashEmpty,
        .hash_commitment = variableHashCommitment,
    };

    var scratch_buf: [aegis.AEGIS128L_RAF_SCRATCH_SIZE(1024)]u8 align(aegis.AEGIS_RAF_SCRATCH_ALIGN) = undefined;
    const scratch = aegis.aegis_raf_scratch{
        .buf = &scratch_buf,
        .len = scratch_buf.len,
    };

    const cfg = aegis.aegis_raf_config{
        .chunk_size = 1024,
        .flags = aegis.AEGIS_RAF_CREATE,
        .scratch = &scratch,
        .merkle = &merkle_cfg,
    };

    var ctx: aegis.aegis128l_raf_ctx align(32) = undefined;
    const ret = aegis.aegis128l_raf_create(&ctx, &file.io(), &rng(), &cfg, &key);
    try testing.expect(ret != 0);
}

test "aegis128l_raf_merkle - hash_len below min is rejected" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    var file = MemoryFile.init(testing.allocator);
    defer file.deinit();

    var key: [aegis.aegis128l_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    const max_chunks: u64 = 3;
    var merkle_buf: [2048]u8 = undefined;
    @memset(&merkle_buf, 0);

    var merkle_cfg = aegis.aegis_raf_merkle_config{
        .buf = &merkle_buf,
        .len = merkle_buf.len,
        .hash_len = aegis.AEGIS_RAF_MERKLE_HASH_MIN - 1,
        .max_chunks = max_chunks,
        .user = null,
        .hash_leaf = variableHashLeaf,
        .hash_parent = variableHashParent,
        .hash_empty = variableHashEmpty,
        .hash_commitment = variableHashCommitment,
    };

    var scratch_buf: [aegis.AEGIS128L_RAF_SCRATCH_SIZE(1024)]u8 align(aegis.AEGIS_RAF_SCRATCH_ALIGN) = undefined;
    const scratch = aegis.aegis_raf_scratch{
        .buf = &scratch_buf,
        .len = scratch_buf.len,
    };

    const cfg = aegis.aegis_raf_config{
        .chunk_size = 1024,
        .flags = aegis.AEGIS_RAF_CREATE,
        .scratch = &scratch,
        .merkle = &merkle_cfg,
    };

    var ctx: aegis.aegis128l_raf_ctx align(32) = undefined;
    const ret = aegis.aegis128l_raf_create(&ctx, &file.io(), &rng(), &cfg, &key);
    try testing.expect(ret != 0);
}

test "aegis128l_raf_merkle - truncate to zero clears all leaves" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    var file = MemoryFile.init(testing.allocator);
    defer file.deinit();

    var key: [aegis.aegis128l_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    const max_chunks: u64 = 8;
    var merkle_buf: [256]u8 = undefined;
    @memset(&merkle_buf, 0);

    const merkle_cfg = aegis.aegis_raf_merkle_config{
        .buf = &merkle_buf,
        .len = merkle_buf.len,
        .hash_len = MERKLE_HASH_LEN,
        .max_chunks = max_chunks,
        .user = null,
        .hash_leaf = xorHashLeaf,
        .hash_parent = xorHashParent,
        .hash_empty = xorHashEmpty,
        .hash_commitment = xorHashCommitment,
    };

    var scratch_buf: [aegis.AEGIS128L_RAF_SCRATCH_SIZE(1024)]u8 align(aegis.AEGIS_RAF_SCRATCH_ALIGN) = undefined;
    const scratch = aegis.aegis_raf_scratch{
        .buf = &scratch_buf,
        .len = scratch_buf.len,
    };

    const cfg = aegis.aegis_raf_config{
        .chunk_size = 1024,
        .flags = aegis.AEGIS_RAF_CREATE,
        .scratch = &scratch,
        .merkle = &merkle_cfg,
    };

    var ctx: aegis.aegis128l_raf_ctx align(32) = undefined;

    var ret = aegis.aegis128l_raf_create(&ctx, &file.io(), &rng(), &cfg, &key);
    try testing.expectEqual(ret, 0);

    var empty_root: [MERKLE_HASH_LEN]u8 = undefined;
    try testing.expectEqual(aegis.aegis128l_raf_merkle_commitment(&ctx, &empty_root, MERKLE_HASH_LEN), 0);

    var large_data: [5000]u8 = undefined;
    for (&large_data, 0..) |*b, i| {
        b.* = @truncate(i);
    }

    var bytes_written: usize = undefined;
    ret = aegis.aegis128l_raf_write(&ctx, &bytes_written, &large_data, large_data.len, 0);
    try testing.expectEqual(ret, 0);

    ret = aegis.aegis128l_raf_truncate(&ctx, 0);
    try testing.expectEqual(ret, 0);

    var size: u64 = undefined;
    ret = aegis.aegis128l_raf_get_size(&ctx, &size);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(size, 0);

    ret = aegis.aegis128l_raf_merkle_verify(&ctx, null);
    try testing.expectEqual(ret, 0);

    aegis.aegis128l_raf_close(&ctx);
}

test "aegis128l_raf_merkle - truncate preserves earlier chunks" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    var file = MemoryFile.init(testing.allocator);
    defer file.deinit();

    var key: [aegis.aegis128l_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    const max_chunks: u64 = 8;
    var merkle_buf: [256]u8 = undefined;
    @memset(&merkle_buf, 0);

    const merkle_cfg = aegis.aegis_raf_merkle_config{
        .buf = &merkle_buf,
        .len = merkle_buf.len,
        .hash_len = MERKLE_HASH_LEN,
        .max_chunks = max_chunks,
        .user = null,
        .hash_leaf = xorHashLeaf,
        .hash_parent = xorHashParent,
        .hash_empty = xorHashEmpty,
        .hash_commitment = xorHashCommitment,
    };

    var scratch_buf: [aegis.AEGIS128L_RAF_SCRATCH_SIZE(1024)]u8 align(aegis.AEGIS_RAF_SCRATCH_ALIGN) = undefined;
    const scratch = aegis.aegis_raf_scratch{
        .buf = &scratch_buf,
        .len = scratch_buf.len,
    };

    const cfg = aegis.aegis_raf_config{
        .chunk_size = 1024,
        .flags = aegis.AEGIS_RAF_CREATE,
        .scratch = &scratch,
        .merkle = &merkle_cfg,
    };

    var ctx: aegis.aegis128l_raf_ctx align(32) = undefined;

    var ret = aegis.aegis128l_raf_create(&ctx, &file.io(), &rng(), &cfg, &key);
    try testing.expectEqual(ret, 0);

    var large_data: [5000]u8 = undefined;
    for (&large_data, 0..) |*b, i| {
        b.* = @truncate(i);
    }

    var bytes_written: usize = undefined;
    ret = aegis.aegis128l_raf_write(&ctx, &bytes_written, &large_data, large_data.len, 0);
    try testing.expectEqual(ret, 0);

    ret = aegis.aegis128l_raf_truncate(&ctx, 2000);
    try testing.expectEqual(ret, 0);

    ret = aegis.aegis128l_raf_merkle_verify(&ctx, null);
    try testing.expectEqual(ret, 0);

    var read_buf: [2000]u8 = undefined;
    var bytes_read: usize = undefined;
    ret = aegis.aegis128l_raf_read(&ctx, &read_buf, &bytes_read, 2000, 0);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(bytes_read, 2000);
    try testing.expectEqualSlices(u8, large_data[0..2000], &read_buf);

    aegis.aegis128l_raf_close(&ctx);
}

test "aegis128l_raf_merkle - truncate grow rebuild matches incremental" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    var file = MemoryFile.init(testing.allocator);
    defer file.deinit();

    var key: [aegis.aegis128l_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    const max_chunks: u64 = 8;
    var merkle_buf1: [256]u8 = undefined;
    var merkle_buf2: [256]u8 = undefined;
    @memset(&merkle_buf1, 0);
    @memset(&merkle_buf2, 0);

    var merkle_cfg1 = aegis.aegis_raf_merkle_config{
        .buf = &merkle_buf1,
        .len = merkle_buf1.len,
        .hash_len = MERKLE_HASH_LEN,
        .max_chunks = max_chunks,
        .user = null,
        .hash_leaf = xorHashLeaf,
        .hash_parent = xorHashParent,
        .hash_empty = xorHashEmpty,
        .hash_commitment = xorHashCommitment,
    };

    var scratch_buf: [aegis.AEGIS128L_RAF_SCRATCH_SIZE(1024)]u8 align(aegis.AEGIS_RAF_SCRATCH_ALIGN) = undefined;
    const scratch = aegis.aegis_raf_scratch{
        .buf = &scratch_buf,
        .len = scratch_buf.len,
    };

    const cfg1 = aegis.aegis_raf_config{
        .chunk_size = 1024,
        .flags = aegis.AEGIS_RAF_CREATE,
        .scratch = &scratch,
        .merkle = &merkle_cfg1,
    };

    var ctx: aegis.aegis128l_raf_ctx align(32) = undefined;

    var ret = aegis.aegis128l_raf_create(&ctx, &file.io(), &rng(), &cfg1, &key);
    try testing.expectEqual(ret, 0);

    const data = "Hello!";
    var bytes_written: usize = undefined;
    ret = aegis.aegis128l_raf_write(&ctx, &bytes_written, data.ptr, data.len, 0);
    try testing.expectEqual(ret, 0);

    ret = aegis.aegis128l_raf_truncate(&ctx, 2500);
    try testing.expectEqual(ret, 0);

    var incremental_root: [MERKLE_HASH_LEN]u8 = undefined;
    try testing.expectEqual(aegis.aegis128l_raf_merkle_commitment(&ctx, &incremental_root, MERKLE_HASH_LEN), 0);

    aegis.aegis128l_raf_close(&ctx);

    var merkle_cfg2 = aegis.aegis_raf_merkle_config{
        .buf = &merkle_buf2,
        .len = merkle_buf2.len,
        .hash_len = MERKLE_HASH_LEN,
        .max_chunks = max_chunks,
        .user = null,
        .hash_leaf = xorHashLeaf,
        .hash_parent = xorHashParent,
        .hash_empty = xorHashEmpty,
        .hash_commitment = xorHashCommitment,
    };

    const cfg2 = aegis.aegis_raf_config{
        .chunk_size = 0,
        .flags = 0,
        .scratch = &scratch,
        .merkle = &merkle_cfg2,
    };

    ret = aegis.aegis128l_raf_open(&ctx, &file.io(), &rng(), &cfg2, &key);
    try testing.expectEqual(ret, 0);

    ret = aegis.aegis128l_raf_merkle_rebuild(&ctx);
    try testing.expectEqual(ret, 0);

    var rebuilt_root: [MERKLE_HASH_LEN]u8 = undefined;
    try testing.expectEqual(aegis.aegis128l_raf_merkle_commitment(&ctx, &rebuilt_root, MERKLE_HASH_LEN), 0);

    try testing.expectEqualSlices(u8, &incremental_root, &rebuilt_root);

    aegis.aegis128l_raf_close(&ctx);
}

test "aegis128l_raf_merkle - overwrite preserves tree consistency" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    var file = MemoryFile.init(testing.allocator);
    defer file.deinit();

    var key: [aegis.aegis128l_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    const max_chunks: u64 = 8;
    var merkle_buf: [256]u8 = undefined;
    @memset(&merkle_buf, 0);

    const merkle_cfg = aegis.aegis_raf_merkle_config{
        .buf = &merkle_buf,
        .len = merkle_buf.len,
        .hash_len = MERKLE_HASH_LEN,
        .max_chunks = max_chunks,
        .user = null,
        .hash_leaf = xorHashLeaf,
        .hash_parent = xorHashParent,
        .hash_empty = xorHashEmpty,
        .hash_commitment = xorHashCommitment,
    };

    var scratch_buf: [aegis.AEGIS128L_RAF_SCRATCH_SIZE(1024)]u8 align(aegis.AEGIS_RAF_SCRATCH_ALIGN) = undefined;
    const scratch = aegis.aegis_raf_scratch{
        .buf = &scratch_buf,
        .len = scratch_buf.len,
    };

    const cfg = aegis.aegis_raf_config{
        .chunk_size = 1024,
        .flags = aegis.AEGIS_RAF_CREATE,
        .scratch = &scratch,
        .merkle = &merkle_cfg,
    };

    var ctx: aegis.aegis128l_raf_ctx align(32) = undefined;

    var ret = aegis.aegis128l_raf_create(&ctx, &file.io(), &rng(), &cfg, &key);
    try testing.expectEqual(ret, 0);

    var data: [3000]u8 = undefined;
    @memset(&data, 0x11);
    var bytes_written: usize = undefined;
    ret = aegis.aegis128l_raf_write(&ctx, &bytes_written, &data, data.len, 0);
    try testing.expectEqual(ret, 0);

    ret = aegis.aegis128l_raf_merkle_verify(&ctx, null);
    try testing.expectEqual(ret, 0);

    var patch: [500]u8 = undefined;
    @memset(&patch, 0x22);
    ret = aegis.aegis128l_raf_write(&ctx, &bytes_written, &patch, patch.len, 1200);
    try testing.expectEqual(ret, 0);

    ret = aegis.aegis128l_raf_merkle_verify(&ctx, null);
    try testing.expectEqual(ret, 0);

    @memset(&patch, 0x33);
    ret = aegis.aegis128l_raf_write(&ctx, &bytes_written, &patch, patch.len, 800);
    try testing.expectEqual(ret, 0);

    ret = aegis.aegis128l_raf_merkle_verify(&ctx, null);
    try testing.expectEqual(ret, 0);

    aegis.aegis128l_raf_close(&ctx);
}

test "aegis128l_raf_merkle - non power of 2 chunk count" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    var file = MemoryFile.init(testing.allocator);
    defer file.deinit();

    var key: [aegis.aegis128l_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    const max_chunks: u64 = 5;
    var merkle_buf: [512]u8 = undefined;
    @memset(&merkle_buf, 0);

    const merkle_cfg = aegis.aegis_raf_merkle_config{
        .buf = &merkle_buf,
        .len = merkle_buf.len,
        .hash_len = MERKLE_HASH_LEN,
        .max_chunks = max_chunks,
        .user = null,
        .hash_leaf = xorHashLeaf,
        .hash_parent = xorHashParent,
        .hash_empty = xorHashEmpty,
        .hash_commitment = xorHashCommitment,
    };

    var scratch_buf: [aegis.AEGIS128L_RAF_SCRATCH_SIZE(1024)]u8 align(aegis.AEGIS_RAF_SCRATCH_ALIGN) = undefined;
    const scratch = aegis.aegis_raf_scratch{
        .buf = &scratch_buf,
        .len = scratch_buf.len,
    };

    const cfg = aegis.aegis_raf_config{
        .chunk_size = 1024,
        .flags = aegis.AEGIS_RAF_CREATE,
        .scratch = &scratch,
        .merkle = &merkle_cfg,
    };

    var ctx: aegis.aegis128l_raf_ctx align(32) = undefined;

    var ret = aegis.aegis128l_raf_create(&ctx, &file.io(), &rng(), &cfg, &key);
    try testing.expectEqual(ret, 0);

    var data: [5120]u8 = undefined;
    for (&data, 0..) |*b, i| {
        b.* = @truncate(i);
    }

    var bytes_written: usize = undefined;
    ret = aegis.aegis128l_raf_write(&ctx, &bytes_written, &data, data.len, 0);
    try testing.expectEqual(ret, 0);

    ret = aegis.aegis128l_raf_merkle_verify(&ctx, null);
    try testing.expectEqual(ret, 0);

    aegis.aegis128l_raf_close(&ctx);

    var merkle_buf2: [512]u8 = undefined;
    @memset(&merkle_buf2, 0);

    const merkle_cfg2 = aegis.aegis_raf_merkle_config{
        .buf = &merkle_buf2,
        .len = merkle_buf2.len,
        .hash_len = MERKLE_HASH_LEN,
        .max_chunks = max_chunks,
        .user = null,
        .hash_leaf = xorHashLeaf,
        .hash_parent = xorHashParent,
        .hash_empty = xorHashEmpty,
        .hash_commitment = xorHashCommitment,
    };

    const cfg2 = aegis.aegis_raf_config{
        .chunk_size = 0,
        .flags = 0,
        .scratch = &scratch,
        .merkle = &merkle_cfg2,
    };

    ret = aegis.aegis128l_raf_open(&ctx, &file.io(), &rng(), &cfg2, &key);
    try testing.expectEqual(ret, 0);

    ret = aegis.aegis128l_raf_merkle_rebuild(&ctx);
    try testing.expectEqual(ret, 0);

    try testing.expectEqualSlices(u8, merkle_buf[0..256], merkle_buf2[0..256]);

    ret = aegis.aegis128l_raf_merkle_verify(&ctx, null);
    try testing.expectEqual(ret, 0);

    aegis.aegis128l_raf_close(&ctx);
}

test "aegis128l_raf_merkle - 3 max chunks odd tree" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    var file = MemoryFile.init(testing.allocator);
    defer file.deinit();

    var key: [aegis.aegis128l_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    const max_chunks: u64 = 3;
    var merkle_buf: [256]u8 = undefined;
    @memset(&merkle_buf, 0);

    const merkle_cfg = aegis.aegis_raf_merkle_config{
        .buf = &merkle_buf,
        .len = merkle_buf.len,
        .hash_len = MERKLE_HASH_LEN,
        .max_chunks = max_chunks,
        .user = null,
        .hash_leaf = xorHashLeaf,
        .hash_parent = xorHashParent,
        .hash_empty = xorHashEmpty,
        .hash_commitment = xorHashCommitment,
    };

    var scratch_buf: [aegis.AEGIS128L_RAF_SCRATCH_SIZE(1024)]u8 align(aegis.AEGIS_RAF_SCRATCH_ALIGN) = undefined;
    const scratch = aegis.aegis_raf_scratch{
        .buf = &scratch_buf,
        .len = scratch_buf.len,
    };

    const cfg = aegis.aegis_raf_config{
        .chunk_size = 1024,
        .flags = aegis.AEGIS_RAF_CREATE,
        .scratch = &scratch,
        .merkle = &merkle_cfg,
    };

    var ctx: aegis.aegis128l_raf_ctx align(32) = undefined;

    var ret = aegis.aegis128l_raf_create(&ctx, &file.io(), &rng(), &cfg, &key);
    try testing.expectEqual(ret, 0);

    var data: [3000]u8 = undefined;
    for (&data, 0..) |*b, i| {
        b.* = @truncate(i ^ 0x55);
    }

    var bytes_written: usize = undefined;
    ret = aegis.aegis128l_raf_write(&ctx, &bytes_written, &data, data.len, 0);
    try testing.expectEqual(ret, 0);

    ret = aegis.aegis128l_raf_merkle_verify(&ctx, null);
    try testing.expectEqual(ret, 0);

    var patch: [100]u8 = undefined;
    @memset(&patch, 0xAA);
    ret = aegis.aegis128l_raf_write(&ctx, &bytes_written, &patch, patch.len, 1100);
    try testing.expectEqual(ret, 0);

    ret = aegis.aegis128l_raf_merkle_verify(&ctx, null);
    try testing.expectEqual(ret, 0);

    aegis.aegis128l_raf_close(&ctx);
}

test "aegis128l_raf_merkle - write extending file" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    var file = MemoryFile.init(testing.allocator);
    defer file.deinit();

    var key: [aegis.aegis128l_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    const max_chunks: u64 = 16;
    var merkle_buf: [1024]u8 = undefined;
    @memset(&merkle_buf, 0);

    const merkle_cfg = aegis.aegis_raf_merkle_config{
        .buf = &merkle_buf,
        .len = merkle_buf.len,
        .hash_len = MERKLE_HASH_LEN,
        .max_chunks = max_chunks,
        .user = null,
        .hash_leaf = xorHashLeaf,
        .hash_parent = xorHashParent,
        .hash_empty = xorHashEmpty,
        .hash_commitment = xorHashCommitment,
    };

    var scratch_buf: [aegis.AEGIS128L_RAF_SCRATCH_SIZE(1024)]u8 align(aegis.AEGIS_RAF_SCRATCH_ALIGN) = undefined;
    const scratch = aegis.aegis_raf_scratch{
        .buf = &scratch_buf,
        .len = scratch_buf.len,
    };

    const cfg = aegis.aegis_raf_config{
        .chunk_size = 1024,
        .flags = aegis.AEGIS_RAF_CREATE,
        .scratch = &scratch,
        .merkle = &merkle_cfg,
    };

    var ctx: aegis.aegis128l_raf_ctx align(32) = undefined;

    var ret = aegis.aegis128l_raf_create(&ctx, &file.io(), &rng(), &cfg, &key);
    try testing.expectEqual(ret, 0);

    const data1 = "First data";
    var bytes_written: usize = undefined;
    ret = aegis.aegis128l_raf_write(&ctx, &bytes_written, data1.ptr, data1.len, 0);
    try testing.expectEqual(ret, 0);

    var size: u64 = undefined;
    ret = aegis.aegis128l_raf_get_size(&ctx, &size);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(size, data1.len);

    const data2 = "Extended data";
    ret = aegis.aegis128l_raf_write(&ctx, &bytes_written, data2.ptr, data2.len, 2048);
    try testing.expectEqual(ret, 0);

    ret = aegis.aegis128l_raf_get_size(&ctx, &size);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(size, 2048 + data2.len);

    ret = aegis.aegis128l_raf_merkle_verify(&ctx, null);
    try testing.expectEqual(ret, 0);

    aegis.aegis128l_raf_close(&ctx);
}

test "aegis128l_raf_merkle - buffer too small fails validation" {
    var small_buf: [10]u8 = undefined;
    @memset(&small_buf, 0);

    const merkle_cfg = aegis.aegis_raf_merkle_config{
        .buf = &small_buf,
        .len = small_buf.len,
        .hash_len = MERKLE_HASH_LEN,
        .max_chunks = 8,
        .user = null,
        .hash_leaf = xorHashLeaf,
        .hash_parent = xorHashParent,
        .hash_empty = xorHashEmpty,
        .hash_commitment = xorHashCommitment,
    };

    const required = aegis.aegis_raf_merkle_buffer_size(&merkle_cfg);
    try testing.expect(required > small_buf.len);
}

test "aegis128l_raf_merkle - different data different roots" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    var file = MemoryFile.init(testing.allocator);
    defer file.deinit();

    var key: [aegis.aegis128l_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    const max_chunks: u64 = 4;
    var merkle_buf: [256]u8 = undefined;
    @memset(&merkle_buf, 0);

    const merkle_cfg = aegis.aegis_raf_merkle_config{
        .buf = &merkle_buf,
        .len = merkle_buf.len,
        .hash_len = MERKLE_HASH_LEN,
        .max_chunks = max_chunks,
        .user = null,
        .hash_leaf = xorHashLeaf,
        .hash_parent = xorHashParent,
        .hash_empty = xorHashEmpty,
        .hash_commitment = xorHashCommitment,
    };

    var scratch_buf: [aegis.AEGIS128L_RAF_SCRATCH_SIZE(1024)]u8 align(aegis.AEGIS_RAF_SCRATCH_ALIGN) = undefined;
    const scratch = aegis.aegis_raf_scratch{
        .buf = &scratch_buf,
        .len = scratch_buf.len,
    };

    const cfg = aegis.aegis_raf_config{
        .chunk_size = 1024,
        .flags = aegis.AEGIS_RAF_CREATE,
        .scratch = &scratch,
        .merkle = &merkle_cfg,
    };

    var ctx: aegis.aegis128l_raf_ctx align(32) = undefined;

    var ret = aegis.aegis128l_raf_create(&ctx, &file.io(), &rng(), &cfg, &key);
    try testing.expectEqual(ret, 0);

    const data1 = "AAAA";
    var bytes_written: usize = undefined;
    ret = aegis.aegis128l_raf_write(&ctx, &bytes_written, data1.ptr, data1.len, 0);
    try testing.expectEqual(ret, 0);

    var root1: [MERKLE_HASH_LEN]u8 = undefined;
    try testing.expectEqual(aegis.aegis128l_raf_merkle_commitment(&ctx, &root1, MERKLE_HASH_LEN), 0);

    ret = aegis.aegis128l_raf_truncate(&ctx, 0);
    try testing.expectEqual(ret, 0);

    const data2 = "BBBB";
    ret = aegis.aegis128l_raf_write(&ctx, &bytes_written, data2.ptr, data2.len, 0);
    try testing.expectEqual(ret, 0);

    var root2: [MERKLE_HASH_LEN]u8 = undefined;
    try testing.expectEqual(aegis.aegis128l_raf_merkle_commitment(&ctx, &root2, MERKLE_HASH_LEN), 0);

    try testing.expect(!std.mem.eql(u8, &root1, &root2));

    aegis.aegis128l_raf_close(&ctx);
}

test "aegis128l_raf_merkle - single byte change changes root" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    var file = MemoryFile.init(testing.allocator);
    defer file.deinit();

    var key: [aegis.aegis128l_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    const max_chunks: u64 = 4;
    var merkle_buf: [256]u8 = undefined;
    @memset(&merkle_buf, 0);

    const merkle_cfg = aegis.aegis_raf_merkle_config{
        .buf = &merkle_buf,
        .len = merkle_buf.len,
        .hash_len = MERKLE_HASH_LEN,
        .max_chunks = max_chunks,
        .user = null,
        .hash_leaf = xorHashLeaf,
        .hash_parent = xorHashParent,
        .hash_empty = xorHashEmpty,
        .hash_commitment = xorHashCommitment,
    };

    var scratch_buf: [aegis.AEGIS128L_RAF_SCRATCH_SIZE(1024)]u8 align(aegis.AEGIS_RAF_SCRATCH_ALIGN) = undefined;
    const scratch = aegis.aegis_raf_scratch{
        .buf = &scratch_buf,
        .len = scratch_buf.len,
    };

    const cfg = aegis.aegis_raf_config{
        .chunk_size = 1024,
        .flags = aegis.AEGIS_RAF_CREATE,
        .scratch = &scratch,
        .merkle = &merkle_cfg,
    };

    var ctx: aegis.aegis128l_raf_ctx align(32) = undefined;

    var ret = aegis.aegis128l_raf_create(&ctx, &file.io(), &rng(), &cfg, &key);
    try testing.expectEqual(ret, 0);

    var data: [2000]u8 = undefined;
    @memset(&data, 0x00);
    var bytes_written: usize = undefined;
    ret = aegis.aegis128l_raf_write(&ctx, &bytes_written, &data, data.len, 0);
    try testing.expectEqual(ret, 0);

    var root_before: [MERKLE_HASH_LEN]u8 = undefined;
    try testing.expectEqual(aegis.aegis128l_raf_merkle_commitment(&ctx, &root_before, MERKLE_HASH_LEN), 0);

    const single_byte: [1]u8 = .{0xFF};
    ret = aegis.aegis128l_raf_write(&ctx, &bytes_written, &single_byte, 1, 1500);
    try testing.expectEqual(ret, 0);

    var root_after: [MERKLE_HASH_LEN]u8 = undefined;
    try testing.expectEqual(aegis.aegis128l_raf_merkle_commitment(&ctx, &root_after, MERKLE_HASH_LEN), 0);

    try testing.expect(!std.mem.eql(u8, &root_before, &root_after));

    aegis.aegis128l_raf_close(&ctx);
}

test "aegis256_raf_merkle - verify with different AEGIS variant" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    var file = MemoryFile.init(testing.allocator);
    defer file.deinit();

    var key: [aegis.aegis256_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    const max_chunks: u64 = 8;
    var merkle_buf: [256]u8 = undefined;
    @memset(&merkle_buf, 0);

    const merkle_cfg = aegis.aegis_raf_merkle_config{
        .buf = &merkle_buf,
        .len = merkle_buf.len,
        .hash_len = MERKLE_HASH_LEN,
        .max_chunks = max_chunks,
        .user = null,
        .hash_leaf = xorHashLeaf,
        .hash_parent = xorHashParent,
        .hash_empty = xorHashEmpty,
        .hash_commitment = xorHashCommitment,
    };

    var scratch_buf: [aegis.AEGIS256_RAF_SCRATCH_SIZE(1024)]u8 align(aegis.AEGIS_RAF_SCRATCH_ALIGN) = undefined;
    const scratch = aegis.aegis_raf_scratch{
        .buf = &scratch_buf,
        .len = scratch_buf.len,
    };

    const cfg = aegis.aegis_raf_config{
        .chunk_size = 1024,
        .flags = aegis.AEGIS_RAF_CREATE,
        .scratch = &scratch,
        .merkle = &merkle_cfg,
    };

    var ctx: aegis.aegis256_raf_ctx align(32) = undefined;

    var ret = aegis.aegis256_raf_create(&ctx, &file.io(), &rng(), &cfg, &key);
    try testing.expectEqual(ret, 0);

    const test_data = "AEGIS-256 variant test data";
    var bytes_written: usize = undefined;
    ret = aegis.aegis256_raf_write(&ctx, &bytes_written, test_data.ptr, test_data.len, 0);
    try testing.expectEqual(ret, 0);

    ret = aegis.aegis256_raf_merkle_verify(&ctx, null);
    try testing.expectEqual(ret, 0);

    aegis.aegis256_raf_close(&ctx);

    var merkle_buf2: [256]u8 = undefined;
    @memset(&merkle_buf2, 0);

    const merkle_cfg2 = aegis.aegis_raf_merkle_config{
        .buf = &merkle_buf2,
        .len = merkle_buf2.len,
        .hash_len = MERKLE_HASH_LEN,
        .max_chunks = max_chunks,
        .user = null,
        .hash_leaf = xorHashLeaf,
        .hash_parent = xorHashParent,
        .hash_empty = xorHashEmpty,
        .hash_commitment = xorHashCommitment,
    };

    const cfg2 = aegis.aegis_raf_config{
        .chunk_size = 0,
        .flags = 0,
        .scratch = &scratch,
        .merkle = &merkle_cfg2,
    };

    ret = aegis.aegis256_raf_open(&ctx, &file.io(), &rng(), &cfg2, &key);
    try testing.expectEqual(ret, 0);

    ret = aegis.aegis256_raf_merkle_rebuild(&ctx);
    try testing.expectEqual(ret, 0);

    ret = aegis.aegis256_raf_merkle_verify(&ctx, null);
    try testing.expectEqual(ret, 0);

    aegis.aegis256_raf_close(&ctx);
}

test "aegis128l_raf_merkle - root commitment consistency" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    var file = MemoryFile.init(testing.allocator);
    defer file.deinit();

    var key: [aegis.aegis128l_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    const max_chunks: u64 = 4;
    var merkle_buf: [256]u8 = undefined;
    @memset(&merkle_buf, 0);

    const merkle_cfg = aegis.aegis_raf_merkle_config{
        .buf = &merkle_buf,
        .len = merkle_buf.len,
        .hash_len = MERKLE_HASH_LEN,
        .max_chunks = max_chunks,
        .user = null,
        .hash_leaf = xorHashLeaf,
        .hash_parent = xorHashParent,
        .hash_empty = xorHashEmpty,
        .hash_commitment = xorHashCommitment,
    };

    var scratch_buf: [aegis.AEGIS128L_RAF_SCRATCH_SIZE(1024)]u8 align(aegis.AEGIS_RAF_SCRATCH_ALIGN) = undefined;
    const scratch = aegis.aegis_raf_scratch{
        .buf = &scratch_buf,
        .len = scratch_buf.len,
    };

    const cfg = aegis.aegis_raf_config{
        .chunk_size = 1024,
        .flags = aegis.AEGIS_RAF_CREATE,
        .scratch = &scratch,
        .merkle = &merkle_cfg,
    };

    var ctx: aegis.aegis128l_raf_ctx align(32) = undefined;

    var ret = aegis.aegis128l_raf_create(&ctx, &file.io(), &rng(), &cfg, &key);
    try testing.expectEqual(ret, 0);

    var root1: [MERKLE_HASH_LEN]u8 = undefined;
    var root2: [MERKLE_HASH_LEN]u8 = undefined;
    var root3: [MERKLE_HASH_LEN]u8 = undefined;
    try testing.expectEqual(aegis.aegis128l_raf_merkle_commitment(&ctx, &root1, MERKLE_HASH_LEN), 0);
    try testing.expectEqual(aegis.aegis128l_raf_merkle_commitment(&ctx, &root2, MERKLE_HASH_LEN), 0);
    try testing.expectEqual(aegis.aegis128l_raf_merkle_commitment(&ctx, &root3, MERKLE_HASH_LEN), 0);
    try testing.expectEqualSlices(u8, &root1, &root2);
    try testing.expectEqualSlices(u8, &root2, &root3);

    const test_data = "test";
    var bytes_written: usize = undefined;
    ret = aegis.aegis128l_raf_write(&ctx, &bytes_written, test_data.ptr, test_data.len, 0);
    try testing.expectEqual(ret, 0);

    var root4: [MERKLE_HASH_LEN]u8 = undefined;
    try testing.expectEqual(aegis.aegis128l_raf_merkle_commitment(&ctx, &root4, MERKLE_HASH_LEN), 0);
    try testing.expect(!std.mem.eql(u8, &root1, &root4));

    aegis.aegis128l_raf_close(&ctx);
}

test "aegis128l_raf_merkle - exact chunk size writes" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    var file = MemoryFile.init(testing.allocator);
    defer file.deinit();

    var key: [aegis.aegis128l_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    const max_chunks: u64 = 4;
    var merkle_buf: [256]u8 = undefined;
    @memset(&merkle_buf, 0);

    const merkle_cfg = aegis.aegis_raf_merkle_config{
        .buf = &merkle_buf,
        .len = merkle_buf.len,
        .hash_len = MERKLE_HASH_LEN,
        .max_chunks = max_chunks,
        .user = null,
        .hash_leaf = xorHashLeaf,
        .hash_parent = xorHashParent,
        .hash_empty = xorHashEmpty,
        .hash_commitment = xorHashCommitment,
    };

    const chunk_size = 1024;
    var scratch_buf: [aegis.AEGIS128L_RAF_SCRATCH_SIZE(chunk_size)]u8 align(aegis.AEGIS_RAF_SCRATCH_ALIGN) = undefined;
    const scratch = aegis.aegis_raf_scratch{
        .buf = &scratch_buf,
        .len = scratch_buf.len,
    };

    const cfg = aegis.aegis_raf_config{
        .chunk_size = chunk_size,
        .flags = aegis.AEGIS_RAF_CREATE,
        .scratch = &scratch,
        .merkle = &merkle_cfg,
    };

    var ctx: aegis.aegis128l_raf_ctx align(32) = undefined;

    var ret = aegis.aegis128l_raf_create(&ctx, &file.io(), &rng(), &cfg, &key);
    try testing.expectEqual(ret, 0);

    var roots: [4][MERKLE_HASH_LEN]u8 = undefined;
    var chunk_data: [chunk_size]u8 = undefined;
    var bytes_written: usize = undefined;

    for (0..4) |i| {
        @memset(&chunk_data, @as(u8, @truncate(i + 1)));
        ret = aegis.aegis128l_raf_write(&ctx, &bytes_written, &chunk_data, chunk_size, @as(u64, i) * chunk_size);
        try testing.expectEqual(ret, 0);
        try testing.expectEqual(bytes_written, chunk_size);

        try testing.expectEqual(aegis.aegis128l_raf_merkle_commitment(&ctx, &roots[i], MERKLE_HASH_LEN), 0);

        if (i > 0) {
            try testing.expect(!std.mem.eql(u8, &roots[i - 1], &roots[i]));
        }
    }

    ret = aegis.aegis128l_raf_merkle_verify(&ctx, null);
    try testing.expectEqual(ret, 0);

    aegis.aegis128l_raf_close(&ctx);
}

const FuzzOp = enum(u8) {
    write_sequential,
    write_random_offset,
    write_cross_chunk,
    write_gap,
    write_exact_chunk,
    write_single_byte,
    read_and_verify,
    truncate_shrink,
    truncate_grow,
    truncate_zero,
    truncate_within_chunk,
    overwrite_partial,
    reopen_and_rebuild,
    verify_merkle,
};

const FuzzState = struct {
    shadow: std.ArrayListUnmanaged(u8),
    file: *MemoryFile,
    ctx: aegis.aegis128l_raf_ctx align(32),
    merkle_buf: [4096]u8,
    merkle_cfg: aegis.aegis_raf_merkle_config,
    scratch_buf: [aegis.AEGIS128L_RAF_SCRATCH_SIZE(1024)]u8 align(aegis.AEGIS_RAF_SCRATCH_ALIGN),
    key: [aegis.aegis128l_KEYBYTES]u8,
    is_open: bool,
    chunk_size: u32,
    max_chunks: u64,
    allocator: std.mem.Allocator,

    fn init(allocator: std.mem.Allocator, file: *MemoryFile, rand: std.Random) FuzzState {
        var state: FuzzState = undefined;
        state.allocator = allocator;
        state.file = file;
        state.shadow = .{};
        state.is_open = false;
        state.chunk_size = 1024;
        state.max_chunks = 32;
        rand.bytes(&state.key);
        @memset(&state.merkle_buf, 0);
        return state;
    }

    fn deinit(self: *FuzzState) void {
        if (self.is_open) {
            aegis.aegis128l_raf_close(&self.ctx);
            self.is_open = false;
        }
        self.shadow.deinit(self.allocator);
    }

    fn create(self: *FuzzState) !void {
        if (self.is_open) {
            aegis.aegis128l_raf_close(&self.ctx);
            self.is_open = false;
        }
        self.shadow.clearRetainingCapacity();
        @memset(&self.merkle_buf, 0);

        self.merkle_cfg = .{
            .buf = &self.merkle_buf,
            .len = self.merkle_buf.len,
            .hash_len = MERKLE_HASH_LEN,
            .max_chunks = self.max_chunks,
            .user = null,
            .hash_leaf = xorHashLeaf,
            .hash_parent = xorHashParent,
            .hash_empty = xorHashEmpty,
            .hash_commitment = xorHashCommitment,
        };

        const scratch = aegis.aegis_raf_scratch{
            .buf = &self.scratch_buf,
            .len = self.scratch_buf.len,
        };

        const cfg = aegis.aegis_raf_config{
            .chunk_size = self.chunk_size,
            .flags = aegis.AEGIS_RAF_CREATE | aegis.AEGIS_RAF_TRUNCATE,
            .scratch = &scratch,
            .merkle = &self.merkle_cfg,
        };

        const ret = aegis.aegis128l_raf_create(&self.ctx, &self.file.io(), &rng(), &cfg, &self.key);
        try testing.expectEqual(ret, 0);
        self.is_open = true;
    }

    fn reopen(self: *FuzzState) !void {
        var old_root: [MERKLE_HASH_LEN]u8 = undefined;
        if (self.is_open) {
            try testing.expectEqual(aegis.aegis128l_raf_merkle_commitment(&self.ctx, &old_root, MERKLE_HASH_LEN), 0);
            aegis.aegis128l_raf_close(&self.ctx);
            self.is_open = false;
        }

        @memset(&self.merkle_buf, 0);
        self.merkle_cfg = .{
            .buf = &self.merkle_buf,
            .len = self.merkle_buf.len,
            .hash_len = MERKLE_HASH_LEN,
            .max_chunks = self.max_chunks,
            .user = null,
            .hash_leaf = xorHashLeaf,
            .hash_parent = xorHashParent,
            .hash_empty = xorHashEmpty,
            .hash_commitment = xorHashCommitment,
        };

        const scratch = aegis.aegis_raf_scratch{
            .buf = &self.scratch_buf,
            .len = self.scratch_buf.len,
        };

        const cfg = aegis.aegis_raf_config{
            .chunk_size = 0,
            .flags = 0,
            .scratch = &scratch,
            .merkle = &self.merkle_cfg,
        };

        var ret = aegis.aegis128l_raf_open(&self.ctx, &self.file.io(), &rng(), &cfg, &self.key);
        try testing.expectEqual(ret, 0);
        self.is_open = true;

        ret = aegis.aegis128l_raf_merkle_rebuild(&self.ctx);
        try testing.expectEqual(ret, 0);

        var new_root: [MERKLE_HASH_LEN]u8 = undefined;
        try testing.expectEqual(aegis.aegis128l_raf_merkle_commitment(&self.ctx, &new_root, MERKLE_HASH_LEN), 0);
        try testing.expectEqualSlices(u8, &old_root, &new_root);
    }

    fn doWrite(self: *FuzzState, data: []const u8, offset: u64) !void {
        if (!self.is_open) return;

        const end = offset + data.len;
        const new_num_chunks = (end + self.chunk_size - 1) / self.chunk_size;
        if (new_num_chunks > self.max_chunks) return;

        var bytes_written: usize = undefined;
        const ret = aegis.aegis128l_raf_write(&self.ctx, &bytes_written, data.ptr, data.len, offset);
        try testing.expectEqual(ret, 0);
        try testing.expectEqual(bytes_written, data.len);

        const end_usize = @as(usize, @intCast(end));
        const off_usize = @as(usize, @intCast(offset));
        if (end_usize > self.shadow.items.len) {
            const old_len = self.shadow.items.len;
            self.shadow.resize(self.allocator, end_usize) catch unreachable;
            if (old_len < off_usize) {
                @memset(self.shadow.items[old_len..off_usize], 0);
            }
        }
        @memcpy(self.shadow.items[off_usize..end_usize], data);
    }

    fn doRead(self: *FuzzState) !void {
        if (!self.is_open) return;
        if (self.shadow.items.len == 0) return;

        var read_buf: [8192]u8 = undefined;
        const len = @min(self.shadow.items.len, read_buf.len);
        var bytes_read: usize = undefined;
        const ret = aegis.aegis128l_raf_read(&self.ctx, &read_buf, &bytes_read, len, 0);
        try testing.expectEqual(ret, 0);
        try testing.expectEqual(bytes_read, len);
        try testing.expectEqualSlices(u8, self.shadow.items[0..len], read_buf[0..len]);
    }

    fn doTruncate(self: *FuzzState, new_size: u64) !void {
        if (!self.is_open) return;

        const new_num_chunks = if (new_size == 0) 0 else (new_size + self.chunk_size - 1) / self.chunk_size;
        if (new_num_chunks > self.max_chunks) return;

        const ret = aegis.aegis128l_raf_truncate(&self.ctx, new_size);
        try testing.expectEqual(ret, 0);

        const ns = @as(usize, @intCast(new_size));
        if (ns < self.shadow.items.len) {
            self.shadow.shrinkRetainingCapacity(ns);
        } else if (ns > self.shadow.items.len) {
            const old_len = self.shadow.items.len;
            self.shadow.resize(self.allocator, ns) catch unreachable;
            @memset(self.shadow.items[old_len..], 0);
        }
    }

    fn verifySize(self: *FuzzState) !void {
        if (!self.is_open) return;
        var size: u64 = undefined;
        const ret = aegis.aegis128l_raf_get_size(&self.ctx, &size);
        try testing.expectEqual(ret, 0);
        try testing.expectEqual(size, self.shadow.items.len);
    }

    fn verifyMerkle(self: *FuzzState) !void {
        if (!self.is_open) return;
        const ret = aegis.aegis128l_raf_merkle_verify(&self.ctx, null);
        try testing.expectEqual(ret, 0);
    }
};

test "fuzz - random RAF operations with merkle" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    var file = MemoryFile.init(testing.allocator);
    defer file.deinit();

    var io_src = std.Random.IoSource{ .io = testing.io };
    const rand = io_src.interface();

    var state = FuzzState.init(testing.allocator, &file, rand);
    defer state.deinit();
    try state.create();

    const num_iterations = 500;

    for (0..num_iterations) |_| {
        const op: FuzzOp = rand.enumValue(FuzzOp);

        switch (op) {
            .write_sequential => {
                var buf: [256]u8 = undefined;
                const len = rand.intRangeAtMost(usize, 1, buf.len);
                rand.bytes(buf[0..len]);
                const offset = state.shadow.items.len;
                try state.doWrite(buf[0..len], @intCast(offset));
            },
            .write_random_offset => {
                var buf: [200]u8 = undefined;
                const len = rand.intRangeAtMost(usize, 1, buf.len);
                rand.bytes(buf[0..len]);
                const max_off = @as(u64, state.max_chunks) * state.chunk_size;
                const offset = rand.intRangeLessThan(u64, 0, max_off - len);
                try state.doWrite(buf[0..len], offset);
            },
            .write_cross_chunk => {
                if (state.shadow.items.len < state.chunk_size) {
                    var buf: [300]u8 = undefined;
                    rand.bytes(&buf);
                    try state.doWrite(&buf, 0);
                    continue;
                }
                var buf: [300]u8 = undefined;
                const len = rand.intRangeAtMost(usize, 2, buf.len);
                rand.bytes(buf[0..len]);
                const cs = @as(u64, state.chunk_size);
                const num_chunks = (state.shadow.items.len + cs - 1) / cs;
                if (num_chunks < 2) continue;
                const boundary = rand.intRangeAtMost(u64, 1, num_chunks - 1) * cs;
                const half: u64 = @intCast(len / 2);
                const offset = if (boundary > half) boundary - half else 0;
                try state.doWrite(buf[0..len], offset);
            },
            .write_gap => {
                var buf: [64]u8 = undefined;
                const len = rand.intRangeAtMost(usize, 1, buf.len);
                rand.bytes(buf[0..len]);
                const gap_start: u64 = @intCast(state.shadow.items.len);
                const gap = rand.intRangeAtMost(u64, 1, 2 * state.chunk_size);
                const offset = gap_start + gap;
                try state.doWrite(buf[0..len], offset);
            },
            .write_exact_chunk => {
                var buf: [1024]u8 = undefined;
                rand.bytes(&buf);
                const cs = @as(u64, state.chunk_size);
                const num_chunks = (state.shadow.items.len + cs - 1) / cs;
                const chunk_idx = if (num_chunks > 0)
                    rand.intRangeLessThan(u64, 0, @min(num_chunks + 1, state.max_chunks))
                else
                    0;
                try state.doWrite(&buf, chunk_idx * cs);
            },
            .write_single_byte => {
                var buf: [1]u8 = undefined;
                rand.bytes(&buf);
                const max_off = @as(u64, @intCast(state.shadow.items.len));
                const offset = if (max_off > 0) rand.intRangeLessThan(u64, 0, max_off) else 0;
                try state.doWrite(&buf, offset);
            },
            .read_and_verify => {
                try state.doRead();
                try state.verifySize();
            },
            .truncate_shrink => {
                if (state.shadow.items.len > 0) {
                    const new_size = rand.intRangeLessThan(u64, 0, @intCast(state.shadow.items.len));
                    try state.doTruncate(new_size);
                }
            },
            .truncate_grow => {
                const current = @as(u64, @intCast(state.shadow.items.len));
                const grow = rand.intRangeAtMost(u64, 1, state.chunk_size);
                try state.doTruncate(current + grow);
            },
            .truncate_zero => {
                try state.doTruncate(0);
            },
            .truncate_within_chunk => {
                if (state.shadow.items.len > 0) {
                    const cs = @as(u64, state.chunk_size);
                    const current: u64 = @intCast(state.shadow.items.len);
                    const current_chunk = (current + cs - 1) / cs;
                    if (current_chunk > 0) {
                        const chunk_start = (current_chunk - 1) * cs;
                        const new_size = chunk_start + rand.intRangeAtMost(u64, 1, cs - 1);
                        try state.doTruncate(@min(new_size, current));
                    }
                }
            },
            .overwrite_partial => {
                if (state.shadow.items.len >= 2) {
                    var buf: [100]u8 = undefined;
                    const max_len = @min(buf.len, state.shadow.items.len);
                    const len = rand.intRangeAtMost(usize, 1, max_len);
                    rand.bytes(buf[0..len]);
                    const max_off = state.shadow.items.len - len;
                    const offset = rand.intRangeLessThan(u64, 0, @intCast(max_off + 1));
                    try state.doWrite(buf[0..len], offset);
                }
            },
            .reopen_and_rebuild => {
                if (state.shadow.items.len > 0) {
                    try state.verifyMerkle();
                    try state.reopen();
                    try state.doRead();
                }
            },
            .verify_merkle => {
                try state.verifyMerkle();
            },
        }

        if (rand.intRangeLessThan(u8, 0, 4) == 0) {
            try state.verifyMerkle();
        }
    }

    try state.doRead();
    try state.verifySize();
    try state.verifyMerkle();
}

test "fuzz - rapid write-truncate cycles with merkle" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    var file = MemoryFile.init(testing.allocator);
    defer file.deinit();

    var io_src = std.Random.IoSource{ .io = testing.io };
    const rand = io_src.interface();

    var state = FuzzState.init(testing.allocator, &file, rand);
    defer state.deinit();
    try state.create();

    for (0..200) |_| {
        var buf: [512]u8 = undefined;
        const len = rand.intRangeAtMost(usize, 1, buf.len);
        rand.bytes(buf[0..len]);
        const offset = rand.intRangeLessThan(u64, 0, 4096);
        try state.doWrite(buf[0..len], offset);

        if (rand.boolean()) {
            const cur: u64 = @intCast(state.shadow.items.len);
            if (cur > 0) {
                const new_size = rand.intRangeLessThan(u64, 0, cur + 1);
                try state.doTruncate(new_size);
            }
        }

        try state.verifyMerkle();
    }

    try state.doRead();
    try state.verifySize();
}

test "fuzz - gap fill stress with merkle" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    var file = MemoryFile.init(testing.allocator);
    defer file.deinit();

    var io_src = std.Random.IoSource{ .io = testing.io };
    const rand = io_src.interface();

    var state = FuzzState.init(testing.allocator, &file, rand);
    defer state.deinit();
    try state.create();

    for (0..100) |i| {
        const gap: u64 = rand.intRangeAtMost(u64, 0, 3 * state.chunk_size);
        const offset: u64 = @as(u64, @intCast(state.shadow.items.len)) + gap;
        const end = offset + 64;
        const max = @as(u64, state.max_chunks) * state.chunk_size;
        if (end > max) continue;

        var buf: [64]u8 = undefined;
        @memset(&buf, @as(u8, @truncate(i)));
        try state.doWrite(&buf, offset);
        try state.verifyMerkle();
    }

    try state.reopen();
    try state.verifyMerkle();
    try state.doRead();
}

test "fuzz - incremental vs rebuild consistency" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    var file = MemoryFile.init(testing.allocator);
    defer file.deinit();

    var io_src = std.Random.IoSource{ .io = testing.io };
    const rand = io_src.interface();

    var state = FuzzState.init(testing.allocator, &file, rand);
    defer state.deinit();
    try state.create();

    for (0..50) |_| {
        var buf: [300]u8 = undefined;
        const len = rand.intRangeAtMost(usize, 1, buf.len);
        rand.bytes(buf[0..len]);
        const max_off = @as(u64, state.max_chunks) * state.chunk_size;
        if (max_off <= len) continue;
        const offset = rand.intRangeLessThan(u64, 0, max_off - len);
        try state.doWrite(buf[0..len], offset);
    }

    try state.verifyMerkle();

    var incremental_root: [MERKLE_HASH_LEN]u8 = undefined;
    try testing.expectEqual(aegis.aegis128l_raf_merkle_commitment(&state.ctx, &incremental_root, MERKLE_HASH_LEN), 0);

    try state.reopen();

    var rebuilt_root: [MERKLE_HASH_LEN]u8 = undefined;
    try testing.expectEqual(aegis.aegis128l_raf_merkle_commitment(&state.ctx, &rebuilt_root, MERKLE_HASH_LEN), 0);
    try testing.expectEqualSlices(u8, &incremental_root, &rebuilt_root);
    try state.verifyMerkle();
}

test "fuzz - write-read data integrity across reopens" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    var file = MemoryFile.init(testing.allocator);
    defer file.deinit();

    var io_src = std.Random.IoSource{ .io = testing.io };
    const rand = io_src.interface();

    var state = FuzzState.init(testing.allocator, &file, rand);
    defer state.deinit();
    try state.create();

    for (0..30) |_| {
        var buf: [500]u8 = undefined;
        const len = rand.intRangeAtMost(usize, 1, buf.len);
        rand.bytes(buf[0..len]);

        const max_off = @as(u64, state.max_chunks) * state.chunk_size;
        if (max_off <= len) continue;
        const offset = rand.intRangeLessThan(u64, 0, max_off - len);
        try state.doWrite(buf[0..len], offset);
        try state.doRead();

        if (rand.intRangeLessThan(u8, 0, 3) == 0) {
            try state.reopen();
            try state.doRead();
        }
    }

    try state.reopen();
    try state.doRead();
    try state.verifySize();
    try state.verifyMerkle();
}

test "fuzz - truncate to every interesting boundary" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    var file = MemoryFile.init(testing.allocator);
    defer file.deinit();

    var io_src = std.Random.IoSource{ .io = testing.io };
    const rand = io_src.interface();

    var state = FuzzState.init(testing.allocator, &file, rand);
    defer state.deinit();
    try state.create();

    var buf: [5120]u8 = undefined;
    rand.bytes(&buf);
    try state.doWrite(&buf, 0);
    try state.verifyMerkle();

    const cs: u64 = state.chunk_size;
    const boundaries = [_]u64{
        0,
        1,
        cs / 2,
        cs - 1,
        cs,
        cs + 1,
        cs * 2 - 1,
        cs * 2,
        cs * 2 + 1,
        cs * 3,
        cs * 4,
        cs * 5 - 1,
        cs * 5,
    };

    for (boundaries) |target| {
        if (target > state.shadow.items.len) {
            try state.doTruncate(target);
        }

        rand.bytes(&buf);
        const write_len = @min(buf.len, @as(u64, state.max_chunks) * cs - target);
        if (write_len > 0) {
            try state.doWrite(buf[0..@intCast(write_len)], target);
        }

        try state.verifyMerkle();

        try state.doTruncate(target);
        try state.verifyMerkle();

        try state.doRead();
        try state.verifySize();
    }
}

test "fuzz - max_chunks boundary enforcement" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    var file = MemoryFile.init(testing.allocator);
    defer file.deinit();

    var io_src = std.Random.IoSource{ .io = testing.io };
    const rand = io_src.interface();

    var state = FuzzState.init(testing.allocator, &file, rand);
    state.max_chunks = 4;
    defer state.deinit();
    try state.create();

    const cs = @as(u64, state.chunk_size);
    const max_bytes = state.max_chunks * cs;

    var wbuf: [1024]u8 = undefined;
    rand.bytes(&wbuf);
    try state.doWrite(&wbuf, 0);
    try state.doWrite(&wbuf, cs);
    try state.doWrite(&wbuf, cs * 2);
    try state.doWrite(&wbuf, cs * 3);

    try state.verifyMerkle();

    var overflow_buf: [1]u8 = .{0xFF};
    var bytes_written: usize = undefined;
    const ret = aegis.aegis128l_raf_write(&state.ctx, &bytes_written, &overflow_buf, 1, max_bytes);
    try testing.expect(ret != 0);
    try testing.expectEqual(std.c._errno().*, @intFromEnum(std.c.E.OVERFLOW));

    try state.verifyMerkle();
    try state.doRead();
}

test "fuzz - odd max_chunks tree shapes" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    const odd_counts = [_]u64{ 1, 3, 5, 7, 9, 11, 13, 15 };

    for (odd_counts) |max_chunks| {
        var file = MemoryFile.init(testing.allocator);
        defer file.deinit();

        var io_src = std.Random.IoSource{ .io = testing.io };
        const rand = io_src.interface();

        var state = FuzzState.init(testing.allocator, &file, rand);
        state.max_chunks = max_chunks;
        defer state.deinit();
        try state.create();

        for (0..20) |_| {
            var buf: [100]u8 = undefined;
            rand.bytes(&buf);
            const max_off = max_chunks * state.chunk_size;
            if (max_off <= buf.len) continue;
            const offset = rand.intRangeLessThan(u64, 0, max_off - buf.len);
            try state.doWrite(&buf, offset);
        }

        try state.verifyMerkle();
        try state.reopen();
        try state.verifyMerkle();
        try state.doRead();
    }
}

test "fuzz - different hash lengths" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    const hash_lens = [_]u32{
        aegis.AEGIS_RAF_MERKLE_HASH_MIN,
        12,
        16,
        24,
        32,
        48,
        aegis.AEGIS_RAF_MERKLE_HASH_MAX,
    };

    for (hash_lens) |hash_len| {
        var file = MemoryFile.init(testing.allocator);
        defer file.deinit();

        var merkle_buf: [4096]u8 = undefined;
        @memset(&merkle_buf, 0);

        var merkle_cfg = aegis.aegis_raf_merkle_config{
            .buf = &merkle_buf,
            .len = merkle_buf.len,
            .hash_len = hash_len,
            .max_chunks = 8,
            .user = null,
            .hash_leaf = variableHashLeaf,
            .hash_parent = variableHashParent,
            .hash_empty = variableHashEmpty,
            .hash_commitment = variableHashCommitment,
        };

        const merkle_size = aegis.aegis_raf_merkle_buffer_size(&merkle_cfg);
        try testing.expect(merkle_size <= merkle_buf.len);

        var key: [aegis.aegis128l_KEYBYTES]u8 = undefined;
        random.bytes(&key);

        var scratch_buf: [aegis.AEGIS128L_RAF_SCRATCH_SIZE(1024)]u8 align(aegis.AEGIS_RAF_SCRATCH_ALIGN) = undefined;
        const scratch = aegis.aegis_raf_scratch{
            .buf = &scratch_buf,
            .len = scratch_buf.len,
        };

        const cfg = aegis.aegis_raf_config{
            .chunk_size = 1024,
            .flags = aegis.AEGIS_RAF_CREATE,
            .scratch = &scratch,
            .merkle = &merkle_cfg,
        };

        var ctx: aegis.aegis128l_raf_ctx align(32) = undefined;
        var ret = aegis.aegis128l_raf_create(&ctx, &file.io(), &rng(), &cfg, &key);
        try testing.expectEqual(ret, 0);

        var data: [3000]u8 = undefined;
        random.bytes(&data);
        var bytes_written: usize = undefined;
        ret = aegis.aegis128l_raf_write(&ctx, &bytes_written, &data, data.len, 0);
        try testing.expectEqual(ret, 0);

        ret = aegis.aegis128l_raf_merkle_verify(&ctx, null);
        try testing.expectEqual(ret, 0);

        var root_copy: [aegis.AEGIS_RAF_MERKLE_HASH_MAX]u8 = undefined;
        try testing.expectEqual(aegis.aegis128l_raf_merkle_commitment(&ctx, &root_copy, hash_len), 0);

        aegis.aegis128l_raf_close(&ctx);

        @memset(&merkle_buf, 0);
        var merkle_cfg2 = aegis.aegis_raf_merkle_config{
            .buf = &merkle_buf,
            .len = merkle_buf.len,
            .hash_len = hash_len,
            .max_chunks = 8,
            .user = null,
            .hash_leaf = variableHashLeaf,
            .hash_parent = variableHashParent,
            .hash_empty = variableHashEmpty,
            .hash_commitment = variableHashCommitment,
        };

        const cfg2 = aegis.aegis_raf_config{
            .chunk_size = 0,
            .flags = 0,
            .scratch = &scratch,
            .merkle = &merkle_cfg2,
        };

        ret = aegis.aegis128l_raf_open(&ctx, &file.io(), &rng(), &cfg2, &key);
        try testing.expectEqual(ret, 0);

        ret = aegis.aegis128l_raf_merkle_rebuild(&ctx);
        try testing.expectEqual(ret, 0);

        var rebuilt_root: [aegis.AEGIS_RAF_MERKLE_HASH_MAX]u8 = undefined;
        try testing.expectEqual(aegis.aegis128l_raf_merkle_commitment(&ctx, &rebuilt_root, hash_len), 0);
        try testing.expectEqualSlices(u8, root_copy[0..hash_len], rebuilt_root[0..hash_len]);

        ret = aegis.aegis128l_raf_merkle_verify(&ctx, null);
        try testing.expectEqual(ret, 0);

        aegis.aegis128l_raf_close(&ctx);
    }
}

test "fuzz - RAF without merkle random operations" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    var file = MemoryFile.init(testing.allocator);
    defer file.deinit();

    var io_src = std.Random.IoSource{ .io = testing.io };
    const rand = io_src.interface();

    var key: [aegis.aegis128l_KEYBYTES]u8 = undefined;
    rand.bytes(&key);

    var shadow: std.ArrayListUnmanaged(u8) = .{};
    defer shadow.deinit(testing.allocator);

    var scratch_buf: [aegis.AEGIS128L_RAF_SCRATCH_SIZE(1024)]u8 align(aegis.AEGIS_RAF_SCRATCH_ALIGN) = undefined;
    const scratch = aegis.aegis_raf_scratch{
        .buf = &scratch_buf,
        .len = scratch_buf.len,
    };

    const cfg = aegis.aegis_raf_config{
        .chunk_size = 1024,
        .flags = aegis.AEGIS_RAF_CREATE,
        .scratch = &scratch,
        .merkle = null,
    };

    var ctx: aegis.aegis128l_raf_ctx align(32) = undefined;
    var ret = aegis.aegis128l_raf_create(&ctx, &file.io(), &rng(), &cfg, &key);
    try testing.expectEqual(ret, 0);

    const chunk_size: u64 = 1024;
    const max_file: u64 = 16 * chunk_size;

    for (0..300) |_| {
        const action = rand.intRangeLessThan(u8, 0, 5);

        switch (action) {
            0, 1 => {
                var buf: [400]u8 = undefined;
                const len = rand.intRangeAtMost(usize, 1, buf.len);
                rand.bytes(buf[0..len]);
                const offset = rand.intRangeLessThan(u64, 0, max_file - len);
                const end = offset + len;

                var bytes_written: usize = undefined;
                ret = aegis.aegis128l_raf_write(&ctx, &bytes_written, buf[0..len].ptr, len, offset);
                try testing.expectEqual(ret, 0);

                const end_usize = @as(usize, @intCast(end));
                const off_usize = @as(usize, @intCast(offset));
                if (end_usize > shadow.items.len) {
                    const old_len = shadow.items.len;
                    shadow.resize(testing.allocator, end_usize) catch unreachable;
                    if (old_len < off_usize) {
                        @memset(shadow.items[old_len..off_usize], 0);
                    }
                }
                @memcpy(shadow.items[off_usize..end_usize], buf[0..len]);
            },
            2 => {
                if (shadow.items.len > 0) {
                    var read_buf: [8192]u8 = undefined;
                    const len = @min(shadow.items.len, read_buf.len);
                    var bytes_read: usize = undefined;
                    ret = aegis.aegis128l_raf_read(&ctx, &read_buf, &bytes_read, len, 0);
                    try testing.expectEqual(ret, 0);
                    try testing.expectEqualSlices(u8, shadow.items[0..len], read_buf[0..len]);
                }
            },
            3 => {
                if (shadow.items.len > 0) {
                    const new_size = rand.intRangeLessThan(u64, 0, @intCast(shadow.items.len));
                    ret = aegis.aegis128l_raf_truncate(&ctx, new_size);
                    try testing.expectEqual(ret, 0);
                    shadow.shrinkRetainingCapacity(@intCast(new_size));
                }
            },
            4 => {
                if (shadow.items.len > 0) {
                    aegis.aegis128l_raf_close(&ctx);

                    const cfg2 = aegis.aegis_raf_config{
                        .chunk_size = 0,
                        .flags = 0,
                        .scratch = &scratch,
                        .merkle = null,
                    };

                    ret = aegis.aegis128l_raf_open(&ctx, &file.io(), &rng(), &cfg2, &key);
                    try testing.expectEqual(ret, 0);

                    var read_buf: [8192]u8 = undefined;
                    const len = @min(shadow.items.len, read_buf.len);
                    var bytes_read: usize = undefined;
                    ret = aegis.aegis128l_raf_read(&ctx, &read_buf, &bytes_read, len, 0);
                    try testing.expectEqual(ret, 0);
                    try testing.expectEqualSlices(u8, shadow.items[0..len], read_buf[0..len]);
                }
            },
            else => {},
        }
    }

    aegis.aegis128l_raf_close(&ctx);
}

test "fuzz - cross-chunk write patterns" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    var file = MemoryFile.init(testing.allocator);
    defer file.deinit();

    var io_src = std.Random.IoSource{ .io = testing.io };
    const rand = io_src.interface();

    var state = FuzzState.init(testing.allocator, &file, rand);
    defer state.deinit();
    try state.create();

    const cs = @as(u64, state.chunk_size);

    for (0..50) |i| {
        const offset = cs * @as(u64, @intCast(i % 8));
        var buf: [200]u8 = undefined;
        const len = rand.intRangeAtMost(usize, 1, buf.len);
        rand.bytes(buf[0..len]);

        const boundary = (offset / cs + 1) * cs;
        const write_offset = if (boundary > len / 2) boundary - len / 2 else 0;
        if (write_offset + len > state.max_chunks * cs) continue;

        try state.doWrite(buf[0..len], write_offset);
        try state.verifyMerkle();
    }

    try state.reopen();
    try state.verifyMerkle();
    try state.doRead();
}

test "fuzz - aegis256 random operations with merkle" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    var file = MemoryFile.init(testing.allocator);
    defer file.deinit();

    var io_src = std.Random.IoSource{ .io = testing.io };
    const rand = io_src.interface();

    var key: [aegis.aegis256_KEYBYTES]u8 = undefined;
    rand.bytes(&key);

    var shadow: std.ArrayListUnmanaged(u8) = .{};
    defer shadow.deinit(testing.allocator);

    const max_chunks: u64 = 16;
    const chunk_size: u32 = 1024;
    var merkle_buf: [4096]u8 = undefined;
    @memset(&merkle_buf, 0);

    var merkle_cfg = aegis.aegis_raf_merkle_config{
        .buf = &merkle_buf,
        .len = merkle_buf.len,
        .hash_len = MERKLE_HASH_LEN,
        .max_chunks = max_chunks,
        .user = null,
        .hash_leaf = xorHashLeaf,
        .hash_parent = xorHashParent,
        .hash_empty = xorHashEmpty,
        .hash_commitment = xorHashCommitment,
    };

    var scratch_buf: [aegis.AEGIS256_RAF_SCRATCH_SIZE(1024)]u8 align(aegis.AEGIS_RAF_SCRATCH_ALIGN) = undefined;
    const scratch = aegis.aegis_raf_scratch{
        .buf = &scratch_buf,
        .len = scratch_buf.len,
    };

    const cfg = aegis.aegis_raf_config{
        .chunk_size = chunk_size,
        .flags = aegis.AEGIS_RAF_CREATE,
        .scratch = &scratch,
        .merkle = &merkle_cfg,
    };

    var ctx: aegis.aegis256_raf_ctx align(32) = undefined;
    var ret = aegis.aegis256_raf_create(&ctx, &file.io(), &rng(), &cfg, &key);
    try testing.expectEqual(ret, 0);

    const max_bytes = max_chunks * chunk_size;

    for (0..200) |_| {
        const action = rand.intRangeLessThan(u8, 0, 4);

        switch (action) {
            0, 1 => {
                var buf: [300]u8 = undefined;
                const len = rand.intRangeAtMost(usize, 1, buf.len);
                rand.bytes(buf[0..len]);
                if (max_bytes <= len) continue;
                const offset = rand.intRangeLessThan(u64, 0, max_bytes - len);
                const end = offset + len;

                var bytes_written: usize = undefined;
                ret = aegis.aegis256_raf_write(&ctx, &bytes_written, buf[0..len].ptr, len, offset);
                try testing.expectEqual(ret, 0);

                const end_usize = @as(usize, @intCast(end));
                const off_usize = @as(usize, @intCast(offset));
                if (end_usize > shadow.items.len) {
                    const old_len = shadow.items.len;
                    shadow.resize(testing.allocator, end_usize) catch unreachable;
                    if (old_len < off_usize) {
                        @memset(shadow.items[old_len..off_usize], 0);
                    }
                }
                @memcpy(shadow.items[off_usize..end_usize], buf[0..len]);
            },
            2 => {
                if (shadow.items.len > 0) {
                    const new_size = rand.intRangeLessThan(u64, 0, @intCast(shadow.items.len + 1));
                    ret = aegis.aegis256_raf_truncate(&ctx, new_size);
                    try testing.expectEqual(ret, 0);
                    shadow.shrinkRetainingCapacity(@intCast(new_size));
                }
            },
            3 => {
                if (shadow.items.len > 0) {
                    var read_buf: [8192]u8 = undefined;
                    const len = @min(shadow.items.len, read_buf.len);
                    var bytes_read: usize = undefined;
                    ret = aegis.aegis256_raf_read(&ctx, &read_buf, &bytes_read, len, 0);
                    try testing.expectEqual(ret, 0);
                    try testing.expectEqualSlices(u8, shadow.items[0..len], read_buf[0..len]);
                }
            },
            else => {},
        }

        if (rand.intRangeLessThan(u8, 0, 5) == 0) {
            ret = aegis.aegis256_raf_merkle_verify(&ctx, null);
            try testing.expectEqual(ret, 0);
        }
    }

    ret = aegis.aegis256_raf_merkle_verify(&ctx, null);
    try testing.expectEqual(ret, 0);

    aegis.aegis256_raf_close(&ctx);
}

test "fuzz - write then corrupt then detect" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    var io_src = std.Random.IoSource{ .io = testing.io };
    const rand = io_src.interface();

    for (0..20) |_| {
        var file = MemoryFile.init(testing.allocator);
        defer file.deinit();

        var key: [aegis.aegis128l_KEYBYTES]u8 = undefined;
        rand.bytes(&key);

        const max_chunks: u64 = 8;
        var merkle_buf: [4096]u8 = undefined;
        @memset(&merkle_buf, 0);

        const merkle_cfg = aegis.aegis_raf_merkle_config{
            .buf = &merkle_buf,
            .len = merkle_buf.len,
            .hash_len = MERKLE_HASH_LEN,
            .max_chunks = max_chunks,
            .user = null,
            .hash_leaf = xorHashLeaf,
            .hash_parent = xorHashParent,
            .hash_empty = xorHashEmpty,
            .hash_commitment = xorHashCommitment,
        };

        var scratch_buf: [aegis.AEGIS128L_RAF_SCRATCH_SIZE(1024)]u8 align(aegis.AEGIS_RAF_SCRATCH_ALIGN) = undefined;
        const scratch = aegis.aegis_raf_scratch{
            .buf = &scratch_buf,
            .len = scratch_buf.len,
        };

        const cfg = aegis.aegis_raf_config{
            .chunk_size = 1024,
            .flags = aegis.AEGIS_RAF_CREATE,
            .scratch = &scratch,
            .merkle = &merkle_cfg,
        };

        var ctx: aegis.aegis128l_raf_ctx align(32) = undefined;
        var ret = aegis.aegis128l_raf_create(&ctx, &file.io(), &rng(), &cfg, &key);
        try testing.expectEqual(ret, 0);

        const num_chunks = rand.intRangeAtMost(u64, 1, max_chunks);
        const data_len = @as(usize, @intCast(num_chunks)) * 1024;
        const data = try testing.allocator.alloc(u8, data_len);
        defer testing.allocator.free(data);
        rand.bytes(data);

        var bytes_written: usize = undefined;
        ret = aegis.aegis128l_raf_write(&ctx, &bytes_written, data.ptr, data.len, 0);
        try testing.expectEqual(ret, 0);

        ret = aegis.aegis128l_raf_merkle_verify(&ctx, null);
        try testing.expectEqual(ret, 0);

        const corrupt_chunk = rand.intRangeLessThan(u64, 0, num_chunks);
        const leaf_offset = @as(usize, @intCast(corrupt_chunk)) * MERKLE_HASH_LEN;
        merkle_buf[leaf_offset] ^= 0xFF;

        var corrupted_chunk: u64 = undefined;
        ret = aegis.aegis128l_raf_merkle_verify(&ctx, &corrupted_chunk);
        try testing.expect(ret != 0);
        try testing.expectEqual(corrupted_chunk, corrupt_chunk);

        merkle_buf[leaf_offset] ^= 0xFF;

        ret = aegis.aegis128l_raf_merkle_verify(&ctx, null);
        try testing.expectEqual(ret, 0);

        aegis.aegis128l_raf_close(&ctx);
    }
}

test "aegis128l_raf_merkle_commitment - returns 0 with merkle enabled" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    var file = MemoryFile.init(testing.allocator);
    defer file.deinit();

    var key: [aegis.aegis128l_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    var scratch_buf: [aegis.AEGIS128L_RAF_SCRATCH_SIZE(1024)]u8 align(aegis.AEGIS_RAF_SCRATCH_ALIGN) = undefined;
    const scratch = aegis.aegis_raf_scratch{ .buf = &scratch_buf, .len = scratch_buf.len };

    var merkle_buf: [4096]u8 = undefined;
    @memset(&merkle_buf, 0);

    const merkle_cfg = aegis.aegis_raf_merkle_config{
        .buf = &merkle_buf,
        .len = merkle_buf.len,
        .hash_len = MERKLE_HASH_LEN,
        .max_chunks = 16,
        .user = null,
        .hash_leaf = xorHashLeaf,
        .hash_parent = xorHashParent,
        .hash_empty = xorHashEmpty,
        .hash_commitment = xorHashCommitment,
    };

    const cfg = aegis.aegis_raf_config{
        .chunk_size = 1024,
        .flags = aegis.AEGIS_RAF_CREATE,
        .scratch = &scratch,
        .merkle = &merkle_cfg,
    };

    var ctx: aegis.aegis128l_raf_ctx align(32) = undefined;
    var ret = aegis.aegis128l_raf_create(&ctx, &file.io(), &rng(), &cfg, &key);
    try testing.expectEqual(ret, 0);

    const test_data = "Hello commitment";
    var bytes_written: usize = undefined;
    ret = aegis.aegis128l_raf_write(&ctx, &bytes_written, test_data.ptr, test_data.len, 0);
    try testing.expectEqual(ret, 0);

    var commitment: [MERKLE_HASH_LEN]u8 = undefined;
    ret = aegis.aegis128l_raf_merkle_commitment(&ctx, &commitment, MERKLE_HASH_LEN);
    try testing.expectEqual(ret, 0);

    aegis.aegis128l_raf_close(&ctx);
}

test "aegis128l_raf_merkle_commitment - returns ENOTSUP without merkle" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    var file = MemoryFile.init(testing.allocator);
    defer file.deinit();

    var key: [aegis.aegis128l_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    var scratch_buf: [aegis.AEGIS128L_RAF_SCRATCH_SIZE(1024)]u8 align(aegis.AEGIS_RAF_SCRATCH_ALIGN) = undefined;
    const scratch = aegis.aegis_raf_scratch{ .buf = &scratch_buf, .len = scratch_buf.len };

    const cfg = aegis.aegis_raf_config{
        .chunk_size = 1024,
        .flags = aegis.AEGIS_RAF_CREATE,
        .scratch = &scratch,
        .merkle = null,
    };

    var ctx: aegis.aegis128l_raf_ctx align(32) = undefined;
    var ret = aegis.aegis128l_raf_create(&ctx, &file.io(), &rng(), &cfg, &key);
    try testing.expectEqual(ret, 0);

    var commitment: [MERKLE_HASH_LEN]u8 = undefined;
    ret = aegis.aegis128l_raf_merkle_commitment(&ctx, &commitment, MERKLE_HASH_LEN);
    try testing.expectEqual(ret, -1);

    aegis.aegis128l_raf_close(&ctx);
}

test "aegis128l_raf_merkle_commitment - bound to file identity" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    var file1 = MemoryFile.init(testing.allocator);
    defer file1.deinit();
    var file2 = MemoryFile.init(testing.allocator);
    defer file2.deinit();

    var key: [aegis.aegis128l_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    const max_chunks: u64 = 8;
    var merkle_buf1: [256]u8 = undefined;
    var merkle_buf2: [256]u8 = undefined;
    @memset(&merkle_buf1, 0);
    @memset(&merkle_buf2, 0);

    const merkle_cfg1 = aegis.aegis_raf_merkle_config{
        .buf = &merkle_buf1,
        .len = merkle_buf1.len,
        .hash_len = MERKLE_HASH_LEN,
        .max_chunks = max_chunks,
        .user = null,
        .hash_leaf = xorHashLeaf,
        .hash_parent = xorHashParent,
        .hash_empty = xorHashEmpty,
        .hash_commitment = xorHashCommitment,
    };

    const merkle_cfg2 = aegis.aegis_raf_merkle_config{
        .buf = &merkle_buf2,
        .len = merkle_buf2.len,
        .hash_len = MERKLE_HASH_LEN,
        .max_chunks = max_chunks,
        .user = null,
        .hash_leaf = xorHashLeaf,
        .hash_parent = xorHashParent,
        .hash_empty = xorHashEmpty,
        .hash_commitment = xorHashCommitment,
    };

    var scratch_buf: [aegis.AEGIS128L_RAF_SCRATCH_SIZE(1024)]u8 align(aegis.AEGIS_RAF_SCRATCH_ALIGN) = undefined;
    const scratch = aegis.aegis_raf_scratch{
        .buf = &scratch_buf,
        .len = scratch_buf.len,
    };

    const cfg1 = aegis.aegis_raf_config{
        .chunk_size = 1024,
        .flags = aegis.AEGIS_RAF_CREATE,
        .scratch = &scratch,
        .merkle = &merkle_cfg1,
    };

    const cfg2 = aegis.aegis_raf_config{
        .chunk_size = 1024,
        .flags = aegis.AEGIS_RAF_CREATE,
        .scratch = &scratch,
        .merkle = &merkle_cfg2,
    };

    var ctx1: aegis.aegis128l_raf_ctx align(32) = undefined;
    var ctx2: aegis.aegis128l_raf_ctx align(32) = undefined;

    var ret = aegis.aegis128l_raf_create(&ctx1, &file1.io(), &rng(), &cfg1, &key);
    try testing.expectEqual(ret, 0);
    ret = aegis.aegis128l_raf_create(&ctx2, &file2.io(), &rng(), &cfg2, &key);
    try testing.expectEqual(ret, 0);

    const test_data = "Identical data for both files";
    var bytes_written: usize = undefined;
    ret = aegis.aegis128l_raf_write(&ctx1, &bytes_written, test_data.ptr, test_data.len, 0);
    try testing.expectEqual(ret, 0);
    ret = aegis.aegis128l_raf_write(&ctx2, &bytes_written, test_data.ptr, test_data.len, 0);
    try testing.expectEqual(ret, 0);

    var root1: [MERKLE_HASH_LEN]u8 = undefined;
    var root2: [MERKLE_HASH_LEN]u8 = undefined;
    try testing.expectEqual(aegis.aegis128l_raf_merkle_commitment(&ctx1, &root1, MERKLE_HASH_LEN), 0);
    try testing.expectEqual(aegis.aegis128l_raf_merkle_commitment(&ctx2, &root2, MERKLE_HASH_LEN), 0);

    // Different files have different file_ids, so commitments must differ
    // even when data, key, and chunk_size are identical.
    try testing.expect(!std.mem.eql(u8, &root1, &root2));

    aegis.aegis128l_raf_close(&ctx1);
    aegis.aegis128l_raf_close(&ctx2);
}

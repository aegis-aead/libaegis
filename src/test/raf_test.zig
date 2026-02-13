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
    file_size: u64,
) callconv(.c) c_int {
    _ = out_len;
    _ = file_size;
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
    };

    try testing.expectEqual(aegis.aegis_raf_merkle_buffer_size(&cfg), 0);

    cfg.max_chunks = 1;
    try testing.expectEqual(aegis.aegis_raf_merkle_buffer_size(&cfg), 16);

    cfg.max_chunks = 2;
    try testing.expectEqual(aegis.aegis_raf_merkle_buffer_size(&cfg), 48);

    cfg.max_chunks = 4;
    try testing.expectEqual(aegis.aegis_raf_merkle_buffer_size(&cfg), 112);
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

    const root0 = aegis.aegis_raf_merkle_root(&merkle_cfg);
    // Root pointer should be valid

    var root_before: [MERKLE_HASH_LEN]u8 = undefined;
    @memcpy(&root_before, root0[0..MERKLE_HASH_LEN]);

    const test_data = "Hello, Merkle!";
    var bytes_written: usize = undefined;
    ret = aegis.aegis128l_raf_write(&ctx, &bytes_written, test_data.ptr, test_data.len, 0);
    try testing.expectEqual(ret, 0);

    const root1 = aegis.aegis_raf_merkle_root(&merkle_cfg);
    // Root pointer should be valid

    try testing.expect(!std.mem.eql(u8, &root_before, root1[0..MERKLE_HASH_LEN]));

    var root_after_write: [MERKLE_HASH_LEN]u8 = undefined;
    @memcpy(&root_after_write, root1[0..MERKLE_HASH_LEN]);

    const more_data = "More data here";
    ret = aegis.aegis128l_raf_write(&ctx, &bytes_written, more_data.ptr, more_data.len, 2048);
    try testing.expectEqual(ret, 0);

    const root2 = aegis.aegis_raf_merkle_root(&merkle_cfg);
    try testing.expect(!std.mem.eql(u8, &root_after_write, root2[0..MERKLE_HASH_LEN]));

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
    const root_ptr = aegis.aegis_raf_merkle_root(&merkle_cfg1);
    @memcpy(&incremental_root, root_ptr[0..MERKLE_HASH_LEN]);

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
    const root_ptr2 = aegis.aegis_raf_merkle_root(&merkle_cfg2);
    @memcpy(&rebuilt_root, root_ptr2[0..MERKLE_HASH_LEN]);

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
    const root1 = aegis.aegis_raf_merkle_root(&merkle_cfg);
    @memcpy(&root_before_truncate, root1[0..MERKLE_HASH_LEN]);

    ret = aegis.aegis128l_raf_truncate(&ctx, 500);
    try testing.expectEqual(ret, 0);

    var root_after_truncate: [MERKLE_HASH_LEN]u8 = undefined;
    const root2 = aegis.aegis_raf_merkle_root(&merkle_cfg);
    @memcpy(&root_after_truncate, root2[0..MERKLE_HASH_LEN]);

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
    const root1 = aegis.aegis_raf_merkle_root(&merkle_cfg);
    @memcpy(&root_before_truncate, root1[0..MERKLE_HASH_LEN]);

    ret = aegis.aegis128l_raf_truncate(&ctx, 1200);
    try testing.expectEqual(ret, 0);

    var root_after_truncate: [MERKLE_HASH_LEN]u8 = undefined;
    const root2 = aegis.aegis_raf_merkle_root(&merkle_cfg);
    @memcpy(&root_after_truncate, root2[0..MERKLE_HASH_LEN]);

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
    const root1 = aegis.aegis_raf_merkle_root(&merkle_cfg);
    @memcpy(&root_before, root1[0..MERKLE_HASH_LEN]);

    var patch: [11]u8 = undefined;
    @memset(&patch, 0xFF);
    ret = aegis.aegis128l_raf_write(&ctx, &bytes_written, &patch, patch.len, 100);
    try testing.expectEqual(ret, 0);

    var root_after: [MERKLE_HASH_LEN]u8 = undefined;
    const root2 = aegis.aegis_raf_merkle_root(&merkle_cfg);
    @memcpy(&root_after, root2[0..MERKLE_HASH_LEN]);

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

    const root = aegis.aegis_raf_merkle_root(&merkle_cfg);
    try testing.expect(root != null);

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

    const empty_root = aegis.aegis_raf_merkle_root(&merkle_cfg);
    try testing.expect(empty_root != null);

    var empty_root_copy: [MERKLE_HASH_LEN]u8 = undefined;
    @memcpy(&empty_root_copy, empty_root[0..MERKLE_HASH_LEN]);

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

test "aegis128l_raf_merkle - determinism same data same root" {
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

    const test_data = "Identical data for both files to test determinism";
    var bytes_written: usize = undefined;
    ret = aegis.aegis128l_raf_write(&ctx1, &bytes_written, test_data.ptr, test_data.len, 0);
    try testing.expectEqual(ret, 0);
    ret = aegis.aegis128l_raf_write(&ctx2, &bytes_written, test_data.ptr, test_data.len, 0);
    try testing.expectEqual(ret, 0);

    const root1 = aegis.aegis_raf_merkle_root(&merkle_cfg1);
    const root2 = aegis.aegis_raf_merkle_root(&merkle_cfg2);
    try testing.expectEqualSlices(u8, root1[0..MERKLE_HASH_LEN], root2[0..MERKLE_HASH_LEN]);

    aegis.aegis128l_raf_close(&ctx1);
    aegis.aegis128l_raf_close(&ctx2);
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

    const root1 = aegis.aegis_raf_merkle_root(&merkle_cfg);
    var root1_copy: [MERKLE_HASH_LEN]u8 = undefined;
    @memcpy(&root1_copy, root1[0..MERKLE_HASH_LEN]);

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

    const root2 = aegis.aegis_raf_merkle_root(&merkle_cfg2);
    try testing.expectEqualSlices(u8, &root1_copy, root2[0..MERKLE_HASH_LEN]);

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
    const r1 = aegis.aegis_raf_merkle_root(&merkle_cfg);
    @memcpy(&root_after_chunk0, r1[0..MERKLE_HASH_LEN]);

    @memset(&chunk_data, 0x22);
    ret = aegis.aegis128l_raf_write(&ctx, &bytes_written, &chunk_data, chunk_data.len, 1024);
    try testing.expectEqual(ret, 0);

    var root_after_chunk1: [MERKLE_HASH_LEN]u8 = undefined;
    const r2 = aegis.aegis_raf_merkle_root(&merkle_cfg);
    @memcpy(&root_after_chunk1, r2[0..MERKLE_HASH_LEN]);

    try testing.expect(!std.mem.eql(u8, &root_after_chunk0, &root_after_chunk1));

    @memset(&chunk_data, 0x33);
    ret = aegis.aegis128l_raf_write(&ctx, &bytes_written, &chunk_data, chunk_data.len, 1536);
    try testing.expectEqual(ret, 0);

    var root_after_spanning: [MERKLE_HASH_LEN]u8 = undefined;
    const r3 = aegis.aegis_raf_merkle_root(&merkle_cfg);
    @memcpy(&root_after_spanning, r3[0..MERKLE_HASH_LEN]);

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
    const r0 = aegis.aegis_raf_merkle_root(&merkle_cfg);
    @memcpy(&empty_root, r0[0..MERKLE_HASH_LEN]);

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
    const root1 = aegis.aegis_raf_merkle_root(&merkle_cfg1);
    @memcpy(&incremental_root, root1[0..MERKLE_HASH_LEN]);

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
    const root2 = aegis.aegis_raf_merkle_root(&merkle_cfg2);
    @memcpy(&rebuilt_root, root2[0..MERKLE_HASH_LEN]);

    try testing.expectEqualSlices(u8, &incremental_root, &rebuilt_root);

    aegis.aegis128l_raf_close(&ctx);
}

test "aegis128l_raf_merkle - incremental writes same as bulk" {
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

    var test_data: [3000]u8 = undefined;
    for (&test_data, 0..) |*b, i| {
        b.* = @truncate(i *% 7);
    }

    var bytes_written: usize = undefined;
    ret = aegis.aegis128l_raf_write(&ctx1, &bytes_written, &test_data, test_data.len, 0);
    try testing.expectEqual(ret, 0);

    ret = aegis.aegis128l_raf_write(&ctx2, &bytes_written, test_data[0..1000].ptr, 1000, 0);
    try testing.expectEqual(ret, 0);
    ret = aegis.aegis128l_raf_write(&ctx2, &bytes_written, test_data[1000..2000].ptr, 1000, 1000);
    try testing.expectEqual(ret, 0);
    ret = aegis.aegis128l_raf_write(&ctx2, &bytes_written, test_data[2000..3000].ptr, 1000, 2000);
    try testing.expectEqual(ret, 0);

    const root1 = aegis.aegis_raf_merkle_root(&merkle_cfg1);
    const root2 = aegis.aegis_raf_merkle_root(&merkle_cfg2);
    try testing.expectEqualSlices(u8, root1[0..MERKLE_HASH_LEN], root2[0..MERKLE_HASH_LEN]);

    aegis.aegis128l_raf_close(&ctx1);
    aegis.aegis128l_raf_close(&ctx2);
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
    const r1 = aegis.aegis_raf_merkle_root(&merkle_cfg);
    @memcpy(&root1, r1[0..MERKLE_HASH_LEN]);

    ret = aegis.aegis128l_raf_truncate(&ctx, 0);
    try testing.expectEqual(ret, 0);

    const data2 = "BBBB";
    ret = aegis.aegis128l_raf_write(&ctx, &bytes_written, data2.ptr, data2.len, 0);
    try testing.expectEqual(ret, 0);

    var root2: [MERKLE_HASH_LEN]u8 = undefined;
    const r2 = aegis.aegis_raf_merkle_root(&merkle_cfg);
    @memcpy(&root2, r2[0..MERKLE_HASH_LEN]);

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
    const r1 = aegis.aegis_raf_merkle_root(&merkle_cfg);
    @memcpy(&root_before, r1[0..MERKLE_HASH_LEN]);

    const single_byte: [1]u8 = .{0xFF};
    ret = aegis.aegis128l_raf_write(&ctx, &bytes_written, &single_byte, 1, 1500);
    try testing.expectEqual(ret, 0);

    var root_after: [MERKLE_HASH_LEN]u8 = undefined;
    const r2 = aegis.aegis_raf_merkle_root(&merkle_cfg);
    @memcpy(&root_after, r2[0..MERKLE_HASH_LEN]);

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

test "aegis128l_raf_merkle - root pointer stability" {
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

    const root1 = aegis.aegis_raf_merkle_root(&merkle_cfg);
    const root2 = aegis.aegis_raf_merkle_root(&merkle_cfg);
    const root3 = aegis.aegis_raf_merkle_root(&merkle_cfg);

    try testing.expectEqual(root1, root2);
    try testing.expectEqual(root2, root3);

    const test_data = "test";
    var bytes_written: usize = undefined;
    ret = aegis.aegis128l_raf_write(&ctx, &bytes_written, test_data.ptr, test_data.len, 0);
    try testing.expectEqual(ret, 0);

    const root4 = aegis.aegis_raf_merkle_root(&merkle_cfg);
    try testing.expectEqual(root1, root4);

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

        const r = aegis.aegis_raf_merkle_root(&merkle_cfg);
        @memcpy(&roots[i], r[0..MERKLE_HASH_LEN]);

        if (i > 0) {
            try testing.expect(!std.mem.eql(u8, &roots[i - 1], &roots[i]));
        }
    }

    ret = aegis.aegis128l_raf_merkle_verify(&ctx, null);
    try testing.expectEqual(ret, 0);

    aegis.aegis128l_raf_close(&ctx);
}

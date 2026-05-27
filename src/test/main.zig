const aegis = @import("aegis");
const std = @import("std");
const testing = std.testing;

var io_source = std.Random.IoSource{ .io = testing.io };
const random = io_source.interface();

const max_msg_len: usize = 1000;
const max_ad_len: usize = 1000;
const iterations = 50000;

fn rep(comptime T: type, comptime arr: []const T, comptime n: usize) [arr.len * n]T {
    var out: [arr.len * n]T = undefined;
    inline for (0..n) |i| {
        inline for (arr, 0..) |x, j| out[i * arr.len + j] = x;
    }
    return out;
}

test "aegis-128l - encrypt_detached oneshot" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    inline for ([_]usize{ 16, 32 }) |mac_len| {
        var msg_buf: [max_msg_len]u8 = undefined;
        var msg2_buf: [msg_buf.len]u8 = undefined;
        var ad_buf: [max_ad_len]u8 = undefined;
        var c_buf: [msg_buf.len]u8 = undefined;
        var mac: [mac_len]u8 = undefined;

        random.bytes(&msg_buf);
        random.bytes(&ad_buf);

        for (0..iterations) |_| {
            const msg_len = random.intRangeAtMost(usize, 0, msg_buf.len);
            const msg = msg_buf[0..msg_len];
            var c = c_buf[0..msg_len];
            _ = &c;

            const ad_len = random.intRangeAtMost(usize, 0, ad_buf.len);
            const ad = &ad_buf[0..ad_len];

            var nonce: [aegis.aegis128l_NPUBBYTES]u8 = undefined;
            random.bytes(&nonce);
            var key: [aegis.aegis128l_KEYBYTES]u8 = undefined;
            random.bytes(&key);

            var ret = aegis.aegis128l_encrypt_detached(c.ptr, &mac, mac_len, msg.ptr, msg.len, ad.ptr, ad.len, &nonce, &key);
            try testing.expectEqual(ret, 0);

            var msg2 = msg2_buf[0..msg_len];
            _ = &msg2;
            ret = aegis.aegis128l_decrypt_detached(msg2.ptr, c.ptr, c.len, &mac, mac_len, ad.ptr, ad.len, &nonce, &key);
            try testing.expectEqual(ret, 0);
            try testing.expectEqualSlices(u8, msg, msg2);
        }
    }
}

test "aegis-256 - encrypt_detached oneshot" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    inline for ([_]usize{ 16, 32 }) |mac_len| {
        var msg_buf: [max_msg_len]u8 = undefined;
        var msg2_buf: [msg_buf.len]u8 = undefined;
        var ad_buf: [max_ad_len]u8 = undefined;
        var c_buf: [msg_buf.len]u8 = undefined;
        var mac: [mac_len]u8 = undefined;

        random.bytes(&msg_buf);
        random.bytes(&ad_buf);

        for (0..iterations) |_| {
            const msg_len = random.intRangeAtMost(usize, 0, msg_buf.len);
            const msg = msg_buf[0..msg_len];
            var c = c_buf[0..msg_len];
            _ = &c;

            const ad_len = random.intRangeAtMost(usize, 0, ad_buf.len);
            const ad = &ad_buf[0..ad_len];

            var nonce: [aegis.aegis256_NPUBBYTES]u8 = undefined;
            random.bytes(&nonce);
            var key: [aegis.aegis256_KEYBYTES]u8 = undefined;
            random.bytes(&key);

            var ret = aegis.aegis256_encrypt_detached(c.ptr, &mac, mac_len, msg.ptr, msg.len, ad.ptr, ad.len, &nonce, &key);
            try testing.expectEqual(ret, 0);

            var msg2 = msg2_buf[0..msg_len];
            _ = &msg2;
            ret = aegis.aegis256_decrypt_detached(msg2.ptr, c.ptr, c.len, &mac, mac_len, ad.ptr, ad.len, &nonce, &key);
            try testing.expectEqual(ret, 0);
            try testing.expectEqualSlices(u8, msg, msg2);
        }
    }
}

test "aegis-128l - incremental encryption" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    const mac_len: usize = 16;
    var msg_buf: [max_msg_len]u8 = undefined;
    var msg2_buf: [msg_buf.len]u8 = undefined;
    var ad_buf: [max_ad_len]u8 = undefined;
    var c_buf: [msg_buf.len]u8 = undefined;
    var c2_buf: [c_buf.len]u8 = undefined;
    var mac: [mac_len]u8 = undefined;

    random.bytes(&ad_buf);

    const msg_len = random.intRangeAtMost(usize, 0, msg_buf.len);

    for (&msg_buf, 0..) |*m, i| {
        m.* = @truncate(i);
    }

    const msg = msg_buf[0..msg_len];
    var c = c_buf[0..msg_len];
    _ = &c;
    var c2 = c2_buf[0..msg_len];
    _ = &c2;

    const ad_len = random.intRangeAtMost(usize, 0, ad_buf.len);
    const ad = ad_buf[0..ad_len];

    var nonce: [aegis.aegis256_NPUBBYTES]u8 = undefined;
    random.bytes(&nonce);
    var key: [aegis.aegis256_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    var st: aegis.aegis128l_state align(32) = undefined;

    aegis.aegis128l_state_init(&st, ad.ptr, ad.len, &nonce, &key);

    var cx = c;

    const m0 = msg[0 .. msg.len / 3];
    const m1 = msg[msg.len / 3 .. 2 * msg.len / 3];
    const m2 = msg[2 * msg.len / 3 ..];

    var ret = aegis.aegis128l_state_encrypt_update(&st, cx.ptr, m0.ptr, m0.len);
    try testing.expectEqual(ret, 0);
    cx = cx[m0.len..];

    ret = aegis.aegis128l_state_encrypt_update(&st, cx.ptr, m1.ptr, m1.len);
    try testing.expectEqual(ret, 0);
    cx = cx[m1.len..];

    ret = aegis.aegis128l_state_encrypt_update(&st, cx.ptr, m2.ptr, m2.len);
    try testing.expectEqual(ret, 0);
    cx = cx[m2.len..];

    ret = aegis.aegis128l_state_encrypt_final(&st, &mac, mac.len);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(cx.len, 0);

    ret = aegis.aegis128l_encrypt_detached(c2.ptr, &mac, mac_len, msg.ptr, msg.len, ad.ptr, ad.len, &nonce, &key);
    try testing.expectEqual(ret, 0);

    try testing.expectEqualSlices(u8, c, c2);

    var msg2 = msg2_buf[0..msg_len];
    _ = &msg2;
    ret = aegis.aegis128l_decrypt_detached(msg2.ptr, c.ptr, c.len, &mac, mac_len, ad.ptr, ad.len, &nonce, &key);
    try testing.expectEqual(ret, 0);
    try testing.expectEqualSlices(u8, msg, msg2);
}

test "aegis-256 - incremental encryption" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    const mac_len: usize = 16;
    var msg_buf: [max_msg_len]u8 = undefined;
    var msg2_buf: [msg_buf.len]u8 = undefined;
    var ad_buf: [max_ad_len]u8 = undefined;
    var c_buf: [msg_buf.len]u8 = undefined;
    var c2_buf: [c_buf.len]u8 = undefined;
    var mac: [mac_len]u8 = undefined;

    random.bytes(&ad_buf);

    const msg_len = random.intRangeAtMost(usize, 0, msg_buf.len);

    for (&msg_buf, 0..) |*m, i| {
        m.* = @truncate(i);
    }

    const msg = msg_buf[0..msg_len];
    var c = c_buf[0..msg_len];
    _ = &c;
    var c2 = c2_buf[0..msg_len];
    _ = &c2;

    const ad_len = random.intRangeAtMost(usize, 0, ad_buf.len);
    const ad = ad_buf[0..ad_len];

    var nonce: [aegis.aegis256_NPUBBYTES]u8 = undefined;
    random.bytes(&nonce);
    var key: [aegis.aegis256_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    var st: aegis.aegis256_state = undefined;

    aegis.aegis256_state_init(&st, ad.ptr, ad.len, &nonce, &key);

    var cx = c;

    const m0 = msg[0 .. msg.len / 3];
    const m1 = msg[msg.len / 3 .. 2 * msg.len / 3];
    const m2 = msg[2 * msg.len / 3 ..];

    var ret = aegis.aegis256_state_encrypt_update(&st, cx.ptr, m0.ptr, m0.len);
    try testing.expectEqual(ret, 0);
    cx = cx[m0.len..];

    ret = aegis.aegis256_state_encrypt_update(&st, cx.ptr, m1.ptr, m1.len);
    try testing.expectEqual(ret, 0);
    cx = cx[m1.len..];

    ret = aegis.aegis256_state_encrypt_update(&st, cx.ptr, m2.ptr, m2.len);
    try testing.expectEqual(ret, 0);
    cx = cx[m2.len..];

    ret = aegis.aegis256_state_encrypt_final(&st, &mac, mac.len);
    try testing.expectEqual(ret, 0);

    try testing.expectEqual(cx.len, 0);

    ret = aegis.aegis256_encrypt_detached(c2.ptr, &mac, mac_len, msg.ptr, msg.len, ad.ptr, ad.len, &nonce, &key);
    try testing.expectEqual(ret, 0);

    try testing.expectEqualSlices(u8, c, c2);

    var msg2 = msg2_buf[0..msg_len];
    _ = &msg2;
    ret = aegis.aegis256_decrypt_detached(msg2.ptr, c.ptr, c.len, &mac, mac_len, ad.ptr, ad.len, &nonce, &key);
    try testing.expectEqual(ret, 0);
    try testing.expectEqualSlices(u8, msg, msg2);
}

test "aegis-256 - incremental encryption 2" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    const mac_len: usize = 16;
    var msg: [633]u8 = undefined;
    var msg2: [msg.len]u8 = undefined;
    var ad: [10]u8 = undefined;
    var c: [msg.len + mac_len]u8 = undefined;
    var c2: [c.len]u8 = undefined;

    random.bytes(&ad);
    random.bytes(&msg);

    var nonce: [aegis.aegis256_NPUBBYTES]u8 = undefined;
    random.bytes(&nonce);
    var key: [aegis.aegis256_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    var st: aegis.aegis256_state = undefined;

    aegis.aegis256_state_init(&st, &ad, ad.len, &nonce, &key);

    var cx: []u8 = c[0..];

    const m0 = msg[0..11];
    const m1 = msg[11 .. 11 + 21];
    const m2 = msg[11 + 21 .. 11 + 21 + 311];
    const m3 = msg[11 + 21 + 311 ..];

    var ret = aegis.aegis256_state_encrypt_update(&st, cx.ptr, m0.ptr, m0.len);
    try testing.expectEqual(ret, 0);
    cx = cx[m0.len..];

    ret = aegis.aegis256_state_encrypt_update(&st, cx.ptr, m1.ptr, m1.len);
    try testing.expectEqual(ret, 0);
    cx = cx[m1.len..];

    ret = aegis.aegis256_state_encrypt_update(&st, cx.ptr, m2.ptr, m2.len);
    try testing.expectEqual(ret, 0);
    cx = cx[m2.len..];

    ret = aegis.aegis256_state_encrypt_update(&st, cx.ptr, m3.ptr, m3.len);
    try testing.expectEqual(ret, 0);
    cx = cx[m3.len..];

    ret = aegis.aegis256_state_encrypt_final(&st, cx.ptr, mac_len);
    try testing.expectEqual(ret, 0);
    cx = cx[mac_len..];
    try testing.expectEqual(cx.len, 0);

    ret = aegis.aegis256_encrypt(&c2, mac_len, &msg, msg.len, &ad, ad.len, &nonce, &key);
    try testing.expectEqual(ret, 0);

    try testing.expectEqualSlices(u8, &c, &c2);

    ret = aegis.aegis256_decrypt(&msg2, &c, c.len, mac_len, &ad, ad.len, &nonce, &key);
    try testing.expectEqual(ret, 0);
    try testing.expectEqualSlices(u8, &msg, &msg2);
}

test "aegis-128l - incremental decryption" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    const mac_len: usize = 16;
    var msg_buf: [max_msg_len]u8 = undefined;
    var msg2_buf: [msg_buf.len]u8 = undefined;
    var ad_buf: [max_ad_len]u8 = undefined;
    var c_buf: [msg_buf.len]u8 = undefined;
    var mac: [mac_len]u8 = undefined;

    random.bytes(&ad_buf);

    const msg_len = random.intRangeAtMost(usize, 0, msg_buf.len);

    for (&msg_buf, 0..) |*m, i| {
        m.* = @truncate(i);
    }

    const msg = msg_buf[0..msg_len];
    var c = c_buf[0..msg_len];

    const ad_len = random.intRangeAtMost(usize, 0, ad_buf.len);
    const ad = ad_buf[0..ad_len];

    var nonce: [aegis.aegis256_NPUBBYTES]u8 = undefined;
    random.bytes(&nonce);
    var key: [aegis.aegis256_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    var ret = aegis.aegis128l_encrypt_detached(c.ptr, &mac, mac_len, msg.ptr, msg.len, ad.ptr, ad.len, &nonce, &key);
    try testing.expectEqual(ret, 0);

    var st: aegis.aegis128l_state align(32) = undefined;

    const c0 = c[0 .. c.len / 3];
    const c1 = c[c.len / 3 .. 2 * c.len / 3];
    var c2 = c[2 * c.len / 3 ..];
    _ = &c2;

    var mx = msg2_buf[0..c.len];

    aegis.aegis128l_state_init(&st, ad.ptr, ad.len, &nonce, &key);

    ret = aegis.aegis128l_state_decrypt_update(&st, mx.ptr, c0.ptr, c0.len);
    try testing.expectEqual(ret, 0);
    mx = mx[c0.len..];

    ret = aegis.aegis128l_state_decrypt_update(&st, mx.ptr, c1.ptr, c1.len);
    try testing.expectEqual(ret, 0);
    mx = mx[c1.len..];

    ret = aegis.aegis128l_state_decrypt_update(&st, mx.ptr, c2.ptr, c2.len);
    try testing.expectEqual(ret, 0);
    mx = mx[c2.len..];

    ret = aegis.aegis128l_state_decrypt_final(&st, &mac, mac.len);
    try testing.expectEqual(ret, 0);

    try testing.expectEqual(mx.len, 0);
    try testing.expectEqualSlices(u8, msg, msg2_buf[0..msg.len]);
}

test "aegis-256 - incremental decryption" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    const mac_len: usize = 16;
    var msg_buf: [max_msg_len]u8 = undefined;
    var msg2_buf: [msg_buf.len]u8 = undefined;
    var ad_buf: [max_ad_len]u8 = undefined;
    var c_buf: [msg_buf.len]u8 = undefined;
    var mac: [mac_len]u8 = undefined;

    random.bytes(&ad_buf);

    const msg_len = random.intRangeAtMost(usize, 0, msg_buf.len);

    for (&msg_buf, 0..) |*m, i| {
        m.* = @truncate(i);
    }

    const msg = msg_buf[0..msg_len];
    var c = c_buf[0..msg_len];

    const ad_len = random.intRangeAtMost(usize, 0, ad_buf.len);
    const ad = ad_buf[0..ad_len];

    var nonce: [aegis.aegis256_NPUBBYTES]u8 = undefined;
    random.bytes(&nonce);
    var key: [aegis.aegis256_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    var ret = aegis.aegis256_encrypt_detached(c.ptr, &mac, mac_len, msg.ptr, msg.len, ad.ptr, ad.len, &nonce, &key);
    try testing.expectEqual(ret, 0);

    var st: aegis.aegis256_state = undefined;

    var c0 = c[0 .. c.len / 3];
    _ = &c0;
    var c1 = c[c.len / 3 .. 2 * c.len / 3];
    _ = &c1;
    var c2 = c[2 * c.len / 3 ..];
    _ = &c2;

    var mx = msg2_buf[0..c.len];

    aegis.aegis256_state_init(&st, ad.ptr, ad.len, &nonce, &key);

    ret = aegis.aegis256_state_decrypt_update(&st, mx.ptr, c0.ptr, c0.len);
    try testing.expectEqual(ret, 0);
    mx = mx[c0.len..];

    ret = aegis.aegis256_state_decrypt_update(&st, mx.ptr, c1.ptr, c1.len);
    try testing.expectEqual(ret, 0);
    mx = mx[c1.len..];

    ret = aegis.aegis256_state_decrypt_update(&st, mx.ptr, c2.ptr, c2.len);
    try testing.expectEqual(ret, 0);
    mx = mx[c2.len..];

    ret = aegis.aegis256_state_decrypt_final(&st, &mac, mac.len);
    try testing.expectEqual(ret, 0);

    try testing.expectEqual(mx.len, 0);
    try testing.expectEqualSlices(u8, msg, msg2_buf[0..msg.len]);
}

test "aegis-128x2 - test vector" {
    const key = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    const nonce = [_]u8{ 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31 };
    const ad = rep(u8, &[_]u8{ 1, 2, 3, 4 }, 2);
    const msg = rep(u8, &[_]u8{ 4, 5, 6, 7 }, 30);
    var c: [msg.len]u8 = @splat(0);
    var mac: [16]u8 = @splat(0);
    var mac256: [32]u8 = @splat(0);
    var ret = aegis.aegis128x2_encrypt_detached(&c, &mac, mac.len, &msg, msg.len, &ad, ad.len, &nonce, &key);
    try testing.expectEqual(ret, 0);
    ret = aegis.aegis128x2_encrypt_detached(&c, &mac256, mac256.len, &msg, msg.len, &ad, ad.len, &nonce, &key);
    try testing.expectEqual(ret, 0);

    const expected_ciphertext_hex = "5795544301997f93621b278809d6331b3bfa6f18e90db12c4aa35965b5e98c5fc6fb4e54bcb6111842c20637252eff747cb3a8f85b37de80919a589fe0f24872bc926360696739e05520647e390989e1eb5fd42f99678a0276a498f8c454761c9d6aacb647ad56be62b29c22cd4b5761b38f43d5a5ee062f";
    try testing.expectEqualSlices(u8, &std.fmt.bytesToHex(c, .lower), expected_ciphertext_hex);

    const expected_tag_hex = "1aebc200804f405cab637f2adebb6d77";
    try testing.expectEqualSlices(u8, &std.fmt.bytesToHex(mac, .lower), expected_tag_hex);

    var msg2: [msg.len]u8 = @splat(0);
    ret = aegis.aegis128x2_decrypt_detached(&msg2, &c, c.len, &mac, mac.len, &ad, ad.len, &nonce, &key);
    try testing.expectEqual(ret, 0);
    try std.testing.expectEqualSlices(u8, &msg, &msg2);
}

test "aegis-128x2 - encrypt_detached oneshot" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    inline for ([_]usize{ 16, 32 }) |mac_len| {
        var msg_buf: [max_msg_len]u8 = undefined;
        var msg2_buf: [msg_buf.len]u8 = undefined;
        var ad_buf: [max_ad_len]u8 = undefined;
        var c_buf: [msg_buf.len]u8 = undefined;
        var mac: [mac_len]u8 = undefined;

        random.bytes(&msg_buf);
        random.bytes(&ad_buf);

        for (0..iterations) |_| {
            const msg_len = random.intRangeAtMost(usize, 0, msg_buf.len);
            const msg = msg_buf[0..msg_len];
            var c = c_buf[0..msg_len];
            _ = &c;

            const ad_len = random.intRangeAtMost(usize, 0, ad_buf.len);
            const ad = &ad_buf[0..ad_len];

            var nonce: [aegis.aegis128x2_NPUBBYTES]u8 = undefined;
            random.bytes(&nonce);
            var key: [aegis.aegis128x2_KEYBYTES]u8 = undefined;
            random.bytes(&key);

            var ret = aegis.aegis128x2_encrypt_detached(c.ptr, &mac, mac_len, msg.ptr, msg.len, ad.ptr, ad.len, &nonce, &key);
            try testing.expectEqual(ret, 0);

            var msg2 = msg2_buf[0..msg_len];
            _ = &msg2;
            ret = aegis.aegis128x2_decrypt_detached(msg2.ptr, c.ptr, c.len, &mac, mac_len, ad.ptr, ad.len, &nonce, &key);
            try testing.expectEqual(ret, 0);
            try testing.expectEqualSlices(u8, msg, msg2);
        }
    }
}

test "aegis-128x4 - encrypt_detached oneshot" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    inline for ([_]usize{ 16, 32 }) |mac_len| {
        var msg_buf: [max_msg_len]u8 = undefined;
        var msg2_buf: [msg_buf.len]u8 = undefined;
        var ad_buf: [max_ad_len]u8 = undefined;
        var c_buf: [msg_buf.len]u8 = undefined;
        var mac: [mac_len]u8 = undefined;

        random.bytes(&msg_buf);
        random.bytes(&ad_buf);

        for (0..iterations) |_| {
            const msg_len = random.intRangeAtMost(usize, 0, msg_buf.len);
            const msg = msg_buf[0..msg_len];
            const c = c_buf[0..msg_len];

            const ad_len = random.intRangeAtMost(usize, 0, ad_buf.len);
            const ad = &ad_buf[0..ad_len];

            var nonce: [aegis.aegis128x4_NPUBBYTES]u8 = undefined;
            random.bytes(&nonce);
            var key: [aegis.aegis128x4_KEYBYTES]u8 = undefined;
            random.bytes(&key);

            var ret = aegis.aegis128x4_encrypt_detached(c.ptr, &mac, mac_len, msg.ptr, msg.len, ad.ptr, ad.len, &nonce, &key);
            try testing.expectEqual(ret, 0);

            var msg2 = msg2_buf[0..msg_len];
            _ = &msg2;
            ret = aegis.aegis128x4_decrypt_detached(msg2.ptr, c.ptr, c.len, &mac, mac_len, ad.ptr, ad.len, &nonce, &key);
            try testing.expectEqual(ret, 0);
            try testing.expectEqualSlices(u8, msg, msg2);
        }
    }
}

test "aegis-128x4 - test vector" {
    const key = [_]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    const nonce = [_]u8{ 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31 };
    const ad = rep(u8, &[_]u8{ 1, 2, 3, 4 }, 2);
    const msg = rep(u8, &[_]u8{ 4, 5, 6, 7 }, 30);
    var c: [msg.len]u8 = @splat(0);
    var mac: [16]u8 = @splat(0);
    var mac256: [32]u8 = @splat(0);
    var ret = aegis.aegis128x4_encrypt_detached(&c, &mac, mac.len, &msg, msg.len, &ad, ad.len, &nonce, &key);
    try testing.expectEqual(ret, 0);
    ret = aegis.aegis128x4_encrypt_detached(&c, &mac256, mac256.len, &msg, msg.len, &ad, ad.len, &nonce, &key);
    try testing.expectEqual(ret, 0);

    const expected_ciphertext_hex = "e836118562f4479c9d35c17356a833114c21f9aa39e4dda5e5c87f4152a00fce9a7c38f832eafe8b1c12f8a7cf12a81a1ad8a9c24ba9dedfbdaa586ffea67ddc801ea97d9ab4a872f42d0e352e2713dacd609f9442c17517c5a29daf3e2a3fac4ff6b1380c4e46df7b086af6ce6bc1ed594b8dd64aed2a7e";
    try testing.expectEqualSlices(u8, &std.fmt.bytesToHex(c, .lower), expected_ciphertext_hex);

    const expected_tag_hex = "0e56ab94e2e85db80f9d54010caabfb4";
    try testing.expectEqualSlices(u8, &std.fmt.bytesToHex(mac, .lower), expected_tag_hex);

    var msg2: [msg.len]u8 = @splat(0);
    ret = aegis.aegis128x4_decrypt_detached(&msg2, &c, c.len, &mac, mac.len, &ad, ad.len, &nonce, &key);
    try testing.expectEqual(ret, 0);
    try std.testing.expectEqualSlices(u8, &msg, &msg2);
}

test "aegis-256x2 - test vector" {
    const key = [32]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31 };
    const nonce = [32]u8{ 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47 };
    const ad = rep(u8, &[_]u8{ 1, 2, 3, 4 }, 2);
    const msg = rep(u8, &[_]u8{ 4, 5, 6, 7 }, 30);
    var c: [msg.len]u8 = @splat(0);
    var mac: [16]u8 = @splat(0);
    var mac256: [32]u8 = @splat(0);
    var ret = aegis.aegis256x2_encrypt_detached(&c, &mac, mac.len, &msg, msg.len, &ad, ad.len, &nonce, &key);
    try testing.expectEqual(ret, 0);
    ret = aegis.aegis256x2_encrypt_detached(&c, &mac256, mac256.len, &msg, msg.len, &ad, ad.len, &nonce, &key);
    try testing.expectEqual(ret, 0);

    const expected_ciphertext_hex = "72120c2ea8236180d67859001f4729077b7064c414384fe3a7b52f1571f4f8a7d0f01e18db4f3bc0adb150702e5d147a8d36522132761b994c1bd395589e2ccf0790dfe2a3d12d61cd666b2859827739db4037dd3124c78424459376f6cac08e1a7223a2a43e398ce6385cd654a19f481cba3b8f25910b42";
    try testing.expectEqualSlices(u8, &std.fmt.bytesToHex(c, .lower), expected_ciphertext_hex);

    const expected_tag_hex = "635d391828520bf1512763f0c8f5cdbd";
    try testing.expectEqualSlices(u8, &std.fmt.bytesToHex(mac, .lower), expected_tag_hex);

    var msg2: [msg.len]u8 = @splat(0);
    ret = aegis.aegis256x2_decrypt_detached(&msg2, &c, c.len, &mac, mac.len, &ad, ad.len, &nonce, &key);
    try testing.expectEqual(ret, 0);
    try std.testing.expectEqualSlices(u8, &msg, &msg2);
}

test "aegis-256x4 - test vector" {
    const key = [32]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31 };
    const nonce = [32]u8{ 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47 };
    const ad = rep(u8, &[_]u8{ 1, 2, 3, 4 }, 2);
    const msg = rep(u8, &[_]u8{ 4, 5, 6, 7 }, 30);
    var c: [msg.len]u8 = @splat(0);
    var mac: [16]u8 = @splat(0);
    var mac256: [32]u8 = @splat(0);
    var ret = aegis.aegis256x4_encrypt_detached(&c, &mac, mac.len, &msg, msg.len, &ad, ad.len, &nonce, &key);
    try testing.expectEqual(ret, 0);
    ret = aegis.aegis256x4_encrypt_detached(&c, &mac256, mac256.len, &msg, msg.len, &ad, ad.len, &nonce, &key);
    try testing.expectEqual(ret, 0);

    const expected_ciphertext_hex = "bfc2085b7e8017da99b0b6d646ae4d01f4ba8f2e7dfca1d759ae48a135139b9aaac6b4f5db810d426be1fdaff4e1454153a34b11da78ed7e418ee2ee9853042e95536aecbb694cea1b16a478eb0d4d1bf6509b1ce652a45af58e0e46ffccfa2d0426e702391d2ff5813808b81748a490dd656465fed61f09";
    try testing.expectEqualSlices(u8, &std.fmt.bytesToHex(c, .lower), expected_ciphertext_hex);

    const expected_tag_hex = "b63b611b13975e2f3dc3cb6c2397bfcd";
    try testing.expectEqualSlices(u8, &std.fmt.bytesToHex(mac, .lower), expected_tag_hex);

    var msg2: [msg.len]u8 = @splat(0);
    ret = aegis.aegis256x4_decrypt_detached(&msg2, &c, c.len, &mac, mac.len, &ad, ad.len, &nonce, &key);
    try testing.expectEqual(ret, 0);
    try std.testing.expectEqualSlices(u8, &msg, &msg2);
}

test "aegis128l - Unauthenticated encryption" {
    const key = [16]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    const nonce = [16]u8{ 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31 };
    var msg: [100]u8 = undefined;
    var msg2: [100]u8 = undefined;

    random.bytes(&msg);
    aegis.aegis128l_encrypt_unauthenticated(&msg2, &msg, msg.len, &nonce, &key);
    try testing.expect(!std.mem.eql(u8, &msg, &msg2));
    aegis.aegis128l_decrypt_unauthenticated(&msg2, &msg2, msg2.len, &nonce, &key);
    try testing.expectEqualSlices(u8, &msg, &msg2);
}

test "aegis128l - Random stream" {
    const key = [16]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    var nonce = [16]u8{ 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31 };
    var msg: [100]u8 = undefined;
    var msg2: [100]u8 = undefined;
    aegis.aegis128l_stream(&msg, msg.len, &nonce, &key);
    aegis.aegis128l_stream(&msg2, msg2.len, &nonce, &key);
    try testing.expectEqualSlices(u8, &msg, &msg2);
    nonce[0] ^= 0x01;
    aegis.aegis128l_stream(&msg2, msg2.len, &nonce, &key);
    try testing.expect(!std.mem.eql(u8, &msg, &msg2));
}

test "aegis128l - MAC" {
    const key = [16]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    const nonce: [16]u8 = @splat(0);
    const msg = rep(u8, &[_]u8{ 1, 2, 3 }, 100);
    const msg2 = rep(u8, &[_]u8{ 4, 5, 6, 7, 8 }, 100) ++ [_]u8{0};
    var st0: aegis.aegis128l_mac_state align(32) = undefined;
    aegis.aegis128l_mac_init(&st0, &key, &nonce);

    var st: aegis.aegis128l_mac_state align(32) = undefined;
    aegis.aegis128l_mac_state_clone(&st, &st0);
    var ret = aegis.aegis128l_mac_update(&st, &msg, msg.len);
    try testing.expectEqual(ret, 0);
    ret = aegis.aegis128l_mac_update(&st, &msg2, msg2.len);
    try testing.expectEqual(ret, 0);
    var mac: [32]u8 = undefined;
    ret = aegis.aegis128l_mac_final(&st, &mac, mac.len);
    try testing.expectEqual(ret, 0);

    aegis.aegis128l_mac_state_clone(&st, &st0);
    ret = aegis.aegis128l_mac_update(&st, &msg, msg.len);
    try testing.expectEqual(ret, 0);
    ret = aegis.aegis128l_mac_update(&st, &msg2, msg2.len);
    try testing.expectEqual(ret, 0);
    ret = aegis.aegis128l_mac_verify(&st, &mac, mac.len);
    try testing.expectEqual(ret, 0);

    aegis.aegis128l_mac_state_clone(&st, &st0);
    const msg3 = msg ++ msg2;
    ret = aegis.aegis128l_mac_update(&st, &msg3, msg3.len);
    try testing.expectEqual(ret, 0);
    ret = aegis.aegis128l_mac_verify(&st, &mac, mac.len);
    try testing.expectEqual(ret, 0);

    var mac2: [mac.len]u8 = undefined;
    ret = aegis.aegis128l_encrypt_detached(&mac2, &mac2, mac2.len, "", 0, &msg3, msg3.len, &nonce, &key);
    try testing.expectEqual(ret, 0);
    try testing.expect(!std.mem.eql(u8, &mac, &mac2));
}

test "aegis128x2 - MAC" {
    const key = [16]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    const nonce: [16]u8 = @splat(0);
    const msg = rep(u8, &[_]u8{ 1, 2, 3 }, 100);
    const msg2 = rep(u8, &[_]u8{ 4, 5, 6, 7, 8 }, 100) ++ [_]u8{0};
    var st0: aegis.aegis128x2_mac_state align(64) = undefined;
    aegis.aegis128x2_mac_init(&st0, &key, &nonce);

    var st: aegis.aegis128x2_mac_state align(64) = undefined;
    aegis.aegis128x2_mac_state_clone(&st, &st0);
    var ret = aegis.aegis128x2_mac_update(&st, &msg, msg.len);
    try testing.expectEqual(ret, 0);
    ret = aegis.aegis128x2_mac_update(&st, &msg2, msg2.len);
    try testing.expectEqual(ret, 0);
    var mac: [32]u8 = undefined;
    ret = aegis.aegis128x2_mac_final(&st, &mac, mac.len);
    try testing.expectEqual(ret, 0);

    aegis.aegis128x2_mac_state_clone(&st, &st0);
    ret = aegis.aegis128x2_mac_update(&st, &msg, msg.len);
    try testing.expectEqual(ret, 0);
    ret = aegis.aegis128x2_mac_update(&st, &msg2, msg2.len);
    try testing.expectEqual(ret, 0);
    ret = aegis.aegis128x2_mac_verify(&st, &mac, mac.len);
    try testing.expectEqual(ret, 0);

    aegis.aegis128x2_mac_state_clone(&st, &st0);
    const msg3 = msg ++ msg2;
    ret = aegis.aegis128x2_mac_update(&st, &msg3, msg3.len);
    try testing.expectEqual(ret, 0);
    ret = aegis.aegis128x2_mac_verify(&st, &mac, mac.len);
    try testing.expectEqual(ret, 0);

    var mac2: [mac.len]u8 = undefined;
    ret = aegis.aegis128x2_encrypt_detached(&mac2, &mac2, mac2.len, "", 0, &msg3, msg3.len, &nonce, &key);
    try testing.expectEqual(ret, 0);
    try testing.expect(!std.mem.eql(u8, &mac, &mac2));
}

test "aegis128x4 - MAC" {
    const key = [16]u8{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    const nonce: [16]u8 = @splat(0);
    const msg = rep(u8, &[_]u8{ 1, 2, 3 }, 100) ++ [_]u8{0};
    const msg2 = rep(u8, &[_]u8{ 4, 5, 6, 7, 8 }, 100);
    var st0: aegis.aegis128x4_mac_state align(64) = undefined;
    aegis.aegis128x4_mac_init(&st0, &key, &nonce);

    var st: aegis.aegis128x4_mac_state align(64) = undefined;
    aegis.aegis128x4_mac_state_clone(&st, &st0);
    var ret = aegis.aegis128x4_mac_update(&st, &msg, msg.len);
    try testing.expectEqual(ret, 0);
    ret = aegis.aegis128x4_mac_update(&st, &msg2, msg2.len);
    try testing.expectEqual(ret, 0);
    var mac: [32]u8 = undefined;
    ret = aegis.aegis128x4_mac_final(&st, &mac, mac.len);
    try testing.expectEqual(ret, 0);

    aegis.aegis128x4_mac_state_clone(&st, &st0);
    ret = aegis.aegis128x4_mac_update(&st, &msg, msg.len);
    try testing.expectEqual(ret, 0);
    ret = aegis.aegis128x4_mac_update(&st, &msg2, msg2.len);
    try testing.expectEqual(ret, 0);
    ret = aegis.aegis128x4_mac_verify(&st, &mac, mac.len);
    try testing.expectEqual(ret, 0);

    aegis.aegis128x4_mac_state_clone(&st, &st0);
    const msg3 = msg ++ msg2;
    ret = aegis.aegis128x4_mac_update(&st, &msg3, msg3.len);
    try testing.expectEqual(ret, 0);
    ret = aegis.aegis128x4_mac_verify(&st, &mac, mac.len);
    try testing.expectEqual(ret, 0);

    var mac2: [mac.len]u8 = undefined;
    ret = aegis.aegis128x4_encrypt_detached(&mac2, &mac2, mac2.len, "", 0, &msg3, msg3.len, &nonce, &key);
    try testing.expectEqual(ret, 0);
    try testing.expect(!std.mem.eql(u8, &mac, &mac2));
}

test "aegis128l - MAC test vector" {
    const key = [_]u8{ 0x10, 0x01 } ++ @as([16 - 2]u8, @splat(0x00));
    const nonce = [_]u8{ 0x10, 0x00, 0x02 } ++ @as([16 - 3]u8, @splat(0x00));
    var msg: [35]u8 = undefined;
    for (&msg, 0..) |*byte, i| byte.* = @truncate(i);
    var mac128: [16]u8 = undefined;
    var mac256: [32]u8 = undefined;
    var st: aegis.aegis128l_mac_state align(32) = undefined;
    var ret: c_int = undefined;
    aegis.aegis128l_mac_init(&st, &key, &nonce);
    ret = aegis.aegis128l_mac_update(&st, &msg, msg.len);
    try testing.expectEqual(ret, 0);
    ret = aegis.aegis128l_mac_final(&st, &mac128, mac128.len);
    try testing.expectEqual(ret, 0);
    aegis.aegis128l_mac_reset(&st);
    ret = aegis.aegis128l_mac_update(&st, &msg, msg.len);
    try testing.expectEqual(ret, 0);
    ret = aegis.aegis128l_mac_final(&st, &mac256, mac256.len);
    try testing.expectEqual(ret, 0);
    const expected128_hex = "d3f09b2842ad301687d6902c921d7818";
    const expected256_hex = "9490e7c89d420c9f37417fa625eb38e8cad53c5cbec55285e8499ea48377f2a3";
    var expected128: [16]u8 = undefined;
    var expected256: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected128, expected128_hex);
    _ = try std.fmt.hexToBytes(&expected256, expected256_hex);
    try std.testing.expectEqualSlices(u8, &expected128, &mac128);
    try std.testing.expectEqualSlices(u8, &expected256, &mac256);
}

test "aegis128x2 - MAC test vector" {
    const key = [_]u8{ 0x10, 0x01 } ++ @as([16 - 2]u8, @splat(0x00));
    const nonce = [_]u8{ 0x10, 0x00, 0x02 } ++ @as([16 - 3]u8, @splat(0x00));
    var msg: [35]u8 = undefined;
    for (&msg, 0..) |*byte, i| byte.* = @truncate(i);
    var mac128: [16]u8 = undefined;
    var mac256: [32]u8 = undefined;
    var st: aegis.aegis128x2_mac_state align(64) = undefined;
    var ret: c_int = undefined;
    aegis.aegis128x2_mac_init(&st, &key, &nonce);
    ret = aegis.aegis128x2_mac_update(&st, &msg, msg.len);
    try testing.expectEqual(ret, 0);
    ret = aegis.aegis128x2_mac_final(&st, &mac128, mac128.len);
    try testing.expectEqual(ret, 0);
    aegis.aegis128x2_mac_reset(&st);
    ret = aegis.aegis128x2_mac_update(&st, &msg, msg.len);
    try testing.expectEqual(ret, 0);
    ret = aegis.aegis128x2_mac_final(&st, &mac256, mac256.len);
    try testing.expectEqual(ret, 0);
    const expected128_hex = "6873ee34e6b5c59143b6d35c5e4f2c6e";
    const expected256_hex = "afcba3fc2d63c8d6c7f2d63f3ec8fbbbaf022e15ac120e78ffa7755abccd959c";
    var expected128: [16]u8 = undefined;
    var expected256: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected128, expected128_hex);
    _ = try std.fmt.hexToBytes(&expected256, expected256_hex);
    try std.testing.expectEqualSlices(u8, &expected128, &mac128);
    try std.testing.expectEqualSlices(u8, &expected256, &mac256);
}

test "aegis128x4 - MAC test vector" {
    const key = [_]u8{ 0x10, 0x01 } ++ @as([16 - 2]u8, @splat(0x00));
    const nonce = [_]u8{ 0x10, 0x00, 0x02 } ++ @as([16 - 3]u8, @splat(0x00));
    var msg: [35]u8 = undefined;
    for (&msg, 0..) |*byte, i| byte.* = @truncate(i);
    var mac128: [16]u8 = undefined;
    var mac256: [32]u8 = undefined;
    var st: aegis.aegis128x4_mac_state align(64) = undefined;
    var ret: c_int = undefined;
    aegis.aegis128x4_mac_init(&st, &key, &nonce);
    ret = aegis.aegis128x4_mac_update(&st, &msg, msg.len);
    try testing.expectEqual(ret, 0);
    ret = aegis.aegis128x4_mac_final(&st, &mac128, mac128.len);
    try testing.expectEqual(ret, 0);
    aegis.aegis128x4_mac_reset(&st);
    ret = aegis.aegis128x4_mac_update(&st, &msg, msg.len);
    try testing.expectEqual(ret, 0);
    ret = aegis.aegis128x4_mac_final(&st, &mac256, mac256.len);
    try testing.expectEqual(ret, 0);
    const expected128_hex = "c45a98fd9ab8956ce616eb008cfe4e53";
    const expected256_hex = "26fdc76f41b1da7aec7779f6e964beae8904e662f05aca8345ae3befb357412a";
    var expected128: [16]u8 = undefined;
    var expected256: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected128, expected128_hex);
    _ = try std.fmt.hexToBytes(&expected256, expected256_hex);
    try std.testing.expectEqualSlices(u8, &expected128, &mac128);
    try std.testing.expectEqualSlices(u8, &expected256, &mac256);
}

test "aegis256 - MAC test vector" {
    const key = [_]u8{ 0x10, 0x01 } ++ @as([32 - 2]u8, @splat(0x00));
    const nonce = [_]u8{ 0x10, 0x00, 0x02 } ++ @as([32 - 3]u8, @splat(0x00));
    var msg: [35]u8 = undefined;
    for (&msg, 0..) |*byte, i| byte.* = @truncate(i);
    var mac128: [16]u8 = undefined;
    var mac256: [32]u8 = undefined;
    var st: aegis.aegis256_mac_state = undefined;
    var ret: c_int = undefined;
    aegis.aegis256_mac_init(&st, &key, &nonce);
    ret = aegis.aegis256_mac_update(&st, &msg, msg.len);
    try testing.expectEqual(ret, 0);
    ret = aegis.aegis256_mac_final(&st, &mac128, mac128.len);
    try testing.expectEqual(ret, 0);
    aegis.aegis256_mac_reset(&st);
    ret = aegis.aegis256_mac_update(&st, &msg, msg.len);
    try testing.expectEqual(ret, 0);
    ret = aegis.aegis256_mac_final(&st, &mac256, mac256.len);
    try testing.expectEqual(ret, 0);
    const expected128_hex = "c08e20cfc56f27195a46c9cef5c162d4";
    const expected256_hex = "a5c906ede3d69545c11e20afa360b221f936e946ed2dba3d7c75ad6dc2784126";
    var expected128: [16]u8 = undefined;
    var expected256: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected128, expected128_hex);
    _ = try std.fmt.hexToBytes(&expected256, expected256_hex);
    try std.testing.expectEqualSlices(u8, &expected128, &mac128);
    try std.testing.expectEqualSlices(u8, &expected256, &mac256);
}

test "aegis256x2 - MAC test vector" {
    const key = [_]u8{ 0x10, 0x01 } ++ @as([32 - 2]u8, @splat(0x00));
    const nonce = [_]u8{ 0x10, 0x00, 0x02 } ++ @as([32 - 3]u8, @splat(0x00));
    var msg: [35]u8 = undefined;
    for (&msg, 0..) |*byte, i| byte.* = @truncate(i);
    var mac128: [16]u8 = undefined;
    var mac256: [32]u8 = undefined;
    var st: aegis.aegis256x2_mac_state align(32) = undefined;
    var ret: c_int = undefined;
    aegis.aegis256x2_mac_init(&st, &key, &nonce);
    ret = aegis.aegis256x2_mac_update(&st, &msg, msg.len);
    try testing.expectEqual(ret, 0);
    ret = aegis.aegis256x2_mac_final(&st, &mac128, mac128.len);
    try testing.expectEqual(ret, 0);
    aegis.aegis256x2_mac_reset(&st);
    ret = aegis.aegis256x2_mac_update(&st, &msg, msg.len);
    try testing.expectEqual(ret, 0);
    ret = aegis.aegis256x2_mac_final(&st, &mac256, mac256.len);
    try testing.expectEqual(ret, 0);
    const expected128_hex = "fb319cb6dd728a764606fb14d37f2a5e";
    const expected256_hex = "0844b20ed5147ceae89c7a160263afd4b1382d6b154ecf560ce8a342cb6a8fd1";
    var expected128: [16]u8 = undefined;
    var expected256: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected128, expected128_hex);
    _ = try std.fmt.hexToBytes(&expected256, expected256_hex);
    try std.testing.expectEqualSlices(u8, &expected128, &mac128);
    try std.testing.expectEqualSlices(u8, &expected256, &mac256);
}

test "aegis256x4 - MAC test vector" {
    const key = [_]u8{ 0x10, 0x01 } ++ @as([32 - 2]u8, @splat(0x00));
    const nonce = [_]u8{ 0x10, 0x00, 0x02 } ++ @as([32 - 3]u8, @splat(0x00));
    var msg: [35]u8 = undefined;
    for (&msg, 0..) |*byte, i| byte.* = @truncate(i);
    var mac128: [16]u8 = undefined;
    var mac256: [32]u8 = undefined;
    var st: aegis.aegis256x4_mac_state align(64) = undefined;
    var ret: c_int = undefined;
    aegis.aegis256x4_mac_init(&st, &key, &nonce);
    ret = aegis.aegis256x4_mac_update(&st, &msg, msg.len);
    try testing.expectEqual(ret, 0);
    ret = aegis.aegis256x4_mac_final(&st, &mac128, mac128.len);
    try testing.expectEqual(ret, 0);
    aegis.aegis256x4_mac_reset(&st);
    ret = aegis.aegis256x4_mac_update(&st, &msg, msg.len);
    try testing.expectEqual(ret, 0);
    ret = aegis.aegis256x4_mac_final(&st, &mac256, mac256.len);
    try testing.expectEqual(ret, 0);
    const expected128_hex = "a51f9bc5beae60cce77f0dbc60761edd";
    const expected256_hex = "b36a16ef07c36d75a91f437502f24f545b8dfa88648ed116943c29fead3bf10c";
    var expected128: [16]u8 = undefined;
    var expected256: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected128, expected128_hex);
    _ = try std.fmt.hexToBytes(&expected256, expected256_hex);
    try std.testing.expectEqualSlices(u8, &expected128, &mac128);
    try std.testing.expectEqualSlices(u8, &expected256, &mac256);
}

// Rooterberg tests

const JsonTest = struct {
    tcId: u64,
    key: []const u8,
    iv: []const u8,
    aad: []const u8,
    msg: []const u8,
    ct: []const u8,
    tag: []const u8,
    valid: bool,
};
const JsonTests = struct {
    testType: []const u8,
    algorithm: struct {
        primitive: []const u8,
        keySize: usize,
        ivSize: usize,
        tagSize: usize,
    },
    tests: []const JsonTest,
};

const heap = std.heap;
const zstd = std.compress.zstd;

fn rooterberg(comptime file: []const u8, comptime func: anytype) !void {
    const alloc = std.testing.allocator;
    var window_buffer: [zstd.default_window_len + zstd.block_size_max]u8 = undefined;
    var reader: std.Io.Reader = .fixed(@embedFile(file));
    var decompressor = zstd.Decompress.init(&reader, window_buffer[0..], .{});
    var out: std.Io.Writer.Allocating = .init(alloc);
    defer out.deinit();
    _ = try decompressor.reader.streamRemaining(&out.writer);
    const json = try out.toOwnedSlice();
    defer alloc.free(json);
    const parsed = try std.json.parseFromSlice(JsonTests, alloc, json, .{ .ignore_unknown_fields = true });
    defer parsed.deinit();
    const tests = parsed.value;
    try std.testing.expectEqualSlices(u8, "Aead", tests.testType);
    for (tests.tests) |t| {
        var arena = heap.ArenaAllocator.init(alloc);
        defer arena.deinit();
        var arena_alloc = arena.allocator();
        const key = try arena_alloc.alloc(u8, tests.algorithm.keySize / 8);
        const nonce = try arena_alloc.alloc(u8, tests.algorithm.ivSize / 8);
        const tag = try arena_alloc.alloc(u8, tests.algorithm.tagSize / 8);
        const aad = try arena_alloc.alloc(u8, t.aad.len / 2);
        const ct = try arena_alloc.alloc(u8, t.ct.len / 2);
        const msg = try arena_alloc.alloc(u8, @max(ct.len, t.msg.len / 2));
        const expected_msg = try arena_alloc.alloc(u8, t.msg.len / 2);
        _ = try std.fmt.hexToBytes(key, t.key);
        _ = try std.fmt.hexToBytes(nonce, t.iv);
        _ = try std.fmt.hexToBytes(tag, t.tag);
        _ = try std.fmt.hexToBytes(aad, t.aad);
        _ = try std.fmt.hexToBytes(expected_msg, t.msg);
        _ = try std.fmt.hexToBytes(ct, t.ct);
        const c_res = func(msg.ptr, ct.ptr, ct.len, tag.ptr, tag.len, aad.ptr, aad.len, nonce.ptr, key.ptr);
        const valid = (c_res == 0);
        if (valid == true) try std.testing.expectEqualSlices(u8, msg, expected_msg);
        if (t.valid != valid) {
            std.debug.print("Test failed: {}\n", .{t.tcId});
            try std.testing.expect(false);
        }
    }
}

test "rooterberg test vectors" {
    try rooterberg("rooterberg/aegis128_l.json.zst", aegis.aegis128l_decrypt_detached);
    try rooterberg("rooterberg/aegis128_l_256.json.zst", aegis.aegis128l_decrypt_detached);
    try rooterberg("rooterberg/aegis256.json.zst", aegis.aegis256_decrypt_detached);
    try rooterberg("rooterberg/aegis256_256.json.zst", aegis.aegis256_decrypt_detached);
}

test "aegis-128l - streaming byte-by-byte" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    const mac_len: usize = 16;
    var msg: [50]u8 = undefined;
    var c: [50]u8 = undefined;
    var c2: [50]u8 = undefined;
    var ad: [10]u8 = undefined;
    var mac: [mac_len]u8 = undefined;
    var mac2: [mac_len]u8 = undefined;

    random.bytes(&ad);
    for (&msg, 0..) |*m, i| m.* = @truncate(i);

    var nonce: [aegis.aegis128l_NPUBBYTES]u8 = undefined;
    random.bytes(&nonce);
    var key: [aegis.aegis128l_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    var ret = aegis.aegis128l_encrypt_detached(&c2, &mac2, mac_len, &msg, msg.len, &ad, ad.len, &nonce, &key);
    try testing.expectEqual(ret, 0);

    var st: aegis.aegis128l_state align(32) = undefined;
    var cx: []u8 = &c;
    aegis.aegis128l_state_init(&st, &ad, ad.len, &nonce, &key);

    for (msg) |byte| {
        const single_byte = [_]u8{byte};
        ret = aegis.aegis128l_state_encrypt_update(&st, cx.ptr, &single_byte, 1);
        try testing.expectEqual(ret, 0);
        cx = cx[1..];
    }

    ret = aegis.aegis128l_state_encrypt_final(&st, &mac, mac.len);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(cx.len, 0);

    try testing.expectEqualSlices(u8, &c, &c2);
    try testing.expectEqualSlices(u8, &mac, &mac2);
}

test "aegis-256 - streaming byte-by-byte" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    const mac_len: usize = 32;
    var msg: [40]u8 = undefined;
    var c: [40]u8 = undefined;
    var c2: [40]u8 = undefined;
    var ad: [10]u8 = undefined;
    var mac: [mac_len]u8 = undefined;
    var mac2: [mac_len]u8 = undefined;

    random.bytes(&ad);
    for (&msg, 0..) |*m, i| m.* = @truncate(i);

    var nonce: [aegis.aegis256_NPUBBYTES]u8 = undefined;
    random.bytes(&nonce);
    var key: [aegis.aegis256_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    var ret = aegis.aegis256_encrypt_detached(&c2, &mac2, mac_len, &msg, msg.len, &ad, ad.len, &nonce, &key);
    try testing.expectEqual(ret, 0);

    var st: aegis.aegis256_state = undefined;
    var cx: []u8 = &c;
    aegis.aegis256_state_init(&st, &ad, ad.len, &nonce, &key);

    for (msg) |byte| {
        const single_byte = [_]u8{byte};
        ret = aegis.aegis256_state_encrypt_update(&st, cx.ptr, &single_byte, 1);
        try testing.expectEqual(ret, 0);
        cx = cx[1..];
    }

    ret = aegis.aegis256_state_encrypt_final(&st, &mac, mac.len);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(cx.len, 0);

    try testing.expectEqualSlices(u8, &c, &c2);
    try testing.expectEqualSlices(u8, &mac, &mac2);
}

test "aegis-128l - streaming at RATE boundaries" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    const mac_len: usize = 16;
    const rate: usize = 32;

    const test_sizes = [_]usize{ rate - 1, rate, rate + 1, rate * 2, rate * 2 + 1, rate * 3 + 5 };

    inline for (test_sizes) |msg_len| {
        var msg: [msg_len]u8 = undefined;
        var c: [msg_len]u8 = undefined;
        var c2: [msg_len]u8 = undefined;
        var ad: [10]u8 = undefined;
        var mac: [mac_len]u8 = undefined;
        var mac2: [mac_len]u8 = undefined;

        random.bytes(&ad);
        for (&msg, 0..) |*byte, i| byte.* = @truncate(i);

        var nonce: [aegis.aegis128l_NPUBBYTES]u8 = undefined;
        random.bytes(&nonce);
        var key: [aegis.aegis128l_KEYBYTES]u8 = undefined;
        random.bytes(&key);

        var ret = aegis.aegis128l_encrypt_detached(&c2, &mac2, mac_len, &msg, msg_len, &ad, ad.len, &nonce, &key);
        try testing.expectEqual(ret, 0);

        var st: aegis.aegis128l_state align(32) = undefined;
        var cx: []u8 = &c;
        var mx_src: []const u8 = &msg;

        aegis.aegis128l_state_init(&st, &ad, ad.len, &nonce, &key);

        while (mx_src.len >= rate) {
            const chunk = mx_src[0..rate];
            ret = aegis.aegis128l_state_encrypt_update(&st, cx.ptr, chunk.ptr, rate);
            try testing.expectEqual(ret, 0);
            cx = cx[rate..];
            mx_src = mx_src[rate..];
        }

        if (mx_src.len > 0) {
            ret = aegis.aegis128l_state_encrypt_update(&st, cx.ptr, mx_src.ptr, mx_src.len);
            try testing.expectEqual(ret, 0);
            cx = cx[mx_src.len..];
        }

        ret = aegis.aegis128l_state_encrypt_final(&st, &mac, mac.len);
        try testing.expectEqual(ret, 0);
        try testing.expectEqual(cx.len, 0);

        try testing.expectEqualSlices(u8, &c, &c2);
        try testing.expectEqualSlices(u8, &mac, &mac2);
    }
}

test "aegis-256 - streaming at RATE boundaries" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    const mac_len: usize = 32;
    const rate: usize = 16;

    const test_sizes = [_]usize{ rate - 1, rate, rate + 1, rate * 2, rate * 5 + 7 };

    inline for (test_sizes) |msg_len| {
        var msg: [msg_len]u8 = undefined;
        var c: [msg_len]u8 = undefined;
        var c2: [msg_len]u8 = undefined;
        var ad: [10]u8 = undefined;
        var mac: [mac_len]u8 = undefined;
        var mac2: [mac_len]u8 = undefined;

        random.bytes(&ad);
        for (&msg, 0..) |*byte, i| byte.* = @truncate(i);

        var nonce: [aegis.aegis256_NPUBBYTES]u8 = undefined;
        random.bytes(&nonce);
        var key: [aegis.aegis256_KEYBYTES]u8 = undefined;
        random.bytes(&key);

        var ret = aegis.aegis256_encrypt_detached(&c2, &mac2, mac_len, &msg, msg_len, &ad, ad.len, &nonce, &key);
        try testing.expectEqual(ret, 0);

        var st: aegis.aegis256_state = undefined;
        var cx: []u8 = &c;
        var mx_src: []const u8 = &msg;

        aegis.aegis256_state_init(&st, &ad, ad.len, &nonce, &key);

        while (mx_src.len >= rate) {
            const chunk = mx_src[0..rate];
            ret = aegis.aegis256_state_encrypt_update(&st, cx.ptr, chunk.ptr, rate);
            try testing.expectEqual(ret, 0);
            cx = cx[rate..];
            mx_src = mx_src[rate..];
        }

        if (mx_src.len > 0) {
            ret = aegis.aegis256_state_encrypt_update(&st, cx.ptr, mx_src.ptr, mx_src.len);
            try testing.expectEqual(ret, 0);
            cx = cx[mx_src.len..];
        }

        ret = aegis.aegis256_state_encrypt_final(&st, &mac, mac.len);
        try testing.expectEqual(ret, 0);
        try testing.expectEqual(cx.len, 0);

        try testing.expectEqualSlices(u8, &c, &c2);
        try testing.expectEqualSlices(u8, &mac, &mac2);
    }
}

test "aegis-128l - streaming with empty updates" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    const mac_len: usize = 16;
    var msg: [100]u8 = undefined;
    var c: [100]u8 = undefined;
    var c2: [100]u8 = undefined;
    var ad: [10]u8 = undefined;
    var mac: [mac_len]u8 = undefined;
    var mac2: [mac_len]u8 = undefined;

    random.bytes(&ad);
    for (&msg, 0..) |*m, i| m.* = @truncate(i);

    var nonce: [aegis.aegis128l_NPUBBYTES]u8 = undefined;
    random.bytes(&nonce);
    var key: [aegis.aegis128l_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    var ret = aegis.aegis128l_encrypt_detached(&c2, &mac2, mac_len, &msg, msg.len, &ad, ad.len, &nonce, &key);
    try testing.expectEqual(ret, 0);

    var st: aegis.aegis128l_state align(32) = undefined;
    var cx: []u8 = &c;
    aegis.aegis128l_state_init(&st, &ad, ad.len, &nonce, &key);

    ret = aegis.aegis128l_state_encrypt_update(&st, cx.ptr, null, 0);
    try testing.expectEqual(ret, 0);

    const mid = msg.len / 2;
    ret = aegis.aegis128l_state_encrypt_update(&st, cx.ptr, &msg, mid);
    try testing.expectEqual(ret, 0);
    cx = cx[mid..];

    ret = aegis.aegis128l_state_encrypt_update(&st, cx.ptr, null, 0);
    try testing.expectEqual(ret, 0);

    ret = aegis.aegis128l_state_encrypt_update(&st, cx.ptr, msg[mid..].ptr, msg.len - mid);
    try testing.expectEqual(ret, 0);
    cx = cx[msg.len - mid ..];

    ret = aegis.aegis128l_state_encrypt_update(&st, cx.ptr, null, 0);
    try testing.expectEqual(ret, 0);

    ret = aegis.aegis128l_state_encrypt_final(&st, &mac, mac.len);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(cx.len, 0);

    try testing.expectEqualSlices(u8, &c, &c2);
    try testing.expectEqualSlices(u8, &mac, &mac2);
}

test "aegis-256 - streaming with empty updates" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    const mac_len: usize = 32;
    var msg: [100]u8 = undefined;
    var c: [100]u8 = undefined;
    var c2: [100]u8 = undefined;
    var ad: [10]u8 = undefined;
    var mac: [mac_len]u8 = undefined;
    var mac2: [mac_len]u8 = undefined;

    random.bytes(&ad);
    for (&msg, 0..) |*m, i| m.* = @truncate(i);

    var nonce: [aegis.aegis256_NPUBBYTES]u8 = undefined;
    random.bytes(&nonce);
    var key: [aegis.aegis256_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    var ret = aegis.aegis256_encrypt_detached(&c2, &mac2, mac_len, &msg, msg.len, &ad, ad.len, &nonce, &key);
    try testing.expectEqual(ret, 0);

    var st: aegis.aegis256_state = undefined;
    var cx: []u8 = &c;
    aegis.aegis256_state_init(&st, &ad, ad.len, &nonce, &key);

    ret = aegis.aegis256_state_encrypt_update(&st, cx.ptr, null, 0);
    try testing.expectEqual(ret, 0);

    const mid = msg.len / 2;
    ret = aegis.aegis256_state_encrypt_update(&st, cx.ptr, &msg, mid);
    try testing.expectEqual(ret, 0);
    cx = cx[mid..];

    ret = aegis.aegis256_state_encrypt_update(&st, cx.ptr, null, 0);
    try testing.expectEqual(ret, 0);

    ret = aegis.aegis256_state_encrypt_update(&st, cx.ptr, msg[mid..].ptr, msg.len - mid);
    try testing.expectEqual(ret, 0);
    cx = cx[msg.len - mid ..];

    ret = aegis.aegis256_state_encrypt_update(&st, cx.ptr, null, 0);
    try testing.expectEqual(ret, 0);

    ret = aegis.aegis256_state_encrypt_final(&st, &mac, mac.len);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(cx.len, 0);

    try testing.expectEqualSlices(u8, &c, &c2);
    try testing.expectEqualSlices(u8, &mac, &mac2);
}

test "aegis-128l - streaming decryption with wrong MAC fails" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    const mac_len: usize = 16;
    var msg: [100]u8 = undefined;
    var msg2: [100]u8 = undefined;
    var c: [100]u8 = undefined;
    var ad: [10]u8 = undefined;
    var mac: [mac_len]u8 = undefined;

    random.bytes(&ad);
    for (&msg, 0..) |*m, i| m.* = @truncate(i);

    var nonce: [aegis.aegis128l_NPUBBYTES]u8 = undefined;
    random.bytes(&nonce);
    var key: [aegis.aegis128l_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    var ret = aegis.aegis128l_encrypt_detached(&c, &mac, mac_len, &msg, msg.len, &ad, ad.len, &nonce, &key);
    try testing.expectEqual(ret, 0);

    mac[0] ^= 0x01;

    var st: aegis.aegis128l_state align(32) = undefined;
    var mx: []u8 = &msg2;

    aegis.aegis128l_state_init(&st, &ad, ad.len, &nonce, &key);
    ret = aegis.aegis128l_state_decrypt_update(&st, mx.ptr, &c, c.len);
    try testing.expectEqual(ret, 0);
    mx = mx[c.len..];

    ret = aegis.aegis128l_state_decrypt_final(&st, &mac, mac_len);
    try testing.expectEqual(ret, -1);
}

test "aegis-256 - streaming decryption with wrong MAC fails" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    const mac_len: usize = 32;
    var msg: [100]u8 = undefined;
    var msg2: [100]u8 = undefined;
    var c: [100]u8 = undefined;
    var ad: [10]u8 = undefined;
    var mac: [mac_len]u8 = undefined;

    random.bytes(&ad);
    for (&msg, 0..) |*m, i| m.* = @truncate(i);

    var nonce: [aegis.aegis256_NPUBBYTES]u8 = undefined;
    random.bytes(&nonce);
    var key: [aegis.aegis256_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    var ret = aegis.aegis256_encrypt_detached(&c, &mac, mac_len, &msg, msg.len, &ad, ad.len, &nonce, &key);
    try testing.expectEqual(ret, 0);

    mac[15] ^= 0xff;

    var st: aegis.aegis256_state = undefined;
    var mx: []u8 = &msg2;

    aegis.aegis256_state_init(&st, &ad, ad.len, &nonce, &key);
    ret = aegis.aegis256_state_decrypt_update(&st, mx.ptr, &c, c.len);
    try testing.expectEqual(ret, 0);
    mx = mx[c.len..];

    ret = aegis.aegis256_state_decrypt_final(&st, &mac, mac_len);
    try testing.expectEqual(ret, -1);
}

test "aegis-128x2 - streaming at RATE boundaries" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    const mac_len: usize = 16;
    const rate: usize = 64;
    const msg_len: usize = rate * 2 + 13;

    var msg: [msg_len]u8 = undefined;
    var c: [msg_len]u8 = undefined;
    var c2: [msg_len]u8 = undefined;
    var ad: [10]u8 = undefined;
    var mac: [mac_len]u8 = undefined;
    var mac2: [mac_len]u8 = undefined;

    random.bytes(&ad);
    for (&msg, 0..) |*byte, i| byte.* = @truncate(i);

    var nonce: [aegis.aegis128x2_NPUBBYTES]u8 = undefined;
    random.bytes(&nonce);
    var key: [aegis.aegis128x2_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    var ret = aegis.aegis128x2_encrypt_detached(&c2, &mac2, mac_len, &msg, msg_len, &ad, ad.len, &nonce, &key);
    try testing.expectEqual(ret, 0);

    var st: aegis.aegis128x2_state align(64) = undefined;
    var cx: []u8 = &c;
    var mx_src: []const u8 = &msg;

    aegis.aegis128x2_state_init(&st, &ad, ad.len, &nonce, &key);

    while (mx_src.len >= rate) {
        const chunk = mx_src[0..rate];
        ret = aegis.aegis128x2_state_encrypt_update(&st, cx.ptr, chunk.ptr, rate);
        try testing.expectEqual(ret, 0);
        cx = cx[rate..];
        mx_src = mx_src[rate..];
    }

    if (mx_src.len > 0) {
        ret = aegis.aegis128x2_state_encrypt_update(&st, cx.ptr, mx_src.ptr, mx_src.len);
        try testing.expectEqual(ret, 0);
        cx = cx[mx_src.len..];
    }

    ret = aegis.aegis128x2_state_encrypt_final(&st, &mac, mac.len);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(cx.len, 0);

    try testing.expectEqualSlices(u8, &c, &c2);
    try testing.expectEqualSlices(u8, &mac, &mac2);
}

test "aegis-128x4 - streaming at RATE boundaries" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    const mac_len: usize = 32;
    const rate: usize = 128;
    const msg_len: usize = rate * 2 + 17;

    var msg: [msg_len]u8 = undefined;
    var c: [msg_len]u8 = undefined;
    var c2: [msg_len]u8 = undefined;
    var ad: [15]u8 = undefined;
    var mac: [mac_len]u8 = undefined;
    var mac2: [mac_len]u8 = undefined;

    random.bytes(&ad);
    for (&msg, 0..) |*byte, i| byte.* = @truncate(i);

    var nonce: [aegis.aegis128x4_NPUBBYTES]u8 = undefined;
    random.bytes(&nonce);
    var key: [aegis.aegis128x4_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    var ret = aegis.aegis128x4_encrypt_detached(&c2, &mac2, mac_len, &msg, msg_len, &ad, ad.len, &nonce, &key);
    try testing.expectEqual(ret, 0);

    var st: aegis.aegis128x4_state align(64) = undefined;
    var cx: []u8 = &c;
    var mx_src: []const u8 = &msg;

    aegis.aegis128x4_state_init(&st, &ad, ad.len, &nonce, &key);

    while (mx_src.len >= rate) {
        const chunk = mx_src[0..rate];
        ret = aegis.aegis128x4_state_encrypt_update(&st, cx.ptr, chunk.ptr, rate);
        try testing.expectEqual(ret, 0);
        cx = cx[rate..];
        mx_src = mx_src[rate..];
    }

    if (mx_src.len > 0) {
        ret = aegis.aegis128x4_state_encrypt_update(&st, cx.ptr, mx_src.ptr, mx_src.len);
        try testing.expectEqual(ret, 0);
        cx = cx[mx_src.len..];
    }

    ret = aegis.aegis128x4_state_encrypt_final(&st, &mac, mac.len);
    try testing.expectEqual(ret, 0);
    try testing.expectEqual(cx.len, 0);

    try testing.expectEqualSlices(u8, &c, &c2);
    try testing.expectEqualSlices(u8, &mac, &mac2);
}

test "aegis-256x2 - streaming at RATE boundaries" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    const mac_len: usize = 16;
    const rate: usize = 32;
    const msg_len: usize = rate * 3 + 7;

    var msg: [msg_len]u8 = undefined;
    var c: [msg_len]u8 = undefined;
    var c2: [msg_len]u8 = undefined;
    var ad: [12]u8 = undefined;
    var mac: [mac_len]u8 = undefined;
    var mac2: [mac_len]u8 = undefined;

    random.bytes(&ad);
    for (&msg, 0..) |*byte, i| byte.* = @truncate(i);

    var nonce: [aegis.aegis256x2_NPUBBYTES]u8 = undefined;
    random.bytes(&nonce);
    var key: [aegis.aegis256x2_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    var ret = aegis.aegis256x2_encrypt_detached(&c2, &mac2, mac_len, &msg, msg_len, &ad, ad.len, &nonce, &key);
    try testing.expectEqual(ret, 0);

    var st: aegis.aegis256x2_state align(32) = undefined;
    var cx: []u8 = &c;
    var mx_src: []const u8 = &msg;

    aegis.aegis256x2_state_init(&st, &ad, ad.len, &nonce, &key);

    while (mx_src.len >= rate) {
        const chunk = mx_src[0..rate];
        ret = aegis.aegis256x2_state_encrypt_update(&st, cx.ptr, chunk.ptr, rate);
        try testing.expectEqual(ret, 0);
        cx = cx[rate..];
        mx_src = mx_src[rate..];
    }

    if (mx_src.len > 0) {
        ret = aegis.aegis256x2_state_encrypt_update(&st, cx.ptr, mx_src.ptr, mx_src.len);
        try testing.expectEqual(ret, 0);
        cx = cx[mx_src.len..];
    }

    ret = aegis.aegis256x2_state_encrypt_final(&st, &mac, mac_len);
    try testing.expectEqual(ret, 0);

    try testing.expectEqualSlices(u8, &c, &c2);
    try testing.expectEqualSlices(u8, &mac, &mac2);
}

test "aegis-256x4 - streaming at RATE boundaries" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    const mac_len: usize = 32;
    const rate: usize = 64;
    const msg_len: usize = rate * 2 + 11;

    var msg: [msg_len]u8 = undefined;
    var c: [msg_len]u8 = undefined;
    var c2: [msg_len]u8 = undefined;
    var ad: [20]u8 = undefined;
    var mac: [mac_len]u8 = undefined;
    var mac2: [mac_len]u8 = undefined;

    random.bytes(&ad);
    for (&msg, 0..) |*byte, i| byte.* = @truncate(i);

    var nonce: [aegis.aegis256x4_NPUBBYTES]u8 = undefined;
    random.bytes(&nonce);
    var key: [aegis.aegis256x4_KEYBYTES]u8 = undefined;
    random.bytes(&key);

    var ret = aegis.aegis256x4_encrypt_detached(&c2, &mac2, mac_len, &msg, msg_len, &ad, ad.len, &nonce, &key);
    try testing.expectEqual(ret, 0);

    var st: aegis.aegis256x4_state align(64) = undefined;
    var cx: []u8 = &c;
    var mx_src: []const u8 = &msg;

    aegis.aegis256x4_state_init(&st, &ad, ad.len, &nonce, &key);

    while (mx_src.len >= rate) {
        const chunk = mx_src[0..rate];
        ret = aegis.aegis256x4_state_encrypt_update(&st, cx.ptr, chunk.ptr, rate);
        try testing.expectEqual(ret, 0);
        cx = cx[rate..];
        mx_src = mx_src[rate..];
    }

    if (mx_src.len > 0) {
        ret = aegis.aegis256x4_state_encrypt_update(&st, cx.ptr, mx_src.ptr, mx_src.len);
        try testing.expectEqual(ret, 0);
        cx = cx[mx_src.len..];
    }

    ret = aegis.aegis256x4_state_encrypt_final(&st, &mac, mac_len);
    try testing.expectEqual(ret, 0);

    try testing.expectEqualSlices(u8, &c, &c2);
    try testing.expectEqualSlices(u8, &mac, &mac2);
}

test "aegis-128l - streaming decryption with written validation" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    const mac_len: usize = 16;
    const rate: usize = 32;

    const chunk_sizes = [_]usize{ 1, 7, rate - 1, rate, rate + 1, rate + 7, rate * 2 - 3 };

    inline for (chunk_sizes) |chunk_size| {
        const msg_len: usize = rate * 3 + 13;

        var msg: [msg_len]u8 = undefined;
        var c: [msg_len]u8 = undefined;
        var msg2: [msg_len]u8 = undefined;
        var ad: [10]u8 = undefined;
        var mac: [mac_len]u8 = undefined;

        random.bytes(&ad);
        for (&msg, 0..) |*byte, i| byte.* = @truncate(i);

        var nonce: [aegis.aegis128l_NPUBBYTES]u8 = undefined;
        random.bytes(&nonce);
        var key: [aegis.aegis128l_KEYBYTES]u8 = undefined;
        random.bytes(&key);

        var ret = aegis.aegis128l_encrypt_detached(&c, &mac, mac_len, &msg, msg_len, &ad, ad.len, &nonce, &key);
        try testing.expectEqual(ret, 0);

        var st: aegis.aegis128l_state align(32) = undefined;
        var mx: []u8 = &msg2;
        var cx_src: []const u8 = &c;

        aegis.aegis128l_state_init(&st, &ad, ad.len, &nonce, &key);

        while (cx_src.len > 0) {
            const chunk_len = @min(chunk_size, cx_src.len);
            const chunk = cx_src[0..chunk_len];
            ret = aegis.aegis128l_state_decrypt_update(&st, mx.ptr, chunk.ptr, chunk_len);
            try testing.expectEqual(ret, 0);
            mx = mx[chunk_len..];
            cx_src = cx_src[chunk_len..];
        }

        ret = aegis.aegis128l_state_decrypt_final(&st, &mac, mac_len);
        try testing.expectEqual(ret, 0);
        try testing.expectEqual(mx.len, 0);

        try testing.expectEqualSlices(u8, &msg, &msg2);
    }
}

test "aegis-256 - streaming decryption with written validation" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    const mac_len: usize = 32;
    const rate: usize = 16;

    const chunk_sizes = [_]usize{ 1, 5, rate - 1, rate, rate + 1, rate + 3, rate * 2 - 1 };

    inline for (chunk_sizes) |chunk_size| {
        const msg_len: usize = rate * 4 + 7;

        var msg: [msg_len]u8 = undefined;
        var c: [msg_len]u8 = undefined;
        var msg2: [msg_len]u8 = undefined;
        var ad: [10]u8 = undefined;
        var mac: [mac_len]u8 = undefined;

        random.bytes(&ad);
        for (&msg, 0..) |*byte, i| byte.* = @truncate(i);

        var nonce: [aegis.aegis256_NPUBBYTES]u8 = undefined;
        random.bytes(&nonce);
        var key: [aegis.aegis256_KEYBYTES]u8 = undefined;
        random.bytes(&key);

        var ret = aegis.aegis256_encrypt_detached(&c, &mac, mac_len, &msg, msg_len, &ad, ad.len, &nonce, &key);
        try testing.expectEqual(ret, 0);

        var st: aegis.aegis256_state = undefined;
        var mx: []u8 = &msg2;
        var cx_src: []const u8 = &c;

        aegis.aegis256_state_init(&st, &ad, ad.len, &nonce, &key);

        while (cx_src.len > 0) {
            const chunk_len = @min(chunk_size, cx_src.len);
            const chunk = cx_src[0..chunk_len];
            ret = aegis.aegis256_state_decrypt_update(&st, mx.ptr, chunk.ptr, chunk_len);
            try testing.expectEqual(ret, 0);
            mx = mx[chunk_len..];
            cx_src = cx_src[chunk_len..];
        }

        ret = aegis.aegis256_state_decrypt_final(&st, &mac, mac_len);
        try testing.expectEqual(ret, 0);
        try testing.expectEqual(mx.len, 0);

        try testing.expectEqualSlices(u8, &msg, &msg2);
    }
}

test "aegis-128x2 - streaming decryption with written validation" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    const mac_len: usize = 16;
    const rate: usize = 64;

    const chunk_sizes = [_]usize{ 1, 13, rate - 1, rate, rate + 1, rate + 11, rate * 2 - 5 };

    inline for (chunk_sizes) |chunk_size| {
        const msg_len: usize = rate * 3 + 19;

        var msg: [msg_len]u8 = undefined;
        var c: [msg_len]u8 = undefined;
        var msg2: [msg_len]u8 = undefined;
        var ad: [10]u8 = undefined;
        var mac: [mac_len]u8 = undefined;

        random.bytes(&ad);
        for (&msg, 0..) |*byte, i| byte.* = @truncate(i);

        var nonce: [aegis.aegis128x2_NPUBBYTES]u8 = undefined;
        random.bytes(&nonce);
        var key: [aegis.aegis128x2_KEYBYTES]u8 = undefined;
        random.bytes(&key);

        var ret = aegis.aegis128x2_encrypt_detached(&c, &mac, mac_len, &msg, msg_len, &ad, ad.len, &nonce, &key);
        try testing.expectEqual(ret, 0);

        var st: aegis.aegis128x2_state align(64) = undefined;
        var mx: []u8 = &msg2;
        var cx_src: []const u8 = &c;

        aegis.aegis128x2_state_init(&st, &ad, ad.len, &nonce, &key);

        while (cx_src.len > 0) {
            const chunk_len = @min(chunk_size, cx_src.len);
            const chunk = cx_src[0..chunk_len];
            ret = aegis.aegis128x2_state_decrypt_update(&st, mx.ptr, chunk.ptr, chunk_len);
            try testing.expectEqual(ret, 0);
            mx = mx[chunk_len..];
            cx_src = cx_src[chunk_len..];
        }

        ret = aegis.aegis128x2_state_decrypt_final(&st, &mac, mac_len);
        try testing.expectEqual(ret, 0);
        try testing.expectEqual(mx.len, 0);

        try testing.expectEqualSlices(u8, &msg, &msg2);
    }
}

test "aegis-128x4 - streaming decryption with written validation" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    const mac_len: usize = 32;
    const rate: usize = 128;

    const chunk_sizes = [_]usize{ 1, 17, rate - 1, rate, rate + 1, rate + 23, rate * 2 - 7 };

    inline for (chunk_sizes) |chunk_size| {
        const msg_len: usize = rate * 2 + 29;

        var msg: [msg_len]u8 = undefined;
        var c: [msg_len]u8 = undefined;
        var msg2: [msg_len]u8 = undefined;
        var ad: [15]u8 = undefined;
        var mac: [mac_len]u8 = undefined;

        random.bytes(&ad);
        for (&msg, 0..) |*byte, i| byte.* = @truncate(i);

        var nonce: [aegis.aegis128x4_NPUBBYTES]u8 = undefined;
        random.bytes(&nonce);
        var key: [aegis.aegis128x4_KEYBYTES]u8 = undefined;
        random.bytes(&key);

        var ret = aegis.aegis128x4_encrypt_detached(&c, &mac, mac_len, &msg, msg_len, &ad, ad.len, &nonce, &key);
        try testing.expectEqual(ret, 0);

        var st: aegis.aegis128x4_state align(64) = undefined;
        var mx: []u8 = &msg2;
        var cx_src: []const u8 = &c;

        aegis.aegis128x4_state_init(&st, &ad, ad.len, &nonce, &key);

        while (cx_src.len > 0) {
            const chunk_len = @min(chunk_size, cx_src.len);
            const chunk = cx_src[0..chunk_len];
            ret = aegis.aegis128x4_state_decrypt_update(&st, mx.ptr, chunk.ptr, chunk_len);
            try testing.expectEqual(ret, 0);
            mx = mx[chunk_len..];
            cx_src = cx_src[chunk_len..];
        }

        ret = aegis.aegis128x4_state_decrypt_final(&st, &mac, mac_len);
        try testing.expectEqual(ret, 0);
        try testing.expectEqual(mx.len, 0);

        try testing.expectEqualSlices(u8, &msg, &msg2);
    }
}

test "aegis-256x2 - streaming decryption with written validation" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    const mac_len: usize = 16;
    const rate: usize = 32;

    const chunk_sizes = [_]usize{ 1, 9, rate - 1, rate, rate + 1, rate + 5, rate * 2 - 3 };

    inline for (chunk_sizes) |chunk_size| {
        const msg_len: usize = rate * 3 + 11;

        var msg: [msg_len]u8 = undefined;
        var c: [msg_len]u8 = undefined;
        var msg2: [msg_len]u8 = undefined;
        var ad: [12]u8 = undefined;
        var mac: [mac_len]u8 = undefined;

        random.bytes(&ad);
        for (&msg, 0..) |*byte, i| byte.* = @truncate(i);

        var nonce: [aegis.aegis256x2_NPUBBYTES]u8 = undefined;
        random.bytes(&nonce);
        var key: [aegis.aegis256x2_KEYBYTES]u8 = undefined;
        random.bytes(&key);

        var ret = aegis.aegis256x2_encrypt_detached(&c, &mac, mac_len, &msg, msg_len, &ad, ad.len, &nonce, &key);
        try testing.expectEqual(ret, 0);

        var st: aegis.aegis256x2_state align(32) = undefined;
        var mx: []u8 = &msg2;
        var cx_src: []const u8 = &c;

        aegis.aegis256x2_state_init(&st, &ad, ad.len, &nonce, &key);

        while (cx_src.len > 0) {
            const chunk_len = @min(chunk_size, cx_src.len);
            const chunk = cx_src[0..chunk_len];
            ret = aegis.aegis256x2_state_decrypt_update(&st, mx.ptr, chunk.ptr, chunk_len);
            try testing.expectEqual(ret, 0);
            mx = mx[chunk_len..];
            cx_src = cx_src[chunk_len..];
        }

        ret = aegis.aegis256x2_state_decrypt_final(&st, &mac, mac_len);
        try testing.expectEqual(ret, 0);
        try testing.expectEqual(mx.len, 0);

        try testing.expectEqualSlices(u8, &msg, &msg2);
    }
}

test "aegis-256x4 - streaming decryption with written validation" {
    try testing.expectEqual(aegis.aegis_init(), 0);

    const mac_len: usize = 32;
    const rate: usize = 64;

    const chunk_sizes = [_]usize{ 1, 11, rate - 1, rate, rate + 1, rate + 7, rate * 2 - 9 };

    inline for (chunk_sizes) |chunk_size| {
        const msg_len: usize = rate * 2 + 17;

        var msg: [msg_len]u8 = undefined;
        var c: [msg_len]u8 = undefined;
        var msg2: [msg_len]u8 = undefined;
        var ad: [20]u8 = undefined;
        var mac: [mac_len]u8 = undefined;

        random.bytes(&ad);
        for (&msg, 0..) |*byte, i| byte.* = @truncate(i);

        var nonce: [aegis.aegis256x4_NPUBBYTES]u8 = undefined;
        random.bytes(&nonce);
        var key: [aegis.aegis256x4_KEYBYTES]u8 = undefined;
        random.bytes(&key);

        var ret = aegis.aegis256x4_encrypt_detached(&c, &mac, mac_len, &msg, msg_len, &ad, ad.len, &nonce, &key);
        try testing.expectEqual(ret, 0);

        var st: aegis.aegis256x4_state align(64) = undefined;
        var mx: []u8 = &msg2;
        var cx_src: []const u8 = &c;

        aegis.aegis256x4_state_init(&st, &ad, ad.len, &nonce, &key);

        while (cx_src.len > 0) {
            const chunk_len = @min(chunk_size, cx_src.len);
            const chunk = cx_src[0..chunk_len];
            ret = aegis.aegis256x4_state_decrypt_update(&st, mx.ptr, chunk.ptr, chunk_len);
            try testing.expectEqual(ret, 0);
            mx = mx[chunk_len..];
            cx_src = cx_src[chunk_len..];
        }

        ret = aegis.aegis256x4_state_decrypt_final(&st, &mac, mac_len);
        try testing.expectEqual(ret, 0);
        try testing.expectEqual(mx.len, 0);

        try testing.expectEqualSlices(u8, &msg, &msg2);
    }
}

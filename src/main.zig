const std = @import("std");

const Storage = u8;

const CascadeBitSet = struct {
    bits: []Storage,
    allocator: std.mem.Allocator,
    size: usize,

    pub fn init(allocator: std.mem.Allocator, size: usize) !@This() {
        const sz = (size + @sizeOf(Storage) - 1) / @sizeOf(Storage);
        const bits = try allocator.alloc(Storage, sz);
        for (bits) |*b| {
            b.* = 0;
        }
        return @This(){
            .bits = bits,
            .allocator = allocator,
            .size = size,
        };
    }

    pub fn deinit(self: *@This()) void {
        self.allocator.free(self.bits);
        self.bits = undefined;
        self.size = 0;
    }

    pub fn toOwnBytes(self: *@This()) []u8 {
        defer self.bits = undefined;
        defer self.size = 0;
        return std.mem.sliceAsBytes(self.bits);
    }

    pub fn asBytes(self: *const @This()) []const u8 {
        return std.mem.sliceAsBytes(self.bits);
    }

    const IncError = error{Overflow};
    pub fn inc(self: *@This()) ?usize {
        var idx: usize = 0;
        var bitcount: usize = 0;
        while (idx < self.bits.len) : (idx += 1) {
            var val = self.bits[idx];
            if (val == std.math.maxInt(Storage)) {
                self.bits[idx] = 0;
                // don't inc bitcount here
                continue;
            }
            val += 1;
            self.bits[idx] = val;
            bitcount += @popCount(Storage, val);
            break;
        } else {
            // overflow
            return null;
        }

        idx += 1;
        while (idx < self.bits.len) : (idx += 1) {
            // finish counting bits
            bitcount += @popCount(Storage, self.bits[idx]);
        }

        return bitcount;
    }
};

const HashType = u32;

const ZcFile = packed struct {
    set_bits: u64,
    byte_count: u64,
    hash: HashType,

    pub fn print(self: *const @This(), writer: anytype) !void {
        try writer.print("Bits: {x}, Bytes: {x}, Hash: {}\n", .{
            self.set_bits,
            self.byte_count,
            std.fmt.fmtSliceHexLower(std.mem.asBytes(&self.hash)),
        });
    }
};

pub fn main() anyerror!void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer {
        _ = gpa.deinit();
    }
    const alloc = gpa.allocator();
    const args = try std.process.argsAlloc(alloc);
    defer std.process.argsFree(alloc, args);
    const out = std.io.getStdOut().writer();
    if (args.len != 3) {
        try out.print("Usage: {s} FUNCTION FILE\n", .{args[0]});
        return;
    }

    const file = try std.fs.cwd().openFile(args[2], .{});
    errdefer file.close();
    const zcf = try file.reader().readStruct(ZcFile);
    file.close();

    try zcf.print(out);

    var bits = try CascadeBitSet.init(alloc, zcf.byte_count);
    defer bits.deinit();

    while (bits.inc()) |count| {
        if (count != zcf.set_bits) continue;
        //var hash: [32]u8 = undefined;
        //std.crypto.hash.sha2.Sha256.hash(bits.asBytes(), &hash, .{});
        if (std.hash.Crc32.hash(bits.asBytes()) == zcf.hash)
            break;
        //if (std.mem.eql(u8, &zcf.hash, &hash)) {
        //    break;
        //}
    } else {
        try out.print("oop no results, probably a bug somewhere...\n", .{});
        return;
    }

    try out.writeAll(bits.asBytes());
}

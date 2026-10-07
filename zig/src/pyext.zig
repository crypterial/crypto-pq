//! crypto_pq._cpq, the CPython extension module of the Python package's native backend: the C ABI
//! of capi.zig called in place, one Python call per operation, for CPython 3.11 and later with a
//! GIL (its stable ABI, abi3). ctypes serves the other interpreters with the plain library.
//!
//! The functions keep the C ABI's rules and the ctypes binding's: inputs come through the buffer
//! protocol and stay exported until the call returns; outputs are new bytes objects of the exact
//! size, written in place by the library and zeroed if the call fails; keys, hash states,
//! configured algorithms and stateful signers live in slots, memory that the module allocates and
//! wipes when the slot object goes. A call that computes releases the GIL, as hashlib does for
//! large inputs (releasing it costs about 20 ns, against microseconds of work): a hash, XOF or MAC
//! of 2048 bytes or more,
//! and key generation, private and ML-DSA public key import, encapsulation, decapsulation,
//! signing and verification when every input is a bytes object, which no other thread can change
//! meanwhile. Copies, exports and checks keep it. Statuses become the exceptions of the package's
//! own `failure` function, which `setup` hands over.

const std = @import("std");

const capi = @import("capi.zig");
const ct = @import("ct.zig");
const py = @import("pyext/cpython.zig");

const common = capi.common;

const Object = py.Object;

pub const panic = std.debug.no_panic;

pub const _DllMainCRTStartup = capi._DllMainCRTStartup;

const invalid_length: c_int = 1;

const invalid_public_key: c_int = 4;

const invalid_private_key: c_int = 5;

const self_test_failed: c_int = 9;

const unsupported: c_int = 13;

const refused = "the native library refused the operation";

// hashlib keeps the GIL below this many bytes, where releasing it costs more than it gives.
const unlocked_size = 2048;

const State = struct {
    slot_type: ?*Object,
    bytes_type: ?*Object,
    failure: ?*Object,
};

fn stateOf(module: *Object) *State {
    return @ptrCast(@alignCast(py.PyModule_GetState(module).?));
}

fn none() *Object {
    const object = py.none();

    py.Py_IncRef(object);

    return object;
}

fn boolean(value: bool) ?*Object {
    return py.PyBool_FromLong(@intFromBool(value));
}

fn typeError(message: [*:0]const u8) ?*Object {
    py.PyErr_SetString(py.exception("PyExc_TypeError"), message);

    return null;
}

// The exception that the package's failure(status, message) makes, raised.
fn raise(module: *Object, status: c_int, message: [*:0]const u8) ?*Object {
    const failure = stateOf(module).failure orelse {
        py.PyErr_SetString(py.exception("PyExc_RuntimeError"), "crypto_pq._cpq was not set up");

        return null;
    };

    const arguments = tuple(&.{ py.PyLong_FromLong(status), py.PyUnicode_FromString(message) }) orelse return null;

    defer py.Py_DecRef(arguments);

    const exception = py.PyObject_CallObject(failure, arguments) orelse return null;

    defer py.Py_DecRef(exception);

    py.PyErr_SetObject(exception.type.?, exception);

    return null;
}

// A tuple of new references, which it takes over; null, with every one of them released, when one
// is missing or the tuple cannot be made.
fn tuple(items: []const ?*Object) ?*Object {
    const out = py.PyTuple_New(@intCast(items.len)) orelse {
        for (items) |item| py.Py_DecRef(item);

        return null;
    };

    var failed = false;

    for (items, 0..) |item, i| {
        if (item) |object| {
            if (py.PyTuple_SetItem(out, @intCast(i), object) != 0) failed = true;
        } else {
            failed = true;
        }
    }

    if (!failed) return out;

    py.Py_DecRef(out);

    return null;
}

// The GIL, released for the library call when `release` says so.
const Gil = struct {
    thread: ?*anyopaque,

    fn release(condition: bool) Gil {
        return .{ .thread = if (condition) py.PyEval_SaveThread() else null };
    }

    fn restore(self: Gil) void {
        if (self.thread) |thread| py.PyEval_RestoreThread(thread);
    }
};

// A new bytes object of `length` bytes that the library writes.
const Output = struct {
    object: *Object,
    bytes: []u8,

    fn init(length: usize) ?Output {
        if (length > std.math.maxInt(isize)) {
            _ = py.PyErr_NoMemory();

            return null;
        }

        const object = py.PyBytes_FromStringAndSize(null, @intCast(length)) orelse return null;

        return .{ .object = object, .bytes = py.PyBytes_AsString(object).?[0..length] };
    }

    // For an output that may hold part of a secret.
    fn discard(self: Output) void {
        ct.wipe(self.bytes);

        py.Py_DecRef(self.object);
    }
};

fn finish(module: *Object, status: c_int, message: [*:0]const u8, result: Output) ?*Object {
    if (status == common.ok) return result.object;

    result.discard();

    return raise(module, status, message);
}

// A slot: the library's memory for one key, hash state or stateful signer, inside a bytearray
// that it holds exported, so that nothing can resize it, and that holds nothing else.
const Slot = extern struct {
    object: Object,
    view: py.Buffer,
    memory: [*]u8,
    size: usize,
    algorithm: u32,

    fn base(self: *Slot) *Object {
        return &self.object;
    }

    fn drop(self: *Slot) void {
        py.Py_DecRef(&self.object);
    }
};

fn newSlot(module: *Object, slot_type: common.SlotType, algorithm: u32) ?*Slot {
    const size = capi.slotSize(@intFromEnum(slot_type), algorithm);

    if (size == 0) {
        _ = raise(module, common.bad_argument, refused);

        return null;
    }

    const memory = py.PyByteArray_FromStringAndSize(null, @intCast(size + common.slot_alignment - 1)) orelse return null;

    defer py.Py_DecRef(memory);

    const slot: *Slot = @ptrCast(@alignCast(py.PyType_GenericAlloc(stateOf(module).slot_type.?, 0) orelse return null));

    if (py.PyObject_GetBuffer(memory, &slot.view, py.PyBUF_WRITABLE) != 0) {
        slot.view.obj = null;

        slot.drop();

        return null;
    }

    const start = @intFromPtr(slot.view.buf.?);

    slot.memory = @ptrFromInt(std.mem.alignForward(usize, start, common.slot_alignment));

    slot.size = size;

    slot.algorithm = algorithm;

    // The library creates slots only in memory that holds none.
    @memset(slot.memory[0..@sizeOf(common.Header)], 0);

    return slot;
}

// A wipe that the library refuses, as it does for a slot that a call is inside, keeps the memory
// and its export for good rather than free them under that call. No slot object goes while a call
// holds it, so this does not happen.
fn slotDealloc(object: ?*Object) callconv(.c) void {
    const slot: *Slot = @ptrCast(@alignCast(object.?));

    const slot_type = slot.object.type.?;

    if (slot.view.obj != null and capi.slotWipe(slot.memory, slot.size) == common.ok) {
        ct.wipe(slot.view.buf.?[0..@intCast(slot.view.len)]);

        py.PyBuffer_Release(&slot.view);
    }

    const release: *const fn (?*anyopaque) callconv(.c) void = @ptrCast(@alignCast(py.PyType_GetSlot(slot_type, py.Py_tp_free).?));

    release(object);

    py.Py_DecRef(slot_type);
}

// A copy would keep the address of the memory and wipe it when it goes.
fn slotReduce(object: ?*Object, protocol: ?*Object) callconv(.c) ?*Object {
    _ = .{ object, protocol };

    return typeError("crypto-pq's native keys and states cannot be copied or pickled");
}

// The memory, its slot's offset and its size, for the tests that check the wipe.
fn slotMemory(object: ?*Object, closure: ?*anyopaque) callconv(.c) ?*Object {
    _ = closure;

    const slot: *Slot = @ptrCast(@alignCast(object.?));

    py.Py_IncRef(slot.view.obj);

    return slot.view.obj;
}

fn slotOffset(object: ?*Object, closure: ?*anyopaque) callconv(.c) ?*Object {
    _ = closure;

    const slot: *Slot = @ptrCast(@alignCast(object.?));

    return py.PyLong_FromUnsignedLongLong(@intFromPtr(slot.memory) - @intFromPtr(slot.view.buf.?));
}

fn slotSize(object: ?*Object, closure: ?*anyopaque) callconv(.c) ?*Object {
    _ = closure;

    const slot: *Slot = @ptrCast(@alignCast(object.?));

    return py.PyLong_FromUnsignedLongLong(slot.size);
}

const slot_methods = [_]py.MethodDef{
    .{ .name = "__reduce_ex__", .method = @ptrCast(&slotReduce), .flags = py.METH_O, .doc = null },
    .{ .name = null, .method = null, .flags = 0, .doc = null },
};

const slot_getset = [_]py.GetSetDef{
    .{ .name = "_memory", .get = &slotMemory, .set = null, .doc = null, .closure = null },
    .{ .name = "offset", .get = &slotOffset, .set = null, .doc = null, .closure = null },
    .{ .name = "size", .get = &slotSize, .set = null, .doc = null, .closure = null },
    .{ .name = null, .get = null, .set = null, .doc = null, .closure = null },
};

const slot_type_slots = [_]py.TypeSlot{
    .{ .slot = py.Py_tp_dealloc, .value = @ptrCast(&slotDealloc) },
    .{ .slot = py.Py_tp_methods, .value = @ptrCast(&slot_methods) },
    .{ .slot = py.Py_tp_getset, .value = @ptrCast(&slot_getset) },
    .{ .slot = 0, .value = null },
};

const slot_spec = py.TypeSpec{
    .name = "crypto_pq._cpq.Slot",
    .basic_size = @sizeOf(Slot),
    .item_size = 0,
    .flags = py.Py_TPFLAGS_DISALLOW_INSTANTIATION | py.Py_TPFLAGS_IMMUTABLETYPE,
    .slots = &slot_type_slots,
};

// A buffer argument; `fixed` when it is a bytes object, which no thread can change.
const Input = struct {
    bytes: []const u8,
    fixed: bool,
};

fn allFixed(inputs: []const Input) bool {
    for (inputs) |item| {
        if (!item.fixed) return false;
    }

    return true;
}

// An output length; a negative one is crypto-pq's INVALID_LENGTH, as in the pure backend.
const Length = struct {
    value: usize,
};

fn inputArgument(module: *Object, object: *Object, view: *py.Buffer, held: *bool) ?Input {
    if (py.PyObject_GetBuffer(object, view, py.PyBUF_SIMPLE) != 0) {
        // A buffer that is not C-contiguous is the same TypeError as in the pure backend.
        if (py.PyErr_ExceptionMatches(py.exception("PyExc_BufferError")) != 0) _ = typeError("a C-contiguous bytes-like object is required");

        return null;
    }

    held.* = true;

    const length: usize = @intCast(view.len);

    const bytes: []const u8 = if (length == 0) &.{} else view.buf.?[0..length];

    return .{ .bytes = bytes, .fixed = view.obj != null and view.obj.?.type == stateOf(module).bytes_type };
}

fn integer(comptime T: type, object: *Object) ?T {
    const value = py.PyLong_AsUnsignedLongLong(object);

    if (value == std.math.maxInt(c_ulonglong) and py.PyErr_Occurred() != null) return null;

    if (value > std.math.maxInt(T)) {
        py.PyErr_SetString(py.exception("PyExc_OverflowError"), "the integer is out of range");

        return null;
    }

    return @intCast(value);
}

fn lengthArgument(module: *Object, object: *Object) ?Length {
    const value = py.PyLong_AsLongLong(object);

    if (value == -1 and py.PyErr_Occurred() != null) return null;

    if (value < 0) {
        _ = raise(module, invalid_length, "length must not be negative");

        return null;
    }

    return .{ .value = @intCast(value) };
}

fn slotArgument(module: *Object, object: *Object) ?*Slot {
    if (object.type != stateOf(module).slot_type) {
        _ = typeError("expected a slot of crypto_pq._cpq");

        return null;
    }

    return @ptrCast(@alignCast(object));
}

fn arity(comptime F: type) usize {
    return @typeInfo(F).@"fn".params.len - 1;
}

// The METH_FASTCALL function of `f`, whose first parameter is the module and whose others are
// converted from the arguments by their types. Buffers are released after the call returns.
fn fast(comptime f: anytype) *const anyopaque {
    const F = @TypeOf(f);

    const params = @typeInfo(F).@"fn".params;

    const count = arity(F);

    return @ptrCast(&struct {
        fn call(self: ?*Object, args: [*]const ?*Object, given: isize) callconv(.c) ?*Object {
            const module = self.?;

            if (given != count) return typeError(std.fmt.comptimePrint("the function takes {d} arguments", .{count}));

            var values: std.meta.ArgsTuple(F) = undefined;

            values[0] = module;

            var views: [count]py.Buffer = undefined;

            var held: [count]bool = @splat(false);

            defer {
                for (&views, held) |*view, h| {
                    if (h) py.PyBuffer_Release(view);
                }
            }

            inline for (params[1..], 0..) |param, i| {
                const object = args[i].?;

                values[i + 1] = switch (param.type.?) {
                    Input => inputArgument(module, object, &views[i], &held[i]) orelse return null,
                    ?Input => if (object == py.none()) null else inputArgument(module, object, &views[i], &held[i]) orelse return null,
                    u32, u64, usize => |T| integer(T, object) orelse return null,
                    Length => lengthArgument(module, object) orelse return null,
                    *Slot => slotArgument(module, object) orelse return null,
                    *Object => object,
                    else => @compileError("no conversion for " ++ @typeName(param.type.?)),
                };
            }

            return @call(.auto, f, values);
        }
    }.call);
}

fn method(comptime name: [:0]const u8, comptime f: anytype) py.MethodDef {
    return .{ .name = name, .method = fast(f), .flags = py.METH_FASTCALL, .doc = null };
}

fn abiVersion(module: *Object) ?*Object {
    _ = module;

    return py.PyLong_FromUnsignedLongLong(capi.abiVersion());
}

// The package's failure(status, message), which turns statuses into its exceptions.
fn setup(module: *Object, failure: *Object) ?*Object {
    if (py.PyCallable_Check(failure) == 0) return typeError("failure must be callable");

    const state = stateOf(module);

    py.Py_IncRef(failure);

    py.Py_DecRef(state.failure);

    state.failure = failure;

    return none();
}

fn slotInfo(module: *Object, slot: *Slot) ?*Object {
    var out: [3]u32 = undefined;

    const status = capi.slotInfo(slot.memory, slot.size, &out);

    if (status != common.ok) return raise(module, status, refused);

    return tuple(&.{ py.PyLong_FromUnsignedLongLong(out[0]), py.PyLong_FromUnsignedLongLong(out[1]), py.PyLong_FromUnsignedLongLong(out[2]) });
}

// Ends the slot before its object goes, as a test does to check that a wiped slot is refused.
fn wipe(module: *Object, slot: *Slot) ?*Object {
    _ = module;

    return py.PyLong_FromLong(capi.slotWipe(slot.memory, slot.size));
}

fn created(module: *Object, slot: *Slot, status: c_int, message: [*:0]const u8) ?*Object {
    if (status == common.ok) return slot.base();

    slot.drop();

    return raise(module, status, message);
}

// A slot made from a key, or None when the library finds the key invalid with `invalid`.
fn imported(module: *Object, slot: *Slot, status: c_int, invalid: c_int) ?*Object {
    if (status != invalid) return created(module, slot, status, refused);

    slot.drop();

    return none();
}

// An exported private key, or None when the key holds no such form.
fn exported(module: *Object, out: Output, status: c_int) ?*Object {
    if (status != unsupported) return finish(module, status, refused, out);

    out.discard();

    return none();
}

// The answer to a question: True, False for `no`, an exception for anything else.
fn answer(module: *Object, status: c_int, no: c_int) ?*Object {
    if (status == common.ok or status == no) return boolean(status == common.ok);

    return raise(module, status, refused);
}

const kem = struct {
    fn generate(module: *Object, algorithm: u32, seed: Input) ?*Object {
        const slot = newSlot(module, .kem_private, algorithm) orelse return null;

        const gil = Gil.release(seed.fixed);

        const status = capi.kem.keygen(algorithm, seed.bytes.ptr, seed.bytes.len, capi.kem.fill_cache, slot.memory, slot.size);

        gil.restore();

        return created(module, slot, status, refused);
    }

    fn importPublic(module: *Object, algorithm: u32, key: Input) ?*Object {
        const slot = newSlot(module, .kem_public, algorithm) orelse return null;

        return imported(module, slot, capi.kem.importPublic(algorithm, key.bytes.ptr, key.bytes.len, slot.memory, slot.size), invalid_public_key);
    }

    fn importPrivate(module: *Object, algorithm: u32, key: Input) ?*Object {
        const slot = newSlot(module, .kem_private, algorithm) orelse return null;

        const gil = Gil.release(key.fixed);

        const status = capi.kem.importPrivate(algorithm, key.bytes.ptr, key.bytes.len, slot.memory, slot.size);

        gil.restore();

        return imported(module, slot, status, invalid_private_key);
    }

    fn public(module: *Object, algorithm: u32, private: *Slot) ?*Object {
        const slot = newSlot(module, .kem_public, algorithm) orelse return null;

        return created(module, slot, capi.kem.publicFromPrivate(private.memory, private.size, slot.memory, slot.size), refused);
    }

    fn exportPublic(module: *Object, slot: *Slot, size: usize) ?*Object {
        const out = Output.init(size) orelse return null;

        return finish(module, capi.kem.exportPublic(slot.memory, slot.size, out.bytes.ptr, out.bytes.len), refused, out);
    }

    fn exportPrivate(module: *Object, slot: *Slot, which: u32, size: usize) ?*Object {
        const out = Output.init(size) orelse return null;

        return exported(module, out, capi.kem.exportPrivate(slot.memory, slot.size, which, out.bytes.ptr, out.bytes.len));
    }

    // (shared secret, ciphertext).
    fn encapsulate(module: *Object, slot: *Slot, randomness: Input, size: usize) ?*Object {
        const ciphertext = Output.init(size) orelse return null;

        const secret = Output.init(32) orelse {
            py.Py_DecRef(ciphertext.object);

            return null;
        };

        const gil = Gil.release(randomness.fixed);

        const status = capi.kem.encapsulate(slot.memory, slot.size, randomness.bytes.ptr, randomness.bytes.len, ciphertext.bytes.ptr, ciphertext.bytes.len, secret.bytes.ptr, secret.bytes.len);

        gil.restore();

        if (status != common.ok) {
            secret.discard();

            py.Py_DecRef(ciphertext.object);

            return raise(module, status, refused);
        }

        return tuple(&.{ secret.object, ciphertext.object });
    }

    fn decapsulate(module: *Object, slot: *Slot, ciphertext: Input) ?*Object {
        const secret = Output.init(32) orelse return null;

        const gil = Gil.release(ciphertext.fixed);

        const status = capi.kem.decapsulate(slot.memory, slot.size, ciphertext.bytes.ptr, ciphertext.bytes.len, secret.bytes.ptr, secret.bytes.len);

        gil.restore();

        return finish(module, status, refused, secret);
    }

    fn selfTest(module: *Object, slot: *Slot, randomness: Input) ?*Object {
        const gil = Gil.release(randomness.fixed);

        const status = capi.kem.selfTest(slot.memory, slot.size, randomness.bytes.ptr, randomness.bytes.len);

        gil.restore();

        return answer(module, status, self_test_failed);
    }
};

const signature = struct {
    fn generate(module: *Object, algorithm: u32, seed: Input, flags: u32) ?*Object {
        const slot = newSlot(module, .signature_private, algorithm) orelse return null;

        const gil = Gil.release(seed.fixed);

        const status = capi.signature.keygen(algorithm, seed.bytes.ptr, seed.bytes.len, flags, slot.memory, slot.size);

        gil.restore();

        return created(module, slot, status, refused);
    }

    // ML-DSA hashes the key to tr.
    fn importPublic(module: *Object, algorithm: u32, key: Input) ?*Object {
        const slot = newSlot(module, .signature_public, algorithm) orelse return null;

        const gil = Gil.release(key.fixed);

        const status = capi.signature.importPublic(algorithm, key.bytes.ptr, key.bytes.len, slot.memory, slot.size);

        gil.restore();

        return created(module, slot, status, refused);
    }

    // SLH-DSA builds its key's tree to check it.
    fn importPrivate(module: *Object, algorithm: u32, key: Input) ?*Object {
        const slot = newSlot(module, .signature_private, algorithm) orelse return null;

        const gil = Gil.release(key.fixed);

        const status = capi.signature.importPrivate(algorithm, key.bytes.ptr, key.bytes.len, slot.memory, slot.size);

        gil.restore();

        return imported(module, slot, status, invalid_private_key);
    }

    fn public(module: *Object, algorithm: u32, private: *Slot) ?*Object {
        const slot = newSlot(module, .signature_public, algorithm) orelse return null;

        return created(module, slot, capi.signature.publicFromPrivate(private.memory, private.size, slot.memory, slot.size), refused);
    }

    fn exportPublic(module: *Object, slot: *Slot, size: usize) ?*Object {
        const out = Output.init(size) orelse return null;

        return finish(module, capi.signature.exportPublic(slot.memory, slot.size, out.bytes.ptr, out.bytes.len), refused, out);
    }

    fn exportPrivate(module: *Object, slot: *Slot, which: u32, size: usize) ?*Object {
        const out = Output.init(size) orelse return null;

        return exported(module, out, capi.signature.exportPrivate(slot.memory, slot.size, which, out.bytes.ptr, out.bytes.len));
    }

    fn sign(module: *Object, slot: *Slot, message: Input, context: Input, pre_hash: u32, randomness: Input, flags: u32, size: usize) ?*Object {
        const out = Output.init(size) orelse return null;

        const gil = Gil.release(allFixed(&.{ message, context, randomness }));

        const status = capi.signature.sign(slot.memory, slot.size, message.bytes.ptr, message.bytes.len, context.bytes.ptr, context.bytes.len, pre_hash, randomness.bytes.ptr, randomness.bytes.len, flags, out.bytes.ptr, out.bytes.len);

        gil.restore();

        return finish(module, status, refused, out);
    }

    fn verify(module: *Object, slot: *Slot, signature_bytes: Input, message: Input, context: Input, pre_hash: u32, flags: u32) ?*Object {
        const gil = Gil.release(allFixed(&.{ signature_bytes, message, context }));

        const status = capi.signature.verify(slot.memory, slot.size, signature_bytes.bytes.ptr, signature_bytes.bytes.len, message.bytes.ptr, message.bytes.len, context.bytes.ptr, context.bytes.len, pre_hash, flags);

        gil.restore();

        return answer(module, status, common.rejected);
    }
};

// One-shot hashes, XOFs and MACs with their default options, one function per algorithm: hash0
// to hash18, xof0 to xof5, mac0 to mac7 and mac_verify0 to mac_verify7, by the C ABI's ids, and
// hmac0 to hmac3 and hmac_verify0 to hmac_verify3, the names of ABI version 1 for the first four.
fn OneShot(comptime id: u32) type {
    return struct {
        fn hash(module: *Object, data: Input) ?*Object {
            const out = Output.init(capi.hash.algorithms[id].digest_size) orelse return null;

            const gil = Gil.release(data.bytes.len >= unlocked_size);

            const status = capi.hash.digest(id, data.bytes.ptr, data.bytes.len, out.bytes.ptr, out.bytes.len);

            gil.restore();

            return finish(module, status, refused, out);
        }

        fn xof(module: *Object, data: Input, size: Length) ?*Object {
            const out = Output.init(size.value) orelse return null;

            const gil = Gil.release(data.bytes.len + size.value >= unlocked_size);

            const status = capi.hash.xof(id, data.bytes.ptr, data.bytes.len, out.bytes.ptr, out.bytes.len);

            gil.restore();

            return finish(module, status, refused, out);
        }

        fn mac(module: *Object, key: Input, data: Input) ?*Object {
            const out = Output.init(capi.hash.macs[id].digest_size) orelse return null;

            const gil = Gil.release(data.bytes.len >= unlocked_size);

            const status = capi.hash.hmac(id, key.bytes.ptr, key.bytes.len, data.bytes.ptr, data.bytes.len, out.bytes.ptr, out.bytes.len);

            gil.restore();

            return finish(module, status, refused, out);
        }

        fn macVerify(module: *Object, key: Input, data: Input, tag: Input) ?*Object {
            const gil = Gil.release(data.bytes.len >= unlocked_size);

            const status = capi.hash.hmacVerify(id, key.bytes.ptr, key.bytes.len, data.bytes.ptr, data.bytes.len, tag.bytes.ptr, tag.bytes.len);

            gil.restore();

            return answer(module, status, common.rejected);
        }
    };
}

// Configured algorithms (hash.configure, xof.configure, mac.configure in Python) live in slots of
// their own, which the calls below only read.
const configured = struct {
    fn hash(module: *Object, algorithm: u32, salt: Input, personalization: Input) ?*Object {
        const slot = newSlot(module, .configured_hash, algorithm) orelse return null;

        return created(module, slot, capi.hash.configureHash(algorithm, salt.bytes.ptr, salt.bytes.len, personalization.bytes.ptr, personalization.bytes.len, slot.memory, slot.size), refused);
    }

    fn hashWith(module: *Object, spec: *Slot, data: Input) ?*Object {
        const out = Output.init(states.digestSize(spec.algorithm)) orelse return null;

        const gil = Gil.release(data.bytes.len >= unlocked_size);

        const status = capi.hash.digestWith(spec.memory, spec.size, data.bytes.ptr, data.bytes.len, out.bytes.ptr, out.bytes.len);

        gil.restore();

        return finish(module, status, refused, out);
    }

    fn hashInitWith(module: *Object, spec: *Slot) ?*Object {
        const slot = newSlot(module, .hasher, spec.algorithm) orelse return null;

        return created(module, slot, capi.hash.initWith(spec.memory, spec.size, slot.memory, slot.size), refused);
    }

    // The function name is for hazmat's cSHAKE only.
    fn xof(module: *Object, algorithm: u32, function_name: Input, customization: Input) ?*Object {
        const slot = newSlot(module, .configured_xof, algorithm) orelse return null;

        return created(module, slot, capi.hash.configureXof(algorithm, function_name.bytes.ptr, function_name.bytes.len, customization.bytes.ptr, customization.bytes.len, slot.memory, slot.size), refused);
    }

    fn xofWith(module: *Object, spec: *Slot, data: Input, size: Length) ?*Object {
        const out = Output.init(size.value) orelse return null;

        const gil = Gil.release(data.bytes.len + size.value >= unlocked_size);

        const status = capi.hash.xofWith(spec.memory, spec.size, data.bytes.ptr, data.bytes.len, out.bytes.ptr, out.bytes.len);

        gil.restore();

        return finish(module, status, refused, out);
    }

    fn xofInitWith(module: *Object, spec: *Slot) ?*Object {
        const slot = newSlot(module, .xof, spec.algorithm) orelse return null;

        return created(module, slot, capi.hash.xofInitWith(spec.memory, spec.size, slot.memory, slot.size), refused);
    }

    // flags: 1 KMACXOF, 2 `size` is the length (else the default, size 0); first is KMAC's
    // customization or BLAKE2's salt, second BLAKE2's personalization.
    fn mac(module: *Object, algorithm: u32, size: usize, flags: u32, first: Input, second: Input) ?*Object {
        const slot = newSlot(module, .configured_mac, algorithm) orelse return null;

        return created(module, slot, capi.hash.configureMac(algorithm, size, flags, first.bytes.ptr, first.bytes.len, second.bytes.ptr, second.bytes.len, slot.memory, slot.size), refused);
    }

    // `size` is the configured length, which Python keeps.
    fn macWith(module: *Object, spec: *Slot, key: Input, data: Input, size: usize) ?*Object {
        const out = Output.init(size) orelse return null;

        const gil = Gil.release(data.bytes.len >= unlocked_size);

        const status = capi.hash.macWith(spec.memory, spec.size, key.bytes.ptr, key.bytes.len, data.bytes.ptr, data.bytes.len, out.bytes.ptr, out.bytes.len);

        gil.restore();

        return finish(module, status, refused, out);
    }

    fn macVerifyWith(module: *Object, spec: *Slot, key: Input, data: Input, tag: Input) ?*Object {
        const gil = Gil.release(data.bytes.len >= unlocked_size);

        const status = capi.hash.macVerifyWith(spec.memory, spec.size, key.bytes.ptr, key.bytes.len, data.bytes.ptr, data.bytes.len, tag.bytes.ptr, tag.bytes.len);

        gil.restore();

        return answer(module, status, common.rejected);
    }

    fn macInitWith(module: *Object, spec: *Slot, key: Input) ?*Object {
        const slot = newSlot(module, .hmac, spec.algorithm) orelse return null;

        return created(module, slot, capi.hash.macInitWith(spec.memory, spec.size, key.bytes.ptr, key.bytes.len, slot.memory, slot.size), refused);
    }
};

// HKDF by the C ABI's KDF ids; a length is crypto-pq's INVALID_LENGTH when negative, as elsewhere.
const kdf = struct {
    fn derive(module: *Object, algorithm: u32, ikm: Input, salt: Input, info: Input, size: Length) ?*Object {
        const out = Output.init(size.value) orelse return null;

        const status = capi.hash.kdfDerive(algorithm, ikm.bytes.ptr, ikm.bytes.len, salt.bytes.ptr, salt.bytes.len, info.bytes.ptr, info.bytes.len, out.bytes.ptr, out.bytes.len);

        return finish(module, status, refused, out);
    }

    fn extract(module: *Object, algorithm: u32, ikm: Input, salt: Input) ?*Object {
        const out = Output.init(if (algorithm < capi.hash.kdf_count) capi.hash.kdfs[algorithm].hashSize() else 0) orelse return null;

        const status = capi.hash.kdfExtract(algorithm, ikm.bytes.ptr, ikm.bytes.len, salt.bytes.ptr, salt.bytes.len, out.bytes.ptr, out.bytes.len);

        return finish(module, status, refused, out);
    }

    fn expand(module: *Object, algorithm: u32, prk: Input, info: Input, size: Length) ?*Object {
        const out = Output.init(size.value) orelse return null;

        const status = capi.hash.kdfExpand(algorithm, prk.bytes.ptr, prk.bytes.len, info.bytes.ptr, info.bytes.len, out.bytes.ptr, out.bytes.len);

        return finish(module, status, refused, out);
    }
};

// Incremental states. Their Python objects take one call at a time, with a lock of their own.
const states = struct {
    fn hashInit(module: *Object, algorithm: u32) ?*Object {
        const slot = newSlot(module, .hasher, algorithm) orelse return null;

        return created(module, slot, capi.hash.init(algorithm, slot.memory, slot.size), refused);
    }

    fn hashUpdate(module: *Object, slot: *Slot, data: Input) ?*Object {
        const gil = Gil.release(data.bytes.len >= unlocked_size);

        const status = capi.hash.update(slot.memory, slot.size, data.bytes.ptr, data.bytes.len);

        gil.restore();

        if (status != common.ok) return raise(module, status, refused);

        return none();
    }

    fn hashFinal(module: *Object, slot: *Slot) ?*Object {
        const out = Output.init(digestSize(slot.algorithm)) orelse return null;

        return finish(module, capi.hash.final(slot.memory, slot.size, out.bytes.ptr, out.bytes.len), refused, out);
    }

    fn xofInit(module: *Object, algorithm: u32) ?*Object {
        const slot = newSlot(module, .xof, algorithm) orelse return null;

        return created(module, slot, capi.hash.xofInit(algorithm, slot.memory, slot.size), refused);
    }

    fn xofUpdate(module: *Object, slot: *Slot, data: Input) ?*Object {
        const gil = Gil.release(data.bytes.len >= unlocked_size);

        const status = capi.hash.xofUpdate(slot.memory, slot.size, data.bytes.ptr, data.bytes.len);

        gil.restore();

        if (status != common.ok) return raise(module, status, "cannot update after read");

        return none();
    }

    fn xofRead(module: *Object, slot: *Slot, size: usize) ?*Object {
        const out = Output.init(size) orelse return null;

        const gil = Gil.release(size >= unlocked_size);

        const status = capi.hash.xofRead(slot.memory, slot.size, out.bytes.ptr, out.bytes.len);

        gil.restore();

        return finish(module, status, refused, out);
    }

    fn hmacInit(module: *Object, algorithm: u32, key: Input) ?*Object {
        const slot = newSlot(module, .hmac, algorithm) orelse return null;

        return created(module, slot, capi.hash.hmacInit(algorithm, key.bytes.ptr, key.bytes.len, slot.memory, slot.size), refused);
    }

    fn hmacUpdate(module: *Object, slot: *Slot, data: Input) ?*Object {
        const gil = Gil.release(data.bytes.len >= unlocked_size);

        const status = capi.hash.hmacUpdate(slot.memory, slot.size, data.bytes.ptr, data.bytes.len);

        gil.restore();

        if (status != common.ok) return raise(module, status, refused);

        return none();
    }

    fn hmacFinal(module: *Object, slot: *Slot) ?*Object {
        const out = Output.init(digestSize(slot.algorithm)) orelse return null;

        return finish(module, capi.hash.hmacFinal(slot.memory, slot.size, out.bytes.ptr, out.bytes.len), refused, out);
    }

    fn hmacFinalVerify(module: *Object, slot: *Slot, tag: Input) ?*Object {
        return answer(module, capi.hash.hmacFinalVerify(slot.memory, slot.size, tag.bytes.ptr, tag.bytes.len), common.rejected);
    }

    // The tag of a MAC state of any kind; `size` is its length, which Python keeps.
    fn macFinal(module: *Object, slot: *Slot, size: usize) ?*Object {
        const out = Output.init(size) orelse return null;

        return finish(module, capi.hash.hmacFinal(slot.memory, slot.size, out.bytes.ptr, out.bytes.len), refused, out);
    }

    // HMAC ids name the hashes of the same ids.
    fn digestSize(algorithm: u32) usize {
        return if (algorithm < capi.hash.hash_count) capi.hash.algorithms[algorithm].digest_size else 0;
    }
};

// The stateful keys' signers (section 10 of the C ABI). The Python key keeps the state machine.
const stateful = struct {
    // Seed size, state size, public key size, signature size, capacity and the bytes that a
    // signer of these parameters allocates.
    fn info(module: *Object, kind: u32, section: Input) ?*Object {
        var out: [6]u64 = undefined;

        const status = capi.stateful.info(kind, section.bytes.ptr, section.bytes.len, &out);

        if (status != common.ok) return raise(module, status, "invalid parameters");

        var items: [6]?*Object = undefined;

        for (&items, out) |*item, value| item.* = py.PyLong_FromUnsignedLongLong(value);

        return tuple(&items);
    }

    fn verify(module: *Object, kind: u32, key: Input, message: Input, signature_bytes: Input) ?*Object {
        const gil = Gil.release(allFixed(&.{ key, message, signature_bytes }));

        const status = capi.stateful.verify(kind, key.bytes.ptr, key.bytes.len, message.bytes.ptr, message.bytes.len, signature_bytes.bytes.ptr, signature_bytes.bytes.len);

        gil.restore();

        return answer(module, status, common.rejected);
    }

    fn checkPublicKey(module: *Object, kind: u32, key: Input) ?*Object {
        return answer(module, capi.stateful.checkPublicKey(kind, key.bytes.ptr, key.bytes.len), invalid_public_key);
    }

    // (signer slot, sealed state blob of `index`).
    fn create(module: *Object, kind: u32, section: Input, seed: Input, index: u64) ?*Object {
        var sizes: [6]u64 = undefined;

        const known = capi.stateful.info(kind, section.bytes.ptr, section.bytes.len, &sizes);

        if (known != common.ok) return raise(module, known, "invalid parameters");

        const state = Output.init(@intCast(sizes[1])) orelse return null;

        const slot = newSlot(module, .signer, kind) orelse {
            py.Py_DecRef(state.object);

            return null;
        };

        const gil = Gil.release(section.fixed and seed.fixed);

        const status = capi.stateful.create(kind, section.bytes.ptr, section.bytes.len, seed.bytes.ptr, seed.bytes.len, index, state.bytes.ptr, state.bytes.len, slot.memory, slot.size);

        gil.restore();

        if (status != common.ok) {
            state.discard();

            slot.drop();

            return raise(module, status, "the key cannot be created");
        }

        return tuple(&.{ slot.base(), state.object });
    }

    // (signer slot, the state's index); `cache` is a tree cache or None.
    fn load(module: *Object, kind: u32, state: Input, cache: ?Input) ?*Object {
        const slot = newSlot(module, .signer, kind) orelse return null;

        const tree_cache = cache orelse Input{ .bytes = &.{}, .fixed = true };

        var index: u64 = 0;

        const gil = Gil.release(state.fixed and tree_cache.fixed);

        const status = capi.stateful.load(kind, state.bytes.ptr, state.bytes.len, tree_cache.bytes.ptr, tree_cache.bytes.len, if (cache == null) 0 else capi.stateful.with_tree_cache, slot.memory, slot.size, &index);

        gil.restore();

        if (status != common.ok) {
            slot.drop();

            return raise(module, status, "the stored key state or its tree cache is invalid");
        }

        return tuple(&.{ slot.base(), py.PyLong_FromUnsignedLongLong(index) });
    }

    fn sign(module: *Object, slot: *Slot, index: u64, message: Input, size: usize) ?*Object {
        const out = Output.init(size) orelse return null;

        const gil = Gil.release(message.fixed);

        const status = capi.stateful.sign(slot.memory, slot.size, index, message.bytes.ptr, message.bytes.len, out.bytes.ptr, out.bytes.len);

        gil.restore();

        return finish(module, status, "the signer refused the index", out);
    }

    fn publicKey(module: *Object, slot: *Slot, size: usize) ?*Object {
        const out = Output.init(size) orelse return null;

        return finish(module, capi.stateful.publicKey(slot.memory, slot.size, out.bytes.ptr, out.bytes.len), refused, out);
    }

    // Capacity, next allowed index, signature size and the bytes the signer holds.
    fn signerInfo(module: *Object, slot: *Slot) ?*Object {
        var out: [4]u64 = undefined;

        const status = capi.stateful.signerInfo(slot.memory, slot.size, &out);

        if (status != common.ok) return raise(module, status, refused);

        var items: [4]?*Object = undefined;

        for (&items, out) |*item, value| item.* = py.PyLong_FromUnsignedLongLong(value);

        return tuple(&items);
    }

    // The size changes when a signature starts a new lower tree; the caller holds the key's lock
    // across this call.
    fn treeCache(module: *Object, slot: *Slot) ?*Object {
        var size: u64 = 0;

        const sized = capi.stateful.treeCacheSize(slot.memory, slot.size, &size);

        if (sized != common.ok) return raise(module, sized, refused);

        const out = Output.init(@intCast(size)) orelse return null;

        const gil = Gil.release(true);

        const status = capi.stateful.exportTreeCache(slot.memory, slot.size, out.bytes.ptr, out.bytes.len);

        gil.restore();

        return finish(module, status, refused, out);
    }

    // A signer that the library finds in use is left to its slot's wipe.
    fn free(module: *Object, slot: *Slot) ?*Object {
        _ = module;

        _ = capi.stateful.free(slot.memory, slot.size);

        return none();
    }

    // A copy of a valid state blob, resealed to claim the indices below `index`.
    fn reseal(module: *Object, kind: u32, state: Input, index: u64) ?*Object {
        const out = Output.init(state.bytes.len) orelse return null;

        @memcpy(out.bytes, state.bytes);

        return finish(module, capi.stateful.reseal(kind, out.bytes.ptr, out.bytes.len, index), "the key state cannot be advanced", out);
    }
};

const one_shot_count = capi.hash.hash_count + capi.hash.xof_count + 2 * capi.hash.hmac_count + 2 * capi.hash.mac_count;

fn oneShotMethods() [one_shot_count]py.MethodDef {
    var out: [one_shot_count]py.MethodDef = undefined;

    var next: usize = 0;

    for (0..capi.hash.hash_count) |id| {
        out[next] = method(std.fmt.comptimePrint("hash{d}", .{id}), OneShot(id).hash);

        next += 1;
    }

    for (0..capi.hash.xof_count) |id| {
        out[next] = method(std.fmt.comptimePrint("xof{d}", .{id}), OneShot(id).xof);

        next += 1;
    }

    for (0..capi.hash.hmac_count) |id| {
        out[next] = method(std.fmt.comptimePrint("hmac{d}", .{id}), OneShot(id).mac);

        out[next + 1] = method(std.fmt.comptimePrint("hmac_verify{d}", .{id}), OneShot(id).macVerify);

        next += 2;
    }

    for (0..capi.hash.mac_count) |id| {
        out[next] = method(std.fmt.comptimePrint("mac{d}", .{id}), OneShot(id).mac);

        out[next + 1] = method(std.fmt.comptimePrint("mac_verify{d}", .{id}), OneShot(id).macVerify);

        next += 2;
    }

    return out;
}

const methods = [_]py.MethodDef{
    method("abi_version", abiVersion),
    method("setup", setup),
    method("slot_info", slotInfo),
    method("wipe", wipe),
    method("kem_generate", kem.generate),
    method("kem_import_public", kem.importPublic),
    method("kem_import_private", kem.importPrivate),
    method("kem_public", kem.public),
    method("kem_export_public", kem.exportPublic),
    method("kem_export_private", kem.exportPrivate),
    method("kem_encapsulate", kem.encapsulate),
    method("kem_decapsulate", kem.decapsulate),
    method("kem_self_test", kem.selfTest),
    method("signature_generate", signature.generate),
    method("signature_import_public", signature.importPublic),
    method("signature_import_private", signature.importPrivate),
    method("signature_public", signature.public),
    method("signature_export_public", signature.exportPublic),
    method("signature_export_private", signature.exportPrivate),
    method("sign", signature.sign),
    method("verify", signature.verify),
    method("hash_init", states.hashInit),
    method("hash_update", states.hashUpdate),
    method("hash_final", states.hashFinal),
    method("xof_init", states.xofInit),
    method("xof_update", states.xofUpdate),
    method("xof_read", states.xofRead),
    method("hmac_init", states.hmacInit),
    method("hmac_update", states.hmacUpdate),
    method("hmac_final", states.hmacFinal),
    method("hmac_final_verify", states.hmacFinalVerify),
    method("mac_init", states.hmacInit),
    method("mac_update", states.hmacUpdate),
    method("mac_final", states.macFinal),
    method("mac_final_verify", states.hmacFinalVerify),
    method("hash_configure", configured.hash),
    method("hash_with", configured.hashWith),
    method("hash_init_with", configured.hashInitWith),
    method("xof_configure", configured.xof),
    method("xof_with", configured.xofWith),
    method("xof_init_with", configured.xofInitWith),
    method("mac_configure", configured.mac),
    method("mac_with", configured.macWith),
    method("mac_verify_with", configured.macVerifyWith),
    method("mac_init_with", configured.macInitWith),
    method("kdf_derive", kdf.derive),
    method("kdf_extract", kdf.extract),
    method("kdf_expand", kdf.expand),
    method("stateful_info", stateful.info),
    method("stateful_verify", stateful.verify),
    method("stateful_check_public_key", stateful.checkPublicKey),
    method("signer_create", stateful.create),
    method("signer_load", stateful.load),
    method("signer_sign", stateful.sign),
    method("signer_public_key", stateful.publicKey),
    method("signer_info", stateful.signerInfo),
    method("signer_tree_cache", stateful.treeCache),
    method("signer_free", stateful.free),
    method("state_reseal", stateful.reseal),
} ++ oneShotMethods() ++ [_]py.MethodDef{.{ .name = null, .method = null, .flags = 0, .doc = null }};

fn exec(module: ?*Object) callconv(.c) c_int {
    const state = stateOf(module.?);

    const slot_type = py.PyType_FromModuleAndSpec(module.?, &slot_spec, null) orelse return -1;

    state.slot_type = slot_type;

    const empty = py.PyBytes_FromStringAndSize(null, 0) orelse return -1;

    // The bytes type is static: its address needs no reference.
    state.bytes_type = empty.type;

    py.Py_DecRef(empty);

    return py.PyModule_AddObjectRef(module.?, "Slot", slot_type);
}

fn traverseState(module: ?*Object, visit: py.Visit, argument: ?*anyopaque) callconv(.c) c_int {
    const state: *State = @ptrCast(@alignCast(py.PyModule_GetState(module) orelse return 0));

    for ([_]?*Object{ state.slot_type, state.failure }) |item| {
        if (item) |object| {
            const result = visit(object, argument);

            if (result != 0) return result;
        }
    }

    return 0;
}

fn clearState(module: ?*Object) callconv(.c) c_int {
    const state: *State = @ptrCast(@alignCast(py.PyModule_GetState(module) orelse return 0));

    py.Py_DecRef(state.slot_type);

    py.Py_DecRef(state.failure);

    state.slot_type = null;

    state.failure = null;

    return 0;
}

fn freeState(module: ?*anyopaque) callconv(.c) void {
    _ = clearState(@ptrCast(@alignCast(module)));
}

const module_slots = [_]py.ModuleDefSlot{
    .{ .slot = py.Py_mod_exec, .value = @ptrCast(&exec) },
    .{ .slot = 0, .value = null },
};

var definition: py.ModuleDef = .{
    .name = "_cpq",
    .doc = null,
    .size = @sizeOf(State),
    .methods = &methods,
    .slots = &module_slots,
    .traverse = &traverseState,
    .clear = &clearState,
    .free = &freeState,
};

export fn PyInit__cpq() callconv(.c) ?*Object {
    return py.PyModuleDef_Init(&definition);
}

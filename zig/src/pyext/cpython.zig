//! The part of CPython's stable ABI that the extension module uses, declared from the documented
//! limited API of Python 3.11: no Python headers are needed to build it. The layouts are those of
//! the interpreters with a GIL; a free-threaded interpreter has others and never loads the module.
//!
//! On Linux and macOS the symbols stay undefined and come from the interpreter that loads the
//! module. On Windows they come from python3.dll, through an import library that the build writes
//! from python3.zig, whose lists must name every function and data object declared here.

const std = @import("std");
const builtin = @import("builtin");

const python3 = @import("python3.zig");

pub const Object = extern struct {
    refcnt: isize,
    type: ?*Object,
};

pub const Getter = *const fn (?*Object, ?*anyopaque) callconv(.c) ?*Object;

pub const MethodDef = extern struct {
    name: ?[*:0]const u8,
    method: ?*const anyopaque,
    flags: c_int,
    doc: ?[*:0]const u8,
};

pub const GetSetDef = extern struct {
    name: ?[*:0]const u8,
    get: ?Getter,
    set: ?*const anyopaque,
    doc: ?[*:0]const u8,
    closure: ?*anyopaque,
};

pub const ModuleDefSlot = extern struct {
    slot: c_int,
    value: ?*const anyopaque,
};

pub const Visit = *const fn (?*Object, ?*anyopaque) callconv(.c) c_int;

pub const ModuleDef = extern struct {
    base: extern struct {
        object: Object = .{ .refcnt = 1, .type = null },
        init: ?*const anyopaque = null,
        index: isize = 0,
        copy: ?*Object = null,
    } = .{},
    name: [*:0]const u8,
    doc: ?[*:0]const u8,
    size: isize,
    methods: ?[*]const MethodDef,
    slots: ?[*]const ModuleDefSlot,
    traverse: ?*const fn (?*Object, Visit, ?*anyopaque) callconv(.c) c_int,
    clear: ?*const fn (?*Object) callconv(.c) c_int,
    free: ?*const fn (?*anyopaque) callconv(.c) void,
};

pub const TypeSlot = extern struct {
    slot: c_int,
    value: ?*const anyopaque,
};

pub const TypeSpec = extern struct {
    name: [*:0]const u8,
    basic_size: c_int,
    item_size: c_int,
    flags: c_uint,
    slots: [*]const TypeSlot,
};

// Py_buffer, part of the stable ABI since 3.11.
pub const Buffer = extern struct {
    buf: ?[*]u8,
    obj: ?*Object,
    len: isize,
    item_size: isize,
    readonly: c_int,
    ndim: c_int,
    format: ?[*:0]u8,
    shape: ?*isize,
    strides: ?*isize,
    suboffsets: ?*isize,
    internal: ?*anyopaque,
};

pub const METH_O: c_int = 0x0008;

pub const METH_FASTCALL: c_int = 0x0080;

pub const Py_mod_exec: c_int = 2;

pub const Py_tp_dealloc: c_int = 52;

pub const Py_tp_methods: c_int = 64;

pub const Py_tp_getset: c_int = 73;

pub const Py_tp_free: c_int = 74;

pub const Py_TPFLAGS_DISALLOW_INSTANTIATION: c_uint = 1 << 7;

pub const Py_TPFLAGS_IMMUTABLETYPE: c_uint = 1 << 8;

pub const PyBUF_SIMPLE: c_int = 0;

pub const PyBUF_WRITABLE: c_int = 0x0001;

pub extern fn PyModuleDef_Init(*ModuleDef) callconv(.c) ?*Object;

pub extern fn PyModule_GetState(?*Object) callconv(.c) ?*anyopaque;

pub extern fn PyModule_AddObjectRef(*Object, [*:0]const u8, *Object) callconv(.c) c_int;

pub extern fn PyType_FromModuleAndSpec(*Object, *const TypeSpec, ?*Object) callconv(.c) ?*Object;

pub extern fn PyType_GetSlot(*Object, c_int) callconv(.c) ?*anyopaque;

pub extern fn PyType_GenericAlloc(*Object, isize) callconv(.c) ?*Object;

pub extern fn PyObject_GetBuffer(*Object, *Buffer, c_int) callconv(.c) c_int;

pub extern fn PyBuffer_Release(*Buffer) callconv(.c) void;

pub extern fn PyObject_CallObject(*Object, ?*Object) callconv(.c) ?*Object;

pub extern fn PyCallable_Check(*Object) callconv(.c) c_int;

pub extern fn PyBytes_FromStringAndSize(?[*]const u8, isize) callconv(.c) ?*Object;

pub extern fn PyBytes_AsString(*Object) callconv(.c) ?[*]u8;

pub extern fn PyByteArray_FromStringAndSize(?[*]const u8, isize) callconv(.c) ?*Object;

pub extern fn PyLong_FromLong(c_long) callconv(.c) ?*Object;

pub extern fn PyLong_FromUnsignedLongLong(c_ulonglong) callconv(.c) ?*Object;

pub extern fn PyLong_AsUnsignedLongLong(*Object) callconv(.c) c_ulonglong;

pub extern fn PyLong_AsLongLong(*Object) callconv(.c) c_longlong;

pub extern fn PyBool_FromLong(c_long) callconv(.c) ?*Object;

pub extern fn PyTuple_New(isize) callconv(.c) ?*Object;

pub extern fn PyTuple_SetItem(*Object, isize, *Object) callconv(.c) c_int;

pub extern fn PyUnicode_FromString([*:0]const u8) callconv(.c) ?*Object;

pub extern fn PyErr_SetString(*Object, [*:0]const u8) callconv(.c) void;

pub extern fn PyErr_SetObject(*Object, *Object) callconv(.c) void;

pub extern fn PyErr_Occurred() callconv(.c) ?*Object;

pub extern fn PyErr_ExceptionMatches(*Object) callconv(.c) c_int;

pub extern fn PyErr_NoMemory() callconv(.c) ?*Object;

pub extern fn PyEval_SaveThread() callconv(.c) ?*anyopaque;

pub extern fn PyEval_RestoreThread(?*anyopaque) callconv(.c) void;

pub extern fn Py_IncRef(?*Object) callconv(.c) void;

pub extern fn Py_DecRef(?*Object) callconv(.c) void;

fn listed(names: []const []const u8, name: []const u8) bool {
    for (names) |known| {
        if (std.mem.eql(u8, known, name)) return true;
    }

    return false;
}

comptime {
    @setEvalBranchQuota(100_000);

    for (@typeInfo(@This()).@"struct".decls) |decl| {
        if (@typeInfo(@TypeOf(@field(@This(), decl.name))) == .@"fn" and std.mem.startsWith(u8, decl.name, "Py") and !listed(&python3.functions, decl.name)) {
            @compileError(decl.name ++ " is missing from python3.zig");
        }
    }
}

// A data object of the interpreter. On Windows the loader writes its address into the import
// address table, at `__imp_` and its name.
fn data(comptime T: type, comptime name: []const u8) *T {
    if (comptime !listed(&python3.data, name)) @compileError(name ++ " is missing from python3.zig");

    if (builtin.os.tag == .windows) return @extern(*const *T, .{ .name = "__imp_" ++ name }).*;

    return @extern(*T, .{ .name = name });
}

pub fn none() *Object {
    return data(Object, "_Py_NoneStruct");
}

pub fn exception(comptime name: []const u8) *Object {
    return data(*Object, name).*;
}

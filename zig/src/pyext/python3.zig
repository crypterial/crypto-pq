//! What the extension module imports from python3.dll on Windows: the build writes the import
//! library's definition file from these lists, and cpython.zig checks that they name every symbol
//! it declares.

pub const functions = [_][]const u8{
    "PyBool_FromLong",
    "PyBuffer_Release",
    "PyByteArray_FromStringAndSize",
    "PyBytes_AsString",
    "PyBytes_FromStringAndSize",
    "PyCallable_Check",
    "PyErr_ExceptionMatches",
    "PyErr_NoMemory",
    "PyErr_Occurred",
    "PyErr_SetObject",
    "PyErr_SetString",
    "PyEval_RestoreThread",
    "PyEval_SaveThread",
    "PyLong_AsLongLong",
    "PyLong_AsUnsignedLongLong",
    "PyLong_FromLong",
    "PyLong_FromUnsignedLongLong",
    "PyModuleDef_Init",
    "PyModule_AddObjectRef",
    "PyModule_GetState",
    "PyObject_CallObject",
    "PyObject_GetBuffer",
    "PyTuple_New",
    "PyTuple_SetItem",
    "PyType_FromModuleAndSpec",
    "PyType_GenericAlloc",
    "PyType_GetSlot",
    "PyUnicode_FromString",
    "Py_DecRef",
    "Py_IncRef",
};

pub const data = [_][]const u8{
    "PyExc_BufferError",
    "PyExc_OverflowError",
    "PyExc_RuntimeError",
    "PyExc_TypeError",
    "_Py_NoneStruct",
};

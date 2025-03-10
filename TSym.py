# Allows for exporting program data into easy to read and parse text files.
# For anyone inspecting the code: this script is sort of messy as I don't write much python, ssorry.
# @author DexrnZacAttack
# @version 1.0.0
# @category Symbol

#region imports
import math
import os

import ghidra
from ghidra.program.model.address import AddressSet
try:
    from ghidra.ghidra_builtins import *
except:
    pass
from ghidra.program.model.listing import FunctionManager, CodeUnit
from ghidra.program.model.data import ParameterDefinition, DefaultDataType
from ghidra.util.task import TaskMonitor # TODO
from ghidra.program.database.function import FunctionManagerDB
from ghidra.program.database.data import StructureDB, TypedefDB, PointerDB
from ghidra.program.model.data import BuiltInDataType, PointerDataType
from ghidra.program.model.symbol import Symbol, SymbolType
from ghidra.util import Msg
from java.nio.file import Path, Paths, Files
#endregion

#region constants
tsym_ver = "1.1.1"
tsym_symbols_ver = 1
tsym_comments_ver = 1
tsym_labels_ver = 1
#endregion

def deldir(dpath):
    for filename in os.listdir(dpath):
        fpath = os.path.join(dpath, filename)

        if os.path.isdir(fpath):
            deldir(fpath)
        elif os.path.isfile(fpath):
            os.remove(fpath)

    os.rmdir(dpath)

#region globals
folder = askDirectory("Select a folder to place symbols in", "Select")
path = Paths.get(folder.getAbsolutePath())

if os.path.exists(str(path.resolve("types"))):
    deldir(str(path.resolve("types")))

symbols = open(str(path.resolve("symbols.txt")), "w")
comments = open(str(path.resolve("comments.txt")), "w")
labels = open(str(path.resolve("labels.txt")), "w")
symbols.write("# TSym-Symbols " + str(tsym_symbols_ver) + " | TSym " + tsym_ver + "\n")
comments.write("# TSym-Comments " + str(tsym_comments_ver) + " | TSym " + tsym_ver + "\n")
labels.write("# TSym-Labels " + str(tsym_labels_ver) + " | TSym " + tsym_ver + "\n")

# its very FUN
fun_manager = currentProgram.getFunctionManager()
dat_manager = currentProgram.getDataTypeManager()
sym_table = currentProgram.getSymbolTable()
all_syms = sym_table.getAllSymbols(True)
#endregion

#region functions
# just to keep it semicolon seperated.
def append(arr, string):
    """
    Suffixes string with a semicolon and appends it to the end of the given array.
    """
    arr.append(string.replace(";", "ts_smc"))
    arr.append(";")


url_arr = {
    '<': '%3C', '>': '%3E', ':': '%3A', '"': '%22', '\\': '%5C',
    '|': '%7C', '?': '%3F', '*': '%2A', '\x00': '%00', '\x1F': '%1F'
}


def remove_from_array(string, remove):
    for rep in remove:
        string = string.replace(rep, "")
    return string

# janky url encode since can't find the python3 one from ghidra
# doesn't include / so that paths still work
def url_encode(string):
    """
    Encodes chars that cannot be used in Windows filenames.

    This exists because whatever python version Ghidra uses doesn't have urllib.parse.
    """
    return ''.join(url_arr.get(char, char) for char in string)
#endregion

#region internal_names
internal_names = ["TS_INHERIT", "TS_PUBLIC", "TS_PRIVATE", "TS_PROTECTED"]
#endregion

#region comments writer
comment_builder = []

# comments
print("Writing comments")
# address;string;type
for i in range(0, 5):
    comments_list = currentProgram.getListing().getCommentCodeUnitIterator(i, AddressSet(currentProgram.getMemory()))
    for comment in comments_list:  # type: ghidra.program.model.listing.CodeUnit
        if comment.getComment(i) is not None:
            append(comment_builder, comment.address.toString())
            append(comment_builder, comment.getComment(i))
            append(comment_builder, str(i))
            comment_builder.append("\n")

comments.write(''.join(comment_builder))
#endregion

#region function writer
# function symbols
print("Writing functions")
# address;callconv;nmsp_size;[namespace];name;args_size;[args];hasVarArgs;
for func in fun_manager.getFunctions(False):  # type: ghidra.program.model.listing.Function
    # closest thing to StringBuilder
    builder = []

    append(builder, func.getEntryPoint().toString())
    append(builder, func.getReturnType().getPathName())
    append(builder, func.getCallingConventionName())

    namespaces = []
    nmsp_size = 0
    parent_nmsp = func.getParentNamespace()

    while True:
        if parent_nmsp is None:
            break

        append(namespaces, parent_nmsp.getName())
        nmsp_size += 1
        parent_nmsp = parent_nmsp.getParentNamespace()

    append(builder, str(nmsp_size))
    # what is this syntax eww
    builder.append("".join(namespaces))

    append(builder, func.getName())

    args = []
    args_size = 0

    for arg in func.getSignature().getArguments():  # type: ghidra.program.model.data.ParameterDefinition
        args_size += 1
        append(args, arg.getName())
        append(args, arg.getDataType().getPathName())

    append(builder, str(args_size))
    builder.append("".join(args))

    builder.append(str(func.hasVarArgs()))

    symbols.write(''.join(builder) + "\n")
#endregion

#region types writer (struct, typedef, enum)
# types
print("Writing types (struct, typedef, enum, union)")
# these go into their own .h file
for dat_type in dat_manager.getAllDataTypes():
    path_name = url_encode(dat_type.getPathName().replace("::", "/"))
    parent_path = path_name.rpartition('/')[0].lstrip("/")
    if isinstance(dat_type, ghidra.program.database.data.StructureDB) or isinstance(dat_type, ghidra.program.database.data.UnionDB):
        inherits = []
        inherit_comments = []

        t_name = "struct"
        if isinstance(dat_type, ghidra.program.database.data.UnionDB):
            t_name = "union"

        i = 0
        imports = []
        type_path = path.resolve("types").resolve(parent_path)
        Files.createDirectories(type_path)

        struct = open(str(type_path.resolve(path_name.rpartition('/')[-1].lstrip("/") + ".h")), "w+")

        for component in dat_type.getComponents():  # type: ghidra.program.model.data.DataTypeComponent
            try:
                if (component.getFieldName() == "inherit" or component.comment == "inherit" or str(component.comment).__contains__("TS_INHERIT")) and t_name == "struct":
                    inherits.append("public " + os.path.basename(component.getDataType().getPathName().lstrip("/")))
                    if component.comment is not None:
                        inherit_comments.append(remove_from_array(str(component.comment), internal_names))
                    else:
                        inherit_comments.append(None)

                # this assumes the user has an import path set at root dir (types)
                dtype = component.getDataType()
                while isinstance(dtype, PointerDB):
                    dtype = dtype.getDataType()

                imp_path = dtype.getPathName().lstrip("/").replace("*", "").strip()

                if not imports.__contains__(url_encode(imp_path) + ".h") and not isinstance(dtype, BuiltInDataType) and not isinstance(dtype, DefaultDataType):
                    imports.append(url_encode(imp_path) + ".h")
            except Exception as e:
                struct.write("// " + str(e) + "\n")

        for imp in imports:
            struct.write("#include " + "\"" + imp + "\"" + "\n")

        # type: ghidra.program.database.data.StructureDB
        # print("struct " + dat_type.getPathName())
        # struct.write("#pragma pack(push, 1)")
        inherit = ""
        if inherits:
            inherit += " : "
            for i, i1 in enumerate(inherits):
                if inherit_comments and inherit_comments[i]:
                    inherit += " /* " + str(inherit_comments[i]).strip() + " */ "
                inherit += i1
                if i < len(inherits) - 1:
                    inherit += ", "

        struct.write(t_name + " " + dat_type.getDisplayName() + inherit + " {")

        for component in dat_type.getComponents():  # type: ghidra.program.model.data.DataTypeComponent
            try:
                st_name = "field_" + str(component.getOffset())

                if component.getFieldName():
                    st_name = component.getFieldName()

                if (st_name == "inherit" or component.comment == "inherit" or str(component.comment).__contains__("TS_INHERIT")) and t_name == "struct":
                    continue

                struct.write("\n    " + os.path.basename(component.getDataType().getPathName().lstrip("/")) + " " + st_name + ";")

                if component.comment:
                    struct.write(" // " + remove_from_array(component.comment, internal_names))
            except Exception as e:
                struct.write("\n    // " + str(e))
            i += 1

        struct.write("\n}")
        if dat_type.description:
            struct.write(" // " + dat_type.description)

        struct.close()

    elif isinstance(dat_type, ghidra.program.database.data.TypedefDB):
        type_path = path.resolve("types").resolve(parent_path)
        Files.createDirectories(type_path)

        typedef = open(str(type_path.resolve(path_name.rpartition('/')[-1].lstrip("/") + ".h")), "w")

        imports = []

        # this assumes the user has an import path set at root dir (types)
        try:
            dtype = dat_type.getBaseDataType()
            while isinstance(dtype, PointerDB):
                dtype = dtype.getDataType()

            imp_path = dtype.getPathName().lstrip("/").replace("*", "").strip()

            if not imports.__contains__(url_encode(imp_path) + ".h") and not isinstance(dtype, BuiltInDataType) and not isinstance(dtype, DefaultDataType):
                imports.append(url_encode(imp_path) + ".h")
        except Exception as e:
            typedef.write("// " + str(e) + "\n")

        for imp in imports:
            typedef.write("#include " + "\"" + imp + "\"" + "\n")

        # type: ghidra.program.database.data.TypedefDB
        # print("Typedef " + dat_type.getPathName())
        # we use the ghidra path so it can be easily read back
        # when reading from blank slate all other types should have been created before this is ran.
        typedef.write(
            "typedef " + os.path.basename(dat_type.getBaseDataType().getPathName().lstrip("/")) + " " + dat_type.getDisplayName() + ";")

        if dat_type.description:
            typedef.write(" // " + dat_type.description)

        typedef.close()

    elif isinstance(dat_type, ghidra.program.database.data.EnumDB):
        type_path = path.resolve("types").resolve(parent_path)
        Files.createDirectories(type_path)

        enum = open(str(type_path.resolve(path_name.rpartition('/')[-1].lstrip("/") + ".h")), "w")

        enum.write("enum " + dat_type.getDisplayName() + " : uint" + str(
            int(math.log(dat_type.getMaxPossibleValue() + 1, 2))) + "_t {")

        # type: ghidra.program.database.data.EnumDB
        # print("Enum " + dat_type.getPathName())
        for i in range(0, dat_type.count):
            try:
                enum.write("\n    " + dat_type.names[i] + " = " + str(dat_type.values[i]) + ";")

                if dat_type.getComment(dat_type.names[i]):
                    enum.write(" // " + dat_type.getComment(dat_type.names[i]))
            except IndexError:
                enum.write("\n    // Couldn't index into array with value " + str(i))

        enum.write("\n}")

        if dat_type.description:
            enum.write(" // " + dat_type.description)

        enum.close()
#endregion

#region label writer
sym_builder = []

print("Writing DAT symbols (may take a while)")
# address;name;is_deleted;is_pinned;is_external;source_display_string;id;namespace_count;[namespaces];has_data_type;data_type
for sym in sym_table.getAllSymbols(True):  # type: ghidra.program.model.symbol.Symbol
    if sym.getSymbolType() == SymbolType.LABEL:
        append(sym_builder, sym.address.toString())
        append(sym_builder, sym.getName())
        append(sym_builder, str(sym.deleted))
        append(sym_builder, str(sym.pinned))
        append(sym_builder, str(sym.external))
        append(sym_builder, str(sym.source.getDisplayString()))
        append(sym_builder, str(sym.getID()))

        namespaces = []
        nmsp_size = 0
        parent_nmsp = sym.getParentNamespace()

        while True:
            if parent_nmsp is None:
                break

            append(namespaces, parent_nmsp.getName())
            nmsp_size += 1
            parent_nmsp = parent_nmsp.getParentNamespace()

        append(sym_builder, str(nmsp_size))
        sym_builder.append("".join(namespaces))

        data = currentProgram.getListing().getDataAt(sym.address)

        append(sym_builder, str(data is not None))

        if data is not None:
            append(sym_builder, str(data.getDataType().getPathName().lstrip("/")))

        sym_builder.append("\n")

labels.write(''.join(sym_builder))
#endregion

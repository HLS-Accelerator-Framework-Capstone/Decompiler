from ghidra.app.decompiler import DecompInterface

def decompile_function(func):
    """ Decompile a function and return its C-like code """
    di = DecompInterface()
    di.openProgram(currentProgram)
    result = di.decompileFunction(func, 60, monitor)  # 60s timeout per function
    if result.decompileCompleted():
        return result.getDecompiledFunction().getC()
    return None

# Get all functions in the disassembled ASM file
listing = currentProgram.getListing()
output_path = "C:/Users/itsty/ghidra_scripts/decompiled_code.c"  # Update this path

with open(output_path, "w") as f:
    for func in listing.getFunctions(True):
        decompiled_code = decompile_function(func)
        if decompiled_code:
            f.write("// Function: {}\n{}\n\n".format(func.getName(), decompiled_code))


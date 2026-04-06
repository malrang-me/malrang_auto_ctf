// Ghidra headless script: decompile all functions to individual files
// Output dir is passed as first script argument
//@category CTF
//@keybinding
//@menupath
//@toolbar

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

import java.io.File;
import java.io.FileWriter;

public class DecompileToFiles extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String outputDir = args.length > 0 ? args[0] : "/tmp/ghidra_decompiled";
        String targetFunc = args.length > 1 ? args[1] : "";
        boolean listOnly = args.length > 2 && args[2].equals("--list");

        File outDir = new File(outputDir);
        outDir.mkdirs();

        if (listOnly) {
            // Just list function names and addresses
            File listFile = new File(outDir, "_functions.txt");
            FileWriter lw = new FileWriter(listFile);
            FunctionIterator funcs = currentProgram.getFunctionManager().getFunctions(true);
            while (funcs.hasNext()) {
                Function f = funcs.next();
                if (!f.isThunk() && f.getBody().getNumAddresses() > 2) {
                    lw.write(String.format("0x%x %s (%d bytes)\n",
                        f.getEntryPoint().getOffset(), f.getName(),
                        f.getBody().getNumAddresses()));
                }
            }
            lw.close();
            println("[ghidra] Function list written to " + listFile.getPath());
            return;
        }

        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        FunctionIterator funcs = currentProgram.getFunctionManager().getFunctions(true);
        int count = 0;

        while (funcs.hasNext()) {
            Function f = funcs.next();
            if (f.isThunk() || f.getBody().getNumAddresses() <= 2) continue;
            if (!targetFunc.isEmpty() && !f.getName().equals(targetFunc)) continue;

            DecompileResults result = decomp.decompileFunction(f, 30, monitor);
            if (result.decompileCompleted()) {
                String code = result.getDecompiledFunction().getC();
                String safeName = f.getName().replaceAll("[^a-zA-Z0-9_]", "_");
                String addr = String.format("0x%x", f.getEntryPoint().getOffset());
                File outFile = new File(outDir, safeName + ".c");
                FileWriter fw = new FileWriter(outFile);
                fw.write("// Function: " + f.getName() + " @ " + addr + "\n");
                fw.write("// Size: " + f.getBody().getNumAddresses() + " bytes\n\n");
                fw.write(code);
                fw.close();
                count++;
            }
        }

        decomp.dispose();
        println("[ghidra] Decompiled " + count + " function(s) to " + outputDir);
    }
}

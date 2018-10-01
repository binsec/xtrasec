#include "pin.H"
#include <iostream>
#include <fstream>

/* ================================================================== */
// Global variables 
/* ================================================================== */

#define __STDC_FORMAT_MACROS
#include <inttypes.h>

static UINT64 insCount = -1;        // number of dynamically executed instructions
static FILE * trace; // Where is the trace output.


// We trace only when this flag is set.
static bool is_tracing = false;

/* ================================================================== */
///////////////// Instruction instrumentation. ////////////////
/* ================================================================== */

// Addresses where to start and stop tracing.
static ADDRINT start_address = 0;
static ADDRINT stop_address = 0;



// Print the instruction, count, address, and opcode.
VOID printip(UINT32 size, ADDRINT ip) {
  insCount++;
  if(!is_tracing) {
    if(ip == start_address) {
      cout << "Start tracing";
      is_tracing = true;
    }
    else return;
  }
  else {
    if(ip == stop_address) {
      cout << "Stop tracing";
      is_tracing = false;
    }
  }
  
  int i = 0;
  fprintf(trace,"ins %" PRIu64 " @%p: code 0x", insCount, (void *)ip);

  // Fetch and prints the opcode.
  assert(size < 15);
  unsigned char buffer[15];
  unsigned int fetched = PIN_SafeCopy(buffer,(char *) ip, size);
  assert(fetched == size);
  for(i = 0; i < (int) size; i++) {
    fprintf(trace,"%02x",(unsigned char) buffer[i]);
  }
  
  fprintf(trace,"\n");
}

/* ================================================================== */
///////////////// Memory access instrumentation. ////////////////
/* ================================================================== */

// Print a memory read record
VOID RecordMemRead(VOID * ip, VOID * addr)
{
  if(is_tracing) fprintf(trace,"mem %" PRIu64 " @%p: R %p\n", insCount, ip, addr);
}

// Print a memory write record
VOID RecordMemWrite(VOID * ip, VOID * addr)
{
  if(is_tracing) fprintf(trace,"mem %" PRIu64 " @%p: W %p\n", insCount, ip, addr);
}



VOID MemoryAccessInstrumentation(INS ins, VOID *v){

    // Instruments memory accesses using a predicated call, i.e.
    // the instrumentation is called iff the instruction will actually be executed.
    //
    // On the IA-32 and Intel(R) 64 architectures conditional moves and REP 
    // prefixed instructions appear as predicated instructions in Pin.
    UINT32 memOperands = INS_MemoryOperandCount(ins);

    // Iterate over each memory operand of the instruction.
    for (UINT32 memOp = 0; memOp < memOperands; memOp++)
    {
        if (INS_MemoryOperandIsRead(ins, memOp))
        {
            INS_InsertCall(
                ins, IPOINT_BEFORE, (AFUNPTR)RecordMemRead,
                IARG_INST_PTR,
                IARG_MEMORYOP_EA, memOp,
                IARG_END);
        }
        // Note that in some architectures a single memory operand can be 
        // both read and written (for instance incl (%eax) on IA-32)
        // In that case we instrument it once for read and once for write.
        if (INS_MemoryOperandIsWritten(ins, memOp))
        {
            INS_InsertCall(
                ins, IPOINT_BEFORE, (AFUNPTR)RecordMemWrite,
                IARG_INST_PTR,
                IARG_MEMORYOP_EA, memOp,
                IARG_END);
        }
    }
}

/* ================================================================== */
///////////////// Registers writes instrumentation. ////////////////
/* ================================================================== */

static bool has_no_fallthrough(INS ins){

  if (INS_IsCall(ins) || INS_IsRet(ins) || INS_Category(ins) == XED_CATEGORY_COND_BR)
        return true;
  if (INS_IsIndirectBranchOrCall(ins)) return true;
  if (INS_IsDirectBranchOrCall(ins)) return true;
  if (INS_Opcode(ins) == XED_ICLASS_SYSENTER) return true;
  if (INS_Opcode(ins) == XED_ICLASS_INT) return true;
  return false;
}

// Print a memory write record
VOID RecordRegWrite(UINT32 _r, ADDRINT v)
{
  REG r = (REG) _r;
  if(is_tracing) fprintf(trace,"reg %s write %p\n", REG_StringShort(r).c_str(), (void *) v);
}

VOID RegisterInstrumentation(INS ins, VOID *v){

  // Get the values written to registers. For this, we need to
  // instrument after the instruction, which does not make sense
  // when the function does not fall through.
  if(has_no_fallthrough(ins)) return;

  UINT32 opCount = INS_OperandCount(ins);

  for(UINT32 op = 0; op < opCount; op++){

    // Instrument register writes.
    if(INS_OperandIsReg(ins,op) && INS_OperandWritten(ins,op)){
      REG r = INS_OperandReg(ins,op);
      r = REG_FullRegName(r);
      if(REG_Size(r) <= 4)
        {
        INS_InsertCall(ins, IPOINT_AFTER, (AFUNPTR) RecordRegWrite,
                       IARG_UINT32, (UINT32) r,
                       IARG_REG_VALUE, r, IARG_END);

      }
    }
  }
}

/* ===================================================================== */
// Instrumentation callbacks
/* ===================================================================== */


static int instr_count;

// Is called for every instruction and instruments reads and writes
VOID Instruction(INS ins, VOID *v)
{
  RTN rtn = INS_Rtn(ins);
  string rtn_name = RTN_Valid(rtn)? RTN_Name(rtn) : "unknown routine";
  // Note: Only returns ".text" or ".plt" instead of the real function name.

  // First instrumentation: shows the adress and operand of the instruction. This is also used to
  // delimit instructions.
  UINT32 size = INS_Size(ins);

    cerr << "Disasm " << rtn_name << " " << dec << (int) insCount
         << " 0x" << hex << INS_Address(ins) << " " << (int) instr_count
         << " " << INS_Disassemble(ins) << endl;
  instr_count++;

  // First instrumentation: instruction address and opcode.
  INS_InsertCall(ins,IPOINT_BEFORE,(AFUNPTR)printip, IARG_UINT32, size, IARG_INST_PTR, IARG_END);

  // Second instrumentation: memory accesses within an instruction
  MemoryAccessInstrumentation(ins,v);

  // Third instrumentation: register values
  RegisterInstrumentation(ins,v);
  
}



/*!
 * Print out analysis results.
 * This function is called when the application exits.
 * @param[in]   code            exit code of the application
 * @param[in]   v               value specified by the tool in the 
 *                              PIN_AddFiniFunction function call
 */
VOID Fini(INT32 code, VOID *v)
{
  cerr << "End of trace";
  fclose(trace);
  // *out <<  "===============================================" << endl;
  // *out <<  "Tracer analysis results: " << endl;
  // *out <<  "Number of instructions: " << insCount  << endl;
  // *out <<  "Number of basic blocks: " << bblCount  << endl;
  // *out <<  "Number of threads: " << threadCount  << endl;
  // *out <<  "===============================================" << endl;
}


// Refine the start_address by searching the entry point of the program.
VOID Image(IMG img, VOID* data) {
    cout << "Image load:" << IMG_Name(img) <<  endl;
	if (// start_at_eip && 
            IMG_IsMainExecutable(img)) {
                // If we cannot find main, we will start at this address.
		cout << "Found Entrypoint:" << hex << IMG_Entry(img) << endl;
                start_address = IMG_Entry(img);
#if 0
                // This does not work.
                RTN rtn = RTN_FindByName(img,"main");
                assert(RTN_Valid(rtn));
                start_address = RTN_Address(rtn);
                if(start_address != 0) {
                  cout << "Could not find address for main; starting at entry point";
                  start_address = IMG_Entry(img);
                }
		cout << "Start Address:" << hex << start_address << endl;
#endif                
                
	}
}

// Pin calls this function once for each routine, before the program is run.
// We use it to refine the start and end address by searching for main and exit.
VOID Routine(RTN rtn, VOID *v)
 {   
   if(RTN_Name(rtn) == "main") {
     // Improve the start address by using main.
     start_address = RTN_Address(rtn);     
     cout << "'main' found: starting at " << hex << start_address << "\n";

#if 0
     // This does not work.
     RTN_Open(rtn);
     INS ins = RTN_InsHeadOnly(rtn);
     INS_InsertCall(ins,IPOINT_BEFORE,(AFUNPTR) start_tracing, IARG_END);     
     RTN_InsertCall(rtn,IPOINT_BEFORE, (AFUNPTR) start_tracing, IARG_END);
     RTN_InsertCall(rtn,IPOINT_AFTER, (AFUNPTR) stop_tracing, IARG_END);
#endif     
   }
   else if(RTN_Name(rtn) == "exit" || RTN_Name(rtn) == "exit@plt"){
     // Improve the end tracing address by using exit.
     stop_address = RTN_Address(rtn);          
     cout << "'exit' found: stopping at " << hex << start_address << "\n";
#if 0
     RTN_Open(rtn);
     RTN_InsertCall(rtn,IPOINT_BEFORE, (AFUNPTR) stop_tracing, IARG_END);
#endif     
   }
 }


/* ===================================================================== */
// Command line switches
/* ===================================================================== */
KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE,  "pintool",
    "o", "", "specify file name for Tracer output");

KNOB<BOOL>   KnobCount(KNOB_MODE_WRITEONCE,  "pintool",
    "count", "1", "count instructions, basic blocks and threads in the application");


/* ===================================================================== */
// Utilities
/* ===================================================================== */

INT32 Usage()
{
    cerr << "This tool prints out the number of dynamically executed " << endl <<
            "instructions, basic blocks and threads in the application." << endl << endl;

    cerr << KNOB_BASE::StringKnobSummary() << endl;

    return -1;
}



/*!
 * The main procedure of the tool.
 * This function is called when the application image is loaded but not yet started.
 * @param[in]   argc            total number of elements in the argv array
 * @param[in]   argv            array of command line arguments, 
 *                              including pin -t <toolname> -- ...
 */
int main(int argc, char *argv[])
{
    // Initialize PIN library. Print help message if -h(elp) is specified
    // in the command line or the command line is invalid 
    if( PIN_Init(argc,argv) )
    {
        return Usage();
    }
    PIN_InitSymbols();
    string fileName = KnobOutputFile.Value();

    if(fileName.empty()) { assert(0);}

    trace = fopen(fileName.c_str(),"w");

    RTN_AddInstrumentFunction(Routine,0);
    INS_AddInstrumentFunction(Instruction, 0);
    IMG_AddInstrumentFunction(Image, 0);
    
    // Register function to be called when the application exits
    PIN_AddFiniFunction(Fini, 0);

    
    cerr <<  "===============================================" << endl;
    cerr <<  "This application is instrumented by Tracer" << endl;
    if (!KnobOutputFile.Value().empty()) 
    {
        cerr << "See file " << KnobOutputFile.Value() << " for analysis results" << endl;
    }
    cerr <<  "===============================================" << endl;

    // Start the program, never returns
    PIN_StartProgram();
    
    return 0;
}

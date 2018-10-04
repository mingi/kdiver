/////////////////////////////////////////////////////////////////////////
// $Id: instrument.cc 12655 2015-02-19 20:23:08Z sshwarts $
/////////////////////////////////////////////////////////////////////////
//
//   Copyright (c) 2006-2015 Stanislav Shwartsman
//          Written by Stanislav Shwartsman [sshwarts at sourceforge net]
//
//  This library is free software; you can redistribute it and/or
//  modify it under the terms of the GNU Lesser General Public
//  License as published by the Free Software Foundation; either
//  version 2 of the License, or (at your option) any later version.
//
//  This library is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
//  Lesser General Public License for more details.
//
//  You should have received a copy of the GNU Lesser General Public
//  License along with this library; if not, write to the Free Software
//  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA


#include <assert.h>

#include "bochs.h"
#include "cpu/cpu.h"
#include "disasm/disasm.h"

#include "mem_interface.h"

// maximum size of an instruction
#define MAX_OPCODE_LENGTH 16

// maximum physical addresses an instruction can generate
#define MAX_DATA_ACCESSES 1024

// maximum register size
#define MAX_REG_SIZE 4

#define COPY_FROM_USER_ADDR 0xc13ab0c0
#define RET_SYSCALL_MMAP    0xc11a2b59

#define START_COVERAGE  0x2f002000
#define STOP_COVERAGE   0x2f003000
#define START_LOG_MEM  0x2f004000
#define STOP_LOG_MEM   0x2f005000

const char* log_path = "./trace";
const char* coverage_path = "./coverage.info";
const char* mem_log_path = "./taint_mem.info";

FILE *fp_log;
FILE *fp_coverage;
FILE *fp_mem;

// Use this variable to turn on/off collection of instrumentation data
// If you are not using the debugger to turn this on/off, then possibly
// start this at 1 instead of 0.
static bx_bool active = 0;
static bx_bool active_coverage = 0;
static bx_bool active_mem = 0;

static disassembler bx_disassembler;

static struct instruction_t {
  bx_bool  ready;         // is current instruction ready to be printed
  unsigned opcode_length;
  Bit8u    opcode[MAX_OPCODE_LENGTH];
  bx_bool  is32, is64;
  unsigned num_data_accesses;
  struct {
    bx_address laddr;     // linear address
    bx_phy_address paddr; // physical address
    unsigned rw;          // BX_READ, BX_WRITE or BX_RW
    unsigned size;        // 1 .. 64
    unsigned memtype;
  } data_access[MAX_DATA_ACCESSES];
  bx_bool is_branch;
  bx_bool is_taken;
  bx_address target_linear;
} *instruction;

static logfunctions *instrument_log = new logfunctions ();
#define LOG_THIS instrument_log->

void bx_instr_init_env(void) {}
void bx_instr_exit_env(void) {}

struct MEM_TAINT {
 unsigned int address;
 unsigned int offset;
};

struct REG_TAINT {

};

//struct MEM_TAINT* taint_mem_list[1024]; 
unsigned int *taint_mem_list;
unsigned int *taint_reg_list;
unsigned int taint_list_offset;

unsigned char *branch_list;

#define LIN_TO_IDX(lin) ((lin) - 0xC0000000)
#define SRC_TO_OFF(lin) ((lin) & 0xFFFFFFF)

bool mark_branch_explore(bx_address address){
  if(address < 0xC0000000) return false;

  if (branch_list[LIN_TO_IDX(address)] == 1){
    return false;
  }
  else{
    print_debug_string_int("[Branch] new branch 0x%x", address);
    print_debug_string(" explored\n");

    if(fp_coverage != NULL){
      fprintf(fp_coverage, "0x%x\n", address);
    }

    branch_list[LIN_TO_IDX(address)] = 1;
    return true;
  }
}

void start_branch_coverage(){
  const size_t _1G = 1024 * 1024 * 1024LL; 

  print_debug_string("[COVERAGE] start branch coverage\n");
  fp_coverage = fopen(coverage_path, "w");

  memset(branch_list, NULL, _1G);
}

void stop_branch_coverage(){
  print_debug_string("[COVERAGE] stop branch coverage\n");
  fclose(fp_coverage);
  fp_coverage = NULL;
}

void start_log_mem(){
  const size_t _1G = 1024 * 1024 * 1024LL; 

  print_debug_string("[MEM] start log memory\n");
  fp_mem = fopen(mem_log_path, "w");

  memset(branch_list, NULL, _1G);
}

void stop_log_mem(){
  print_debug_string("[MEM] stop log memory\n");
  fclose(fp_mem);
  fp_mem = NULL;
}

void initialize() {
  fp_log = fopen(log_path, "w");

  assert(fp_log != NULL);

  const size_t _1G = 1024 * 1024 * 1024LL; 
  const size_t reg_list_size = 8 * 4 * 4LL; // num of reg * reg size * sizeof(uint32)

  taint_mem_list = (unsigned int *)malloc(_1G*4);
  assert(taint_mem_list != NULL);

  memset(taint_mem_list, -1, _1G*4);

  fprintf(stderr, "Taint mem list alloced at 0x%x\n", taint_mem_list);

  taint_reg_list = (unsigned int *)malloc(reg_list_size);
  assert(taint_reg_list != NULL);

  memset(taint_reg_list, -1, reg_list_size);

  fprintf(stderr, "Taint reg list alloced at 0x%x\n", taint_reg_list);
}

void reset_taint() {
  const size_t _1G = 1024 * 1024 * 1024LL; 
  const size_t reg_list_size = 8 * 4 * 4LL; // num of reg * reg size * sizeof(uint32)

  //print_debug_string("[TAINT RESET] Reset taint lists\n");

  if(active){
    memset(taint_mem_list, -1, _1G*4);
    memset(taint_reg_list, -1, reg_list_size);
  }

  system("cp ./trace ./trace.txt");

  if(fp_log == NULL){
   fp_log = fopen(log_path, "w");
  }
}

void stop_taint() {
  //print_debug_string("[TAINT STOP] \n");
    
  if(fp_log != NULL){
    fclose(fp_log);
    fp_log = NULL;
  }
}

void destroy() {
  free(taint_mem_list);
  taint_mem_list = NULL;
  fclose(fp_log);
}

void print_reg_offset(unsigned int reg_idx, size_t size){
  fprintf(fp_log, "{");

  for (int i = 0; i < size; i++){
    if (taint_reg_list[reg_idx*MAX_REG_SIZE+i] != -1)
      fprintf(fp_log, "0x%02x,", taint_reg_list[reg_idx*MAX_REG_SIZE+i]);
    else
      fprintf(fp_log, ",");
  }

  fprintf(fp_log, "}");
}

void print_mem_offset(bx_address addr, size_t size){
  fprintf(fp_log, "{");

  for (int i = 0; i < size; i++){
    if (taint_mem_list[LIN_TO_IDX(addr+i)] != -1)
      fprintf(fp_log, "0x%02x,", taint_mem_list[LIN_TO_IDX(addr+i)]);
    else
      fprintf(fp_log, ",");
  }

  fprintf(fp_log, "}");
}

// ins reg, reg
void print_trace_log(BX_CPU_C *pcpu, char* insdis, char* reg1, char* reg2, size_t size){
  unsigned int reg1_idx = get_reg_idx(reg1);
  unsigned int reg2_idx = get_reg_idx(reg2);
  char op1[12], op2[12];

  memset(op1, NULL, 12);
  memset(op2, NULL, 12);

  if (reg1_idx == -1 || reg2_idx == -1) return;

  print_debug_string("[Print Trace] OP REG REG\n");

  fprintf(fp_log, "0x%x.%s.N.", pcpu->prev_rip, insdis);

  print_reg_offset(reg1_idx, size);
  print_reg_offset(reg2_idx, size);

  memcpy(op1, (void*)&(pcpu->gen_reg[reg1_idx].rrx), size);
  memcpy(op2, (void*)&(pcpu->gen_reg[reg2_idx].rrx), size);

  fprintf(fp_log, ".");

  for(int i=0; i<4; i++)
    fprintf(fp_log, "%02x", (unsigned char) op1[i]);

  fprintf(fp_log, ".");

  for(int i=0; i<4; i++)
    fprintf(fp_log, "%02x", (unsigned char) op2[i]);

  fprintf(fp_log, ".\n");
}

// ins reg, mem
void print_trace_log(BX_CPU_C *pcpu, char* insdis, char* reg1, bx_address addr2, size_t size){
  unsigned int reg1_idx = get_reg_idx(reg1);
  char op1[12], op2[12];

  memset(op1, NULL, 12);
  memset(op2, NULL, 12);

  if (reg1_idx == -1) return;

  print_debug_string("[Print Trace] OP REG MEM\n");

  fprintf(fp_log, "0x%x.%s.N.", pcpu->prev_rip, insdis);

  print_reg_offset(reg1_idx, size);
  print_mem_offset(addr2, size);

  memcpy(op1, (void*)&(pcpu->gen_reg[reg1_idx].rrx), size);
  read_lin_mem(pcpu, addr2, size, op2);

  fprintf(fp_log, ".");

  for(int i=0; i<4; i++)
    fprintf(fp_log, "%02x", (unsigned char) op1[i]);

  fprintf(fp_log, ".%08x.\n", *(unsigned int*)op2);
}

// ins reg, imm
void print_trace_log_imm(BX_CPU_C *pcpu, char* insdis, char* reg1, unsigned int imm, size_t size){
  unsigned int reg1_idx = get_reg_idx(reg1);
  char op1[12], op2[12];

  memset(op1, NULL, 12);
  memset(op2, NULL, 12);

  if (reg1_idx == -1) return;

  print_debug_string("[Print Trace] OP REG MEM\n");

  fprintf(fp_log, "0x%x.%s.N.", pcpu->prev_rip, insdis);

  print_reg_offset(reg1_idx, size);

  memcpy(op1, (void*)&(pcpu->gen_reg[reg1_idx].rrx), size);
  memcpy(op2, (void*)&imm, size);

  fprintf(fp_log, ".");

  for(int i=0; i<4; i++)
    fprintf(fp_log, "%02x", (unsigned char) op1[i]);

  fprintf(fp_log, ".");

  for(int i=0; i<4; i++)
    fprintf(fp_log, "%02x", (unsigned char) op2[i]);

  fprintf(fp_log, ".\n");

}

// ins mem, reg
void print_trace_log(BX_CPU_C *pcpu, char* insdis, bx_address addr1, char* reg2, size_t size){
  unsigned int reg2_idx = get_reg_idx(reg2);
  char op1[12], op2[12];

  memset(op1, NULL, 12);
  memset(op2, NULL, 12);
  
  if (reg2_idx == -1) return;

  print_debug_string("[Print Trace] OP MEM REG\n");

  fprintf(fp_log, "0x%x.%s.N.", pcpu->prev_rip, insdis);

  print_mem_offset(addr1, size);
  print_reg_offset(reg2_idx, size);

  read_lin_mem(pcpu, addr1, size, op1);
  memcpy(op2, (void*)&(pcpu->gen_reg[reg2_idx].rrx), size);

  fprintf(fp_log, ".%08x.", *(unsigned int*)op1);

  for(int i=0; i<4; i++)
    fprintf(fp_log, "%02x", (unsigned char) op2[i]);

  fprintf(fp_log, ".\n");
}

// ins mem, imm
void print_trace_log_imm(BX_CPU_C *pcpu, char* insdis, bx_address addr1, unsigned int imm, size_t size){
  char op1[12], op2[12];

  memset(op1, NULL, 12);
  memset(op2, NULL, 12);
  
  print_debug_string("[Print Trace] OP MEM REG\n");

  fprintf(fp_log, "0x%x.%s.N.", pcpu->prev_rip, insdis);

  print_mem_offset(addr1, size);

  read_lin_mem(pcpu, addr1, size, op1);
  memcpy(op2, (void*)&imm, size);

  fprintf(fp_log, ".%08x.", *(unsigned int*)op1);

  for(int i=0; i<4; i++)
    fprintf(fp_log, "%02x", (unsigned char) op2[i]);

  fprintf(fp_log, ".\n");
}

void print_debug_string(char* str){
  fprintf(stderr, str);
}

void print_debug_string_int(char* str, int val){
  fprintf(stderr, str, val);
}

void add_tainted_mem(unsigned int start, unsigned int size){
  if (start < 0xC0000000) return;

  for (int i=0; i < size; i++){
    // struct MEM_TAINT* mt = new struct MEM_TAINT;
    // mt->address = start + i;
    // mt->offset = i;
    //taint_mem_list[taint_list_offset++] = mt;
    taint_mem_list[LIN_TO_IDX(start+i)] = i;
  }

  //fprintf(stderr, "Memory tainted from 0x%x, size 0x%x\n", start, size);
}

void add_tainted_mem_from_source(unsigned int start, unsigned int source, size_t size){
  if (start < 0xC0000000) return;

  fprintf(stderr, "[TAINT MEM SOURCE] start 0x%x, src, 0x%x, size 0x%x\n", start, source, size);

  for (int i=0; i < size; i++){
    //fprintf(stderr, "[TAINT MEM SOURCE] 0x%x tainted by 0x%x\n", LIN_TO_IDX(start+i), SRC_TO_OFF(source)+i);

    if(active_mem)
      fprintf(fp_mem, "0x%x\n", LIN_TO_IDX(start+i));

    taint_mem_list[LIN_TO_IDX(start+i)] = SRC_TO_OFF(source) + i;
  }

  //fprintf(stderr, "Memory tainted from 0x%x, size 0x%x\n", start, size);
}

void add_tainted_mem_mem(unsigned int dst, unsigned int src, size_t size){
  if (dst < 0xC0000000 || src < 0xC0000000) return;

  //fprintf(stderr, "[TAINT MEM MEM] dst 0x%x, src, 0x%x, size 0x%x\n", dst, src, size);

  for (int i=0; i < size; i++){
    if(active_mem)
      fprintf(fp_mem, "0x%x\n", LIN_TO_IDX(dst+i));

    taint_mem_list[LIN_TO_IDX(dst+i)] = taint_mem_list[LIN_TO_IDX(src+i)];
  }
}

void add_tainted_mem_reg(unsigned int dst, char* reg_src, size_t size){
  if (dst < 0xC0000000) return;
  if (size > MAX_REG_SIZE) return;

  unsigned int src_idx = get_reg_idx(reg_src);

  if(src_idx == -1) return;

  fprintf(stderr, "[TAINT MEM REG] dst 0x%x, src %s, size 0x%x\n", dst, reg_src, size);

  for (int i = 0; i < size; i++){
    if(active_mem)
      fprintf(fp_mem, "0x%x\n", LIN_TO_IDX(dst+i));

    taint_mem_list[LIN_TO_IDX(dst+i)] = taint_reg_list[src_idx*MAX_REG_SIZE + i];
    fprintf(stderr, "\t0x%x tainted by 0x%x\n", LIN_TO_IDX(dst+i), taint_reg_list[src_idx*MAX_REG_SIZE + i]);
  }
}

void remove_tainted_mem(unsigned int start, size_t size){
  if (start < 0xC0000000) return;

  for (int i=0; i < size; i++)
    taint_mem_list[LIN_TO_IDX(start+i)] = -1;

  //fprintf(stderr, "Memory removed from 0x%x, size 0x%x\n", start, size);
}

bool is_mem_tainted(unsigned int address, size_t size){
  if(address < 0xC0000000) return false;

  for (int i = 0; i < size; i++){
    if (taint_mem_list[LIN_TO_IDX(address)] != -1)
      return true;
  }

  return false;
}

unsigned int get_reg_idx(char* reg){
  // print_debug_string("[GET REG IDX] reg: ");
  // print_debug_string(reg);
  // print_debug_string("\n");

  if(!strcmp(reg, "eax")){
    return EAX_INDEX;
  }
  else if(!strcmp(reg, "ecx")){
    return ECX_INDEX;
  }  
  else if(!strcmp(reg, "edx")){
    return EDX_INDEX;
  }
  else if(!strcmp(reg, "ebx")){
    return EBX_INDEX;
  }
  else if(!strcmp(reg, "esp")){
    return ESP_INDEX;
  }
  else if(!strcmp(reg, "ebp")){
    return EBP_INDEX;
  }
  else if(!strcmp(reg, "esi")){
    return ESI_INDEX;
  }
  else if(!strcmp(reg, "edi")){
    return EDI_INDEX;
  }
  else {
    //print_debug_string("[GET REG IDX] Unknown register!!\n");
    return -1;
  }
}

void add_tainted_reg(char* reg){
  // print_debug_string("[TAINT REG] reg tainted ");
  // print_debug_string(reg);
  // print_debug_string("\n"); 

  unsigned int reg_idx = get_reg_idx(reg);

  if(reg_idx == -1) return;

  taint_reg_list[reg_idx*MAX_REG_SIZE] = 0xaa;
}

void add_tainted_reg_reg(char* reg_dst, char* reg_src, size_t size){
  // print_debug_string("[TAINT REG] reg tainted ");
  // print_debug_string(reg);
  // print_debug_string("\n"); 

  if (size > MAX_REG_SIZE) return;

  unsigned int dst_idx = get_reg_idx(reg_dst);
  unsigned int src_idx = get_reg_idx(reg_src);

  if(dst_idx == -1 || src_idx == -1) return;

  fprintf(stderr, "[TAINT REG REG] dst %s, src %s, size 0x%x\n", reg_dst, reg_src, size);

  for (int i = 0; i < size; i++){
    taint_reg_list[dst_idx*MAX_REG_SIZE + i] = taint_reg_list[src_idx*MAX_REG_SIZE + i];
    fprintf(stderr, "\t%s:0x%x tainted by 0x%x\n", reg_dst, i, taint_reg_list[src_idx*MAX_REG_SIZE + i]);
  }
}

void add_tainted_reg_mem(char* reg_dst, unsigned int src, size_t size){
  // print_debug_string("[TAINT REG] reg tainted ");
  // print_debug_string(reg);
  // print_debug_string("\n"); 
  if (src < 0xC0000000) return;
  if (size > MAX_REG_SIZE) return;

  unsigned int dst_idx = get_reg_idx(reg_dst);

  if(dst_idx == -1) return;

  fprintf(stderr, "[TAINT REG MEM] dst %s, src 0x%x, size 0x%x\n", reg_dst, src, size);

  for (int i = 0; i < size; i++){
    taint_reg_list[dst_idx*MAX_REG_SIZE+i] = taint_mem_list[LIN_TO_IDX(src+i)];
    fprintf(stderr, "\t%s:0x%x tainted by 0x%x\n", reg_dst, i, taint_mem_list[LIN_TO_IDX(src+i)]);
  }
}

void remove_tainted_reg(char* reg){
  size_t size = 4;

  unsigned int reg_idx = get_reg_idx(reg);
  
  if(reg_idx == -1) return;

  for (int i = 0; i < size; i++)
    taint_reg_list[reg_idx*MAX_REG_SIZE+i] = -1;
}

void remove_tainted_reg(char* reg, size_t size){
  // print_debug_string("[TAINT REG] reg untainted ");
  // print_debug_string(reg);
  // print_debug_string("\n");

  if (size > MAX_REG_SIZE) return;

  unsigned int reg_idx = get_reg_idx(reg);
  
  if(reg_idx == -1) return;

  for (int i = 0; i < size; i++)
    taint_reg_list[reg_idx*MAX_REG_SIZE+i] = -1;
}

bool is_reg_tainted(char* reg){
  size_t size = 4;

  unsigned int reg_idx = get_reg_idx(reg);

  if(reg_idx == -1) return false;

  for (int i = 0; i < size; i++)
    if (taint_reg_list[reg_idx*MAX_REG_SIZE+i] != -1)
      return true;

  return false;
}

bool is_reg_tainted(char* reg, size_t size){
  if (size > MAX_REG_SIZE) return false;

  unsigned int reg_idx = get_reg_idx(reg);

  if(reg_idx == -1) return false;

  for (int i = 0; i < size; i++)
    if (taint_reg_list[reg_idx*MAX_REG_SIZE+i] != -1)
      return true;

  return false;
}

void print_instruction(unsigned cpu, const instruction_t *i, const char * disasm_tbuf){
  unsigned length = i->opcode_length, n;

  //fprintf(stderr, "----------------------------------------------------------\n");
  fprintf(stderr, "CPU %u: %s\n\n", cpu, disasm_tbuf);
  //disasm_regref
  //fprintf(stderr, "LEN %u\tBYTES: ", length);
  
  //for(n=0;n < length;n++) fprintf(stderr, "%02x", i->opcode[n]);      
  //fprintf(stderr, "\n");
}

void print_mem_access(const instruction_t *i){
  bx_address lin_addr = 0;
  size_t size = 0;

  for(int n=0;n < i->num_data_accesses;n++)
  {
    lin_addr = i->data_access[n].laddr;
    size = i->data_access[n].size;

    fprintf(stderr, "MEM ACCESS[%u]: 0x" FMT_ADDRX " (linear) 0x" FMT_PHY_ADDRX " (physical) %s SIZE: %d\n", n,
                i->data_access[n].laddr,
                i->data_access[n].paddr,
                i->data_access[n].rw == BX_READ ? "RD":"WR",
                i->data_access[n].size);
  }
}


// Callback invoked on Bochs CPU initialization.

void bx_instr_initialize(unsigned cpu)
{
  const size_t _1G = 1024 * 1024 * 1024LL; 

  assert(cpu < BX_SMP_PROCESSORS);

  if (instruction == NULL)
      instruction = new struct instruction_t[BX_SMP_PROCESSORS];

  if(taint_mem_list == NULL)
    initialize();

  if (branch_list == NULL)
    branch_list = (unsigned char*) malloc(_1G);

  fprintf(stderr, "Initialize cpu %u\n", cpu);
}

void bx_instr_reset(unsigned cpu, unsigned type)
{
  instruction[cpu].ready = 0;
  instruction[cpu].num_data_accesses = 0;
  instruction[cpu].is_branch = 0;
}

void bx_print_instruction(unsigned cpu, const instruction_t *i)
{
  char disasm_tbuf[512];	// buffer for instruction disassembly
  unsigned length = i->opcode_length, n;
  bx_address lin_addr = 0, lin_addr_r = 0, lin_addr_w = 0;
  size_t size = 0;
  char op1[12], op2[12];
  BX_CPU_C *pcpu = BX_CPU(cpu);

  memset(op1, '\0', 12);
  memset(op2, '\0', 12);

  bx_disassembler.disasm(i->is32, i->is64, 0, 0, i->opcode, disasm_tbuf);

  if(length != 0)
  {
    if (i->num_data_accesses == 0) { // reg, reg and reg, imm

      if (!memcmp(disasm_tbuf, "mov ", 4)){
        // mov exx, exx
        if (*(disasm_tbuf+4) == 'e' && *(disasm_tbuf+9) == 'e'){
          memcpy(op1, disasm_tbuf+4, 3);
          op1[3] = '\0';

          memcpy(op2, disasm_tbuf+9, 3);
          op2[3] = '\0';

          // op1 taint, op2 free -> op1 free
          if (is_reg_tainted(op1) && !is_reg_tainted(op2)){
            remove_tainted_reg(op1);
          } 
          // op1 taint, op2 taint -> update op1 taint offset
          else if (is_reg_tainted(op1) && !is_reg_tainted(op2)){
            add_tainted_reg_reg(op1, op2, 4);
          }
          // op1 free, op2 taint -> op1 taint
          else if (!is_reg_tainted(op1) && is_reg_tainted(op2)){
            add_tainted_reg_reg(op1, op2, 4);
          }
          // op1 free, op2 free -> do nothing
          else if(!is_reg_tainted(op1) && !is_reg_tainted(op2)){
            
          }

        } 
        // mov exx, imm
        else if (*(disasm_tbuf+4) == 'e' && *(disasm_tbuf+9) == '0'){
          memcpy(op1, disasm_tbuf+4, 3);
          op1[3] = '\0';          

          remove_tainted_reg(op1);
        }
        else {
          //print_debug_string("[TAINT MOV] NOT DWORD OPERAND!!\n");
          //print_instruction(cpu, i, disasm_tbuf);
        }
        
      } else if (!memcmp(disasm_tbuf, "cmp ", 4)){
        //cmp reg reg
        if (*(disasm_tbuf+4) == 'e' && *(disasm_tbuf+9) == 'e'){
          memcpy(op1, disasm_tbuf+4, 3);
          op1[3] = '\0';

          memcpy(op2, disasm_tbuf+9, 3);
          op2[3] = '\0';

          if (is_reg_tainted(op1) || is_reg_tainted(op2)){
            print_debug_string("[TAINT CMP] OP REG REG TAINTED ");
            print_instruction(cpu, i, disasm_tbuf);  
            // log
            print_trace_log(pcpu, disasm_tbuf, op1, op2, 4);
          }
          else{
            // print_debug_string("[TAINT CMP] OP REG REG NONTAINTED ");
            // print_instruction(cpu, i, disasm_tbuf);  
          }
        }
        // cmp reg, imm
        else if (*(disasm_tbuf+4) == 'e' && !memcmp(disasm_tbuf+9, "0x", 2)){
          memcpy(op1, disasm_tbuf+4, 3);
          op1[3] = '\0';

          memcpy(op2, disasm_tbuf+9, 10);
          op2[10] = '\0';

          if(is_reg_tainted(op1)){
            print_debug_string("[TAINT CMP] OP REG IMM TAINTED ");
            print_instruction(cpu, i, disasm_tbuf);          
            // log
            print_trace_log_imm(pcpu, disasm_tbuf, op1, strtol(op2, NULL, 0), 4);

            memset(op2, '\0', 12);
          }
          else{
            // print_debug_string("[TAINT CMP] OP REG IMM NONTAINTED ");
            // print_instruction(cpu, i, disasm_tbuf); 
          }
        }
        else{
          // print_debug_string("[TAINT CMP] ELSE ");
          // print_instruction(cpu, i, disasm_tbuf);
        }

      } 
      else if (!memcmp(disasm_tbuf, "add", 3) || !memcmp(disasm_tbuf, "sub", 3)){
        // add reg reg
        if (*(disasm_tbuf+4) == 'e' && *(disasm_tbuf+9) == 'e'){
          memcpy(op1, disasm_tbuf+4, 3);
          op1[3] = '\0';

          memcpy(op2, disasm_tbuf+9, 3);
          op2[3] = '\0';

          if (is_reg_tainted(op1) || is_reg_tainted(op2)){
            print_debug_string("[TAINT ADD SUB] OP REG REG TAINTED ");
            print_instruction(cpu, i, disasm_tbuf);  
            // log
            print_trace_log(pcpu, disasm_tbuf, op1, op2, 4);
          }
          else{
            // print_debug_string("[TAINT ADD SUB] OP REG REG NONTAINTED ");
            // print_instruction(cpu, i, disasm_tbuf);
          }
        }
        // cmp reg, imm
        else if (*(disasm_tbuf+4) == 'e' && !memcmp(disasm_tbuf+9, "0x", 2)){
          memcpy(op1, disasm_tbuf+4, 3);
          op1[3] = '\0';

          memcpy(op2, disasm_tbuf+9, 10);
          op2[10] = '\0';

          if (is_reg_tainted(op1)){
            print_debug_string("[TAINT ADD SUB] OP REG IMM TAINTED ");
            print_instruction(cpu, i, disasm_tbuf);  
            // log         
            print_trace_log_imm(pcpu, disasm_tbuf, op1, strtol(op2, NULL, 0), 4); 

            memset(op2, '\0', 12);
          }
          else{
            // print_debug_string("[TAINT ADD SUB] OP REG IMM NONTAINTED ");
            // print_instruction(cpu, i, disasm_tbuf);          
          }
        }
        else{
          // print_debug_string("[TAINT ADD SUB] ELSE ");
          // print_instruction(cpu, i, disasm_tbuf);
        }
      }
      else if (!memcmp(disasm_tbuf, "imul", 4)){
        if (!memcmp(disasm_tbuf+5, "e", 1) && !memcmp(disasm_tbuf+10, "e", 1)){
          memcpy(op1, disasm_tbuf+4, 3);
          op1[3] = '\0';

          memcpy(op1, disasm_tbuf+9, 3);
          op1[3] = '\0';

          if (is_reg_tainted(op1) || is_reg_tainted(op2)){
            print_debug_string("[TAINT IMUL] OP REG REG (IMM) TAINTED ");
            print_instruction(cpu, i, disasm_tbuf);  
            // log
            print_trace_log(pcpu, disasm_tbuf, op1, op2, 4);
          } 
          else{

          }
        }
        else {
          print_debug_string("[TAINT IMUL] ELSE ");
          print_instruction(cpu, i, disasm_tbuf);
        }
      }
      // else if (!memcmp(disasm_tbuf, "rep", 3)){
      //   // print_debug_string("[TAINT REP NOP] ");
      //   // print_instruction(cpu, i, disasm_tbuf);
      //   // print_debug_string("REP MOV SIZE: ");
      //   // print_debug_string_int("%d", size*(i->num_data_accesses/2));
      //   // print_debug_string("\n");
      //   // print_mem_access(i);
      // } 
      else {
        //print_instruction(cpu, i, disasm_tbuf);
      }

    } 
    else if (i->num_data_accesses == 1){
      //fprintf(stderr, "Mem access at 0x%x\n", i->data_access[0].laddr); 
      //print_instruction(cpu, i, disasm_tbuf);
      lin_addr = i->data_access[0].laddr;
      size = i->data_access[0].size;

      if (!memcmp(disasm_tbuf, "mov ", 4)){
        // mov exx, mem
        // if (i->data_access[n].rw == BX_READ) change a condition in future
        if (*(disasm_tbuf+4) == 'e'){
          memcpy(op1, disasm_tbuf+4, 3);
          op1[3] = '\0';

          // op1 taint, op2 free -> op1 free
          if (is_reg_tainted(op1) && !is_mem_tainted(lin_addr, size)){
            remove_tainted_reg(op1);
          } 
          // op1 taint, op2 taint -> update op1 taint offset
          else if (is_reg_tainted(op1) && !is_mem_tainted(lin_addr, size)){
            add_tainted_reg_mem(op1, lin_addr, 4);
          }
          // op1 free, op2 taint -> op1 taint
          else if (!is_reg_tainted(op1) && is_mem_tainted(lin_addr, size)){
            add_tainted_reg_mem(op1, lin_addr, 4);
          }
          // op1 free, op2 free -> do nothing
          else if(!is_reg_tainted(op1) && !is_mem_tainted(lin_addr, size)){
            
          }
        }
        // mov mem, exx
        else if (*(disasm_tbuf+strlen(disasm_tbuf)-3) == 'e'){
          memcpy(op2, disasm_tbuf+strlen(disasm_tbuf)-3, 3);
          op2[3] = '\0';

          // op1 taint, op2 free -> op1 free
          if (is_mem_tainted(lin_addr, size) && !is_reg_tainted(op2)){
            remove_tainted_mem(lin_addr, size);
          } 
          // op1 taint, op2 taint -> update op1 taint offset
          else if (is_mem_tainted(lin_addr, size) && !is_reg_tainted(op2)){
            add_tainted_mem_reg(lin_addr, op2, size);
          }
          // op1 free, op2 taint -> op1 taint
          else if (!is_mem_tainted(lin_addr, size) && is_reg_tainted(op2)){
            add_tainted_mem_reg(lin_addr, op2, size);
          }
          // op1 free, op2 free -> do nothing
          else if(!is_mem_tainted(lin_addr, size) && !is_reg_tainted(op2)){
            
          }
        }
        // mov mem, imm
        else if (!memcmp(disasm_tbuf+4, "dword", 5), !memcmp(disasm_tbuf+strlen(disasm_tbuf)-10, "0x", 2)){
          // print_debug_string("[TAINT MOV] MEM_IMM ");
          // print_instruction(cpu, i , disasm_tbuf);
          remove_tainted_mem(lin_addr, size);
        } 
        else {
          //print_instruction(cpu, i, disasm_tbuf);
          //print_debug_string("[TAINT MOV] NOT DWORD OPERAND!!\n");
        }
        
      } 
      else if (!memcmp(disasm_tbuf, "cmp ", 4)){
        // cmp reg, mem
        if (!memcmp(disasm_tbuf+4, "e", 1) && !memcmp(disasm_tbuf+9, "dw", 2)){
          memcpy(op1, disasm_tbuf+4, 3);
          op1[3] = '\0';

          if (is_reg_tainted(op1) || is_mem_tainted(lin_addr, size)){
            print_debug_string("[TAINT CMP] OP REG MEM TAINTED ");
            print_instruction(cpu, i, disasm_tbuf);
            // log
            print_trace_log(pcpu, disasm_tbuf, op1, lin_addr, 4);
          }
          else{
            // print_debug_string("[TAINT CMP] OP REG MEM NONTAINT ");
            // print_instruction(cpu, i, disasm_tbuf);
          }
        }
        // cmp mem, imm
        else if (!memcmp(disasm_tbuf+4, "dw", 2) && !memcmp(disasm_tbuf+strlen(disasm_tbuf)-10, "0x", 2)) {
          memcpy(op2, disasm_tbuf+strlen(disasm_tbuf)-10, 10);
          op2[10] = '\0';

          if (is_mem_tainted(lin_addr, size)){
            print_debug_string("[TAINT CMP] OP MEM IMM TAINTED ");
            print_instruction(cpu, i, disasm_tbuf);
            // log
            print_trace_log_imm(pcpu, disasm_tbuf, lin_addr, strtol(op2, NULL, 0), 4);

            memset(op2, '\0', 12);
          }
          else{
            // print_debug_string("[TAINT CMP] OP MEM IMM NONTAINT ");
            // print_instruction(cpu, i, disasm_tbuf);
          }
        }
        // cmp mem, reg
        else if (!memcmp(disasm_tbuf+4, "dw", 2) && !memcmp(disasm_tbuf+strlen(disasm_tbuf)-3, "e", 1)) {
          memcpy(op2, disasm_tbuf+strlen(disasm_tbuf)-3, 3);
          op2[3] = '\0';

          if (is_mem_tainted(lin_addr, size) || is_reg_tainted(op2)){
            print_debug_string("[TAINT CMP] OP MEM REG TAINTED ");
            print_instruction(cpu, i, disasm_tbuf);
            // log            
            print_trace_log(pcpu, disasm_tbuf, lin_addr, op2, 4);
          }
          else{
            // print_debug_string("[TAINT CMP] OP MEM REG NONTAINTED ");
            // print_instruction(cpu, i, disasm_tbuf);
          }
        }
        else {
          // print_debug_string("[TAINT CMP] ELSE ");
          // print_instruction(cpu, i, disasm_tbuf);
        }

      }
      else if (!memcmp(disasm_tbuf, "add", 3) || !memcmp(disasm_tbuf, "sub", 3)){
        // add reg, mem
        if (!memcmp(disasm_tbuf+4, "e", 1) && !memcmp(disasm_tbuf+9, "dw", 2)){
          memcpy(op1, disasm_tbuf+4, 3);
          op1[3] = '\0';

          if (is_reg_tainted(op1) || is_mem_tainted(lin_addr, size)){
            print_debug_string("[TAINT ADD SUB] OP REG MEM TAINTED ");
            print_instruction(cpu, i, disasm_tbuf);
            // log
            print_trace_log(pcpu, disasm_tbuf, op1, lin_addr, 4);
          }
          else{
            // print_debug_string("[TAINT ADD SUB] OP REG MEM NONTAINT ");
            // print_instruction(cpu, i, disasm_tbuf);
          }
        }
        // add mem, imm
        else if (!memcmp(disasm_tbuf+4, "dw", 2) && !memcmp(disasm_tbuf+strlen(disasm_tbuf)-10, "0x", 2)) {
          // print_debug_string("[TAINT ADD SUB] OP MEM IMM ");
          // print_instruction(cpu, i, disasm_tbuf);

          memcpy(op2, disasm_tbuf+strlen(disasm_tbuf)-10, 10);
          op2[10] = '\0';

          if (is_mem_tainted(lin_addr, size)){
            print_debug_string("[TAINT ADD SUB] OP MEM IMM TAINTED ");
            print_instruction(cpu, i, disasm_tbuf);
            // log
            print_trace_log_imm(pcpu, disasm_tbuf, lin_addr, strtol(op2, NULL, 0), 4);

            memset(op2, '\0', 12);
          }
          else{
            // print_debug_string("[TAINT ADD SUB] OP MEM IMM NONTAINT ");
            // print_instruction(cpu, i, disasm_tbuf);
          }
        }
        // add mem, reg
        else if (!memcmp(disasm_tbuf+4, "dw", 2) && !memcmp(disasm_tbuf+strlen(disasm_tbuf)-3, "e", 1)) {
          memcpy(op2, disasm_tbuf+strlen(disasm_tbuf)-3, 3);
          op2[3] = '\0';

          if (is_mem_tainted(lin_addr, size) || is_reg_tainted(op2)){
            print_debug_string("[TAINT ADD SUB] OP MEM REG TAINTED ");
            print_instruction(cpu, i, disasm_tbuf);
            // log
            print_trace_log(pcpu, disasm_tbuf, lin_addr, op2, 4);
          }
          else{
            // print_debug_string("[TAINT ADD SUB] OP MEM REG NONTAINT ");
            // print_instruction(cpu, i, disasm_tbuf);
          }
        }
        else {
          // print_debug_string("[TAINT ADD SUB] OP MEM  ");
          // print_instruction(cpu, i, disasm_tbuf);
        }

      }
      else if (!memcmp(disasm_tbuf, "imul", 4)){
        // imul reg, mem
        if (!memcmp(disasm_tbuf+5, "e", 1) && !memcmp(disasm_tbuf+10, "dw", 2)){
          memcpy(op1, disasm_tbuf+5, 3);
          op1[3] = '\0';

          if (is_reg_tainted(op1) || is_mem_tainted(lin_addr, size)){
            print_debug_string("[TAINT IMUL] OP REG MEM TAINTED ");
            print_instruction(cpu, i, disasm_tbuf);
            // log
            print_trace_log(pcpu, disasm_tbuf, op1, lin_addr, 4);
          }
          else{
            // print_debug_string("[TAINT IMUL] OP REG MEM NONTAINT ");
            // print_instruction(cpu, i, disasm_tbuf);
          }
        }
        // imul mem imm
        // else if(!memcmp(disasm_tbuf+5, "dw", 2) && !memcmp(disasm_tbuf+strlen(disasm_tbuf)-10, "0x", 2)){
        //   print_debug_string("[TAINT IMUL] OP MEM IMM ");
        //   print_instruction(cpu, i, disasm_tbuf);
        // }
        else{
          print_debug_string("[TAINT IMUL] ELSE");
          print_instruction(cpu, i, disasm_tbuf);
        }
        
      }
      //else if (!memcmp(disasm_tbuf, "rep", 3)){
        //rep ret
        //print_debug_string("[TAINT REP SINGLE] ");
        //print_instruction(cpu, i, disasm_tbuf);
      //}
      else {
        // print_debug_string("[TAINT SINGLE MEM ACCESS] ");
        // print_instruction(cpu, i, disasm_tbuf);
      }
    } 
    // 
    else if(i->num_data_accesses > 1){
      if (!memcmp(disasm_tbuf, "rep", 3)){
        if (!memcmp(disasm_tbuf+4, "mov", 3)){
          lin_addr_r = i->data_access[0].laddr;
          lin_addr_w = i->data_access[1].laddr;
          size = i->data_access[0].size;
        
          for (int n = 0; n < i->num_data_accesses/2; n++) 
            add_tainted_mem_mem(lin_addr_w, lin_addr_r, size);
          
          //add_tainted_mem_mem(lin_addr_w, lin_addr_r, size*(i->num_data_accesses/2));

          //if (is_mem_tainted(lin_addr_w)){
            // print_debug_string("[TAINT REP MOV MUL] ");
            // print_instruction(cpu, i, disasm_tbuf);
            // print_debug_string("REP MOV SIZE: ");
            // print_debug_string_int("%d", size*(i->num_data_accesses/2));
            // print_debug_string("\n");
            // print_mem_access(i);
          //}
        }
      } 
      // else if (!memcmp(disasm_tbuf, "call", 4)){

      // } 
      // else if (!memcmp(disasm_tbuf, "push", 4)){

      // } 
      // else if (!memcmp(disasm_tbuf, "pop", 3)){

      // }
      else
      {
        //print_debug_string("[TAINT MUL MEM] ");
        //print_instruction(cpu, i, disasm_tbuf);
      }
    }
  }
  //active = 0;
}

void bx_instr_before_execution(unsigned cpu, bxInstruction_c *bx_instr)
{
  BX_CPU_C *pcpu = BX_CPU(cpu);

  // Note: DO NOT change order of these ifs. long64_mode must be called
  // before protected_mode, since it will also return "true" on protected_mode
  // query (well, long mode is technically protected mode).
  if (pcpu->long64_mode()) {
    printf("Instrumentation not supported in 64-bit mode. aborting\n");
    abort();
  } else if (!pcpu->protected_mode()) {
    // No other modes than protected mode are interesting.
    return;
  }
  
  bx_address pc = pcpu->prev_rip;
  unsigned int edi = pcpu->gen_reg[BX_32BIT_REG_EDI].rrx;
  unsigned int esi = pcpu->gen_reg[BX_32BIT_REG_ESI].rrx;
  unsigned int ecx = pcpu->gen_reg[BX_32BIT_REG_ECX].rrx;
  unsigned int edx = pcpu->gen_reg[BX_32BIT_REG_EDX].rrx;
  unsigned int eax = pcpu->gen_reg[BX_32BIT_REG_EAX].rrx;

  unsigned int ret = 0;
  unsigned int argv[3];
  unsigned int size = 0;
  bx_address src = 0;
  bx_address dst = 0;

  // copy_from_user 
  if(pc == COPY_FROM_USER_ADDR){ 
  
    //get return address of copy_from_user
    read_lin_mem(pcpu, pcpu->gen_reg[BX_32BIT_REG_ESP].rrx, 4, &ret);
    //read_lin_mem(pcpu, pcpu->gen_reg[BX_32BIT_REG_ESP].rrx+4, 12, argv);

    src = edx;
    dst = eax;
    size = ecx;


    if(src >= 0x20000000 && src < 0x2f000000 && ret != RET_SYSCALL_MMAP){

      fprintf(stderr, "[COPY_FROM_USER] pc %x, ret %x, ptr: %x\n", pc, ret, src);
      //fprintf(stderr, "pc %x, ecx %x, edx %x, eax %x\n", pc, ecx, edx, eax);

      active = 1;
      if(fp_log == NULL)
        fp_log = fopen(log_path, "w");

      add_tainted_mem_from_source(dst, src, size);
    } 
    // stop taint (tricky)    
    else if(src == 0x2f000000){
      active = 0;
      reset_taint();
    } 
    else if(src == 0x2f001000){
      active = 0;
      stop_taint();
    }
    else if(src == START_COVERAGE){
      active_coverage = 1;
      start_branch_coverage();
    }
    else if(src == STOP_COVERAGE){
      active_coverage = 0;
      stop_branch_coverage();
    }
    else if(src == START_LOG_MEM){
      active_mem = 1;
      start_log_mem();
    }
    else if(src == STOP_LOG_MEM){
      active_mem = 0;
      stop_log_mem();    }
  }

  if (!active) return;

  instruction_t *i = &instruction[cpu];

  if (i->ready) bx_print_instruction(cpu, i);

  // prepare instruction_t structure for new instruction
  i->ready = 1;
  i->num_data_accesses = 0;
  i->is_branch = 0;

  i->is32 = BX_CPU(cpu)->sregs[BX_SEG_REG_CS].cache.u.segment.d_b;
  i->is64 = BX_CPU(cpu)->long64_mode();
  i->opcode_length = bx_instr->ilen();
  memcpy(i->opcode, bx_instr->get_opcode_bytes(), i->opcode_length);
}

void bx_instr_after_execution(unsigned cpu, bxInstruction_c *bx_instr)
{
  if (!active) return;

  instruction_t *i = &instruction[cpu];
  if (i->ready) {
    bx_print_instruction(cpu, i);
    i->ready = 0;
  }
}

static void branch_taken(unsigned cpu, bx_address new_eip)
{
  if(active_coverage)
   mark_branch_explore(new_eip);

  if (!active || !instruction[cpu].ready) return;

  instruction[cpu].is_branch = 1;
  instruction[cpu].is_taken = 1;

  // find linear address
  instruction[cpu].target_linear = BX_CPU(cpu)->get_laddr(BX_SEG_REG_CS, new_eip);

}

void bx_instr_cnear_branch_taken(unsigned cpu, bx_address branch_eip, bx_address new_eip)
{
  branch_taken(cpu, new_eip);
}

void bx_instr_cnear_branch_not_taken(unsigned cpu, bx_address branch_eip)
{
  if (!active || !instruction[cpu].ready) return;

  instruction[cpu].is_branch = 1;
  instruction[cpu].is_taken = 0;
}

void bx_instr_ucnear_branch(unsigned cpu, unsigned what, bx_address branch_eip, bx_address new_eip)
{
  branch_taken(cpu, new_eip);
}

void bx_instr_far_branch(unsigned cpu, unsigned what, Bit16u prev_cs, bx_address prev_eip, Bit16u new_cs, bx_address new_eip)
{
  branch_taken(cpu, new_eip);
}

void bx_instr_interrupt(unsigned cpu, unsigned vector)
{
  // if(active)
  // {
  //   fprintf(stderr, "CPU %u: interrupt %02xh\n", cpu, vector);
  // }
}

void bx_instr_exception(unsigned cpu, unsigned vector, unsigned error_code)
{
  // if(active)
  // {
  //   fprintf(stderr, "CPU %u: exception %02xh, error_code = %x\n", cpu, vector, error_code);
  // }
}

void bx_instr_hwinterrupt(unsigned cpu, unsigned vector, Bit16u cs, bx_address eip)
{
  // if(active)
  // {
  //   fprintf(stderr, "CPU %u: hardware interrupt %02xh\n", cpu, vector);
  // }
}

void bx_instr_lin_access(unsigned cpu, bx_address lin, bx_phy_address phy, unsigned len, unsigned memtype, unsigned rw)
{
  if(!active || !instruction[cpu].ready) return;

  unsigned index = instruction[cpu].num_data_accesses;

  if (index < MAX_DATA_ACCESSES) {
    instruction[cpu].data_access[index].laddr = lin;
    instruction[cpu].data_access[index].paddr = phy;
    instruction[cpu].data_access[index].rw    = rw;
    instruction[cpu].data_access[index].size  = len;
    instruction[cpu].data_access[index].memtype = memtype;
    instruction[cpu].num_data_accesses++;
    index++;
  }
}

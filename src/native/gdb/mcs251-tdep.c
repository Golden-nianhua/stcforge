/* STCForge MCS-251 target, SDCC source instruction map.
   SPDX-License-Identifier: GPL-3.0-or-later
   原型只描述已确认的寄存器和数据模型，不伪造尚未实现的 ABI 回溯。 */
#include "extract-store-integer.h"
#include "arch-utils.h"
#include "frame.h"
#include "frame-unwind.h"
#include "gdbtypes.h"
#include "value.h"
#include "regcache.h"
#include "dis-asm.h"
#include "gdbcore.h"
#include "target-descriptions.h"

struct mcs251_tdep : gdbarch_tdep_base {};
static const char *const names[] = {
  "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7",
  "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
  "wr16", "wr18", "wr20", "wr22", "wr24", "wr26", "wr28", "wr30",
  "dpx", "spx", "psw", "psw1", "pc"
};
static const char *reg_name (gdbarch *, int n)
{ return n >= 0 && n < 29 ? names[n] : nullptr; }
static type *reg_type (gdbarch *a, int n)
{
  if (n < 16 || n == 26 || n == 27) return builtin_type(a)->builtin_uint8;
  if (n < 24) return builtin_type(a)->builtin_uint16;
  return builtin_type(a)->builtin_uint32;
}
static CORE_ADDR skip_prologue (gdbarch *, CORE_ADDR pc) { return pc; }
static return_value_convention return_value (gdbarch *, value *, type *,
                                             regcache *, gdb_byte *,
                                             const gdb_byte *)
{
  error (_("MCS-251 inferior calls and return-value ABI are not implemented"));
}
static unwind_stop_reason stop_unwind (const frame_info_ptr &, void **)
{ return UNWIND_UNAVAILABLE; }
static void frame_id (const frame_info_ptr &f, void **, struct frame_id *id)
{
  /* PC advances on every step, but the current function frame remains the
     same.  A PC-based ID invalidates Python Frame objects and frontend frame
     contexts after each instruction.  Keep the unavailable-stack boundary:
     this identifies only the current function, without inventing a caller
     chain or a stable stack address that we do not yet know how to unwind.
     With no function symbol, fall back to PC rather than merging unrelated
     unknown code into a single frame.  */
  CORE_ADDR function = get_frame_func (f);
  *id = frame_id_build_unavailable_stack (function != 0
                                         ? function : get_frame_pc (f));
}
static value *prev_reg (const frame_info_ptr &f, void **, int n)
{ return frame_unwind_got_optimized (f, n); }
static const frame_unwind no_unwinder = {
  "mcs251-unavailable", NORMAL_FRAME, stop_unwind, frame_id, prev_reg,
  nullptr, default_frame_sniffer, nullptr, nullptr
};

struct entry_call_frame
{
  CORE_ADDR caller_pc;
  CORE_ADDR caller_sp;
};

static int entry_call_sniffer (const frame_unwind *, const frame_info_ptr &f,
                              void **cache)
{
  /* At a direct call's destination no callee instruction has run.  Only
     expose a caller if both the return record and the call opcode agree.  */
  if (frame_relative_level (f) != 0)
    return 0;
  CORE_ADDR pc = get_frame_pc (f);
  if (pc == 0 || get_frame_func (f) != pc)
    return 0;

  CORE_ADDR sp = get_frame_register_unsigned (f, 25);
  gdb_byte stack[3], code[5];
  if (sp < 3 || sp > 0x3fff
      || !safe_frame_unwind_memory (f, sp - 2, stack))
    return 0;

  CORE_ADDR far_return = (stack[0] << 16) | (stack[1] << 8) | stack[2];
  CORE_ADDR near_return = (pc & 0xff0000) | (stack[2] << 8) | stack[1];
  CORE_ADDR resume = 0, caller_sp = 0;
  if (far_return >= 4
      && safe_frame_unwind_memory (f, far_return - 4,
                                   gdb::make_array_view (code, 4))
      && code[0] == 0x9a
      && pc == CORE_ADDR ((code[1] << 16) | (code[2] << 8) | code[3]))
    {
      resume = far_return;
      caller_sp = sp - 3;
    }
  else if (near_return >= 3
           && safe_frame_unwind_memory (f, near_return - 3,
                                        gdb::make_array_view (code, 3))
           && code[0] == 0x12 && (pc & 0xffff) == ((code[1] << 8) | code[2]))
    {
      resume = near_return;
      caller_sp = sp - 2;
    }
  else if (near_return >= 2
           && safe_frame_unwind_memory (f, near_return - 2,
                                        gdb::make_array_view (code, 2))
           && (code[0] & 0x1f) == 0x11
           && pc == ((near_return & 0xfff800) | ((code[0] & 0xe0) << 3)
                     | code[1]))
    {
      resume = near_return;
      caller_sp = sp - 2;
    }
  if (resume == 0 || get_pc_function_start (resume - 1) == pc)
    return 0;
  auto *entry = FRAME_OBSTACK_ZALLOC (entry_call_frame);
  entry->caller_pc = resume;
  entry->caller_sp = caller_sp;
  *cache = entry;
  return 1;
}

static value *entry_call_prev_reg (const frame_info_ptr &f, void **cache, int n)
{
  auto *entry = static_cast<entry_call_frame *> (*cache);
  if (n == 28)
    return frame_unwind_got_constant (f, n, entry->caller_pc);
  if (n == 25)
    return frame_unwind_got_constant (f, n, entry->caller_sp);
  return prev_reg (f, cache, n);
}

static const frame_unwind entry_call_unwinder = {
  "mcs251-direct-call-entry", NORMAL_FRAME, default_frame_unwind_stop_reason,
  frame_id, entry_call_prev_reg, nullptr, entry_call_sniffer, nullptr, nullptr
};
constexpr gdb_byte break_insn[] = { 0xb9 };
typedef BP_MANIPULATION (break_insn) mcs251_breakpoint;

/* 有限反汇编器：未知指令显式报错，不能把扩展指令误拆成若干 8051 指令。
   后续完整解码器必须覆盖 source/binary 两种映射；当前仅支持 source。 */
static int print_insn_mcs251 (bfd_vma pc, disassemble_info *i)
{
  bfd_byte b[5];
  int e = i->read_memory_func(pc, b, 1, i);
  if (e) { i->memory_error_func(e, pc, i); return -1; }
  int n = 1;
  switch (b[0]) {
    case 0x00: i->fprintf_func(i->stream, "nop"); return 1;
    case 0x22: i->fprintf_func(i->stream, "ret"); return 1;
    case 0x32: i->fprintf_func(i->stream, "reti"); return 1;
    case 0xb9: i->fprintf_func(i->stream, "break"); return 1;
    case 0x02: case 0x12: n = 3; break;
    case 0x74: case 0x80: case 0xc2: case 0xd2: case 0x92: n = 2; break;
    case 0x7e: case 0x7a: case 0x2e: n = 2; break;
    default:
      i->fprintf_func(i->stream, "<undecoded source opcode 0x%02x>", b[0]);
      return -1;
  }
  e = i->read_memory_func(pc, b, n, i);
  if (e) { i->memory_error_func(e, pc, i); return -1; }
  if (b[0] == 0x7e || b[0] == 0x7a || b[0] == 0x2e) {
    int kind = b[1] & 15;
    if ((b[0] == 0x7e || b[0] == 0x7a) && (kind == 3 || kind == 0xf)) n = 4;
    else if (b[0] == 0x2e && kind == 0) n = 3;
    else if (b[0] == 0x7e && kind == 4) n = 4;
    else {
      i->fprintf_func(i->stream, "<undecoded source opcode 0x%02x%02x>", b[0], b[1]);
      return -1;
    }
    e = i->read_memory_func(pc, b, n, i);
    if (e) { i->memory_error_func(e, pc, i); return -1; }
    int reg = b[1] >> 4;
    unsigned imm = n == 4 ? (b[2] << 8) | b[3] : b[2];
    if (b[0] == 0x2e) i->fprintf_func(i->stream, "add r%d,#0x%02x", reg, imm);
    else if (kind == 4) i->fprintf_func(i->stream, "mov wr%d,#0x%04x", reg * 2, imm);
    else {
      const char *r = kind == 0xf ? "dr" : "r";
      int rn = kind == 0xf ? reg * 4 : reg;
      if (b[0] == 0x7e) i->fprintf_func(i->stream, "mov %s%d,0x%04x", r, rn, imm);
      else i->fprintf_func(i->stream, "mov 0x%04x,%s%d", imm, r, rn);
    }
    return n;
  }
  switch (b[0]) {
    case 0x02: case 0x12:
      i->fprintf_func(i->stream, "%s 0x%06lx", b[0] == 2 ? "ljmp" : "lcall",
                      (unsigned long)((pc & 0xff0000) | (b[1] << 8) | b[2])); break;
    case 0x74: i->fprintf_func(i->stream, "mov a,#0x%02x", b[1]); break;
    case 0x80: i->fprintf_func(i->stream, "sjmp 0x%06lx", (unsigned long)(pc + 2 + (signed char)b[1])); break;
    case 0xc2: case 0xd2: i->fprintf_func(i->stream, "%s 0x%02x", b[0] == 0xc2 ? "clr" : "setb", b[1]); break;
    case 0x92: i->fprintf_func(i->stream, "mov 0x%02x,c", b[1]); break;
  }
  return n;
}
static gdbarch *mcs251_init (gdbarch_info info, gdbarch_list *arches)
{
  if (info.byte_order != BFD_ENDIAN_BIG) return nullptr;
  arches = gdbarch_list_lookup_by_info(arches, &info);
  if (arches) return arches->gdbarch;
  tdesc_arch_data_up description;
  if (tdesc_has_registers(info.target_desc)) {
    const tdesc_feature *feature = tdesc_find_feature(info.target_desc, "org.stcforge.mcs251.core");
    if (!feature) return nullptr;
    description = tdesc_data_alloc();
    for (int n = 0; n < 29; ++n) {
      int bits = n < 16 || n == 26 || n == 27 ? 8 : (n < 24 ? 16 : 32);
      if (!tdesc_numbered_register(feature, description.get(), n, names[n])
          || tdesc_register_bitsize(feature, names[n]) != bits) return nullptr;
    }
  }
  gdbarch *a = gdbarch_alloc(&info, gdbarch_tdep_up(new mcs251_tdep));
  set_gdbarch_short_bit(a, 16);
  set_gdbarch_int_bit(a, 16);
  set_gdbarch_long_bit(a, 32);
  set_gdbarch_long_long_bit(a, 64);
  set_gdbarch_ptr_bit(a, 24);
  set_gdbarch_addr_bit(a, 32);
  set_gdbarch_float_bit(a, 32);
  set_gdbarch_double_bit(a, 32);
  set_gdbarch_long_double_bit(a, 32);
  set_gdbarch_float_format(a, floatformats_ieee_single);
  set_gdbarch_double_format(a, floatformats_ieee_single);
  set_gdbarch_long_double_format(a, floatformats_ieee_single);
  set_gdbarch_char_signed(a, 0);
  set_gdbarch_num_regs(a, 29);
  set_gdbarch_sp_regnum(a, 25);
  set_gdbarch_pc_regnum(a, 28);
  set_gdbarch_ps_regnum(a, 26);
  set_gdbarch_register_name(a, reg_name);
  set_gdbarch_register_type(a, reg_type);
  set_gdbarch_return_value(a, return_value);
  set_gdbarch_skip_prologue(a, skip_prologue);
  set_gdbarch_inner_than(a, core_addr_greaterthan);
  set_gdbarch_breakpoint_kind_from_pc(a, mcs251_breakpoint::kind_from_pc);
  set_gdbarch_sw_breakpoint_from_kind(a, mcs251_breakpoint::bp_from_kind);
  set_gdbarch_decr_pc_after_break(a, 0);
  set_gdbarch_print_insn(a, print_insn_mcs251);
  if (description) tdesc_use_registers(a, info.target_desc, std::move(description));
  frame_unwind_append_unwinder(a, &entry_call_unwinder);
  frame_unwind_append_unwinder(a, &no_unwinder);
  return a;
}
void _initialize_mcs251_tdep ();
void
_initialize_mcs251_tdep ()
{ gdbarch_register(bfd_arch_mcs251, mcs251_init); }

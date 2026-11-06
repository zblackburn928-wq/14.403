/*
 * PS4 firmware 14.02 reference data — DO NOT USE FOR EXPLOITATION.
 *
 * Source folder: ps4-suid-scanner-main (García Casado Security Research /
 * adri22235), files 1402.c, 1402_offsets.txt, webkit_gadgets_1402.js.
 *
 * WHY THIS IS REFERENCE-ONLY:
 *   - 1402.c is byte-for-byte identical to 1400.c. Every address below is the
 *     14.00 value with the version string changed. The folder itself marks the
 *     table "PENDING VERIFICATION against clean 14.02 flash dump".
 *   - 1402_offsets.txt says libSceNKWebKit.sprx has the CSSFontFace UAF
 *     patched in 14.02, and "existing 14.00 exploits DO NOT trigger reliably
 *     on 14.02".
 *   - webkit_gadgets_1402.js is identical to webkit_gadgets_1400.js. Gadget
 *     offsets being unchanged does not help if the trigger itself is patched.
 *
 * Bottom line: on a 14.00 console this file is inert (same numbers as 14.00).
 * On a 14.02 console it is not a working exploit. Stay on 14.00.
 */
(function () {
  "use strict";

  var PS4_1402_REFERENCE = {
    fw: "14.02",
    verified: false,
    source: "ps4-suid-scanner-main/1402.c (copy of 1400.c)",
    note:
      "Identical to 14.00. CSSFontFace UAF patched in 14.02. Do not wire into " +
      "the live 14.00 path.",

    // data (same values as 1400.c)
    XFAST_SYSCALL: 0x000001c0,
    PRISON0: 0x0111fa18,
    ROOTVNODE: 0x02136e90,
    M_TEMP: 0x01520d00,
    MINI_SYSCORE_SELF_BINARY: 0x0153d6c8,
    ALLPROC: 0x01b28538,
    SBL_DRIVER_MAPPED_PAGES: 0x02647350,
    SBL_PFS_SX: 0x0265c080,
    SBL_KEYMGR_KEY_SLOTS: 0x02668040,
    SBL_KEYMGR_KEY_RBTREE: 0x02668050,
    SBL_KEYMGR_BUF_VA: 0x0266c000,
    SBL_KEYMGR_BUF_GVA: 0x0266c808,
    FPU_CTX: 0x026542c0,
    SYSENT: 0x01102b70,

    // common functions
    memcmp: 0x00394d80,
    _sx_xlock: 0x000a3840,
    _sx_xunlock: 0x000a3a00,
    malloc: 0x00009520,
    free: 0x000096e0,
    strstr: 0x0021d010,
    fpu_kern_enter: 0x001e03a0,
    fpu_kern_leave: 0x001e0460,
    memcpy: 0x002bd850,
    memset: 0x001fa500,
    strlen: 0x0036b5a0,
    printf: 0x002e07c0,
    eventhandler_register: 0x002244c0,

    // patch helpers
    vmspace_acquire_ref: 0x002f7990,
    vmspace_free: 0x002f77c0,
    vm_map_lock_read: 0x002f7b20,
    vm_map_unlock_read: 0x002f7b70,
    vm_map_lookup_entry: 0x002f8160,
    proc_rwmem: 0x00366a10,

    // process structure offsets
    proc_p_comm_offset: 0x454,
    proc_path_offset: 0x474,

    // subsystem status quoted from 1402_offsets.txt
    status: {
      webkit: "libSceNKWebKit.sprx: Patched CSSFontFace UAF trigger",
      apm: "Patched race condition (Afterglow mitigated in 14.02)",
      suid: "CVE-2026-49415 candidate (kern_exec.c FreeBSD 9 core unpatched)",
      sound: "CVE-2026-101308 candidate (sound buffer mmap UAF)",
      semaphores: "CVE-2026-58087 candidate (semctl 15-bit wrap)",
    },
  };

  // webkit_gadgets_1402.js is identical to the 14.00 table. Kept here so the
  // reference data is self-contained; it is NOT a new gadget set.
  var webkit_gadgets_1402 = {
    wk_RET: 0x4032,
    wk_LEAVE_RET: 0x1c2f7,
    wk_POP_RAX_RET: 0x14504,
    wk_POP_RBX_RET: 0xb9e8,
    wk_POP_RCX_RET: 0x1fade,
    wk_POP_RDX_RET: 0x1305ba,
    wk_POP_RSI_RET: 0x7245e,
    wk_POP_RDI_RET: 0x60480,
    wk_POP_RBP_RET: 0x40b6,
    wk_POP_RSP_RET: 0x73017,
    wk_POP_R8_RET: 0x230cbe1,
    wk_POP_R12_RET: 0x242ab15,
    wk_POP_R14_RET: 0xa9e91,
    wk_POP_R15_RET: 0x6047f,
    wk_MOV_RAX_RDI_RET: 0x23320,
    wk_MOV_RDX_RAX_RET: 0x1ceba9,
    wk_XCHG_RAX_RSP_RET: 0x3f755a8,
    wk_MOV_QWORD_RDI_RAX_RET: 0x948b,
    wk_MOV_RAX_QWORD_RAX_RET: 0x14021,
    wk_MOV_RAX_QWORD_RDI_RET: 0xe2ea0,
    wk_ADD_RAX_RCX_RET: 0x84f67,
    wk_SUB_RAX_RCX_RET: 0x98736c,
    wk_XOR_RAX_RAX_RET: 0x23d14f6,
    wk_INC_RAX_RET: 0xc5e51c,
    wk_JMP_RAX: 0x4082,
    wk_CALL_RAX: 0x4041,
    wk_JMP_RCX: 0x12a2a,
    wk_POP_R13_POP_R14_POP_R15_RET: 0x6047b,
    wk_POP_RBX_POP_RBP_RET: 0xad0f,
  };

  var out = {
    PS4_1402_REFERENCE: PS4_1402_REFERENCE,
    webkit_gadgets_1402: webkit_gadgets_1402,
  };

  if (typeof module !== "undefined" && module.exports) module.exports = out;
  else window.PS4_1402_REFERENCE_DATA = out;
})();

//! Constants used in rCore

pub const USER_STACK_SIZE: usize = 4096 * 2;
pub const KERNEL_STACK_SIZE: usize = 4096 * 2;
pub const KERNEL_HEAP_SIZE: usize = 0x20_0000;
pub const MEMORY_END: usize = 0x88000000;
pub const PAGE_SIZE: usize = 0x1000;
pub const PAGE_SIZE_BITS: usize = 0xc;
pub const MAX_SYSCALL_NUM: usize = 500;

pub const TRAMPOLINE: usize = usize::MAX - PAGE_SIZE + 1;
pub const TRAP_CONTEXT: usize = TRAMPOLINE - PAGE_SIZE;
pub const CLOCK_FREQ: usize = 12500000;
pub const MMIO: &[(usize, usize)] = &[
    (0x10001000, 0x1000),
];
pub const BIG_STRIDE: u8 = 255;

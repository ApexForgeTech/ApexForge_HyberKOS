ENTRY(_start)
SECTIONS {
  . = 1M;
  .multiboot : { KEEP(*(.multiboot)) }
  .text ALIGN(4096) : { *(.text .text.*) }
  .rodata ALIGN(4096) : { *(.rodata .rodata.*) }
  .data ALIGN(4096) : { *(.data .data.*) }
  .bss ALIGN(4096) : { *(COMMON) *(.bss .bss.*) }
  . = ALIGN(4096);
  kernel_end = .;
  ASSERT(kernel_end < 128M, "kernel exceeds managed RAM window")
  /DISCARD/ : { *(.eh_frame*) *(.comment*) }
}

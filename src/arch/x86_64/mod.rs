pub mod bootinfo;
pub mod paging;
pub mod physicalmem;
pub mod serial;

pub use self::bootinfo::*;
use crate::arch::x86_64::paging::{BasePageSize, LargePageSize, PageSize, PageTableEntryFlags};
use crate::arch::x86_64::serial::SerialPort;
use core::ptr::{copy, write_bytes};
use core::{mem, slice};
use goblin::elf;
use multiboot::information::{MemoryManagement, Multiboot, PAddr};

extern "C" {
	static mb_info: usize;
	static kernel_end: u8;
	static debug_data: usize;
}

// CONSTANTS
pub const ELF_ARCH: u16 = elf::header::EM_X86_64;

const KERNEL_STACK_SIZE: u64 = 32_768;
const SERIAL_PORT_ADDRESS: u16 = 0x3F8;
const SERIAL_PORT_BAUDRATE: u32 = 115200;

// Offsets and values used to interpret the boot params ("zeropage") setup by firecracker
// For the full list of values see
// https://github.com/torvalds/linux/blob/b6839ef26e549de68c10359d45163b0cfb031183/arch/x86/include/uapi/asm/bootparam.h#L151-L198
const LINUX_KERNEL_BOOT_FLAG_MAGIC: u16 = 0xaa55;
const LINUX_KERNEL_HRD_MAGIC: u32 = 0x53726448;
const LINUX_SETUP_HEADER_OFFSET: usize = 0x1f1;
const BOOT_FLAG_OFFSET: usize = 13;
const HDR_MAGIC_OFFSET: usize = 17;
const E820_ENTRIES_OFFSET: usize = 0x1e8;
const E820_TABLE_OFFSET: usize = 0x2d0;
const RAMDISK_IMAGE_OFFSET: usize = 39;
const RAMDISK_SIZE_OFFSET: usize = 43;
const CMD_LINE_PTR_OFFSET: usize = 55;
const CMD_LINE_SIZE_OFFSET: usize = 71;

// VARIABLES
static COM1: SerialPort = SerialPort::new(SERIAL_PORT_ADDRESS);
pub static mut BOOT_INFO: BootInfo = BootInfo::new();

struct Mem;
static mut MEM: Mem = Mem;

impl MemoryManagement for Mem {
	unsafe fn paddr_to_slice<'a>(&self, p: PAddr, sz: usize) -> Option<&'static [u8]> {
		let ptr = mem::transmute(p);
		Some(slice::from_raw_parts(ptr, sz))
	}

	// If you only want to read fields, you can simply return `None`.
	unsafe fn allocate(&mut self, _length: usize) -> Option<(PAddr, &mut [u8])> {
		None
	}

	unsafe fn deallocate(&mut self, addr: PAddr) {
		if addr != 0 {
			unimplemented!()
		}
	}
}

// FUNCTIONS
pub fn message_output_init() {
	COM1.init(SERIAL_PORT_BAUDRATE);
}

pub fn output_message_byte(byte: u8) {
	COM1.write_byte(byte);
}

pub unsafe fn find_kernel() -> &'static [u8] {
	loaderlog!("Debug data: {:#b}", debug_data);

	// Identity-map the Multiboot information.
	assert!(mb_info > 0, "Could not find boot_params");
	loaderlog!("Found boot_params at 0x{:x}", mb_info);

	let page_address = align_down!(mb_info, BasePageSize::SIZE);
	paging::map::<BasePageSize>(page_address, page_address, 1, PageTableEntryFlags::WRITABLE);

	let linux_kernel_boot_flag_magic = *((&(mb_info as usize) + LINUX_SETUP_HEADER_OFFSET + BOOT_FLAG_OFFSET) as *const u16);
	let linux_kernel_header_magic = *((&(mb_info as usize) + LINUX_SETUP_HEADER_OFFSET + HDR_MAGIC_OFFSET) as *const u32);
	if linux_kernel_boot_flag_magic == LINUX_KERNEL_BOOT_FLAG_MAGIC && linux_kernel_header_magic == LINUX_KERNEL_HRD_MAGIC {
		loaderlog!("Found Linux kernel boot flag and header magic! Probably booting in firecracker.");
	} else {
		loaderlog!("Kernel boot flag and hdr magic have values 0x{:x} and 0x{:x} which does not align with the normal linux kernel values", 
			linux_kernel_boot_flag_magic,
			linux_kernel_header_magic
		);
	}

	// Load the boot_param memory-map information
	let linux_e820_entries = *((&(mb_info as usize) + E820_ENTRIES_OFFSET) as *const u8);
	loaderlog!("Number of e820-entries: {}", linux_e820_entries);

	let mut found_entry = false;
	let mut start_address: usize = 0;
	let mut end_address: usize = 0;

	let e820_entries_address = &(mb_info as usize) + E820_TABLE_OFFSET;
	loaderlog!("e820-entry-table at 0x{:x}", e820_entries_address);
	let page_address = align_down!(e820_entries_address, BasePageSize::SIZE);

	paging::map::<BasePageSize>(page_address, page_address, 1, PageTableEntryFlags::empty());

	for index in 0..linux_e820_entries {
		found_entry = true;

		//20: Size of one e820-Entry
		let entry_address = e820_entries_address + (index as usize)*20;
		let entry_start = *(entry_address as *const u64); 
		let entry_size = *((entry_address + 8) as *const u64);
		let entry_type = *((entry_address + 16) as *const u32);

		loaderlog!("e820-Entry with index {}: Address 0x{:x}, Size 0x{:x}, Type 0x{:x}", index, entry_start, entry_size, entry_type);

		let entry_end = entry_start + entry_size;

		if start_address == 0 {
			start_address = entry_start as usize;
		}

		if entry_end as usize > end_address {
			end_address = entry_end as usize;
		}
	}

	loaderlog!(
		"Found available RAM: [0x{:x} - 0x{:x}]",
		start_address,
		end_address
	);

	// Load the RustyHermit-ELF from the initrd supplied by Firecracker
	let ramdisk_address = *((&(mb_info as usize) + LINUX_SETUP_HEADER_OFFSET + RAMDISK_IMAGE_OFFSET) as *const u32);
	let ramdisk_size = *((&(mb_info as usize) + LINUX_SETUP_HEADER_OFFSET + RAMDISK_SIZE_OFFSET) as *const u32);

	loaderlog!("Initrd: Address 0x{:x}, Size 0x{:x}", ramdisk_address, ramdisk_size);

	let elf_start = ramdisk_address as usize;
	let elf_len = ramdisk_size as usize;

	// Memory after the highest end address is unused and available for the physical memory manager.
	physicalmem::init(align_up!(&kernel_end as *const u8 as usize, LargePageSize::SIZE));

	// Identity-map the start of RAM
	assert!(
		found_entry,
		"Could not find any free RAM areas!"
	);
	assert!(start_address > 0);
	loaderlog!("Found a RAM region at 0x{:x}", start_address);
	let page_address = align_down!(start_address, BasePageSize::SIZE);
	let counter =
		(align_up!(start_address, LargePageSize::SIZE) - page_address) / BasePageSize::SIZE;
	loaderlog!(
		"Map {} pages at {:#x} (page size {} KByte)",
		counter,
		page_address,
		BasePageSize::SIZE / 1024
	);
	paging::map::<BasePageSize>(
		page_address,
		page_address,
		counter,
		PageTableEntryFlags::empty(),
	);

	// Map the whole available RAM
	let address = align_up!(start_address, LargePageSize::SIZE);
	let counter = (align_up!(end_address, LargePageSize::SIZE) - address) / LargePageSize::SIZE;
	if counter > 0 {
		loaderlog!(
			"Map {} pages at {:#x} (page size {} KByte)",
			counter,
			address,
			LargePageSize::SIZE / 1024
		);
		paging::map::<LargePageSize>(address, address, counter, PageTableEntryFlags::WRITABLE);
	}

	slice::from_raw_parts(elf_start as *const u8, elf_len)
}

pub unsafe fn boot_kernel(
	elf_address: Option<u64>,
	virtual_address: u64,
	mem_size: u64,
	entry_point: u64,
) -> ! {
	let new_addr = match elf_address {
		Some(addr) => {
			if virtual_address != addr {
				loaderlog!("Copy kernel from {:#x} to {:#x}", virtual_address, addr);

				// copy app to the new start address
				copy(
					virtual_address as *const u8,
					addr as *mut u8,
					mem_size.try_into().unwrap(),
				);
			}

			addr
		}
		None => virtual_address,
	};

	// Supply the parameters to the HermitCore application.
	BOOT_INFO.base = new_addr;
	BOOT_INFO.image_size = mem_size;
	BOOT_INFO.mb_info = mb_info as u64;

	let cmdline_ptr = *((&(mb_info as usize) + LINUX_SETUP_HEADER_OFFSET + CMD_LINE_PTR_OFFSET) as *const u32);
	let cmdline_size = *((&(mb_info as usize) + LINUX_SETUP_HEADER_OFFSET + CMD_LINE_SIZE_OFFSET) as *const u32);

	if cmdline_size > 0 {
		// Identity-map the command line.
		let page_address = align_down!(cmdline_ptr as usize, BasePageSize::SIZE);
		paging::map::<BasePageSize>(page_address, page_address, 1, PageTableEntryFlags::empty());

		//let cmdline = multiboot.command_line().unwrap();
		BOOT_INFO.cmdline = cmdline_ptr as u64;
		BOOT_INFO.cmdsize = cmdline_size as u64;
	}

	// determine boot stack address
	let mut new_stack = align_up!(&kernel_end as *const u8 as usize, BasePageSize::SIZE);

	if new_stack + KERNEL_STACK_SIZE as usize > mb_info as usize {
		new_stack = align_up!(
			mb_info + mem::size_of::<Multiboot<'_, '_>>(),
			BasePageSize::SIZE
		);
	}

	if new_stack + KERNEL_STACK_SIZE as usize > BOOT_INFO.cmdline as usize {
		new_stack = align_up!(
			(BOOT_INFO.cmdline + BOOT_INFO.cmdsize) as usize,
			BasePageSize::SIZE
		);
	}

	BOOT_INFO.current_stack_address = new_stack.try_into().unwrap();

	// map stack in the address space
	paging::map::<BasePageSize>(
		new_stack,
		new_stack,
		KERNEL_STACK_SIZE as usize / BasePageSize::SIZE,
		PageTableEntryFlags::WRITABLE,
	);

	// clear stack
	write_bytes(
		new_stack as *mut u8,
		0,
		KERNEL_STACK_SIZE.try_into().unwrap(),
	);

	loaderlog!("BootInfo located at {:#x}", &BOOT_INFO as *const _ as u64);
	//loaderlog!("BootInfo {:?}", BOOT_INFO);
	loaderlog!("Use stack address {:#x}", BOOT_INFO.current_stack_address);

	// Jump to the kernel entry point and provide the Multiboot information to it.
	loaderlog!(
		"Jumping to HermitCore Application Entry Point at {:#x}",
		entry_point
	);
	let func: extern "C" fn(boot_info: &'static mut BootInfo) -> ! =
		core::mem::transmute(entry_point);

	func(&mut BOOT_INFO);

	// we never reach this point
}

unsafe fn map_memory(address: usize, memory_size: usize) -> usize {
	let address = align_up!(address, LargePageSize::SIZE);
	let page_count = align_up!(memory_size, LargePageSize::SIZE) / LargePageSize::SIZE;

	paging::map::<LargePageSize>(address, address, page_count, PageTableEntryFlags::WRITABLE);

	address
}

pub unsafe fn get_memory(memory_size: u64) -> u64 {
	let address = physicalmem::allocate(align_up!(memory_size as usize, LargePageSize::SIZE));
	map_memory(address, memory_size as usize) as u64
}

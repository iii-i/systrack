import struct
from typing import Tuple, List, Optional, Dict

from ..elf import Symbol, ELF, E_MACHINE
from ..kconfig_options import VERSION_INF
from ..type_hints import KernelVersion
from ..utils import VersionedDict, noprefix

from .arch_base import Arch

SYS_CALL_TABLE = 'sys_call_table'
SYS_CALL_TABLE_EMU = 'sys_call_table_emu'


class ArchS390(Arch):
	name               = 's390'
	syscall_table_name = SYS_CALL_TABLE
	syscall_num_reg    = 'r1'
	syscall_arg_regs   = ('r2', 'r3', 'r4', 'r5', 'r6', 'r7')

	kconfig = VersionedDict((
		# 32-bit abi
		((2,6,12), VERSION_INF, 'COMPAT=y', []),
		# error: invalid hard register usage between output operands
		((2,6,19), VERSION_INF, 'ZCRYPT=n', []),
		# Error: junk at end of line
		((2,6,37), VERSION_INF, 'JUMP_LABEL=n', []),
		# s390-specific pci syscalls
		((3,8), VERSION_INF, 'PCI=y', []),
		# misaligned symbol `__nospec_call_start'
		((4,16), VERSION_INF, 'EXPOLINE=n', []),
		# multiple definition of `purgatory_sha256_digest'
		((4,17),(4,19), 'KEXEC_FILE=n', []),
		# load BTF from vmlinux: Invalid argument
		((5,16), (6,0), 'CONFIG_DEBUG_INFO_BTF=n', []),
	))

	def __init__(self, kernel_version: KernelVersion, abi: str, bits32: bool = False):
		assert not bits32, f'{self.__class__.__name__} is 64-bit only'
		super().__init__(kernel_version, abi, False)

		assert self.abi in ('32', '64')
		if self.abi == '32':
			self.compat = True
			self.abi_bits32 = True
			self.syscall_table_name = SYS_CALL_TABLE_EMU

	@staticmethod
	def match(vmlinux: ELF) -> Optional[Tuple[bool,List[str]]]:
		if vmlinux.e_machine != E_MACHINE.EM_S390:
			return None

		assert not vmlinux.bits32, 'EM_S390 32-bit? WAT'

		if 'sys_call_table_emu' in vmlinux.symbols:
			abis = ['32', '64']
		else:
			abis = ['64']

		return False, abis

	def matches(self, vmlinux: ELF) -> bool:
		return not vmlinux.bits32 and vmlinux.e_machine == E_MACHINE.EM_S390

	def preferred_symbol(self, a: Symbol, b: Symbol) -> Symbol:
		c = self.prefer_compat(a, b)
		if c is not None:
			return c

		# See commit aa0d6e70d3b34e710a6a57a53a3096cb2e0ea99f
		if a.name.startswith('__s390x_'): return a
		if b.name.startswith('__s390x_'): return b
		return super().preferred_symbol(a, b)

	def _normalize_syscall_name(self, name: str) -> str:
		# E.g. COMPAT_SYSCALL_DEFINE1(s390_mmap2, ...)
		# E.g. SYSCALL_DEFINE1(s390_personality, ...)
		return noprefix(name, 's390_')

	def have_syscall_table(self) -> bool:
		return False

	def extract_syscall_vaddrs(self, vmlinux: ELF) -> Dict[int, int]:
		symbol = vmlinux.symbols[self.syscall_table_name]
		size = symbol.size
		if size == 0:
			# sys_call_table_emu immediately follows sys_call_table.
			size = (vmlinux.symbols[SYS_CALL_TABLE_EMU].vaddr -
					vmlinux.symbols[SYS_CALL_TABLE].vaddr)
		entry_size, format = 8, "Q"
		entry0 = vmlinux.vaddr_read(symbol.vaddr, entry_size)
		vaddr0, = struct.unpack(f">{format}", entry0)
		text = vmlinux.sections[".text"]
		if not (text.vaddr <= vaddr0 < text.vaddr + text.size):
			# s390 before commit ff4a742dde3c stored vaddrs as ints.
			entry_size, format = 4, "I"
		count = size // entry_size
		table = vmlinux.vaddr_read(symbol.vaddr, size)
		vaddrs = struct.unpack(">" + format * count, table)
		return dict(enumerate(vaddrs))

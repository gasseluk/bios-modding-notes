# Preface

The described mods, tools have been used during the Hyperless Havoc HWBOT competition.

# Mods

## tRFC Mod

### Approach

Find the lookup table data where the CMOS values are converted into register values and change an existing value to contain the register limit value.

### tRFC Lookup Table

ASUS uses discrete `tRFC` options, starting at 30 ticks, ending at 160 ticks.

![tRFC options ASUS](res/tRFC_options.webp)

The values stored in CMOS are organized `0 => Auto`, `1 => 30 DRAM Clock` and so forth. Somewhere in the BIOS must be a lookup table (LUT) to translate the CMOS value into a register value. Let's use one of the entries and change its value stored in the LUT. 30 ticks is not relevant for benching, therefore let's use that entry.

To find the LUT in the code, let's check which module could be relevant for that matter.

![MMTOOL modules](res/MMTOOL_List.PNG)

MMTOOL lists a bunch of well-known modules like `P6 Micro Code`, `Bootblock`, etc. From [digitalbath's excellent post in the Socket 462 BIOS Workshop thread](https://community.hwbot.org/topic/208124-socket-462-bios-workshop/page/2/#findComment-596258) we know that the `Single Link Arch BIOS` contains the setup code.

### Module 1B - Single Link Arch BIOS

As a first guess, the `Single Link Arch BIOS` (SLAB) looks promising.

To search for the values, let's write them in hex values:

```
Dec => HEX
30 => 0x1E
36 => 0x24
48 => 0x30
60 => 0x3C
...
```

Let's check if we should search for 8 bit or 16 bit values. Therefore consult the datasheet. Unfortunately Intel decided to hide a lot of relevant stuff in the Core i7 datasheet. Luckily they preserved it in the XEON-5500 series datasheet:

![tRFC register](res/tRFC_register.PNG)

There's 9 bits for `tRFC` in the `MC_CHANNEL_n_REFRESH_TIMING` register, therefore the LUT values could also be stored as 16 bit values.

As we deal with a little endian architecture, the values above will be found in the code as follows:

```
1E 00 24 00 30 00 3C 00...
```

Unfortunately 16 bit values yield no results in the `1B` module. Let's try 8 bits.

Search pattern (in ImHEX) could be like these:

- `1E2430`
- `1E??24??30`
- `1E????24????30`
- you got the pattern...

With this pattern we allow some other data to sit between the values.

Our match is here:

![tRFC LUT in 1B](res/tRFC_lut_1b.PNG)

It also shows the assignment of CMOS values to register values: `01` => `1E`, `02` => `24`, ...

After changing those it turns out it is only used for internal calculations in the setup program. The search continues.

Which other modules could be relevant?

- P6 Micro Code? -> nope
- Bootblock? -> Maybe, but it's very small, only 2KB -> There cannot be much logic in here
- ROMID -> Nope
- PCI Option ROMs -> Nope

The list goes on, there is no module in the Rampage III Extreme BIOS that looked to me like it has relevant boot time code for the memory.

### Module 55 - Memory Init Module

I don't know the real name of this module, but it surely contains the memory init code. Disassembling it using IDA reveals that it's a PE32 executable, same as the newer UEFI memory init modules.

Now searching this module yields this:

![tRFC LUT in 55](res/tRFC_lut_55.PNG)

Ok, let's disassemble this:

![tRFC LUT disassembly](res/tRFC_lut_disassembly.PNG)

Seems like the code loads the tRFC register values from immediate values into a structure located at base pointer (ebp) + 0x2C. Maybe IDA can give some more insight into this:

![tRFC LUT fill](res/tRFC_lut_IDA.PNG)

Yep, IDA calls the structure `Var_2C`. Note that it is located directly next to `Var_2E`.

Further down we see that `Var_2E` is referenced for the lookup of the non-auto `tRFC` value:

![tRFC LUT lookup](res/tRFC_lut_lookup.PNG)

So eventually we can modify the loaded value by replacing `1E 00` with `FF 01`, which changes the value from 30 to 511.

![tRFC LUT modified](res/tRFC_lut_modded.PNG)

### Timings Check Routine

As a bonus from the tRFC LUT search, we get the auto timings check routine, that is between the tRFC LUT and its effective lookup code:

![tCL check routine](res/tCL_Check_Routine_annotated.PNG)

## Config Lock Mod

### Approach

The R3E does not lock the `MC_CFG` whereas the R2E does. Let's find the difference between the BIOS sections regarding that register configuration and check 

First, find the register in the datasheet:

![MC_CFG_CONTROL Register](res/MC_CFG_CONTROL_register.PNG)

So the `MC_CFG_CONTROL` register is located at Dev 0 Func 0 Offset 90h

There's multiple ways to access these registers. One is via PCI config space and one is via RDMSR/WRMSR commands. WRMSR seems to be more common here, dunno why.

### Finding the MSR Access

To find out the MSR ID, we need to dig into the BIOS code. The **Rampage III Extreme** might have an option to configure the lock somewhere in a hidden setup entry. Let's open AMIBCP and search through the strings for 'memory configuration':

![AMIBCP Mem Cfg Protect Strings](res/CFG_lock_strings.PNG)

The handle token is `0x0601` --> Find the setup entry that controls this item. With the information from the setup entry, we can find accesses to the CMOS entry. The setup is contained in the 1B module (SLAB).

From the Socket 462 Workshop we know that enumeration setup items have this format:

|||||||
|-|-|-|-|-|-|
| Enum Ident | Token | CMOS Index/Mask Word | Cfg | Help | Label[0] | Label[1] |
| 1B | 2B | 2B | 1B | 1+2B | 2B | 2B |

Assuming this setting is an enumeration, we expect someting like this:

| Enum Ident | Token | CMOS Index/Mask Word | Cfg | Help |  |
|-|-|-|-|-|-|
| 01 | 0601 | ??? |...|...|

The search pattern is then `01 01 06`:

The search result points to offset 395F2:

![CFG lock setup entry](res/CFG_lock_setup_entry.PNG)

It can be interpreted as follows

- Enum
    - Label: 0x0601 "Memory Configuration Protect"
    - **CMOS Index/Mask: 0x16B7**
    - Config: 0x81
    - Help: 0x02 / 0x0602 "Allows you to lock or unlock the memory configuration."
    - Values:
        - 0 => 0x00C9
        - 1 => 0x00C8

Looking up the values in AMIBCP shows:

![CFG lock strings values](res/CFG_lock_strings_values.PNG)

Value 0 = Enabled => Config locked
Value 1 = Disabled => Config NOT locked

A search in the code for the CMOS mask `B7 16` returns multiple results. Each must be checked. With a little practice, it becomes easier to discern code sections from data sections by looking at the hex code... In doubt, disassemble each search result.

Et voilà at offset `C2EF` the section containing the register access is revealed:

![CFG lock register access](res/CFG_lock_register_access.PNG)

An attempt in pseudo code:

```C
int cfg_locked = read_cmos(0x16b7);

if (cfg_locked == 0)
{
    lock_mc();
}

void lock_mc()
{
    int64_t lock_value = 2;

    int cpu_signature = 0;
    cpuid(1, &cpu_signature, ...);

    // CPUID 0x106a4 = i7 920, 940 965
    // CPUID 0x106a5 = i7 920, 930, 950, 960, 975, Xeon W35xx
    // CPUID 0x206c2 = i7 970, 980, 980X, 990X, Xeon W36xx
    if (cpu_signature >= 0x106a4)
    {
        WRMSR(0x2e2, lock_value);
    }
}
```

> **NOTICE:** A quick search online shows that the MSR `0x2e2` allows access to the `MC_CFG_CONTROL` register via `WRMSR`. Interestingly the information online contradicts my findings: The mod prevents the BIOS from writing a value of 2 to the register and the MC configuration is then not locked in the OS. However [code found in the linux kernel](https://github.com/torvalds/linux/blob/v6.18/drivers/edac/i7core_edac.c#L81) documents that writing the value 2 *unlocks* the MC configuration. I have no clue what's happening here. Maybe this mod only causes the MC configuration lock not to be applied at a later stage.

### Translation to Rampage II Extreme

In the R2E BIOS, let's find the code where the MSR `0x2e2` is written.

We use the `mov ecx, 0x2e2` code for the search: `66 B9 E2 02 00 00`

Disassembling the section reveals, that the call to `lock_mc()` is unconditional:

![CFG lock access R2E](res/CFG_lock_access_R2E.PNG)

### Modifying the Code

Now to prevent the BIOS from calling `lock_mc()` we tell it to do nothing instead. We need the call to be replaced by a sequence of `NOP` instructions.

The `NOP` is assembled to `0x90`, so let's just fill the three bytes of the `call 0xccbf` with `90 90 90`.

> IMPORTANT: You must not change the binary size (adding or deleting bytes), otherwise it will no more run!

## UCLK Ratio Mod

### Approach

Use AMIBCP / Module 1B to find the CMOS addresses of UCLK and memory clock settings. With the CMOS addresses, find the places in the code where the 3:2 / 2:1 ratio is enforced.

### Finding the CMOS Addresses

For instruction on how to find the CMOS address, see [Config Lock Mod](#config-lock-mod) section.

| Setup Value | Setup Token | CMOS Address |
|-|-|-|
| DRAM Frequency | 0x007D | 0x3553 |
| UCLK Frequency | 0x04DB | 0x53E8 |

### UCLK Adjustment in Module 1B

The setup module adjusts the values of UCLK / Mem clock if the other one is changed. This needs to be adjusted.

From the MC config lock mod we know that in module 1B we can search for `mov ax, 0x3553` => `B8 53 35`. There are a handful results found, all pretty closeby.

Let's disassemble them all and check what happens to the value.

Offsets 0x40778 and 0x40B4D look promising:

![UCLK adjust module 1B ](res/UCLK_adjust_1B_other.PNG)

These two sections control the automatic adjustments of the setup values when one or the other is changed.

With the multipliers adjusted from 3/4 to 1, the lowest UCLK value is always valid.

![UCLK multipliers](res/UCLK_multipliers.PNG)

### UCLK Adjustment in Module 55

This is the most difficult part. Module 55 uses both PCI config space and CMOS values to access configuration stuff.

TBD:

- How to find the relevant section?
- Dev 3 Func 4 Offset 50 / 54
- 0x85 = 133 = BCLK used for calculations
- [esi + 0x1B5E] = UCLK
- [esi + 0x0E94] = New MCLK
- [esi + 0x03DD] = New Mem Multi

![UCLK mod module 55](res/UCLK_mod_55.PNG)

# Interesting Addresses

During BIOS analysis, I noted some addresses and offsets of values inside the modules and structures. These are usually referenced as shown in the below assembly snippet (IDA).

The CMOS values are only valid for the R3E bios 1502. Probably the offsets in the `edi` structures are valid for many ASUS BIOSes.

## Module 1B Sections

| Address | What |
|-|-|
| 4032B | Memory Clock Values Table |
| 40692 | UCLK Values Table |


## CMOS Indices

Some important CMOS value indices/masks within the Rampage III Extreme BIOS. These apply global because they are read from CMOS memory directly.

The values read from here have values in the format as they are stored in the CMOS registers. There are discrete values like BCLK or enumerations like all timings whereas 0 => Auto, 1 => first non-auto value. Usually values that have a certain range and a step size, like a CPU multiplier are enumerations.

| Address | Value | Intermediate Value |
|-|-|-|
| A700 | BCLK | ? |
| 3553 | DRAM Clock | 3405 |
| 53E8 | UCLK | 53D0 |
| 44F0 | AI Overclock Tuner | ? |
| 3548 | XMP on/off | ? |
| 44AC | tCL | ? |
| 44B0 | ? | ? |
| 53D8 | ? | ? |
| 25E8 | ? | ? |
| 7348 | ? | ? |
| 8318 | ? | ? |

In module 55 these are accessed as 32 bit values.

```asm
; Module 55 code
; Read tCL from CMOS
push 44ACh        ; Store offet on stack
call sub_1953E    ; Call CMOS read routine
; Result in AX
```

Search for these values using the IDA immediate value search (alt + i)

In module 1B, these are accessed as 16 bit values, more like this:

```asm
; Read tCL from CMOS
mov ax, 0x44AC         ; Argument in AX
lcall 0x4000 0x1cc1    ; Call CMOS read routine
; Result in BX
```

## Module 55 Struct Offsets

This seems to be a structure where the configuration values are stored for later write into the registers. Originally these are calculated using an auto routine or copied from the CMOS values.

| Offset | Value |
|-|-|
| 11h | tCL |
| 12h | tRCD |
| 13h | tRP |
| 14h | tRAS |
| 16h | tWTR |
| 17h | tRTP |
| 20h | tRFC |

```asm
; Read tCL from some huge RAM struct (module 55)
mov edi, [ebp+arg_4]   ; struct was passed as a function argument
mov al, [edi+11h]      ; dereference struct offset
```

Access for these values can be searched for in IDA using the immediate value search (alt + i).

# Tools

- IDA Freeware (I used 7.0.191002)
- ImHEX: https://github.com/WerWolv/ImHex
- Online assembler: https://defuse.ca/online-x86-assembler.htm
- 1B utils: https://github.com/pinczakko/AMIBIOS8_1B_Utils
- AMIBCP
- MMTOOL V3.22 BKMOD


# References

- [CPUID - Thomas Krenn Wiki](https://www.thomas-krenn.com/en/wiki/CPUID)
- [X86 Instruction Reference](https://www.felixcloutier.com/x86/)
- [Online X86 Assembler](https://defuse.ca/online-x86-assembler.htm)

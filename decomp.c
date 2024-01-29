#include <stdio.h>
#include <fcntl.h>
#include <libelf.h>
#include <gelf.h>
#include <capstone/capstone.h>

void disassemble_function(char *code, size_t size, uint64_t address, csh handle, Elf *elf, GElf_Shdr sym_shdr) {
    cs_insn *insn;
    size_t count;

    count = cs_disasm(handle, code, size, address, 0, &insn);
    if (count > 0) {
        printf("0x%lx:\n", address);
        for (size_t j = 0; j < count; j++) {
            printf("\t%s\t\t%s\n", insn[j].mnemonic, insn[j].op_str);
        }

        cs_free(insn, count);
    } else {
        fprintf(stderr, "Failed to disassemble the function\n");
    }
}

void disassemble_section(Elf *elf, Elf_Scn *scn, csh handle) {
    GElf_Ehdr ehdr;
    gelf_getehdr(elf, &ehdr);

    GElf_Shdr shdr;
    gelf_getshdr(scn, &shdr);

    if (shdr.sh_type == SHT_PROGBITS && (shdr.sh_flags & SHF_EXECINSTR)) {
        Elf_Data *data = elf_getdata(scn, NULL);
        char *section_code = (char *)data->d_buf;
        size_t section_size = data->d_size;

        // Get section name
        Elf_Scn *str_scn = elf_getscn(elf, ehdr.e_shstrndx);
        Elf_Data *str_data = elf_getdata(str_scn, NULL);
        char *section_name = (char *)(str_data->d_buf + shdr.sh_name);

        printf("Disassembly for section '%s':\n", section_name);

        // Iterate over symbols
        Elf_Scn *sym_scn = NULL;
        while ((sym_scn = elf_nextscn(elf, sym_scn)) != NULL) {
            GElf_Shdr sym_shdr;
            gelf_getshdr(sym_scn, &sym_shdr);

            if (sym_shdr.sh_type == SHT_SYMTAB) {
                Elf_Data *symdata = elf_getdata(sym_scn, NULL);
                Elf64_Sym *sym = (Elf64_Sym *)symdata->d_buf;
                size_t nsyms = symdata->d_size / sizeof(Elf64_Sym);

                for (size_t i = 0; i < nsyms; i++) {
                    if (ELF64_ST_TYPE(sym[i].st_info) == STT_FUNC) {
                        uint64_t address = sym[i].st_value;

                        // Check if the address is within the section range
                        if (address >= shdr.sh_addr && address < shdr.sh_addr + shdr.sh_size) {
                            // Get function name from the symbol section
                            char *function_name = elf_strptr(elf, sym_shdr.sh_link, sym[i].st_name);

                            // Skip disassembling specific functions
                            if (strcmp(function_name, "deregister_tm_clones") == 0 ||
                                strcmp(function_name, "register_tm_clones") == 0 ||
                                strcmp(function_name, "__do_global_dtors_aux") == 0 ||
                                strcmp(function_name, "frame_dummy") == 0 ||
                                strcmp(function_name, "_term_proc") == 0) {
                                continue;
                            }

                            printf("Function: %s\n", function_name);
                            printf("Offset: %lx\n", address);

                            // Get the offset and size for the current function
                            Elf64_Addr func_offset = sym[i].st_value - shdr.sh_addr;
                            size_t func_size = sym[i].st_size;

                            // Allocate a separate buffer for the current function's code
                            char *func_code = section_code + func_offset;

                            disassemble_function(func_code, func_size, address + shdr.sh_addr, handle, elf, sym_shdr);
                            printf("\n");
                        }
                    }
                }
            }
        }
    }
}


int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <elf_file>\n", argv[0]);
        return 1;
    }

    int elf_fd = open(argv[1], O_RDONLY);
    if (elf_fd == -1) {
        perror("Error opening ELF file");
        return 1;
    }

    if (elf_version(EV_CURRENT) == EV_NONE) {
        fprintf(stderr, "ELF library initialization failed: %s\n", elf_errmsg(-1));
        close(elf_fd);
        return 1;
    }

    Elf *elf = elf_begin(elf_fd, ELF_C_READ, NULL);
    if (!elf) {
        fprintf(stderr, "Error initializing ELF descriptor: %s\n", elf_errmsg(-1));
        close(elf_fd);
        return 1;
    }

    // Initialize Capstone
    csh handle;
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
        fprintf(stderr, "Error initializing Capstone\n");
        elf_end(elf);
        close(elf_fd);
        return 1;
    }

    // Iterate over sections
    Elf_Scn *scn = NULL;
    while ((scn = elf_nextscn(elf, scn)) != NULL) {
        disassemble_section(elf, scn, handle);
    }

    // Close Capstone
    cs_close(&handle);

    // Clean up
    elf_end(elf);
    close(elf_fd);

    return 0;
}


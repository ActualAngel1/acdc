#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <libelf.h>
#include <gelf.h>
#include <capstone/capstone.h>

#define max_functions 100
#define max_symbols 1000

// Struct to store information about a function
typedef struct {
    char *name;
    uint64_t start_address;
    uint64_t end_address;
    size_t length;
    cs_insn *instructions;  // Array to store disassembled instructions
} _function;

typedef struct {
	char* name;
	uint64_t addr;
} _symbol;

void make_symbols_from_funcs(_function *functions, size_t num_functions, _symbol *symbols, size_t *num_symbols) {
    for (int i = 0; i < num_functions; i++) {
    	if (*num_symbols < max_symbols) {
		symbols[*num_symbols] = (_symbol){.name = strdup(functions[i].name), .addr = functions[i].start_address};
		(*num_symbols)++;
	} else {
	        printf("You reached the maximum amount of symbols");
	        return;
	}
    }
}

void get_dynamic_symbols(Elf *elf, _symbol *symbols, size_t *num_symbols) {
    Elf_Scn *dynsym_scn = NULL;
    while ((dynsym_scn = elf_nextscn(elf, dynsym_scn)) != NULL) {
        GElf_Shdr dynsym_shdr;
        gelf_getshdr(dynsym_scn, &dynsym_shdr);

        if (dynsym_shdr.sh_type == SHT_DYNSYM) {
            Elf_Data *dynsym_data = elf_getdata(dynsym_scn, NULL);
            Elf64_Sym *dynsym_entries = (Elf64_Sym *)dynsym_data->d_buf;
            size_t num_syms = dynsym_data->d_size / sizeof(Elf64_Sym);

            printf("Dynamic Symbol Table:\n");

            for (size_t i = 0; i < num_syms; i++) {
                if (*num_symbols < max_symbols) {
                    char *sym_name = elf_strptr(elf, dynsym_shdr.sh_link, dynsym_entries[i].st_name);
                    Elf64_Addr sym_address = dynsym_entries[i].st_value;

		    symbols[*num_symbols] = (_symbol){.name = sym_name, .addr = (uint64_t)sym_address};
		    (*num_symbols)++;
		} else {
		    printf("You reached the maximum amount of symbols");
		    return;
		}
            }
        }
    }
}

void disassemble_function(char *code, size_t size, uint64_t section_base, uint64_t func_offset, csh handle, Elf *elf, GElf_Shdr sym_shdr, _function *function) {
    cs_insn *insn;
    size_t count;

    count = cs_disasm(handle, code, size, section_base + func_offset, 0, &insn);
    if (count > 0) {
        // Save function details in the struct
        function->start_address = section_base + func_offset;  // Use sh_addr of the section
        function->end_address = section_base + func_offset + size;  // Correct calculation for end address
        function->length = count;
        function->instructions = insn;
    } else {
        fprintf(stderr, "Failed to disassemble the function\n");
    }
}

void disassemble_section(Elf *elf, Elf_Scn *scn, csh handle, _function *functions, size_t *num_functions) {
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

                            if (*num_functions >= max_functions) {
				printf("You reached the maximum amount of functions");
				return;
                            }
                            
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

                            // Create a function struct to store information
                            _function *function = &functions[*num_functions];
                            function->name = function_name;
                            function->instructions = NULL;  // This will be set in disassemble_function

                            disassemble_function(func_code, func_size, shdr.sh_addr, func_offset, handle, elf, sym_shdr, function);

                            // Increment the number of functions
                            (*num_functions)++;
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

    // Allocate an array to store information about functions
    _function *functions = (_function *)malloc(max_functions * sizeof(_function));
    size_t num_functions = 0;

    _symbol *symbols = (_symbol *)malloc(max_symbols * sizeof(_symbol));
    size_t num_symbols = 0;
    

    // Iterate over sections
    Elf_Scn *scn = NULL;
    while ((scn = elf_nextscn(elf, scn)) != NULL) {
        disassemble_section(elf, scn, handle, functions, &num_functions);
    }

    // Print details of each function
    for (size_t i = 0; i < num_functions; i++) {
        printf("Function Details:\n");
        printf("\tName: %s\n", functions[i].name);
        printf("\tStart Address: 0x%lx\n", functions[i].start_address);
        printf("\tEnd Address: 0x%lx\n", functions[i].end_address);
        printf("\tLength: %zu bytes\n", functions[i].length);
        printf("\tDisassembled Code:\n");
        // Print the disassembled code
        for (size_t j = 0; j < functions[i].length; j++) {
            printf("\t\t%s\t\t%s\n", functions[i].instructions[j].mnemonic, functions[i].instructions[j].op_str);
        }
        printf("\n");
   }

   make_symbols_from_funcs(functions, num_functions, symbols, &num_symbols);

   get_dynamic_symbols(elf, symbols, &num_symbols);

   for (size_t i = 0; i < num_symbols; i++) {
        printf("Symbol: %s\tAddress: 0x%lx\n", symbols[i].name, symbols[i].addr);
   }
  
    // Close Capstone
    cs_close(&handle);

    // Clean up
    free(functions);
    free(symbols);
    elf_end(elf);
    close(elf_fd);

    return 0;
}

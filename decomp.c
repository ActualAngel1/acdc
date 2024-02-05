#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <libelf.h>
#include <gelf.h>
#include <capstone/capstone.h>
#include <stdbool.h>

#define MAX_FUNCTIONS 100
#define MAX_SYMBOLS 1000

// Struct to store information about a function
typedef struct {
    char *name;
    uint64_t start_address;
    uint64_t end_address;
    size_t length;
    cs_insn *instructions;  // Array to store disassembled instructions
} Function;

typedef struct {
    char *name;
    uint64_t addr;
    uint64_t end_addr; // Symbols have a start and size fields, so this just adds the two.
} Symbol;



// Function prototypes
void cleanup_functions(Function *functions, size_t num_functions);
void process_symtab_symbols(Elf *elf, Symbol *symbols, size_t *num_symbols, GElf_Shdr *symtab_shdr, Elf_Scn *symtab_scn);
void add_symbol_if_global_object(Symbol *symbols, size_t *num_symbols, Elf *elf, GElf_Shdr *symtab_shdr, Elf64_Sym *sym_entry);
void update_symbol_end_address(Symbol *symbol, Elf64_Sym *sym_entry);
void get_global_object_symbols(Elf *elf, Symbol *symbols, size_t *num_symbols);
void cleanup_symbols(Symbol *symbols, size_t num_symbols);
void print_function_details(Function *functions, size_t num_functions);
void print_disassembled_code(Function *function);
void make_symbols_from_functions(Function *functions, size_t num_functions, Symbol *symbols, size_t *num_symbols);
void get_dynamic_symbols(Elf *elf, Symbol *symbols, size_t *num_symbols);
void disassemble_function(char *code, size_t size, uint64_t section_base, uint64_t func_offset, csh handle, Elf *elf, GElf_Shdr sym_shdr, Function *function);
void iterate_symbols(Elf *elf, Elf_Scn *sym_scn, Function *functions, size_t *num_functions, const GElf_Shdr *sym_shdr, const GElf_Shdr *shdr, char *section_code, csh handle);
void disassemble_section(Elf *elf, Elf_Scn *scn, csh handle, Function *functions, size_t *num_functions);

Symbol *got_entry_to_symbol(Symbol *symbols, size_t *num_symbols, int64_t got_entry) {
    for (int i = 0; i < *num_symbols; i++) {
        if (symbols[i].addr == got_entry) return &symbols[i];
    }

    return NULL;
}

void link_plt_entry_to_symbol(Symbol *symbols, size_t *num_symbols, int64_t plt_stub_addr, int64_t got_entry) {
    Symbol* symbol = got_entry_to_symbol(symbols, num_symbols, got_entry);
    if (symbol) {
        symbol->addr = plt_stub_addr;
        symbol->end_addr = plt_stub_addr + 0x10;
    }
}

void link_plt_to_symbols(Elf *elf, Symbol *symbols, size_t *num_symbols) {
    Elf_Scn *plt_sec_scn = NULL;
    Elf64_Ehdr *ehdr = elf64_getehdr(elf);

    if (ehdr == NULL) {
        fprintf(stderr, "Failed to get ELF header\n");
        return;
    }

    size_t shstrndx;
    if (elf_getshdrstrndx(elf, &shstrndx) != 0) {
        fprintf(stderr, "Failed to get section header string index\n");
        return;
    }

    // Iterate over sections to find plt.sec section
    while ((plt_sec_scn = elf_nextscn(elf, plt_sec_scn)) != NULL) {
        GElf_Shdr plt_sec_shdr;
        gelf_getshdr(plt_sec_scn, &plt_sec_shdr);

        const char *section_name = elf_strptr(elf, shstrndx, plt_sec_shdr.sh_name);

        // Check if it's a plt.sec section
        if (section_name != NULL && (strcmp(section_name, ".plt.sec") == 0)
                                        || strcmp(section_name, ".plt.got") == 0) {
            // Disassemble the plt.sec section
            Elf_Data *plt_sec_data = elf_getdata(plt_sec_scn, NULL);
            char *plt_sec_code = (char *)plt_sec_data->d_buf;
            size_t plt_sec_size = plt_sec_data->d_size;

            csh handle;
            if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) {
                fprintf(stderr, "Error initializing Capstone\n");
                return;
            }

            cs_insn *plt_sec_insn;
            size_t plt_sec_count = cs_disasm(handle, plt_sec_code, plt_sec_size, plt_sec_shdr.sh_addr, 0, &plt_sec_insn);

            // Check if the disassembly was successful
            if (plt_sec_count > 0) {
                printf("%s Section Disassembly:\n", section_name);
                // Parse operand manually
                for (size_t i = 1; i < plt_sec_count; i += 3) {
                    uint64_t disp;
                    char *op_str = plt_sec_insn[i].op_str;
                    // Assuming the displacement is in the format [rip + displacement]
                    if (sscanf(op_str, "qword ptr [rip + 0x%" SCNx64 "]", &disp) == 1) {
                        printf("start: %lx, got: %lx \n", plt_sec_insn[i-1].address, plt_sec_insn[i+1].address + disp);
                        link_plt_entry_to_symbol(symbols, num_symbols, plt_sec_insn[i-1].address, plt_sec_insn[i+1].address + disp);
                    }
                }
                printf("\n");
            }

            cs_free(plt_sec_insn, plt_sec_count);
            cs_close(&handle);
        }
    }
}

void get_relocation_symbols(Elf *elf, Symbol *symbols, size_t *num_symbols) {
    Elf_Scn *rela_scn = NULL;
    while ((rela_scn = elf_nextscn(elf, rela_scn)) != NULL) {
        GElf_Shdr rela_shdr;
        gelf_getshdr(rela_scn, &rela_shdr);

        if (rela_shdr.sh_type == SHT_RELA) {
            Elf_Data *rela_data = elf_getdata(rela_scn, NULL);
            Elf64_Rela *rela_entries = (Elf64_Rela *)rela_data->d_buf;
            size_t num_relas = rela_data->d_size / sizeof(Elf64_Rela);

            Elf_Scn *dynsym_scn = elf_getscn(elf, rela_shdr.sh_link);
            Elf_Data *dynsym_data = elf_getdata(dynsym_scn, NULL);
            Elf64_Sym *dynsym_entries = (Elf64_Sym *)dynsym_data->d_buf;
            size_t num_dynsyms = dynsym_data->d_size / sizeof(Elf64_Sym);

            Elf_Scn *strtab_scn = NULL;
            Elf_Data *strtab_data = NULL;

            // Get the index of the string table section
            size_t shstrndx;
            if (elf_getshdrstrndx(elf, &shstrndx) != 0) {
                printf("Failed to get section header string index\n");
                return;
            }

            // Retrieve the associated string table for symbol names
            for (size_t i = 0; i < shstrndx; i++) {
                Elf_Scn *scn = elf_getscn(elf, i);
                GElf_Shdr shdr;
                gelf_getshdr(scn, &shdr);

                if (shdr.sh_type == SHT_STRTAB && i != rela_shdr.sh_link) {
                    strtab_scn = scn;
                    strtab_data = elf_getdata(strtab_scn, NULL);
                    break;
                }
            }

            if (strtab_scn == NULL || strtab_data == NULL) {
                printf("String table not found for symbol names\n");
                return;
            }

            for (size_t i = 0; i < num_relas; i++) {
                if (*num_symbols >= MAX_SYMBOLS) {
                    printf("You reached the maximum amount of symbols\n");
                    return;
                }

                Elf64_Sxword sym_index = ELF64_R_SYM(rela_entries[i].r_info);

                if (sym_index < 0 || (size_t)sym_index >= num_dynsyms) {
                    printf("Invalid symbol index at entry %zu\n", i);
                    continue;
                }

                Elf64_Sym *sym_entry = &dynsym_entries[sym_index];

                // Retrieve the symbol name using the string table section
                const char *sym_name = (const char *)(strtab_data->d_buf) + sym_entry->st_name;

                if (sym_name == NULL || sym_name[0] == '\0') {
                    printf("Skipped symbol with NULL or empty name at index %zu\n", i);
                    continue;
                }

                symbols[*num_symbols] = (Symbol) {
                    .name = strdup(sym_name),
                    .addr = rela_entries[i].r_offset,
                    .end_addr = rela_entries[i].r_offset, 
                };

                (*num_symbols)++;
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
    Function *functions = (Function *)malloc(MAX_FUNCTIONS * sizeof(Function));
    size_t num_functions = 0;

    Symbol *symbols = (Symbol *)malloc(MAX_SYMBOLS * sizeof(Symbol));
    size_t num_symbols = 0;

    // Iterate over sections
    Elf_Scn *scn = NULL;
    while ((scn = elf_nextscn(elf, scn)) != NULL) {
        disassemble_section(elf, scn, handle, functions, &num_functions);
    }

    // Print details of each function
    print_function_details(functions, num_functions);

    // Make symbols from functions
    make_symbols_from_functions(functions, num_functions, symbols, &num_symbols);

    get_relocation_symbols(elf, symbols, &num_symbols);

    // Get global object symbols from symtab
    get_global_object_symbols(elf, symbols, &num_symbols);

    link_plt_to_symbols(elf, symbols, &num_symbols);

    // Print symbols
    for (size_t i = 0; i < num_symbols; i++) {
        printf("Symbol: %s\tStart Address: 0x%lx\tEnd Address: 0x%lx\n", symbols[i].name, symbols[i].addr, symbols[i].end_addr);
    }

    // Close Capstone
    cs_close(&handle);

    // Clean up
    cleanup_functions(functions, num_functions);
    cleanup_symbols(symbols, num_symbols);
    elf_end(elf);
    close(elf_fd);

    return 0;
}

void cleanup_functions(Function *functions, size_t num_functions) {
    for (size_t i = 0; i < num_functions; i++) {
        // free(functions[i].name);
        if (functions[i].instructions) {
            cs_free(functions[i].instructions, functions[i].length);
        }
    }
    free(functions);
}

void cleanup_symbols(Symbol *symbols, size_t num_symbols) {
    for (size_t i = 0; i < num_symbols; i++) {
        free(symbols[i].name);
    }
    free(symbols);
}

void print_function_details(Function *functions, size_t num_functions) {
    for (size_t i = 0; i < num_functions; i++) {
        printf("Function Details:\n");
        printf("\tName: %s\n", functions[i].name);
        printf("\tStart Address: 0x%lx\n", functions[i].start_address);
        printf("\tEnd Address: 0x%lx\n", functions[i].end_address);
        printf("\tLength: %zu bytes\n", functions[i].length);
        printf("\tDisassembled Code:\n");
        // Print the disassembled code
        print_disassembled_code(&functions[i]);
        printf("\n");
    }
}

void print_disassembled_code(Function *function) {
    for (size_t j = 0; j < function->length; j++) {
        printf("\t\t%s\t\t%s\n", function->instructions[j].mnemonic, function->instructions[j].op_str);
    }
}

void make_symbols_from_functions(Function *functions, size_t num_functions, Symbol *symbols, size_t *num_symbols) {
    for (size_t i = 0; i < num_functions; i++) {
        if (*num_symbols >= MAX_SYMBOLS) {
            printf("You reached the maximum amount of symbols\n");
            return;
        }

        symbols[*num_symbols] = (Symbol) {
                                .name     = strdup(functions[i].name),
                                .addr     = functions[i].start_address,
                                .end_addr = functions[i].end_address
                                };
        (*num_symbols)++;

    }
}

void disassemble_function(char *code, size_t size, uint64_t section_base, uint64_t func_offset, csh handle, Elf *elf, GElf_Shdr sym_shdr, Function *function) {
    cs_insn *insn;
    size_t count;

    count = cs_disasm(handle, code, size, section_base + func_offset, 0, &insn);
    if (count <= 0) {
        fprintf(stderr, "Failed to disassemble the function\n");
    }
    // Save function details in the struct
    function->start_address = section_base + func_offset;  // Use sh_addr of the section
    function->end_address = section_base + func_offset + size;  // Correct calculation for end address
    function->length = count;
    function->instructions = insn;

}

void iterate_symbols(Elf *elf, Elf_Scn *sym_scn, Function *functions, size_t *num_functions, const GElf_Shdr *sym_shdr, const GElf_Shdr *shdr, char *section_code, csh handle) {
    Elf_Data *symdata = elf_getdata(sym_scn, NULL);
    Elf64_Sym *sym = (Elf64_Sym *)symdata->d_buf;
    size_t nsyms = symdata->d_size / sizeof(Elf64_Sym);

    for (size_t i = 0; i < nsyms; i++) {
        if (ELF64_ST_TYPE(sym[i].st_info) != STT_FUNC) continue;
        uint64_t address = sym[i].st_value;

        // Check if the address is within the section range
        if (address < shdr->sh_addr || address >= shdr->sh_addr + shdr->sh_size) continue;

    
        if (*num_functions >= MAX_FUNCTIONS) {
            printf("You reached the maximum amount of functions\n");
            return;
        }

        // Get function name from the symbol section
        char *function_name = elf_strptr(elf, sym_shdr->sh_link, sym[i].st_name);

        // Skip disassembling specific functions
        if (strcmp(function_name, "deregister_tm_clones") == 0 ||
            strcmp(function_name, "register_tm_clones") == 0 ||
            strcmp(function_name, "__do_global_dtors_aux") == 0 ||
            strcmp(function_name, "frame_dummy") == 0 ||
            strcmp(function_name, "_term_proc") == 0 ||
            strcmp(function_name, "_init") == 0 ||
            strcmp(function_name, "_fini") == 0 ) {
            continue;
        }

        printf("Function: %s\n", function_name);
        printf("Offset: %lx\n", address);

        // Get the offset and size for the current function
        Elf64_Addr func_offset = sym[i].st_value - shdr->sh_addr;
        size_t func_size = sym[i].st_size;

        // Allocate a separate buffer for the current function's code
        char *func_code = section_code + func_offset;

        // Create a function struct to store information
        Function *function = &functions[*num_functions];
        function->name = function_name;
        function->instructions = NULL;  // This will be set in disassemble_function

        disassemble_function(func_code, func_size, shdr->sh_addr, func_offset, handle, elf, *sym_shdr, function);

        // Increment the number of functions
        (*num_functions)++;
        
    }
}

void disassemble_section(Elf *elf, Elf_Scn *scn, csh handle, Function *functions, size_t *num_functions) {
    GElf_Ehdr ehdr;
    gelf_getehdr(elf, &ehdr);

    GElf_Shdr shdr;
    gelf_getshdr(scn, &shdr);

    if (shdr.sh_type != SHT_PROGBITS || !(shdr.sh_flags & SHF_EXECINSTR)) return;
    
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
            iterate_symbols(elf, sym_scn, functions, num_functions, &sym_shdr, &shdr, section_code, handle);
        }
    }   
}

void get_global_object_symbols(Elf *elf, Symbol *symbols, size_t *num_symbols) {
    Elf_Scn *symtab_scn = NULL;
    while ((symtab_scn = elf_nextscn(elf, symtab_scn)) != NULL) {
        GElf_Shdr symtab_shdr;
        gelf_getshdr(symtab_scn, &symtab_shdr);

        if (symtab_shdr.sh_type == SHT_SYMTAB) {
            process_symtab_symbols(elf, symbols, num_symbols, &symtab_shdr, symtab_scn);
        }
    }
}

void process_symtab_symbols(Elf *elf, Symbol *symbols, size_t *num_symbols, GElf_Shdr *symtab_shdr, Elf_Scn *symtab_scn) {
    Elf_Data *symdata = elf_getdata(symtab_scn, NULL);
    Elf64_Sym *sym_entries = (Elf64_Sym *)symdata->d_buf;
    size_t num_syms = symdata->d_size / sizeof(Elf64_Sym);

    for (size_t i = 0; i < num_syms; i++) {
        add_symbol_if_global_object(symbols, num_symbols, elf, symtab_shdr, &sym_entries[i]);
    }
}

void add_symbol_if_global_object(Symbol *symbols, size_t *num_symbols, Elf *elf, GElf_Shdr *symtab_shdr, Elf64_Sym *sym_entry) {
    if (ELF64_ST_TYPE(sym_entry->st_info) == STT_OBJECT &&
        ELF64_ST_BIND(sym_entry->st_info) == STB_GLOBAL) {
        if (*num_symbols >= MAX_SYMBOLS) {
            printf("You reached the maximum amount of symbols\n");
            return;
        }

        const char *sym_name = elf_strptr(elf, symtab_shdr->sh_link, sym_entry->st_name);
        if (sym_name == NULL || sym_name[0] == '\0') {
            printf("Skipped symbol with NULL or empty name\n");
            return;
        }

        symbols[*num_symbols] = (Symbol) {
            .name = strdup(sym_name),
            .addr = sym_entry->st_value,
            .end_addr = 0, // Will be updated later
        };

        update_symbol_end_address(&symbols[*num_symbols], sym_entry);
        (*num_symbols)++;
    }
}


void update_symbol_end_address(Symbol *symbol, Elf64_Sym *sym_entry) {
    symbol->end_addr = sym_entry->st_value + sym_entry->st_size;
}

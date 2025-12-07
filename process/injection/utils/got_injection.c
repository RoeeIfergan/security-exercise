#define _GNU_SOURCE

#include "got_injection.h"

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include <sys/mman.h>

#include <dlfcn.h>
#include <link.h>
#include <elf.h>
#include <stdlib.h>

#include "../../utils/helpers.h"

#define MY_JUMP_SLOT R_AARCH64_JUMP_SLOT

struct hook_ctx {
    const char *symbol_name;
    void *new_func;
    void **orig_func;
    int patched_count;
};

static int make_writable(void *addr)
{
    long page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0) return -1;

    uintptr_t p = (uintptr_t)addr;
    uintptr_t page_start = p & ~(page_size - 1);

    if (mprotect((void *)page_start, page_size,
                 PROT_READ | PROT_WRITE) != 0) {
        perror("[libhook] mprotect");

        return -1;
    }
    return 0;
}

static Elf64_Dyn * get_dynamic_section(
    struct dl_phdr_info *info,
    Elf64_Addr base_load_address
) {
    Elf64_Dyn *dynamic_section = NULL;
    // Find the PT_DYNAMIC section in this shared object
    for (int i = 0; i < info->dlpi_phnum; i++) {
        if (info->dlpi_phdr[i].p_type == PT_DYNAMIC) {
            dynamic_section = (Elf64_Dyn *)(base_load_address + info->dlpi_phdr[i].p_vaddr);
            break;
        }
    }

    return dynamic_section;
}

typedef struct
{
    Elf64_Addr start_of_symbol_table;
    Elf64_Addr start_of_string_table;
    Elf64_Addr start_of_plt_relocation_table;
    Elf64_Xword size_of_plt_relocation_table;
    Elf64_Sxword relocation_format;
} elf_section_info;

static int set_elf_section_info(
    elf_section_info * info,
    Elf64_Dyn *dynamic_section)
{
    Elf64_Addr start_of_symbol_table = 0;
    Elf64_Addr start_of_string_table = 0;
    Elf64_Addr start_of_plt_relocation_table = 0;
    Elf64_Xword size_of_plt_relocation_table = 0;
    Elf64_Sxword relocation_format = 0;

    for (Elf64_Dyn *d = dynamic_section; d->d_tag != DT_NULL; d++) {
        switch (d->d_tag) {
        case DT_SYMTAB:
            start_of_symbol_table = d->d_un.d_ptr;
            break;
        case DT_STRTAB:
            start_of_string_table = d->d_un.d_ptr;
            break;
        case DT_JMPREL:
            start_of_plt_relocation_table = d->d_un.d_ptr;
            break;
        case DT_PLTRELSZ:
            size_of_plt_relocation_table = d->d_un.d_val;
            break;
        case DT_PLTREL:
            relocation_format = d->d_un.d_val;
            break;
        default:
            break;
        }
    }

        if (!start_of_symbol_table
            || !start_of_string_table
            || !start_of_plt_relocation_table
            || !size_of_plt_relocation_table)
    {
        return -1;
    }

    info->relocation_format = relocation_format;
    info->start_of_string_table = start_of_string_table;
    info->start_of_plt_relocation_table = start_of_plt_relocation_table;
    info->size_of_plt_relocation_table = size_of_plt_relocation_table;
    info->start_of_symbol_table = start_of_symbol_table;

    return 1;
}

static int phdr_callback(struct dl_phdr_info *info,
                         size_t size, //unused
                         void *data)
{
    (void)size;
    struct hook_ctx *ctx = (struct hook_ctx *)data;
    Elf64_Addr base_load_address = info->dlpi_addr;

    Elf64_Dyn *dynamic_section = get_dynamic_section(info, base_load_address);

    if (!dynamic_section)
        return 0;   // no dynamic section, skip

    elf_section_info * selection_info = (elf_section_info*) calloc(1, sizeof(elf_section_info));

    if (selection_info == NULL)
    {
        fprintf(stderr, "[libhook] failed to allocate selection_info memory\n");
        return 0;
    }

    if (set_elf_section_info(selection_info, dynamic_section) == -1)
    {
        debug_print(stderr, "[libhook] Invalid selection info\n");
        free(selection_info);
        return 0;
    }

    if (selection_info->relocation_format != DT_RELA) {
        debug_print(stderr, "[libhook] Relocation format isn't RELA\n");

        // AArch64 PLT uses RELA; skip other types.
        free(selection_info);
        return 0;
    }

    Elf64_Sym  *symbol_table = (Elf64_Sym *)selection_info->start_of_symbol_table;
    const char *string_table = (const char *)selection_info->start_of_string_table;
    Elf64_Rela *rela   = (Elf64_Rela *)selection_info->start_of_plt_relocation_table;
    size_t rela_count  = selection_info->size_of_plt_relocation_table / sizeof(Elf64_Rela);

    const char *objname = (info->dlpi_name && info->dlpi_name[0])
                              ? info->dlpi_name : "<main>";

    debug_print(stderr, "[libhook] scanning object: %s\n", objname);

    for (size_t i = 0; i < rela_count; i++) {
        Elf64_Rela *r = &rela[i];
        unsigned long symbol_index = ELF64_R_SYM(r->r_info);
        unsigned long relocation_type    = ELF64_R_TYPE(r->r_info);

        if (relocation_type != MY_JUMP_SLOT)
            continue;

        Elf64_Sym *symbol   = &symbol_table[symbol_index];
        const char *name = string_table + symbol->st_name;

        if (strcmp(name, ctx->symbol_name) != 0)
            continue;

        void **got_entry = (void **)(base_load_address + r->r_offset);
        if (!got_entry)
            continue;

        if (ctx->orig_func && *ctx->orig_func == NULL) {
            *ctx->orig_func = *got_entry;   //save original function
        }

        if (make_writable(got_entry) != 0) {
            fprintf(stderr, "[libhook] failed to mprotect GOT for %s in %s\n",
                    ctx->symbol_name, objname);
            continue;
        }

        fprintf(stderr,
                "[libhook] patching %s in %s: %p -> %p\n",
                ctx->symbol_name, objname,
                *got_entry, ctx->new_func);

        *got_entry = ctx->new_func;
        ctx->patched_count++;
    }

    free(selection_info);


    return 0;
}

int hook_plt_symbol(const char *symbol_name,
                           void *new_func,
                           void **orig_func)
{
    struct hook_ctx ctx = {
        .symbol_name   = symbol_name,
        .new_func      = new_func,
        .orig_func     = orig_func,
        .patched_count = 0,
    };

    dl_iterate_phdr(phdr_callback, &ctx);

    return (ctx.patched_count > 0) ? 0 : -1;
}

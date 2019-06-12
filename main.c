#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include "elf.h"
#define OPTPARSE_IMPLEMENTATION
#define OPTPARSE_API static
#include "optparse.h"

struct arg
{
    FILE *input, *output;
    int assembly;
};

enum token_type
{
    TOK_ADD = 0,
    TOK_SUB,
    TOK_NEXT,
    TOK_PREV,
    TOK_BEG,
    TOK_END,
    TOK_OUT,
    TOK_IN,
    TOK_EOF,
};

struct token
{
    int type, count, level, occurence;
};

struct buffer
{
    uint8_t *data;
    size_t used, allocated;
};

struct relocation
{
    size_t offset;
    const struct token *from;
};

#define die(...) do { printf(__VA_ARGS__); puts(""); exit(EXIT_FAILURE); } while (0)
#define error(...) do { \
    printf("error: "); \
    printf(__VA_ARGS__); \
    printf(": %s", strerror(errno)); \
    puts(""); \
    exit(EXIT_FAILURE); \
} while (0)

static void* malloc_check(size_t size)
{
    void *buffer = malloc(size);
    if (buffer == NULL)
        error("failed to alloc %zd bytes", size);

    return buffer;
}

static struct arg parse_arguments(int argc, char **argv)
{
    int option;
    struct optparse options;
    struct optparse_long longopts[] = {
        { "assembly", 'a', OPTPARSE_NONE },
        { "output",   'o', OPTPARSE_REQUIRED },
        { 0 }
    };
    struct arg args = { .assembly = 0, .input = NULL, .output = NULL };
    char *extra;

    optparse_init(&options, argv);

    while ((option = optparse_long(&options, longopts, NULL)) != -1)
        switch (option) {
        case 'a':
            args.assembly = 1;
            break;
        case 'o':
            args.output = fopen(options.optarg, "w");
            if (args.output == NULL)
                error("can't open file '%s' for writing", options.optarg);
            break;
        default:
            die("%s: %s", argv[0], options.errmsg);
        }

    while ((extra = optparse_arg(&options)) != NULL) {
        if (args.input != NULL)
            die("extra argument '%s' specified", extra);

        if (strcmp(extra, "-") == 0) {
            args.input = stdin;
            continue;
        }

        args.input = fopen(extra, "r");
        if (args.input == NULL)
            error("can't open file '%s' for reading", extra);
    }

    if (args.input == NULL)
        args.input = stdin;

    if (args.output == NULL)
        args.output = stdout;

    if (args.assembly == 0 && args.output != stdout)
        if (fchmod(fileno(args.output), 0777 & (~S_IWGRP) & (~S_IWOTH)) == -1)
            error("failed to change permissions for output file");

    return args;
}

static char* read_file(FILE *file)
{
    char *buffer;
    size_t length;

    if (fseek(file, 0, SEEK_END) == -1)
        error("failed to fseek to end");

    if ((length = ftell(file)) == -1)
        error("failed to ftell");

    if (fseek(file, 0, SEEK_SET) == -1)
        error("failed to fseek to start");

    buffer = malloc_check(length + 1);

    if (fread(buffer, 1, length, file) != length || ferror(file))
        error("failed to fread");

    buffer[length++] = '\0';

    fclose(file);

    return buffer;
}

static int is_valid_token(char x)
{
    return x == '+' || x == '-' || x == '>' || x == '<'
        || x == '[' || x == ']' || x == '.' || x == ',';
}

static int is_repeatable(char x)
{
    return x == '+' || x == '-' || x == '>' || x == '<';
}

static enum token_type char_to_token_type(char x)
{
    switch (x) {
    case '+': return TOK_ADD;
    case '-': return TOK_SUB;
    case '>': return TOK_NEXT;
    case '<': return TOK_PREV;
    case '[': return TOK_BEG;
    case ']': return TOK_END;
    case '.': return TOK_OUT;
    case ',': return TOK_IN;
    default: die("char_to_token_type: invalid char '%c'", x);
    }
}

static void advance_until_valid_token(const char **ptr)
{
    do {
        ++(*ptr);
    } while (**ptr != '\0' && !is_valid_token(**ptr));
}

static char next_valid_token(const char *ptr)
{
    const char *next = ptr;

    advance_until_valid_token(&next);

    return *next;
}

static int calculate_num_tokens(const char *buffer)
{
    int num = 0;

    for (const char *ptr = buffer; *ptr != '\0'; advance_until_valid_token(&ptr))
        if (is_valid_token(*ptr)) {
            while (is_repeatable(*ptr) && next_valid_token(ptr) == *ptr)
                advance_until_valid_token(&ptr);

            ++num;
        }

    return num;
}

static struct token* tokenize_source(const char *buffer)
{
    int num_tokens = calculate_num_tokens(buffer), consecutive = 1, token_idx = 0;
    struct token *tokens = malloc_check((num_tokens + 1) * sizeof(struct token));

    for (const char *ptr = buffer; *ptr != '\0'; advance_until_valid_token(&ptr)) {
        if (!is_valid_token(*ptr))
            continue;

        while (is_repeatable(*ptr) && next_valid_token(ptr) == *ptr) {
            ++consecutive;
            advance_until_valid_token(&ptr);
        }

        tokens[token_idx].type = char_to_token_type(*ptr);
        tokens[token_idx].count = consecutive;
        tokens[token_idx].level = 0;
        tokens[token_idx].occurence = 0;
        ++token_idx;

        consecutive = 1;
    }

    tokens[token_idx].type = TOK_EOF;

    return tokens;
}

static void check_brackets(const struct token *tokens)
{
    int balance = 0;
    const char *word;

    for (const struct token *it = tokens; it->type != TOK_EOF; ++it)
        if (it->type == TOK_BEG)
            ++balance;
        else if (it->type == TOK_END)
            --balance;

    if (balance == 0)
        return;

    if (balance < 0) {
        word = "opening";
        balance = -balance;
    } else
        word = "closing";

    die("missing %d %s bracket%s", balance, word, balance == 1 ? "" : "s");
}

static int count_depth(const struct token *tokens)
{
    int depth = 0, max_depth = 0;

    for (int i = 0; tokens[i].type != TOK_EOF; ++i)
        if (tokens[i].type == TOK_BEG) {
            ++depth;
            if (depth > max_depth)
                max_depth = depth;
        } else if (tokens[i].type == TOK_END)
            --depth;

    return max_depth;
}

static void parse_levels(struct token *tokens)
{
    int level = 0, max_depth = count_depth(tokens),
        *occurence = malloc_check(max_depth * sizeof(int));

    memset(occurence, 0, max_depth * sizeof(int));

    for (struct token *it = tokens; it->type != TOK_EOF; ++it)
        if (it->type == TOK_BEG) {
            it->level = level;
            it->occurence = occurence[level];
            ++level;
        } else if (it->type == TOK_END) {
            --level;
            it->level = level;
            it->occurence = occurence[level];
            ++occurence[level];
        }

    free(occurence);
}

static void output_assembly(const struct token *tokens, FILE *output)
{
    const char *prologue =
        "global _start\n"
        "\n"
        "section .bss\n"
        "tape:\n"
        "    resb 30000 * 8\n"
        "\n"
        "section .text\n"
        "_start:\n"
        "    mov rsi, tape\n"
        "    mov rdx, 1\n"
        "\n"
        , *epilogue =
        "\n"
        "    mov rdi, 0\n"
        "    mov rax, 60\n"
        "    syscall\n"
        , *inchar =
        "    mov rdi, 0\n"
        "    mov rax, 0\n"
        , *outchar =
        "    mov rdi, 1\n"
        "    mov rax, 1\n"
        , *syscall =
        "    syscall\n"
        , *test =
        "    mov r11, [rsi]\n"
        "    test r11, r11\n"
        , *jmp_beg =
        "    jz end_%d_%d\n"
        "beg_%d_%d:\n"
        , *jmp_end =
        "    jnz beg_%d_%d\n"
        "end_%d_%d:\n"
        , *add =
        "    add qword [rsi], %d\n"
        , *sub =
        "    sub qword [rsi], %d\n"
        , *next =
        "    lea rsi, [rsi + %d * 8]\n"
        , *prev =
        "    lea rsi, [rsi - %d * 8]\n";
    int last_io = -1, tested = 0;

    if (fputs(prologue, output) == EOF)
        error("failed to write prologue");

    for (const struct token *it = tokens; it->type != TOK_EOF; ++it)
        switch (it->type) {
        case TOK_ADD:
            fprintf(output, add, it->count);
            tested = 1;
            break;
        case TOK_SUB:
            fprintf(output, sub, it->count);
            tested = 1;
            break;
        case TOK_NEXT:
            fprintf(output, next, it->count);
            tested = 0;
            break;
        case TOK_PREV:
            fprintf(output, prev, it->count);
            tested = 0;
            break;
        case TOK_BEG:
            if (!tested)
                fputs(test, output);
            fprintf(output, jmp_beg, it->level, it->occurence, it->level, it->occurence);
            last_io = -1;
            break;
        case TOK_END:
            if (!tested)
                fputs(test, output);
            fprintf(output, jmp_end, it->level, it->occurence, it->level, it->occurence);
            last_io = -1;
            break;
        case TOK_OUT:
            if (last_io != it->type) {
                last_io = it->type;
                fputs(outchar, output);
            }
            fputs(syscall, output);
            break;
        case TOK_IN:
            if (last_io != it->type) {
                last_io = it->type;
                fputs(inchar, output);
            }
            fputs(syscall, output);
            break;
        default:
            die("bad token type %d", it->type);
        }

    fputs(epilogue, output);
}

static void expand_buffer_memory(struct buffer *buffer)
{
    uint8_t *new;

    while (buffer->used >= buffer->allocated)
        buffer->allocated += 4096;

    new = realloc(buffer->data, buffer->allocated);
    if (new == NULL)
        error("failed to expand buffer");

    buffer->data = new;
}

static uint8_t* reserve_buffer_memory(struct buffer *buffer, size_t by)
{
    size_t initial = buffer->used;

    buffer->used += by;

    if (buffer->used >= buffer->allocated)
        expand_buffer_memory(buffer);

    return buffer->data + initial;
}

static struct buffer create_buffer()
{
    struct buffer buffer;

    buffer.allocated = 4096;
    buffer.used = 0;
    buffer.data = malloc_check(buffer.allocated);

    return buffer;
}

static int count_relocations(const struct token *tokens)
{
    int relocations = 0;

    for (const struct token *it = tokens; it->type != TOK_EOF; ++it)
        if (it->type == TOK_BEG || it->type == TOK_END)
            ++relocations;

    return relocations;
}

static void emit_qword(struct buffer *buffer, uint64_t qword)
{
    uint8_t *write = reserve_buffer_memory(buffer, sizeof(uint64_t));

    *(write + 0) = (qword & 0x00000000000000ff) >> (0 * 8);
    *(write + 1) = (qword & 0x000000000000ff00) >> (1 * 8);
    *(write + 2) = (qword & 0x0000000000ff0000) >> (2 * 8);
    *(write + 3) = (qword & 0x00000000ff000000) >> (3 * 8);
    *(write + 4) = (qword & 0x000000ff00000000) >> (4 * 8);
    *(write + 5) = (qword & 0x0000ff0000000000) >> (5 * 8);
    *(write + 6) = (qword & 0x00ff000000000000) >> (6 * 8);
    *(write + 7) = (qword & 0xff00000000000000) >> (7 * 8);
}

static void encode_dword(uint8_t *data, uint32_t dword)
{
    *(data + 0) = (dword & 0x000000ff) >> (0 * 8);
    *(data + 1) = (dword & 0x0000ff00) >> (1 * 8);
    *(data + 2) = (dword & 0x00ff0000) >> (2 * 8);
    *(data + 3) = (dword & 0xff000000) >> (3 * 8);
}

static void emit_dword(struct buffer *buffer, uint32_t dword)
{
    encode_dword(reserve_buffer_memory(buffer, sizeof(uint32_t)), dword);
}

static void emit_byte(struct buffer *buffer, uint8_t byte)
{
    *reserve_buffer_memory(buffer, sizeof(uint8_t)) = byte;
}

static void emit_bytes(struct buffer *buffer, const uint8_t *bytes, size_t length)
{
    memcpy(reserve_buffer_memory(buffer, length), bytes, length);
}

static void emit_rexw(struct buffer *buffer)
{
    emit_byte(buffer, 0x48);
}

static void emit_prologue(struct buffer *buffer, uintptr_t tape)
{
    /* movabs tape, %rsi */
    emit_rexw(buffer);
    emit_byte(buffer, 0xbe);
    emit_qword(buffer, tape);

    /* mov $0x1, %edx */
    emit_byte(buffer, 0xba);
    emit_dword(buffer, 0x1);
}

static void emit_add(struct buffer *buffer, uint8_t count)
{
    /* addq $count, %(rsi) */
    emit_rexw(buffer);
    emit_byte(buffer, 0x83);
    emit_byte(buffer, 0x06);
    emit_byte(buffer, count);
}

static void emit_sub(struct buffer *buffer, uint8_t count)
{
    /* subq $count, %(rsi) */
    emit_rexw(buffer);
    emit_byte(buffer, 0x83);
    emit_byte(buffer, 0x2e);
    emit_byte(buffer, count);
}

static void emit_lea(struct buffer *buffer, int offset)
{
    uint8_t rel8;
    uint32_t rel32;

    /* lea $count(%rsi), %rsi */
    emit_rexw(buffer);
    emit_byte(buffer, 0x8d);

    if (offset >= -128 && offset <= 127) {
        if (offset < 0) {
            rel8 = -offset;
            rel8 = ~rel8 + 1;
        } else
            rel8 = offset;

        emit_byte(buffer, 0x76);
        emit_byte(buffer, rel8);
    } else {
        if (offset < 0) {
            rel32 = -offset;
            rel32 = ~rel32 + 1;
        } else
            rel32 = offset;

        emit_byte(buffer, 0xb6);
        emit_dword(buffer, rel32);
    }
}

static void emit_next(struct buffer *buffer, int count)
{
    emit_lea(buffer, 8 * count);
}

static void emit_prev(struct buffer *buffer, int count)
{
    emit_lea(buffer, -8 * count);
}

static void emit_test_rsi(struct buffer *buffer)
{
    /* mov (%rsi), %r11 */
    emit_byte(buffer, 0x4c);
    emit_byte(buffer, 0x8b);
    emit_byte(buffer, 0x1e);

    /* test %r11, %r11 */
    emit_byte(buffer, 0x4d);
    emit_byte(buffer, 0x85);
    emit_byte(buffer, 0xdb);
}

static void emit_jmp_beg(struct buffer *buffer)
{
    /* jz rel32 */
    emit_byte(buffer, 0x0f);
    emit_byte(buffer, 0x84);
    emit_dword(buffer, 0x00);
}

static void emit_jmp_end(struct buffer *buffer)
{
    /* jnz rel32 */
    emit_byte(buffer, 0x0f);
    emit_byte(buffer, 0x85);
    emit_dword(buffer, 0x00);
}

static void emit_outchar(struct buffer *buffer)
{
    /* mov $0x1, %edi */
    emit_byte(buffer, 0xbf);
    emit_dword(buffer, 0x1);

    /* mov $0x1, %eax */
    emit_byte(buffer, 0xb8);
    emit_dword(buffer, 0x1);
}

static void emit_inchar(struct buffer *buffer)
{
    /* mov $0x0, %edi */
    emit_byte(buffer, 0xbf);
    emit_dword(buffer, 0x0);

    /* mov $0x0, %eax */
    emit_byte(buffer, 0xb8);
    emit_dword(buffer, 0x0);
}

static void emit_syscall(struct buffer *buffer)
{
    /* syscall */
    emit_byte(buffer, 0x0f);
    emit_byte(buffer, 0x05);
}

static void emit_epilogue(struct buffer *buffer)
{
    /* mov $0x0, %edi */
    emit_byte(buffer, 0xbf);
    emit_dword(buffer, 0x0);

    /* mov $0x3c, %eax */
    emit_byte(buffer, 0xb8);
    emit_dword(buffer, 60);

    emit_syscall(buffer);
}

static struct buffer compile_objects(const struct token *tokens, uintptr_t text, uintptr_t bss)
{
    struct buffer buffer = create_buffer();
    int num_relocations = count_relocations(tokens), relocation_idx = 0, last_io = -1, tested = 0;
    struct relocation *relocations = malloc_check(num_relocations * sizeof(struct relocation));

    emit_prologue(&buffer, bss);

    for (const struct token *it = tokens; it->type != TOK_EOF; ++it)
        switch (it->type) {
        case TOK_ADD:
            emit_add(&buffer, it->count);
            tested = 1;
            break;
        case TOK_SUB:
            emit_sub(&buffer, it->count);
            tested = 1;
            break;
        case TOK_NEXT:
            emit_next(&buffer, it->count);
            tested = 0;
            break;
        case TOK_PREV:
            emit_prev(&buffer, it->count);
            tested = 0;
            break;
        case TOK_BEG:
            if (!tested)
                emit_test_rsi(&buffer);
            emit_jmp_beg(&buffer);
            relocations[relocation_idx].offset = buffer.used;
            relocations[relocation_idx].from = it;
            ++relocation_idx;
            last_io = -1;
            break;
        case TOK_END:
            if (!tested)
                emit_test_rsi(&buffer);
            emit_jmp_end(&buffer);
            relocations[relocation_idx].offset = buffer.used;
            relocations[relocation_idx].from = it;
            ++relocation_idx;
            last_io = -1;
            break;
        case TOK_OUT:
            if (last_io != it->type) {
                last_io = it->type;
                emit_outchar(&buffer);
            }
            emit_syscall(&buffer);
            break;
        case TOK_IN:
            if (last_io != it->type) {
                last_io = it->type;
                emit_inchar(&buffer);
            }
            emit_syscall(&buffer);
            break;
        default:
            die("bad token type %d", it->type);
        }

    emit_epilogue(&buffer);

    for (int i = 0; i < num_relocations; ++i) {
        const struct relocation *this = &relocations[i], *target = NULL;
        int target_type = this->from->type == TOK_BEG ? TOK_END : TOK_BEG;
        intptr_t jump;
        uint32_t near_jump;

        for (int j = 0; j < num_relocations; ++j)
            if (relocations[j].from->level == this->from->level
                    && relocations[j].from->occurence == this->from->occurence
                    && relocations[j].from->type == target_type)
                target = &relocations[j];

        if (target == NULL)
            die("no target relocation found");

        jump = target->offset - this->offset;

        if (jump < 0) {
            near_jump = -jump;
            near_jump = ~near_jump + 1;
        } else
            near_jump = jump;

        encode_dword(buffer.data + this->offset - 4, near_jump);
    }

    free(relocations);

    return buffer;
}

static struct buffer link_elf(struct buffer *objects, uintptr_t text_vaddr, uintptr_t bss_vaddr)
{
    struct buffer elf = create_buffer();
    struct elf64_ehdr header = {
        .e_ident = {
            [ei_mag0] = '\x7f',
            [ei_mag1] = 'E',
            [ei_mag2] = 'L',
            [ei_mag3] = 'F',
            [ei_class] = ELFCLASS64,
            [ei_data] = ELFDATA2LSB,
            [ei_version] = EV_CURRENT,
            [ei_osabi] = ELFOSABI_SYSV,
            [ei_abiversion] = 0,
            [ei_pad ... ei_nident - 1] = 0,
        },
        .e_type = ET_EXEC,
        .e_machine = EM_X86_64,
        .e_version = EV_CURRENT,
        .e_entry = text_vaddr,
        .e_phoff = sizeof(struct elf64_ehdr),
        .e_shoff = 0,
        .e_flags = 0,
        .e_ehsize = sizeof(struct elf64_ehdr),
        .e_phentsize = sizeof(struct elf64_phdr),
        .e_phnum = 2,
        .e_shentsize = 0,
        .e_shnum = 0,
        .e_shstrndx = SHN_UNDEF,
    };
    struct elf64_phdr text = {
        .p_type = PT_LOAD,
        .p_flags = PF_X | PF_R,
        .p_offset = 0,
        .p_vaddr = 0x400000,
        .p_paddr = 0,
        .p_filesz = objects->used,
        .p_memsz = objects->used,
        .p_align = 0x1000,
    }, bss = {
        .p_type = PT_LOAD,
        .p_flags = PF_W | PF_R,
        .p_offset = 0,
        .p_vaddr = bss_vaddr,
        .p_paddr = 0,
        .p_filesz = 0,
        .p_memsz = 30000 * 8,
        .p_align = 0x1000,
    };

    emit_bytes(&elf, (uint8_t*)&header, sizeof(header));
    emit_bytes(&elf, (uint8_t*)&text, sizeof(text));
    emit_bytes(&elf, (uint8_t*)&bss, sizeof(bss));
    emit_bytes(&elf, objects->data, objects->used);

    return elf;
}

static void write_buffer_to_file(const struct buffer *buffer, FILE *output)
{
    if (fwrite(buffer->data, 1, buffer->used, output) != buffer->used)
        error("failed to write");
}

int main(int argc, char **argv)
{
    struct arg args = parse_arguments(argc, argv);
    char *source = read_file(args.input);
    struct token *tokens = tokenize_source(source);
    /* uintptr_t bss = 0x1000, text = bss + 30000 * 8; */
    uintptr_t bss = 0x600000, text = 0x4000b0;
    struct buffer objects, elf;

    check_brackets(tokens);

    parse_levels(tokens);

    if (args.assembly) {
        output_assembly(tokens, args.output);
        goto cleanup;
    }

    if (isatty(fileno(args.output)))
        die("won't dump binary into terminal. pipe output or specify file with -o flag.");

    objects = compile_objects(tokens, text, bss);

    elf = link_elf(&objects, text, bss);

    write_buffer_to_file(&elf, args.output);

    free(objects.data);
    free(elf.data);

cleanup:
    free(tokens);
    free(source);

    if (args.output != stdout)
        fclose(args.output);
}


#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
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

#define print(...) do { printf(__VA_ARGS__); puts(""); } while (0)
#define die(...) do { print(__VA_ARGS__); exit(EXIT_FAILURE); } while (0)
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
    int num_tokens = calculate_num_tokens(buffer);
    struct token *tokens = malloc_check((num_tokens + 1) * sizeof(struct token));
    int consecutive = 1, token_idx = 0;

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
        , *jmp_beg =
        "    mov r11, [rsi]\n"
        "    test r11, r11\n"
        "    jz end_%d_%d\n"
        "beg_%d_%d:\n"
        , *jmp_end =
        "    mov r11, [rsi]\n"
        "    test r11, r11\n"
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
    int last_io = -1;

    if (fputs(prologue, output) == EOF)
        error("failed to write prologue");

    for (const struct token *it = tokens; it->type != TOK_EOF; ++it)
        switch (it->type) {
        case TOK_ADD:
            fprintf(output, add, it->count);
            break;
        case TOK_SUB:
            fprintf(output, sub, it->count);
            break;
        case TOK_NEXT:
            fprintf(output, next, it->count);
            break;
        case TOK_PREV:
            fprintf(output, prev, it->count);
            break;
        case TOK_BEG:
            fprintf(output, jmp_beg, it->level, it->occurence, it->level, it->occurence);
            last_io = -1;
            break;
        case TOK_END:
            fprintf(output, jmp_end, it->level, it->occurence, it->level, it->occurence);
            last_io = -1;
            break;
        case TOK_IN:
            if (last_io != it->type) {
                last_io = it->type;
                fputs(inchar, output);
            }
            fputs(syscall, output);
            break;
        case TOK_OUT:
            if (last_io != it->type) {
                last_io = it->type;
                fputs(outchar, output);
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

    buffer->allocated += 4096;

    new = realloc(buffer->data, buffer->allocated);
    if (new == NULL)
        error("failed to expand buffer");

    buffer->data = new;
}

static void reserve_buffer_memory(struct buffer *buffer, size_t by)
{
    buffer->used += by;

    if (buffer->used >= buffer->allocated)
        expand_buffer_memory(buffer);
}

static struct buffer create_buffer()
{
    struct buffer buffer;

    buffer.allocated = 4096;
    buffer.used = 0;
    buffer.data = malloc_check(buffer.allocated);

    return buffer;
}

static void emit_qwrd(struct buffer *buffer, uint64_t qword)
{
    uint8_t *write = buffer->data + buffer->used;

    reserve_buffer_memory(buffer, sizeof(uint64_t));

    *(write + 0) = (qword & 0xff00000000000000) >> (7 * 8);
    *(write + 1) = (qword & 0x00ff000000000000) >> (6 * 8);
    *(write + 2) = (qword & 0x0000ff0000000000) >> (5 * 8);
    *(write + 3) = (qword & 0x000000ff00000000) >> (4 * 8);
    *(write + 4) = (qword & 0x00000000ff000000) >> (3 * 8);
    *(write + 5) = (qword & 0x0000000000ff0000) >> (2 * 8);
    *(write + 6) = (qword & 0x000000000000ff00) >> (1 * 8);
    *(write + 7) = (qword & 0x00000000000000ff) >> (0 * 8);

    buffer->used += sizeof(uint64_t);
}

static void emit_word(struct buffer *buffer, uint16_t word)
{
    uint8_t *write = buffer->data + buffer->used;

    reserve_buffer_memory(buffer, sizeof(uint16_t));

    *(write + 0) = (word & 0xff00) >> (1 * 8);
    *(write + 1) = (word & 0x00ff) >> (0 * 8);

    buffer->used += sizeof(uint16_t);
}

static void emit_byte(struct buffer *buffer, uint8_t byte)
{
    reserve_buffer_memory(buffer, sizeof(uint8_t));

    *(buffer->data + buffer->used) = byte;

    ++buffer->used;
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
    emit_qwrd(buffer, tape);

    /* mov $0x1, %edx */
    emit_byte(buffer, 0xba);
    emit_word(buffer, 0x1);
}

static void emit_add(struct buffer *buffer, uint8_t count)
{
    emit_rexw(buffer);
    emit_byte(buffer, 0x83);
    emit_byte(buffer, count);
}

static struct buffer compile_objects(const struct token *tokens, uintptr_t bss, uintptr_t text)
{
    struct buffer buffer = create_buffer();

    emit_prologue(&buffer, bss);

    for (const struct token *it = tokens; it->type != TOK_EOF; ++it)
        switch (it->type) {
        case TOK_ADD:
            emit_add(&buffer, it->count);
            break;
        default:
            die("bad token type %d", it->type);
        }

    return buffer;
}

int main(int argc, char **argv)
{
    struct arg args = parse_arguments(argc, argv);
    char *source = read_file(args.input);
    struct token *tokens = tokenize_source(source);
    struct buffer objects;

    parse_levels(tokens);

    if (args.assembly) {
        output_assembly(tokens, args.output);
        goto cleanup;
    }

    objects = compile_objects(tokens, 0, 0);

cleanup:
    free(tokens);
    free(source);
}


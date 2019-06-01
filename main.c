#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
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
    int type;
    int count;
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
        ++token_idx;

        consecutive = 1;
    }

    tokens[token_idx].type = TOK_EOF;

    return tokens;
}

static void indent(FILE *output)
{
    fprintf(output, "    ");
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

static void output_assembly(const struct token *tokens, FILE *output)
{
    const char *prologue =
        "global _start\n"
        "\n"
        "section .data\n"
        "tape:\n"
        "    times 30000 db 0\n"
        "\n"
        "section .text\n"
        "_start:\n"
        "    xor rbx, rbx\n"
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
        "    lea rsi, [tape + rbx]\n"
        "    syscall\n"
        , *jmp_beg =
        "    movzx r11, byte [tape + rbx]\n"
        "    test r11, r11\n"
        "    jz end_%d_%d\n"
        "beg_%d_%d:\n"
        , *jmp_end =
        "    movzx r11, byte [tape + rbx]\n"
        "    test r11, r11\n"
        "    jnz beg_%d_%d\n"
        "end_%d_%d:\n";
    int level = 0, max_depth = count_depth(tokens),
        *occurence = malloc_check(max_depth * sizeof(int)), last_io = -1;

    memset(occurence, 0, max_depth * sizeof(int));

    if (fputs(prologue, output) == EOF)
        error("failed to write prologue");

    for (int i = 0; tokens[i].type != TOK_EOF; ++i)
        switch (tokens[i].type) {
        case TOK_ADD:
            indent(output);
            fprintf(output, "add byte [tape + rbx], %d\n", tokens[i].count);
            break;
        case TOK_SUB:
            indent(output);
            fprintf(output, "sub byte [tape + rbx], %d\n", tokens[i].count);
            break;
        case TOK_NEXT:
            indent(output);
            fprintf(output, "add rbx, %d\n", tokens[i].count);
            break;
        case TOK_PREV:
            indent(output);
            fprintf(output, "sub rbx, %d\n", tokens[i].count);
            break;
        case TOK_BEG:
            fprintf(output, jmp_beg, level, occurence[level], level, occurence[level]);
            ++level;
            last_io = -1;
            break;
        case TOK_END:
            --level;
            fprintf(output, jmp_end, level, occurence[level], level, occurence[level]);
            ++occurence[level];
            last_io = -1;
            break;
        case TOK_IN:
            if (last_io != TOK_IN) {
                last_io = TOK_IN;
                fputs(inchar, output);
            }
            fputs(syscall, output);
            break;
        case TOK_OUT:
            if (last_io != TOK_OUT) {
                last_io = TOK_OUT;
                fputs(outchar, output);
            }
            fputs(syscall, output);
            break;
        default:
            die("bad token type %d", tokens[i].type);
        }

    fputs(epilogue, output);

    free(occurence);
}

int main(int argc, char **argv)
{
    struct arg args = parse_arguments(argc, argv);
    char *source = read_file(args.input);
    struct token *tokens = tokenize_source(source);

    if (args.assembly) {
        output_assembly(tokens, args.output);
        goto cleanup;
    }

cleanup:
    free(tokens);
    free(source);
}


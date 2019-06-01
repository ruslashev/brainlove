#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

static FILE* parse_arguments(int argc, char **argv)
{
    FILE *input;

    if (argc == 1)
        return stdin;

    input = fopen(argv[1], "r");
    if (input == NULL)
        error("can't open file '%s'", argv[1]);

    return input;
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
    case '.': return TOK_IN;
    case ',': return TOK_OUT;
    default: print("char_to_token_type: invalid char '%c'", x); exit(1);
    }
}

static int calculate_num_tokens(const char *buffer)
{
    int num = 0;

    for (const char *ptr = buffer; *ptr != '\0'; ++ptr)
        if (is_valid_token(*ptr)) {
            while (is_repeatable(*ptr) && *(ptr + 1) == *ptr)
                ++ptr;

            ++num;
        }

    return num;
}

static struct token* tokenize_source(const char *buffer)
{
    int num_tokens = calculate_num_tokens(buffer);
    struct token *tokens = malloc_check((num_tokens + 1) * sizeof(struct token));
    int consecutive = 1, token_idx = 0;

    for (const char *ptr = buffer; *ptr != '\0'; ++ptr) {
        if (!is_valid_token(*ptr))
            continue;

        while (is_repeatable(*ptr) && *(ptr + 1) == *ptr) {
            ++consecutive;
            ++ptr;
        }

        tokens[token_idx].type = char_to_token_type(*ptr);
        tokens[token_idx].count = consecutive;
        ++token_idx;

        consecutive = 1;
    }

    tokens[token_idx].type = TOK_EOF;

    return tokens;
}

int main(int argc, char **argv)
{
    FILE *input = parse_arguments(argc, argv);
    char *source = read_file(input);
    struct token *tokens = tokenize_source(source);

    free(tokens);
    free(source);
}


#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define print(...) do { printf(__VA_ARGS__); puts(""); } while (0)
#define error(...) do { \
    printf("error: "); \
    print(__VA_ARGS__); \
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

static void read_file(FILE *file, char **buffer, size_t *length)
{
    if (fseek(file, 0, SEEK_END) == -1)
        error("failed to fseek to end");

    if ((*length = ftell(file)) == -1)
        error("failed to ftell");

    if (fseek(file, 0, SEEK_SET) == -1)
        error("failed to fseek to start");

    *buffer = malloc_check((*length) + 1);

    if (fread(*buffer, 1, *length, file) != *length || ferror(file))
        error("failed to fread");

    (*buffer)[*length++] = '\0';
}

int main(int argc, char **argv)
{
    FILE *input = parse_arguments(argc, argv);
    char *buffer;
    size_t buf_len;

    read_file(input, &buffer, &buf_len);
    fclose(input);

    printf("read: '%s'\n", buffer);

    free(buffer);
}


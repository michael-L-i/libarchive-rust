/* Public-API driver for scripts/test-iso-zisofs. Test code only. */
#include <archive.h>
#include <archive_entry.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv)
{
    if (argc != 6) return 2;
    FILE *input = fopen(argv[3], "rb");
    if (input == NULL || fseek(input, 0, SEEK_END) != 0) return 2;
    long size = ftell(input);
    if (size < 0 || fseek(input, 0, SEEK_SET) != 0) return 2;
    size_t chunk = (size_t)strtoul(argv[4], NULL, 10);
    const char *tail = strchr(argv[4], '+');
    size_t later = tail == NULL ? chunk : (size_t)strtoul(tail + 1, NULL, 10);
    if (chunk == 0 || chunk > 65536 || later == 0 || later > 65536) return 2;
    unsigned char buffer[65536];
    struct archive *a = archive_write_new();
    struct archive_entry *e = archive_entry_new();
    int r = archive_write_set_format_iso9660(a);
    if (r == ARCHIVE_OK) r = archive_write_set_options(a, argv[2]);
    if (r == ARCHIVE_OK) r = archive_write_open_filename(a, argv[1]);
    archive_entry_set_pathname(e, argv[5]);
    archive_entry_set_filetype(e, AE_IFREG);
    archive_entry_set_perm(e, 0644);
    archive_entry_set_size(e, size);
    archive_entry_set_mtime(e, 1700000000, 0);
    if (r == ARCHIVE_OK) r = archive_write_header(a, e);
    while (r == ARCHIVE_OK) {
        size_t n = fread(buffer, 1, chunk, input);
        if (n == 0) break;
        if (archive_write_data(a, buffer, n) != (la_ssize_t)n) r = ARCHIVE_FATAL;
        chunk = later;
    }
    if (r == ARCHIVE_OK && ferror(input)) r = ARCHIVE_FATAL;
    if (r == ARCHIVE_OK) r = archive_write_close(a);
    if (r != ARCHIVE_OK) fprintf(stderr, "%s\n", archive_error_string(a));
    archive_entry_free(e);
    archive_write_free(a);
    fclose(input);
    return r == ARCHIVE_OK ? 0 : 1;
}

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <archive.h>
#include <archive_entry.h>
#include <dlfcn.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, #condition); \
        exit(1); \
    } \
} while (0)

struct stream {
    unsigned char bytes[32768];
    size_t size;
    size_t offset;
    int opened;
    int closed;
    int freed;
};

static int open_stream(struct archive *a, void *opaque)
{
    struct stream *s = (struct stream *)opaque;
    ++s->opened;
    /* Error callbacks may re-enter the archive's shared error state. */
    archive_set_error(a, EIO, "callback %zu", s->size);
    CHECK(archive_errno(a) == EIO);
    CHECK(archive_error_string(a) != NULL);
    archive_clear_error(a);
    return ARCHIVE_OK;
}

static int close_stream(struct archive *a, void *opaque)
{
    (void)a;
    ++((struct stream *)opaque)->closed;
    return ARCHIVE_OK;
}

static int free_stream(struct archive *a, void *opaque)
{
    (void)a;
    ++((struct stream *)opaque)->freed;
    return ARCHIVE_OK;
}

static la_ssize_t write_stream(struct archive *a, void *opaque,
    const void *data, size_t size)
{
    struct stream *s = (struct stream *)opaque;
    if (size > sizeof(s->bytes) - s->size) {
        archive_set_error(a, ENOSPC, "output exceeds %zu bytes", sizeof(s->bytes));
        return -1;
    }
    memcpy(s->bytes + s->size, data, size);
    s->size += size;
    return (la_ssize_t)size;
}

static la_ssize_t read_stream(struct archive *a, void *opaque,
    const void **data)
{
    struct stream *s = (struct stream *)opaque;
    size_t size = s->size - s->offset;
    (void)a;
    if (size > 17)
        size = 17;
    *data = s->bytes + s->offset;
    s->offset += size;
    return (la_ssize_t)size;
}

static la_int64_t skip_stream(struct archive *a, void *opaque, la_int64_t size)
{
    struct stream *s = (struct stream *)opaque;
    size_t remaining = s->size - s->offset;
    (void)a;
    CHECK(size >= 0);
    if ((uint64_t)size > remaining)
        size = (la_int64_t)remaining;
    s->offset += (size_t)size;
    return size;
}

static void check_errors(struct archive *a)
{
    archive_set_error(a, EINVAL, "%s %d %lld %.2f %*.*s %%", "entry", -7,
        (long long)4294967297LL, 1.25, 5, 3, "abcdef");
    CHECK(archive_errno(a) == EINVAL);
    CHECK(strcmp(archive_error_string(a), "entry -7 4294967297 1.25   abc %") == 0);
    archive_set_error(a, EIO, NULL);
    CHECK(archive_errno(a) == EIO);
    CHECK(archive_error_string(a) == NULL);
    archive_clear_error(a);
    CHECK(archive_errno(a) == 0);
}

int main(int argc, char **argv)
{
    struct stream stream;
    struct archive *writer;
    struct archive *reader;
    struct archive_entry *entry;
    struct archive_entry *copy;
    struct archive_entry *detached;
    const char payload[] = "installed library callback roundtrip\n";
    char recovered[sizeof(payload)];
    size_t recovered_size = 0;
    int index;
    memset(&stream, 0, sizeof(stream));
    CHECK(argc == 2);
    CHECK(archive_version_number() == ARCHIVE_VERSION_NUMBER);
    CHECK(strstr(archive_version_string(), "libarchive") != NULL);
    if (strcmp(argv[1], "static") != 0) {
        Dl_info info;
        char actual[4096];
        char expected[4096];
        CHECK(dladdr((void *)(uintptr_t)&archive_version_number, &info) != 0);
        CHECK(realpath(info.dli_fname, actual) != NULL);
        CHECK(realpath(argv[1], expected) != NULL);
        CHECK(strcmp(actual, expected) == 0);
    }

    writer = archive_write_new();
    CHECK(writer != NULL);
    check_errors(writer);
    CHECK(archive_write_set_format_pax_restricted(writer) == ARCHIVE_OK);
    CHECK(archive_write_add_filter_gzip(writer) == ARCHIVE_OK);
    CHECK(archive_write_set_bytes_per_block(writer, 512) == ARCHIVE_OK);
    CHECK(archive_write_open2(writer, &stream, open_stream, write_stream,
        close_stream, free_stream) == ARCHIVE_OK);
    entry = archive_entry_new();
    CHECK(entry != NULL);
    for (index = 0; index != 2; ++index) {
        char name[] = "first.txt";
        archive_entry_copy_pathname(entry, index == 0 ? name : "second.txt");
        name[0] = 'X';
        CHECK(strcmp(archive_entry_pathname(entry), index == 0 ? "first.txt" : "second.txt") == 0);
        archive_entry_set_filetype(entry, AE_IFREG);
        archive_entry_set_perm(entry, 0640);
        archive_entry_set_uid(entry, 123);
        archive_entry_set_gid(entry, 456);
        archive_entry_set_mtime(entry, 1700000000, 0);
        archive_entry_set_size(entry, sizeof(payload) - 1);
        CHECK(archive_write_header(writer, entry) == ARCHIVE_OK);
        CHECK(archive_write_data(writer, payload, sizeof(payload) - 1) == (la_ssize_t)(sizeof(payload) - 1));
        CHECK(archive_write_finish_entry(writer) == ARCHIVE_OK);
    }
    archive_entry_free(entry);
    CHECK(archive_write_close(writer) == ARCHIVE_OK);
    CHECK(archive_write_free(writer) == ARCHIVE_OK);
    CHECK(stream.opened == 1 && stream.closed == 1 && stream.freed == 1);

    reader = archive_read_new();
    CHECK(reader != NULL);
    CHECK(archive_read_support_filter_all(reader) == ARCHIVE_OK);
    CHECK(archive_read_support_format_all(reader) == ARCHIVE_OK);
    CHECK(archive_read_open2(reader, &stream, open_stream, read_stream,
        skip_stream, close_stream) == ARCHIVE_OK);
    CHECK(archive_read_next_header(reader, &entry) == ARCHIVE_OK);
    CHECK(strcmp(archive_entry_pathname(entry), "first.txt") == 0);
    CHECK(archive_read_data_skip(reader) == ARCHIVE_OK);
    CHECK(archive_read_next_header(reader, &entry) == ARCHIVE_OK);
    CHECK(strcmp(archive_entry_pathname(entry), "second.txt") == 0);
    CHECK(archive_entry_perm(entry) == 0640);
    CHECK(archive_entry_uid(entry) == 123 && archive_entry_gid(entry) == 456);
    CHECK(archive_entry_mtime(entry) == 1700000000);
    CHECK(archive_entry_size(entry) == (la_int64_t)(sizeof(payload) - 1));
    while (recovered_size != sizeof(payload) - 1) {
        la_ssize_t size = archive_read_data(reader, recovered + recovered_size, 3);
        CHECK(size > 0 && size <= 3);
        recovered_size += (size_t)size;
        CHECK(recovered_size < sizeof(recovered));
    }
    CHECK(memcmp(recovered, payload, sizeof(payload) - 1) == 0);
    CHECK(archive_read_data(reader, recovered, 1) == 0);
    copy = archive_entry_clone(entry);
    detached = archive_entry_new2(reader);
    CHECK(copy != NULL && detached != NULL);
    CHECK(archive_read_next_header(reader, &entry) == ARCHIVE_EOF);
    CHECK(archive_read_free(reader) == ARCHIVE_OK);
    CHECK(stream.opened == 2 && stream.closed == 2);
    CHECK(strcmp(archive_entry_pathname(copy), "second.txt") == 0);
    archive_entry_copy_pathname(detached, "after-free.txt");
    CHECK(strcmp(archive_entry_pathname(detached), "after-free.txt") == 0);
    archive_entry_free(copy);
    archive_entry_free(detached);
    puts("installed consumer passed");
    return 0;
}

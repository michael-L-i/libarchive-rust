/* Resolve actual public function providers, independently of loader tracing. */
#define _GNU_SOURCE
#include <archive.h>
#include <dlfcn.h>
#include <stdio.h>

int main(void)
{
    const char *symbols[] = {
        "archive_read_new", "archive_write_new", "archive_read_disk_new",
        "archive_set_error"
    };
    puts(archive_version_string());
    for (unsigned i = 0; i < sizeof(symbols) / sizeof(symbols[0]); ++i) {
        Dl_info provider;
        void *function = dlsym(RTLD_DEFAULT, symbols[i]);
        if (function == NULL || dladdr(function, &provider) == 0 ||
            provider.dli_fname == NULL) {
            fprintf(stderr, "cannot resolve %s\n", symbols[i]);
            return 1;
        }
        printf("%s\t%s\n", symbols[i], provider.dli_fname);
    }
    return 0;
}

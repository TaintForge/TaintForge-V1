/*
 * Deterministic oracle for TaintForge task b3fb4b4a70fd8938 (owner H).
 *
 * Replicates VERBATIM the stock .NET 10.0.12 logic from
 *   targets/dotnet-runtime-10.0.12/src/coreclr/gc/unix/cgroup.cpp
 *     - FindCGroupPath        (lines 149-207)  : builds s_memory_cgroup_path
 *     - GetCGroupMemoryLimitV2(lines 456-512)  : walks the cgroup hierarchy upward
 *
 * Only the file I/O is stubbed out (ReadMemoryValueFromFile always fails, which is
 * the real behaviour for cgroup v2 "memory.max" containing the literal "max").
 * The pointer arithmetic under test is byte-for-byte the shipped code.
 *
 * Build:  clang -fsanitize=address,undefined -g -O1 oracle.c -o oracle
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#define CGROUP2_MEMORY_LIMIT_FILENAME "/memory.max"

/* stock cgroup.cpp:822 ReadMemoryValueFromFile - stubbed: cgroup v2 root memory.max
 * holds the literal string "max", so strtoull finds no digits and it returns false. */
static bool ReadMemoryValueFromFile(const char *filename, uint64_t *val)
{
    (void)filename; (void)val;
    return false;
}

/* ---- stock FindCGroupPath (cgroup.cpp:149-207), path-building part only ---- */
static char *BuildCGroupPath(const char *hierarchy_mount,
                             const char *hierarchy_root,
                             const char *cgroup_path_relative_to_mount)
{
    size_t common_path_prefix_len;
    char *cgroup_path = (char *)malloc(strlen(hierarchy_mount) +
                                       strlen(cgroup_path_relative_to_mount) + 1);
    if (cgroup_path == NULL)
        return NULL;

    strcpy(cgroup_path, hierarchy_mount);

    common_path_prefix_len = strlen(hierarchy_root);                       /* :184 */
    if ((common_path_prefix_len == 1) ||
        strncmp(hierarchy_root, cgroup_path_relative_to_mount, common_path_prefix_len) != 0)
    {
        common_path_prefix_len = 0;                                        /* :187 */
    }

    /* cgroup.cpp:191 - the ONLY statement of the invariant, and NDEBUG removes it
     * from RELEASE and RELWITHDEBINFO builds (eng/native/configurecompiler.cmake:62). */
    if (!((cgroup_path_relative_to_mount[common_path_prefix_len] == '/') ||
          (cgroup_path_relative_to_mount[common_path_prefix_len] == '\0')))
    {
        printf("    [assert at cgroup.cpp:191 WOULD FIRE - compiled out under NDEBUG]\n");
    }

    strcat(cgroup_path, cgroup_path_relative_to_mount + common_path_prefix_len); /* :193 */
    return cgroup_path;
}

/* ---- stock GetCGroupMemoryLimitV2 (cgroup.cpp:456-512) ---- */
static bool GetCGroupMemoryLimitV2(uint64_t *val,
                                   const char *s_memory_cgroup_path,
                                   const char *s_memory_cgroup_hierarchy_mount)
{
    if (s_memory_cgroup_path == NULL)
        return false;

    size_t memory_cgroup_hierarchy_mount_length = strlen(s_memory_cgroup_hierarchy_mount);
    uint64_t min_limit = UINT64_MAX;
    uint64_t limit;
    bool found_any_limit = false;

    char *mem_limit_filename = NULL;
    if (asprintf(&mem_limit_filename, "%s%s", s_memory_cgroup_path,
                 CGROUP2_MEMORY_LIMIT_FILENAME) < 0)
        return false;

    size_t cgroupPathLength = strlen(s_memory_cgroup_path);

    int guard = 0;
    do
    {
        if (ReadMemoryValueFromFile(mem_limit_filename, &limit))           /* :478 */
        {
            found_any_limit = true;
            if (limit < min_limit)
                min_limit = limit;
        }

        if (cgroupPathLength == memory_cgroup_hierarchy_mount_length)      /* :487 */
            break;

        /* :493 - start one byte left of the current path end */
        char *parent_directory_end = mem_limit_filename + cgroupPathLength - 1;

        if (++guard > 64) { printf("    [harness guard: runaway loop]\n"); break; }

        /* :494-497 - UNBOUNDED backward scan: no lower bound against the buffer start */
        while (*parent_directory_end != '/')
            parent_directory_end--;

        if (parent_directory_end < mem_limit_filename)
            printf("    [OOB] scan walked %td bytes BEFORE the allocation\n",
                   mem_limit_filename - parent_directory_end);

        cgroupPathLength = (size_t)(parent_directory_end - mem_limit_filename); /* :499 */

        /* :501 - 12-byte write ("/memory.max" + NUL) at the scanned address */
        strcpy(parent_directory_end, CGROUP2_MEMORY_LIMIT_FILENAME);
    }
    while (true);

    free(mem_limit_filename);

    if (found_any_limit)
        *val = min_limit;
    return found_any_limit;
}

static void run(const char *label, const char *mount, const char *root, const char *rel)
{
    printf("[%s]\n  mount=%s\n  root=%s\n  rel=%s\n", label, mount, root, rel);
    char *path = BuildCGroupPath(mount, root, rel);
    printf("    cgroup_path = %s\n", path);
    uint64_t v = 0;
    GetCGroupMemoryLimitV2(&v, path, mount);
    printf("    -> returned normally\n\n");
    free(path);
}

int main(int argc, char **argv)
{
    int which = (argc > 1) ? atoi(argv[1]) : 0;

    if (which == 0 || which == 1)
        /* NEGATIVE CONTROL 1: ordinary non-container cgroup v2 host */
        run("NEG-1 host root cgroup v2", "/sys/fs/cgroup", "/", "/");

    if (which == 0 || which == 2)
        /* NEGATIVE CONTROL 2: docker, root is a clean path-boundary prefix */
        run("NEG-2 docker nested", "/sys/fs/cgroup",
            "/docker/87ee2de57e51bc75175a4d2e81b71d162811b179d549d6601ed70b58cad83578",
            "/docker/87ee2de57e51bc75175a4d2e81b71d162811b179d549d6601ed70b58cad83578/my_named_cgroup");

    if (which == 0 || which == 3)
        /* NEGATIVE CONTROL 3: relative path equals the root exactly */
        run("NEG-3 rel == root", "/sys/fs/cgroup", "/docker/abc", "/docker/abc");

    if (which == 4)
        /* POSITIVE: hierarchy_root is a prefix of the relative path but NOT at a
         * path boundary, so the concatenation yields a cgroup_path whose byte at
         * offset strlen(mount) is not '/'. The walker can then never satisfy the
         * equality test at :487 and runs off the front of the buffer. */
        run("POS   non-boundary prefix", "/sys/fs/cgroup", "/docker/abc", "/docker/abcdef/x");

    printf("done\n");
    return 0;
}

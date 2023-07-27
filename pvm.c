#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>

// Global Definitions
#define FLAGS_SIZE 64
#define PAGE_SIZE 4096
#define ENTRIES_PER_TABLE 512
#define BITS_PER_ENTRY 64
#define PAGE_FLAGS_SIZE 64
#define MAX_LINE_LENGTH 256
#define BUFFER_SIZE 256
#define KB_TO_BYTES 1024
#define PFN_MASK ((1ULL << 55) - 1)
#define SWAP_MASK ((1ULL << 55) | ((1ULL << 63) - 1))

// Structs
// Structure to store virtual memory area information
typedef struct {
    unsigned long start;
    unsigned long end;
    char permissions[5];
    unsigned long offset;
    int dev_major;
    int dev_minor;
    int inode;
    char pathname[MAX_LINE_LENGTH];
} VmaInfo;

// Function Descriptions
int parse_proc_maps(const char *pid, VmaInfo **vma_info_list, size_t *vma_count);
unsigned long calculate_virtual_memory_usage(VmaInfo *vma_info_list, size_t vma_count);
void calculate_physical_memory_usage(unsigned long *exclusive_memory, unsigned long *total_memory);
unsigned long long get_physical_address(const char*, unsigned long long);
unsigned long long parse_va(const char*);
void print_mapping(uintptr_t, uint64_t);
void print_mapping_mapall(uint64_t);
void print_mapping_allin(uint64_t);
void print_memory_size(uint64_t);
void print_flags(uint64_t);
void print_frame_info(uint64_t, uint64_t, uint64_t);

// Main Function
int main(int argc, char *argv[]) {
    // Frame info option
    if (strcmp(argv[1], "-frameinfo") == 0) {
        uint64_t pfn;
        if (strncmp(argv[2], "0x", 2) == 0) {
            pfn = strtoull(argv[2], NULL, 16);
        } else {
            pfn = strtoull(argv[2], NULL, 0);
        }

        // Open /proc/kpageflags file
        int kpageflags_fd = open("/proc/kpageflags", O_RDONLY);
        if (kpageflags_fd == -1) {
            perror("Failed to open /proc/kpageflags");
            return 1;
        }

        // Calculate the offset for the specified PFN
        off_t offset = pfn * sizeof(uint64_t);

        // Read the kpageflags entry for the specified PFN
        uint64_t flags;
        if (lseek(kpageflags_fd, offset, SEEK_SET) == -1 ||
            read(kpageflags_fd, &flags, sizeof(uint64_t)) == -1) {
            perror("Failed to read kpageflags file");
            return 1;
        }

        // Close the kpageflags file
        close(kpageflags_fd);

        // Open /proc/kpagecount file
        int kpagecount_fd = open("/proc/kpagecount", O_RDONLY);
        if (kpagecount_fd == -1) {
            perror("Failed to open /proc/kpagecount");
            return 1;
        }

        // Read the kpagecount entry for the specified PFN
        uint64_t mapping_count;
        if (lseek(kpagecount_fd, offset, SEEK_SET) == -1 ||
            read(kpagecount_fd, &mapping_count, sizeof(uint64_t)) == -1) {
            perror("Failed to read kpagecount file");
            return 1;
        }

        // Close the kpagecount file
        close(kpagecount_fd);

        // Print the frame information
        print_frame_info(pfn, flags, mapping_count);
    }

    // Memory usage option
    else if (strcmp(argv[1], "-memused") == 0) {
       char *pid = argv[2];

        // Retrieve virtual memory areas information
        VmaInfo *vma_info_list;
        size_t vma_count;

        if (parse_proc_maps(pid, &vma_info_list, &vma_count) != 0) {
            return 1;
        }

        // Calculate total virtual memory usage
        unsigned long total_virtual_memory = calculate_virtual_memory_usage(vma_info_list, vma_count);

        // Calculate physical memory usage
        unsigned long exclusive_memory, total_memory;
        calculate_physical_memory_usage(&exclusive_memory, &total_memory);

        // Print the memory usage information
        printf("Total Virtual Memory Used: %lu KB\n", total_virtual_memory);
        printf("Exclusive Physical Memory Used: %lu KB\n", exclusive_memory);
        printf("Total Physical Memory Used: %lu KB\n", total_memory);

        // Free the allocated memory
        free(vma_info_list);
    }

    // Physical address with respect to virtual address option
    else if (strcmp(argv[1], "-mapva") == 0) {
        // Extract the process ID and virtual address from the command-line arguments
        pid_t pid = atoi(argv[2]);
        uintptr_t va = parse_va(argv[3]);

        // Open the process's /proc/pid/pagemap file
        char pagemap_path[256];
        snprintf(pagemap_path, sizeof(pagemap_path), "/proc/%d/pagemap", pid);
        int pagemap_fd = open(pagemap_path, O_RDONLY);
        if (pagemap_fd == -1) {
            perror("Failed to open pagemap file");
            return 1;
        }

        // Calculate the page frame number (PFN) for the virtual address
        off_t pfn_offset = (va / PAGE_SIZE) * sizeof(uint64_t);
        uint64_t pfn;
        if (pread(pagemap_fd, &pfn, sizeof(uint64_t), pfn_offset) != sizeof(uint64_t)) {
            perror("Failed to read PFN from pagemap");
            close(pagemap_fd);
            return 1;
        }

        // Check if the page is present in physical memory
        if (!(pfn & (1ULL << 63))) {
            printf("The virtual address is not present in physical memory\n");
            close(pagemap_fd);
            return 1;
        }

        // Calculate the physical address from the PFN
        uintptr_t phys_addr = (pfn & ((1ULL << 55) - 1)) * PAGE_SIZE;

        // Print the physical address in hexadecimal format
        printf("Physical address: 0x%016lx\n", phys_addr);

        // Close the pagemap file
        close(pagemap_fd);
    }

    // Detailed information of page option
    else if (strcmp(argv[1], "-pte") == 0) {
        // Extract the process ID and virtual address from the command-line arguments
        pid_t pid = atoi(argv[2]);
        uintptr_t va = parse_va(argv[3]);

        // Open the process's /proc/pid/pagemap file
        char pagemap_path[256];
        snprintf(pagemap_path, sizeof(pagemap_path), "/proc/%d/pagemap", pid);
        int pagemap_fd = open(pagemap_path, O_RDONLY);
        if (pagemap_fd == -1) {
            perror("Failed to open pagemap file");
            return 1;
        }

        // Calculate the page frame number (PFN) for the virtual address
        off_t pfn_offset = (va / PAGE_SIZE) * sizeof(uint64_t);
        uint64_t pfn;
        if (pread(pagemap_fd, &pfn, sizeof(uint64_t), pfn_offset) != sizeof(uint64_t)) {
            perror("Failed to read PFN from pagemap");
            close(pagemap_fd);
            return 1;
        }

        // Check if the page is present in physical memory or swapped to disk
        if (!(pfn & (1ULL << 63))) {
            printf("The virtual address is not present in physical memory\n");
            close(pagemap_fd);
            return 1;
        }

        // Extract the PFN and swap offset from the pagemap entry
        uint64_t pfn_value = pfn & PFN_MASK;
        uint64_t swap_offset = pfn & SWAP_MASK;

        // Print the detailed information for the page
        printf("PFN (Physical Frame Number): 0x%016lx\n", pfn_value);
        printf("Swap Offset: 0x%016lx\n", swap_offset);

        // Close the pagemap file
        close(pagemap_fd);
    }

    // Virtual Address range mapping option
    else if (strcmp(argv[1], "-maprange") == 0) {
        // Extract the process ID and virtual address range from the command-line arguments
        pid_t pid = atoi(argv[2]);
        uintptr_t va1 = parse_va(argv[3]);
        uintptr_t va2 = parse_va(argv[4]);

        // Open the process's /proc/pid/pagemap file
        char pagemap_path[256];
        snprintf(pagemap_path, sizeof(pagemap_path), "/proc/%d/pagemap", pid);
        int pagemap_fd = open(pagemap_path, O_RDONLY);
        if (pagemap_fd == -1) {
            perror("Failed to open pagemap file");
            return 1;
        }

        // Calculate the starting and ending page frame numbers (PFN) for the virtual address range
        off_t start_offset = (va1 / PAGE_SIZE) * sizeof(uint64_t);
        off_t end_offset = ((va2 - 1) / PAGE_SIZE) * sizeof(uint64_t);

        // Calculate the number of pages in the range
        size_t num_pages = (end_offset - start_offset) / sizeof(uint64_t) + 1;

        // Allocate memory for reading the page frame numbers
        uint64_t *pfns = (uint64_t *)malloc(num_pages * sizeof(uint64_t));
        if (pfns == NULL) {
            perror("Failed to allocate memory");
            close(pagemap_fd);
            return 1;
        }

        // Read the page frame numbers from the pagemap file
        if (pread(pagemap_fd, pfns, num_pages * sizeof(uint64_t), start_offset) != num_pages * sizeof(uint64_t)) {
            perror("Failed to read PFNs from pagemap");
            free(pfns);
            close(pagemap_fd);
            return 1;
        }

        // Print the mappings for each page in the range
        uintptr_t current_va = va1;
        for (size_t i = 0; i < num_pages; i++) {
            uintptr_t current_va_end = current_va + PAGE_SIZE;
            if (current_va_end > va2) {
                current_va_end = va2;
            }

            uint64_t pfn = pfns[i];
            print_mapping(current_va, pfn);

            current_va = current_va_end;
        }

        // Close the pagemap file and free memory
        close(pagemap_fd);
        free(pfns);
    }

    // Mapping process option
    else if (strcmp(argv[1], "-mapall") == 0) {
        // Extract the process ID from the command-line argument
        pid_t pid = atoi(argv[2]);

        // Open the process's /proc/pid/maps file
        char maps_path[256];
        snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
        FILE *maps_file = fopen(maps_path, "r");
        if (maps_file == NULL) {
            perror("Failed to open maps file");
            return 1;
        }

        // Read and parse the virtual memory mappings from the maps file
        char line[256];
        while (fgets(line, sizeof(line), maps_file) != NULL) {
            uintptr_t start_va, end_va;
            sscanf(line, "%lx-%lx", &start_va, &end_va);

            // Calculate the starting and ending page frame numbers (PFN) for the virtual memory range
            off_t start_offset = (start_va / PAGE_SIZE) * sizeof(uint64_t);
            off_t end_offset = ((end_va - 1) / PAGE_SIZE) * sizeof(uint64_t);

            // Calculate the number of pages in the range
            size_t num_pages = (end_offset - start_offset) / sizeof(uint64_t) + 1;

            // Open the process's /proc/pid/pagemap file
            char pagemap_path[256];
            snprintf(pagemap_path, sizeof(pagemap_path), "/proc/%d/pagemap", pid);
            int pagemap_fd = open(pagemap_path, O_RDONLY);
            if (pagemap_fd == -1) {
                perror("Failed to open pagemap file");
                fclose(maps_file);
                return 1;
            }

            // Seek to the starting offset in the pagemap file
            if (lseek(pagemap_fd, start_offset, SEEK_SET) == -1) {
                perror("Failed to seek pagemap file");
                close(pagemap_fd);
                fclose(maps_file);
                return 1;
            }

            // Read the page frame numbers from the pagemap file
            uint64_t *pfns = (uint64_t *)malloc(num_pages * sizeof(uint64_t));
            if (pfns == NULL) {
                perror("Failed to allocate memory");
                close(pagemap_fd);
                fclose(maps_file);
                return 1;
            }
            if (read(pagemap_fd, pfns, num_pages * sizeof(uint64_t)) != num_pages * sizeof(uint64_t)) {
                free(pfns);
                close(pagemap_fd);
                fclose(maps_file);
                return 1;
            }

            // Print the mappings for each page in the range
            for (size_t i = 0; i < num_pages; i++) {
                uintptr_t current_va = start_va + i * PAGE_SIZE;
                uint64_t pfn = pfns[i];
                printf("Virtual Address: 0x%lx\t", current_va);
                print_mapping_mapall(pfn);
            }

            // Free memory and close the pagemap file
            free(pfns);
            close(pagemap_fd);
        }

        // Close the maps file
        fclose(maps_file);
    }

    // Mapping process option (only for pages in memory)
    else if (strcmp(argv[1], "-mapallin") == 0) {
        // Extract the process ID from the command-line argument
        pid_t pid = atoi(argv[2]);

        // Open the process's /proc/pid/maps file
        char maps_path[256];
        snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
        FILE *maps_file = fopen(maps_path, "r");
        if (maps_file == NULL) {
            perror("Failed to open maps file");
            return 1;
        }

        // Read and parse the virtual memory mappings from the maps file
        char line[256];
        while (fgets(line, sizeof(line), maps_file) != NULL) {
            uintptr_t start_va, end_va;
            sscanf(line, "%lx-%lx", &start_va, &end_va);

            // Calculate the starting and ending page frame numbers (PFN) for the virtual memory range
            off_t start_offset = (start_va / PAGE_SIZE) * sizeof(uint64_t);
            off_t end_offset = ((end_va - 1) / PAGE_SIZE) * sizeof(uint64_t);

            // Calculate the number of pages in the range
            size_t num_pages = (end_offset - start_offset) / sizeof(uint64_t) + 1;

            // Open the process's /proc/pid/pagemap file
            char pagemap_path[256];
            snprintf(pagemap_path, sizeof(pagemap_path), "/proc/%d/pagemap", pid);
            int pagemap_fd = open(pagemap_path, O_RDONLY);
            if (pagemap_fd == -1) {
                perror("Failed to open pagemap file");
                fclose(maps_file);
                return 1;
            }

            // Seek to the starting offset in the pagemap file
            if (lseek(pagemap_fd, start_offset, SEEK_SET) == -1) {
                perror("Failed to seek pagemap file");
                close(pagemap_fd);
                fclose(maps_file);
                return 1;
            }

            // Read the page frame numbers from the pagemap file
            uint64_t *pfns = (uint64_t *)malloc(num_pages * sizeof(uint64_t));
            if (pfns == NULL) {
                perror("Failed to allocate memory");
                close(pagemap_fd);
                fclose(maps_file);
                return 1;
            }
            if (read(pagemap_fd, pfns, num_pages * sizeof(uint64_t)) != num_pages * sizeof(uint64_t)) {
                free(pfns);
                close(pagemap_fd);
                fclose(maps_file);
                return 1;
            }

            // Print the mappings for each page in the range that is in memory
            for (size_t i = 0; i < num_pages; i++) {
                if (pfns[i] & (1ULL << 63)) {
                    uint64_t pfn = pfns[i] & PFN_MASK;
                    printf("Page Number: %zu\t", i);
                    print_mapping_allin(pfn);
                }
            }

            // Free memory and close the pagemap file
            free(pfns);
            close(pagemap_fd);
        }

        // Close the maps file
        fclose(maps_file);
    }

    // Total required memory for page table info option
    else if (strcmp(argv[1], "-alltablesize") == 0) {
        // Extract the process ID from the command-line argument
        pid_t pid = atoi(argv[2]);

        // Open the process's /proc/pid/maps file
        char maps_path[256];
        snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid);
        FILE *maps_file = fopen(maps_path, "r");
        if (maps_file == NULL) {
            perror("Failed to open maps file");
            return 1;
        }

        // Calculate the total memory required for page tables
        uint64_t total_memory_size = 0;
        char line[256];
        while (fgets(line, sizeof(line), maps_file) != NULL) {
            // Calculate the size of the virtual memory region
            uintptr_t start_va, end_va;
            sscanf(line, "%lx-%lx", &start_va, &end_va);
            uint64_t region_size = end_va - start_va;

            // Calculate the number of page table levels required for the region
            uint64_t num_levels = 4 - ((region_size - 1) >> 39);

            // Calculate the memory required for page tables at each level
            uint64_t memory_size = PAGE_SIZE;
            for (uint64_t level = 0; level < num_levels; level++) {
                memory_size *= ENTRIES_PER_TABLE;
            }

            total_memory_size += memory_size;
        }

        // Close the maps file
        fclose(maps_file);

        // Print the total memory size required for page tables
        printf("Total Memory Size Required for Page Tables: ");
        print_memory_size(total_memory_size);
    }

    return 0;
}


// Auxiliary Functions
void print_memory_size(uint64_t size) {
    const char *units[] = {"B", "KB", "MB", "GB", "TB"};
    int unit_index = 0;
    while (size >= 1024 && unit_index < 4) {
        size /= 1024;
        unit_index++;
    }
    printf("%lu %s\n", size, units[unit_index]);
}

void print_mapping_allin(uint64_t pfn) {
    printf("Physical Frame Number: 0x%016llx\n", pfn & PFN_MASK);
}

void print_mapping_mapall(uint64_t pfn) {
    if (!(pfn & (1ULL << 63))) {
        printf("Not in Memory\n");
    } else {
        printf("Physical Frame Number: 0x%016llx\n", pfn & PFN_MASK);
    }
}

void print_mapping(uintptr_t va, uint64_t pfn) {
    printf("Virtual Address: 0x%016lx ", va);
    if (pfn == 0) {
        printf("Unused\n");
    } else if (!(pfn & (1ULL << 63))) {
        printf("Not in Memory\n");
    } else {
        printf("Physical Frame Number: 0x%016llx\n", pfn & PFN_MASK);
    }
}

unsigned long long get_physical_address(const char *pid, unsigned long long va) {
    char path[64];
    snprintf(path, sizeof(path), "/proc/%s/pagemap", pid);

    int fd = open(path, O_RDONLY);
    if (fd == -1) {
        perror("Failed to open pagemap file");
        return 0;
    }

    unsigned long long offset = va / PAGE_SIZE * sizeof(uint64_t);
    unsigned long long pfn;
    if (pread(fd, &pfn, sizeof(pfn), offset) == sizeof(pfn)) {
        if (pfn & (1ULL << 63)) {
            unsigned long long phys_addr = (pfn & ((1ULL << 55) - 1)) * PAGE_SIZE;
            close(fd);
            return phys_addr;
        }
    }

    close(fd);
    return 0;
}

unsigned long long parse_va(const char *va_str) {
    unsigned long long va;
    if (strncmp(va_str, "0x", 2) == 0) {
        va = strtoull(va_str + 2, NULL, 16);  // Hexadecimal format
    } else {
        va = strtoull(va_str, NULL, 10);  // Decimal format
    }
    return va;
}


int parse_proc_maps(const char *pid, VmaInfo **vma_info_list, size_t *vma_count) {
    char maps_filepath[MAX_LINE_LENGTH];
    snprintf(maps_filepath, sizeof(maps_filepath), "/proc/%s/maps", pid);

    FILE *maps_file = fopen(maps_filepath, "r");
    if (!maps_file) {
        perror("Failed to open /proc/PID/maps file");
        return 1;
    }

    size_t vma_list_size = 16;
    *vma_info_list = malloc(vma_list_size * sizeof(VmaInfo));
    *vma_count = 0;

    char line[MAX_LINE_LENGTH];
    while (fgets(line, sizeof(line), maps_file)) {
        VmaInfo vma_info;

        int ret = sscanf(line, "%lx-%lx %4s %lx %x:%x %d",
                         &vma_info.start, &vma_info.end, vma_info.permissions,
                         &vma_info.offset, &vma_info.dev_major, &vma_info.dev_minor,
                         &vma_info.inode);

        if (ret != 7) {
            fprintf(stderr, "Failed to parse /proc/PID/maps file\n");
            fclose(maps_file);
            free(*vma_info_list);
            return 1;
        }

        // Retrieve the pathname (if available)
        char *pathname = strchr(line, '/');
        if (pathname) {
            strncpy(vma_info.pathname, pathname, sizeof(vma_info.pathname));
            vma_info.pathname[strcspn(vma_info.pathname, "\n")] = '\0';
        } else {
            strcpy(vma_info.pathname, "[anon]");
        }

        // Resize the vma_info_list if necessary
        if (*vma_count >= vma_list_size) {
            vma_list_size *= 2;
            *vma_info_list = realloc(*vma_info_list, vma_list_size * sizeof(VmaInfo));
        }

        // Add the VMA info to the list
        (*vma_info_list)[*vma_count] = vma_info;
        (*vma_count)++;
    }

    fclose(maps_file);
    return 0;
}

unsigned long calculate_virtual_memory_usage(VmaInfo *vma_info_list, size_t vma_count) {
    unsigned long total_memory = 0;

    for (size_t i = 0; i < vma_count; i++) {
        unsigned long vma_size = vma_info_list[i].end - vma_info_list[i].start;
        total_memory += vma_size;
    }

    return total_memory;
}

void calculate_physical_memory_usage(unsigned long *exclusive_memory, unsigned long *total_memory) {
    char kpagecount_filepath[] = "/proc/kpagecount";

    FILE *kpagecount_file = fopen(kpagecount_filepath, "r");
    if (!kpagecount_file) {
        perror("Failed to open /proc/kpagecount file");
        return;
    }

    unsigned long exclusive_mem = 0;
    unsigned long total_mem = 0;

    uint64_t mapping_count;
    while (fread(&mapping_count, sizeof(uint64_t), 1, kpagecount_file) == 1) {
        if (mapping_count > 0) {
            total_mem += 4; // Each page is 4 KB in size
            if (mapping_count == 1) {
                exclusive_mem += 4;
            }
        }
    }

    fclose(kpagecount_file);

    *exclusive_memory = exclusive_mem;
    *total_memory = total_mem;
}

void print_flags(uint64_t flags) {
    printf("Flags:\n");
    printf("LOCKED: %d\n", (flags & (1ULL << 0)) != 0);
    printf("ERROR: %d\n", (flags & (1ULL << 1)) != 0);
    printf("REFERENCED: %d\n", (flags & (1ULL << 2)) != 0);
    printf("UPTODATE: %d\n", (flags & (1ULL << 3)) != 0);
    printf("DIRTY: %d\n", (flags & (1ULL << 4)) != 0);
    printf("LRU: %d\n", (flags & (1ULL << 5)) != 0);
    printf("ACTIVE: %d\n", (flags & (1ULL << 6)) != 0);
    printf("SLAB: %d\n", (flags & (1ULL << 7)) != 0);
    printf("WRITEBACK: %d\n", (flags & (1ULL << 8)) != 0);
    printf("RECLAIM: %d\n", (flags & (1ULL << 9)) != 0);
    printf("BUDDY: %d\n", (flags & (1ULL << 10)) != 0);
    printf("MMAP: %d\n", (flags & (1ULL << 11)) != 0);
    printf("ANON: %d\n", (flags & (1ULL << 12)) != 0);
    printf("SWAPCACHE: %d\n", (flags & (1ULL << 13)) != 0);
    printf("SWAPBACKED: %d\n", (flags & (1ULL << 14)) != 0);
    printf("COMPOUND_HEAD: %d\n", (flags & (1ULL << 15)) != 0);
    printf("COMPOUND_TAIL: %d\n", (flags & (1ULL << 16)) != 0);
    printf("HUGE: %d\n", (flags & (1ULL << 17)) != 0);
    printf("UNEVICTABLE: %d\n", (flags & (1ULL << 18)) != 0);
    printf("HWPOISON: %d\n", (flags & (1ULL << 19)) != 0);
    printf("NOPAGE: %d\n", (flags & (1ULL << 20)) != 0);
    printf("KSM: %d\n", (flags & (1ULL << 21)) != 0);
    printf("THP: %d\n", (flags & (1ULL << 22)) != 0);
    printf("BALLOON: %d\n", (flags & (1ULL << 23)) != 0);
    printf("ZERO_PAGE: %d\n", (flags & (1ULL << 24)) != 0);
    printf("IDLE: %d\n", (flags & (1ULL << 25)) != 0);
}

void print_frame_info(uint64_t pfn, uint64_t flags, uint64_t mapping_count) {
    printf("Frame Number: %016lx\n", pfn);
    print_flags(flags);
    printf("Mapping Count: %lu\n", mapping_count);
}
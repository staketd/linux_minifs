#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include "constants.h"
#include <fcntl.h>
#include <sys/mman.h>
#include <unistd.h>
#include "fs.h"
#include <stdlib.h>
#include <sys/stat.h>

size_t min(size_t a, size_t b) {
    return (a < b ? a : b);
}

void unmap(void* addr, size_t length) {
    if (addr == NULL) {
        return;
    }
    munmap(addr, length);
}


super_block* get_super_block(int fd) {
    return mmap(NULL, sizeof(super_block), PROT_WRITE | PROT_READ, MAP_SHARED, fd, BLOCK_SIZE);
}

void* map_block(int fd, size_t block_offset) {
    super_block* sb = get_super_block(fd);
    if (sb->truncated_blocks <= block_offset) {
        ftruncate(fd, min(block_offset * 2, sb->max_number_of_blocks) * BLOCK_SIZE);
    }
    unmap(sb, BLOCK_SIZE);
    return mmap(NULL, BLOCK_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, block_offset * BLOCK_SIZE);
}

mappings_list* get_mapping_list(int fd, inode* inode) {
    struct mapping_node {
        struct mapping_node* next;
        size_t mapping;
    };
    struct mapping_node* head = NULL;
    struct mapping_node* tail = NULL;
    mappings_list* ans = malloc(sizeof(mappings_list));
    ans->mapping_size = 0;
    for (size_t i = 0; i < INODE_DIRECT_MAPPING; ++i) {
        if (inode->mappings[i] != 0) {
            ans->mapping_size++;
            if (head == NULL) {
                head = calloc(1, sizeof(struct mapping_node));
                tail = head;
                tail->mapping = inode->mappings[i];
                continue;
            }
            tail->next = calloc(1, sizeof(struct mapping_node));
            tail = tail->next;
            tail->mapping = inode->mappings[i];
        }
    }
    for (size_t i = INODE_DIRECT_MAPPING; i < INODE_INDIRECT_MAPPING_1 + INODE_DIRECT_MAPPING; ++i) {
        if (inode->mappings[i] == 0) {
            continue;
        }
        void* block = map_block(fd, inode->mappings[i]);
        for (size_t j = 0; j < BLOCK_SIZE / sizeof(size_t); ++j) {
            size_t* mapping = block + j * sizeof(size_t);
            if (*mapping != 0) {
                tail->next = calloc(1, sizeof(struct mapping_node));
                tail = tail->next;
                tail->mapping = *mapping;
                ans->mapping_size++;
            }
        }
    }
    ans->mappings = malloc(sizeof(size_t) * ans->mapping_size);
    size_t i = 0;
    while (head != NULL) {
        ans->mappings[i++] = head->mapping;
        void* to_free = head;
        head = head->next;
        free(to_free);
    }
    return ans;
}


dir_entry* get_dir_entry(void* block, size_t entry_index) {
    dir_entry* entry = block + ENTRY_SIZE * entry_index;
    if (entry->name_len == 0) {
        return NULL;
    }
    dir_entry* ans = malloc(ENTRY_SIZE);
    memcpy(ans, entry, ENTRY_SIZE);
    return ans;
}

size_t get_free_entry_in_block(int fd, size_t block_offset) {
    void* block = map_block(fd, block_offset);
    for (size_t i = 0; i < ENTRIES_PER_BLOCK; ++i) {
        dir_entry* entry = get_dir_entry(block, i);
        if (entry == NULL) {
            return i;
        }
        free(entry);
    }
    return ENTRIES_PER_BLOCK;
}

size_t get_free_bit_in_block(int fd, size_t block_index) {
    void* block = map_block(fd, block_index);
    uint8_t* ptr = block;
    size_t ans = 0;
    for (size_t i = 0; i < BLOCK_SIZE; ++i) {
        if (*ptr == 255) {
            ans += 8;
            ptr++;
            continue;
        }
        for (size_t bit = 0; bit < 8; ++bit) {
            if ((*ptr & (1 << bit)) == 0) {
                unmap(block, BLOCK_SIZE);
                return ans + bit;
            }
        }
    }
    unmap(block, BLOCK_SIZE);
    return BLOCK_SIZE * 8;
}

void init_dir_in_block(int fd, size_t block_offset, size_t inode_index, size_t parent_inode_index) {
    void* block = map_block(fd, block_offset);
    dir_entry self_link = {
            .name = ".",
            .inode_index = inode_index,
            .name_len = 1,
    };
    dir_entry parent_link = {
            .name = "..",
            .inode_index = parent_inode_index,
            .name_len = 2,
    };
    memcpy(block, &self_link, ENTRY_SIZE);
    memcpy(block + ENTRY_SIZE, &parent_link, ENTRY_SIZE);
    unmap(block, BLOCK_SIZE);
}

void set_bit_in_block(int fd, size_t block_index, size_t bit_index, uint8_t value) {
    void* block = map_block(fd, block_index);
    size_t byte_index = bit_index / 8;
    size_t bit_in_byte = bit_index % 8;
    uint8_t* byte_value = block + byte_index;
    *byte_value |= (uint8_t) (1 << bit_in_byte);
    if (value == 0) {
        *byte_value ^= (1 << bit_in_byte);
    }
}

size_t allocate_block(int fd) {
    size_t free_block_index = 0;
    size_t map_block_index = NUMBER_OF_EMPTY_BLOCKS + 1 + IMAP_BLOCKS;
    for (size_t i = 0; i < BMAP_BLOCKS; ++i) {
        size_t free_bit = get_free_bit_in_block(fd, NUMBER_OF_EMPTY_BLOCKS + 1 + IMAP_BLOCKS + i);
        if (free_bit == BLOCK_SIZE * 8) {
            map_block_index++;
            free_block_index += BLOCK_SIZE * 8;
            continue;
        }
        free_block_index += free_bit;
        break;
    }
    set_bit_in_block(fd, map_block_index, free_block_index % (BLOCK_SIZE * 8), 1);
    free_block_index += FIRST_DATA_BLOCK_OFFSET;
    void* block = map_block(fd, free_block_index);
    memset(block, 0, BLOCK_SIZE);
    unmap(block, BLOCK_SIZE);
#ifdef DEBUG_
    printf("allocated block %zu\n", free_block_index);
#endif
    return free_block_index;
}

void deallocate_block(int fd, size_t block_index) {
    size_t bit_in_block = (block_index - FIRST_DATA_BLOCK_OFFSET) % (8 * BLOCK_SIZE);
    size_t map_block_index = (block_index - FIRST_DATA_BLOCK_OFFSET) / (8 * BLOCK_SIZE);
    set_bit_in_block(fd, map_block_index, bit_in_block, 0);
}

void deallocate_inode(int fd, size_t inode_index) {
    set_bit_in_block(fd, 1 + NUMBER_OF_EMPTY_BLOCKS, inode_index, 0);
}

inode* get_inode(int fd, size_t inode_index) {
    size_t inode_block_offset = (1 + MAP_BLOCKS + NUMBER_OF_EMPTY_BLOCKS) + (inode_index - 1) / INODES_PER_BLOCK;
    size_t inode_byte_offset = (inode_index - 1) % 42 * INODE_SIZE;
    void* block = map_block(fd, inode_block_offset);
    inode* inode = calloc(1, INODE_SIZE);
    memcpy(inode, block + inode_byte_offset, INODE_SIZE);
    unmap(block, BLOCK_SIZE);
    return inode;
}

void init_root_directory(int fd) {
    size_t block_index = allocate_block(fd);
    init_dir_in_block(fd, block_index, 1, 1);
}

void init_superblock(int fd) {
    void* map = mmap(NULL, BLOCK_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, fd, BLOCK_SIZE);
    memset(map, 0, BLOCK_SIZE);
    super_block block = {
            .number_of_inodes = INODES_PER_BLOCK * INODES_BLOCKS,
            .max_number_of_blocks = MAX_SIZE / BLOCK_SIZE,
            .imap_blocks = IMAP_BLOCKS,
            .bmap_blocks = BMAP_BLOCKS,
            .max_fs_size = MAX_SIZE,
            .first_data_block = FIRST_DATA_BLOCK_OFFSET,
            .truncated_blocks = FIRST_DATA_BLOCK_OFFSET,
    };
    memcpy(map, &block, sizeof(super_block));
    munmap(map, BLOCK_SIZE);
}

void init_mappings(int fd) {
    void* imap = mmap(NULL, BLOCK_SIZE * IMAP_BLOCKS, PROT_READ | PROT_WRITE, MAP_SHARED, fd,
                      BLOCK_SIZE * (1 + NUMBER_OF_EMPTY_BLOCKS));
    memset(imap, 0, BLOCK_SIZE * IMAP_BLOCKS);
    memset(imap, 1, 1); // setting inode of root
    munmap(imap, BLOCK_SIZE * IMAP_BLOCKS);

    void* bmap = mmap(NULL, BLOCK_SIZE * BMAP_BLOCKS, PROT_WRITE | PROT_WRITE, MAP_SHARED, fd,
                      (1 + NUMBER_OF_EMPTY_BLOCKS + IMAP_BLOCKS) * BLOCK_SIZE);
    memset(bmap, 0, BLOCK_SIZE * BMAP_BLOCKS);
    unmap(bmap, BLOCK_SIZE * BMAP_BLOCKS);
}

void init_inodes(int fd) {
    void* map_blocks = mmap(NULL, IMAP_BLOCKS * BLOCK_SIZE, PROT_WRITE | PROT_READ, MAP_SHARED, fd,
                            BLOCK_SIZE * (1 + MAP_BLOCKS + NUMBER_OF_EMPTY_BLOCKS));

    memset(map_blocks, 0, IMAP_BLOCKS * BLOCK_SIZE);
    unmap(map_blocks, IMAP_BLOCKS * BLOCK_SIZE);

    void* map = mmap(NULL, INODE_SIZE, PROT_WRITE | PROT_READ, MAP_SHARED, fd,
                     BLOCK_SIZE * (1 + MAP_BLOCKS + NUMBER_OF_EMPTY_BLOCKS));
    size_t mappings[INODE_MAPPING_SIZE];
    memset(mappings, 0, sizeof(mappings));
    mappings[0] = FIRST_DATA_BLOCK_OFFSET;
    inode root_inode = {
            .attributes = FOLDER_ATTR,
    };
    memcpy(root_inode.mappings, mappings, sizeof(size_t) * INODE_MAPPING_SIZE);
    memcpy(map, &root_inode, INODE_SIZE);
    munmap(map, INODE_SIZE);
}

void init(int fd) {
    ftruncate(fd, FIRST_DATA_BLOCK_OFFSET * BLOCK_SIZE);
    init_superblock(fd);
    init_mappings(fd);
    init_inodes(fd);
    init_root_directory(fd);
}

uint32_t check_directory(inode* inode) {
    return inode->attributes & (size_t)FOLDER_ATTR;
}

struct dir_entry_list* get_block_dir_entry_list(int fd, size_t block_offset) {
    void* block = map_block(fd, block_offset);
    struct dir_entry_list* entry_list = NULL;
    for (size_t i = 0; i < ENTRIES_PER_BLOCK; ++i) {
        dir_entry* entry = get_dir_entry(block, i);
        if (entry == NULL) {
            continue;
        }
        if (entry_list == NULL) {
            entry_list = calloc(1, sizeof(struct dir_entry_list));
            entry_list->head = calloc(1, sizeof(struct dir_entry_list_node));
            entry_list->tail = entry_list->head;
            entry_list->head->entry = entry;
            entry_list->head->next = NULL;
            continue;
        }
        entry_list->tail->next = malloc(sizeof(struct dir_entry_list_node));
        entry_list->tail = entry_list->tail->next;
        entry_list->tail->entry = entry;
        entry_list->tail->next = NULL;
    }
    return entry_list;
}

struct dir_entry_list* get_dir_entry_list(int fd, mappings_list* list) {
    struct dir_entry_list* ans = NULL;
    for (size_t i = 0; i < list->mapping_size; ++i) {
        struct dir_entry_list* block_list = get_block_dir_entry_list(fd, list->mappings[i]);
        if (ans == NULL) {
            ans = block_list;
            continue;
        }
        ans->tail->next = block_list->head;
        ans->tail = block_list->tail;
    }
    return ans;
}

void free_mappings_list(mappings_list* list) {
    free(list->mappings);
    free(list);
}


void free_entry_dir_list_node(struct dir_entry_list_node* list) {
    if (list == NULL) {
        return;
    }
    free_entry_dir_list_node(list->next);
    free(list->entry);
    free(list);
}

void free_entry_dir_list(struct dir_entry_list* list) {
    free_entry_dir_list_node(list->head);
    free(list);
}


int dir_exists(struct dir_entry_list* list, const char* dir) {
    if (list == NULL) {
        return -1;
    }
    struct dir_entry_list_node* now = list->head;
    while (now != NULL) {
        if (strcmp(now->entry->name, dir) == 0) {
            return 0;
        }
        now = now->next;
    }
    return -1;
}

void print_path(size_t dirs, char* path[]) {
    if (dirs == 0) {
        printf("/");
        return;
    }
    for (size_t i = 0; i < dirs; ++i) {
        printf("/");
        printf("%s", path[i]);
    }
}

size_t get_inode_index(struct dir_entry_list* list, const char* name) {
    if (list == NULL) {
        return 0;
    }

    struct dir_entry_list_node* now = list->head;
    while (now != NULL) {
        if (strcmp(now->entry->name, name) == 0) {
            return now->entry->inode_index;
        }
        now = now->next;
    }
    return 0;
}

inode* get_inode_of_file(int fd, char* path[], size_t depth, size_t current_inode_index, size_t* result_index) {
    inode* current_inode = get_inode(fd, current_inode_index);
    if (depth == 0) {
        if (result_index != NULL) {
            *result_index = current_inode_index;
        }
        return current_inode;
    }
    if (check_directory(current_inode) == 0) {
        free(current_inode);
        return NULL;
    }
    mappings_list* map_list = get_mapping_list(fd, current_inode);
    struct dir_entry_list* dir_list = get_dir_entry_list(fd, map_list);
    if (dir_exists(dir_list, path[0]) == -1) {
        free_mappings_list(map_list);
        free_entry_dir_list(dir_list);
        free(current_inode);
        return NULL;
    }

    size_t next_inode_index = get_inode_index(dir_list, path[0]);
    if (next_inode_index == 0) {
        free_mappings_list(map_list);
        free_entry_dir_list(dir_list);
        free(current_inode);
        return NULL;
    }
    return get_inode_of_file(fd, &path[1], depth - 1, next_inode_index, result_index);
}

int list_directory(int fd, size_t dirs, char* path[], size_t current_inode_index) {
    inode* inode = get_inode_of_file(fd, path, dirs, current_inode_index, NULL);
    if (inode == NULL || check_directory(inode) == 0) {
        unmap(inode, INODE_SIZE);
        return -1;
    }
    mappings_list* listing = get_mapping_list(fd, inode);
    struct dir_entry_list* list = get_dir_entry_list(fd, listing);
    struct dir_entry_list_node* now = list->head;
    while (now != NULL) {
        printf("%s\n", now->entry->name);
        now = now->next;
    }
    free_mappings_list(listing);
    free_entry_dir_list(list);
    unmap(inode, INODE_SIZE);
    return 0;
}

size_t split_path(const char* path_old, char*** ans) {
    char* path = calloc(strlen(path_old) + 1, 1);
    strcpy(path, path_old);
    size_t word_count = 0;
    uint8_t flag = 0;
    for (size_t i = 0; path[i] != '\0'; ++i) {
        if (path[i] == '/') {
            flag = 0;
        } else {
            if (flag == 0) {
                ++word_count;
            }
            flag = 1;
        }
    }
    *ans = calloc(word_count, sizeof(char*));
    char* token = strtok(path, "//");
    for (size_t i = 0; i < word_count; ++i) {
        (*ans)[i] = calloc(strlen(token) + 1, sizeof(char));
        strcpy((*ans)[i], token);
        token = strtok(NULL, "//");
    }
    free(path);
    return word_count;
}

size_t concat_paths(size_t len1, char** path1, size_t len2, char** path2, char*** ans) {
    *ans = calloc(len1 + len2, sizeof(char*));
    memcpy(*ans, path1, sizeof(char*) * len1);
    memcpy(*ans + len1, path2, sizeof(char*) * len2);
    return len1 + len2;
}

size_t find_free_inode_index(int fd) {
    return get_free_bit_in_block(fd, NUMBER_OF_EMPTY_BLOCKS + 1);
}

void add_block_to_inode_mapping(int fd, size_t block_index, size_t inode_index) {
    size_t inode_block_index = (inode_index - 1) / INODES_PER_BLOCK + (1 + NUMBER_OF_EMPTY_BLOCKS + MAP_BLOCKS);
    size_t inode_block_offset = (inode_index - 1) % INODES_PER_BLOCK;
    void* imap_block = map_block(fd, inode_block_index);
    inode* node = imap_block + inode_block_offset * INODE_SIZE;
    for (size_t i = 0; i < INODE_DIRECT_MAPPING; ++i) {
        if (node->mappings[i] == 0) {
            node->mappings[i] = block_index;
            unmap(imap_block, BLOCK_SIZE);
            return;
        }
    }
    for (size_t i = INODE_DIRECT_MAPPING; i < INODE_INDIRECT_MAPPING_1 + INODE_DIRECT_MAPPING; ++i) {
        if (node->mappings[i] == 0) {
            size_t new_block = allocate_block(fd);
            node->mappings[i] = new_block;
            void* block = map_block(fd, new_block);
            *((size_t*)block) = block_index;
            unmap(imap_block, BLOCK_SIZE);
            return;
        }
        void* block = map_block(fd, node->mappings[i]);
        for (size_t j = 0; j < BLOCK_SIZE / sizeof(size_t); ++j) {
            size_t* mapping = block + sizeof(size_t) * j;
            if (*mapping == 0) {
                *mapping = block_index;
                unmap(imap_block, BLOCK_SIZE);
                return;
            }
        }
    }
    printf("Unable to map file more than 48M");
    exit(1);
}

void add_entry(int fd, inode* folder_inode, dir_entry* entry, size_t folder_inode_index) {
    mappings_list* map_list = get_mapping_list(fd, folder_inode);
    size_t entry_index = 0;
    size_t block_index = 0;
    for (size_t i = 0; i < map_list->mapping_size; ++i) {
        entry_index = get_free_entry_in_block(fd, map_list->mappings[i]);
        if (entry_index < ENTRIES_PER_BLOCK) {
            block_index = map_list->mappings[i];
            break;
        }
    }
    if (block_index == 0) { // need to allocate new block
        size_t free_block = allocate_block(fd);
        add_block_to_inode_mapping(fd, free_block, folder_inode_index);
        block_index = free_block;
    }
    void* block = map_block(fd, block_index);
    memcpy(block + entry_index * ENTRY_SIZE, entry, ENTRY_SIZE);
    unmap(block, BLOCK_SIZE);
}

size_t allocate_inode(int fd, uint8_t attrs, uint32_t file_size) {
    size_t inode_index = find_free_inode_index(fd) + 1;
    size_t inode_block = (inode_index - 1) / INODES_PER_BLOCK + (1 + NUMBER_OF_EMPTY_BLOCKS + MAP_BLOCKS);
    size_t inode_offset_in_block = (inode_index - 1) % INODES_PER_BLOCK;
    void* block = map_block(fd, inode_block);
    inode new_inode = {
            .attributes = attrs,
            .file_size = file_size,
    };
    set_bit_in_block(fd, 1 + NUMBER_OF_EMPTY_BLOCKS, inode_index - 1, 1);
    memset(new_inode.mappings, 0, sizeof(size_t) * INODE_MAPPING_SIZE);
    memcpy(block + inode_offset_in_block * INODE_SIZE, &new_inode, INODE_SIZE);
    unmap(block, BLOCK_SIZE);
    return inode_index;
}

void set_mapping_inode(int fd, size_t inode_index, size_t mapping_id, size_t mapping_value) {
    size_t block_index = (1 + NUMBER_OF_EMPTY_BLOCKS + MAP_BLOCKS) + (inode_index - 1) / INODES_PER_BLOCK;
    void* block = map_block(fd, block_index);
    size_t block_byte_offset = (inode_index - 1) % INODES_PER_BLOCK * INODE_SIZE;
    inode* inode = block + block_byte_offset;
    inode->mappings[mapping_id] = mapping_value;
    unmap(block, BLOCK_SIZE);
}

int check_exists(struct dir_entry_list_node* node, const char* name) {
    while (node != NULL) {
        if (strcmp(node->entry->name, name) == 0) {
            return 0;
        }
        node = node->next;
    }
    return -1;
}

int make_dir(int fd, size_t depth, char* path[], size_t current_inode_index) {
    size_t parent_dir_index;
    inode* parent_inode = get_inode_of_file(fd, path, depth - 1, current_inode_index, &parent_dir_index);
    if (parent_inode == NULL || check_directory(parent_inode) == 0) {
        free(parent_inode);
        return -1;
    }
    mappings_list* map_list = get_mapping_list(fd, parent_inode);
    struct dir_entry_list* dir_list = get_dir_entry_list(fd, map_list);
    if (check_exists(dir_list->head, path[depth - 1]) == 0) {
        free_mappings_list(map_list);
        free_entry_dir_list(dir_list);
        return -1;
    }

    free_mappings_list(map_list);
    free_entry_dir_list(dir_list);

    size_t new_block_index = allocate_block(fd);
    size_t new_inode_index = allocate_inode(fd, FOLDER_ATTR, BLOCK_SIZE);

    dir_entry new_entry = {
            .name_len = strlen(path[depth - 1]),
            .inode_index = new_inode_index,
    };

    strcpy(new_entry.name, path[depth - 1]);
    add_entry(fd, parent_inode, &new_entry, new_inode_index);

    set_mapping_inode(fd, new_entry.inode_index, 0, new_block_index);
    init_dir_in_block(fd, new_block_index, new_entry.inode_index, parent_dir_index);

    free(parent_inode);
    return 0;
}

void free_path(char** path, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        free(path[i]);
    }
    free(path);
}

int upload_file(int fd, int file_fd, char* path[], size_t len, size_t current_inode_index) {
    inode* folder_inode = get_inode_of_file(fd, path, len - 1, current_inode_index, NULL);
    if (folder_inode == NULL || check_directory(folder_inode) == 0) {
        free(folder_inode);
        return -1;
    }
    mappings_list* map_list = get_mapping_list(fd, folder_inode);
    struct dir_entry_list* list_dir = get_dir_entry_list(fd, map_list);
    int exists = check_exists(list_dir->head, path[len - 1]);
    free_mappings_list(map_list);
    free_entry_dir_list(list_dir);
    if (exists == 0) {
        return -1;
    }
    struct stat st;
    if (fstat(file_fd, &st) == -1) {
        return -1;
    }
    size_t new_inode_index = allocate_inode(fd, FILE_ATTR, st.st_size);
    dir_entry new_entry = {
            .inode_index = new_inode_index,
            .name_len = strlen(path[len - 1]),
    };
    strcpy(new_entry.name, path[len - 1]);
    add_entry(fd, folder_inode, &new_entry, new_inode_index);

    char buffer[BLOCK_SIZE];
    size_t bytes_read;
    while ((bytes_read = read(file_fd, buffer, BLOCK_SIZE)) != 0) {
        size_t new_file_block = allocate_block(fd);
        add_block_to_inode_mapping(fd, new_file_block, new_inode_index);
        void* block = map_block(fd, new_file_block);
        memcpy(block, buffer, bytes_read);
        unmap(block, BLOCK_SIZE);
    }
    free(folder_inode);
    return 0;
}

int concatenate(int fd, char* path[], size_t len, size_t current_inode_index) {
    inode* file_inode = get_inode_of_file(fd, path, len, current_inode_index, NULL);
    if (file_inode == NULL || check_directory(file_inode) == FOLDER_ATTR) {
        free(file_inode);
        return -1;
    }
    mappings_list* map_list = get_mapping_list(fd, file_inode);
    size_t sz = file_inode->file_size;
    for (size_t i = 0; i < map_list->mapping_size; ++i) {
        void* block = map_block(fd, map_list->mappings[i]);
        write(1, block, min(BLOCK_SIZE, sz));
        if (sz > BLOCK_SIZE) {
            sz -= BLOCK_SIZE;
        } else {
            sz = 0;
        }
        unmap(block, BLOCK_SIZE);
    }
    printf("\n");
    free(file_inode);
    free_mappings_list(map_list);
    return 0;
}

size_t canonize_path(char*** path, size_t len) {
    size_t stack[len + 1];
    size_t stack_top = 0;
    for (size_t i = 0; i < len; ++i) {
        char* token = (*path)[i];
        if (strcmp(token, ".") == 0) {
            free(token);
            continue;
        }
        if (strcmp(token, "..") == 0) {
            free(token);
            if (stack_top == 0) {
                continue;
            }
            stack_top--;
            free((*path)[stack[stack_top]]);
        } else {
            stack[stack_top++] = i;
        }
    }
    char** ans;
    ans = calloc(stack_top, sizeof(char*));
    for (size_t i = 0; i < stack_top; ++i) {
        ans[i] = (*path)[stack[i]];
    }
    *path = ans;
    return stack_top;
}

void remove_entry(int fd, inode* folder_inode, size_t file_inode_index) {
    mappings_list* map_list = get_mapping_list(fd, folder_inode);
    for (size_t i = 0; i < map_list->mapping_size; ++i) {
        void* block = map_block(fd, map_list->mappings[i]);
        for (size_t j = 0; j < ENTRIES_PER_BLOCK; ++j) {
            dir_entry* entry = get_dir_entry(block, j);
            if (entry == NULL) {
                continue;
            }
            if (entry->inode_index == file_inode_index) {
                free(entry);
                memset(block + j * ENTRY_SIZE, 0, ENTRY_SIZE);
                break;
            }
        }
        unmap(block, BLOCK_SIZE);
    }
    free_mappings_list(map_list);
}

int remove_file(int fd, inode* folder_inode, inode* file_inode, size_t file_inode_index) {
    mappings_list* map_list = get_mapping_list(fd, file_inode);
    for (size_t i = 0; i < map_list->mapping_size; ++i) {
        deallocate_block(fd, map_list->mappings[i]);
    }
    deallocate_inode(fd, file_inode_index);
    free_mappings_list(map_list);
    remove_entry(fd, folder_inode, file_inode_index);
    return 0;
}

int remove_dir(int fd, inode* dir_inode) {
    mappings_list* map_list = get_mapping_list(fd, dir_inode);
    struct dir_entry_list* dir_list = get_dir_entry_list(fd, map_list);
    struct dir_entry_list_node* now = dir_list->head;
    size_t this_inode_index;
    inode* parent_inode;
    while (now != NULL) {
        if (strcmp(now->entry->name, ".") == 0 || strcmp(now->entry->name, "..") == 0) {
            if (strcmp(now->entry->name, ".") == 0) {
                this_inode_index = now->entry->inode_index;
            }
            if (strcmp(now->entry->name, "..") == 0) {
                parent_inode = get_inode(fd, now->entry->inode_index);
            }
            now = now->next;
            continue;
        }
        inode* file_inode = get_inode(fd, now->entry->inode_index);
        if (check_directory(file_inode) == FILE_ATTR) {
            remove_file(fd, dir_inode, file_inode, now->entry->inode_index);
        } else {
            remove_dir(fd, file_inode);
        }
        now = now->next;
        free(file_inode);
    }
    remove_entry(fd, parent_inode, this_inode_index);
    for (size_t i = 0; i < map_list->mapping_size; ++i) {
        deallocate_block(fd, map_list->mappings[i]);
    }
    deallocate_inode(fd, this_inode_index);
    free(parent_inode);
    free_mappings_list(map_list);
    free_entry_dir_list(dir_list);
    return 0;
}

int main(int argc, char* argv[]) {
    int fd = open(FILESYSTEM_FILE, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
    if (argc > 1 && strcmp(argv[1], "--init") == 0) {
        init(fd);
//        exit(EXIT_SUCCESS);
    }
    char** current_path = NULL;
    size_t current_depth = 0;
    size_t current_inode_index = 1;
    while (1 == 1) {
        print_path(current_depth, current_path);
        printf(" $>");
        char command[20];
        scanf("%s", command);
        if (strcmp(command, "ls") == 0) {
            char path[BLOCK_SIZE];
            scanf("%s", path);
            char** splitted;
            size_t depth = split_path(path, &splitted);
            if (path[0] == '/') {
                list_directory(fd, depth, splitted, 1);
            } else {
                list_directory(fd, depth, splitted, current_inode_index);
            }
            free_path(splitted, depth);
        } else if (strcmp(command, "lsdir") == 0) {
            list_directory(fd, 0, NULL, current_inode_index);
        } else if (strcmp(command, "mkdir") == 0) {
            char path[BLOCK_SIZE];
            scanf("%s", path);
            char** splitted;
            size_t depth = split_path(path, &splitted);
            if (path[0] == '/') {
                make_dir(fd, depth, splitted, 1);
            } else {
                make_dir(fd, depth, splitted, current_inode_index);
            }
            free_path(splitted, depth);
        } else if (strcmp(command, "cd") == 0) {
            char path[BLOCK_SIZE];
            scanf("%s", path);
            char** splitted;
            size_t len = split_path(path, &splitted);
            if (path[0] == '/') {
                get_inode_of_file(fd, splitted, len, 1, &current_inode_index);
                free_path(current_path, current_depth);
                current_depth = len;
                current_path = splitted;
            } else {
                if (get_inode_of_file(fd, splitted, len, current_inode_index, &current_inode_index) == NULL) {
                    printf("Something has gone wrong\n");
                    continue;
                }
                char** new_path;
                current_depth = concat_paths(current_depth, current_path, len, splitted, &new_path);
                free(current_path);
                current_path = new_path;
                current_depth = canonize_path(&current_path, current_depth);
            }
        } else if (strcmp(command, "upload") == 0) {
            char file_path[BLOCK_SIZE];
            char fs_path[BLOCK_SIZE];
            scanf("%s %s", file_path, fs_path);
            int file_fd = open(file_path, O_RDONLY);
            if (file_fd == -1) {
                printf("File don't exists\n");
                continue;
            }
            char** splitted;
            size_t len = split_path(fs_path, &splitted);
            if (fs_path[0] == '/') {
                upload_file(fd, file_fd, splitted, len, ROOT_INODE_INDEX);
            } else {
                upload_file(fd, file_fd, splitted, len, current_inode_index);
            }
            free_path(splitted, len);
        } else if (strcmp(command, "cat") == 0) {
            char path[BLOCK_SIZE];
            scanf("%s", path);
            char** splitted;
            size_t len = split_path(path, &splitted);
            if (path[0] == '/') {
                concatenate(fd, splitted, len, ROOT_INODE_INDEX);
            } else {
                concatenate(fd, splitted, len, current_inode_index);
            }
            free_path(splitted, len);
        } else if (strcmp(command, "rmf") == 0) {
            char path[BLOCK_SIZE];
            scanf("%s", path);
            char** splitted;
            size_t len = split_path(path, &splitted);
            inode* file_inode;
            inode* folder_inode;
            size_t file_inode_index;
            if (path[0] == '/') {
                file_inode = get_inode_of_file(fd, splitted, len, ROOT_INODE_INDEX, &file_inode_index);
                folder_inode = get_inode_of_file(fd, splitted, len - 1, ROOT_INODE_INDEX, NULL);
            } else {
                file_inode = get_inode_of_file(fd, splitted, len, current_inode_index, &file_inode_index);
                folder_inode = get_inode_of_file(fd, splitted, len - 1, current_inode_index, NULL);
            }
            if (folder_inode == NULL || file_inode == NULL) {
                printf("%s does not exist\n", path);
                continue;
            }
            if (check_directory(file_inode) == FOLDER_ATTR) {
                printf("%s is a directory\n", path);
            }
            remove_file(fd, folder_inode, file_inode, file_inode_index);
            free(file_inode);
        } else if (strcmp(command, "rmd") == 0) {
            char path[BLOCK_SIZE];
            scanf("%s", path);
            char** splitted;
            size_t len = split_path(path, &splitted);
            inode* folder_inode;
            if (path[0] == '/') {
                folder_inode = get_inode_of_file(fd, splitted, len, ROOT_INODE_INDEX, NULL);
            } else {
                folder_inode = get_inode_of_file(fd, splitted, len, current_inode_index, NULL);
            }
            remove_dir(fd, folder_inode);
            free(folder_inode);
            current_path = NULL;
            current_inode_index = ROOT_INODE_INDEX;
        }
    }
}

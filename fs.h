
#ifndef LINUX_2021SPRING_FS_H
#define LINUX_2021SPRING_FS_H
typedef struct {
    size_t number_of_inodes;
    size_t max_number_of_blocks;
    size_t imap_blocks;
    size_t bmap_blocks;
    size_t max_fs_size;
    size_t first_data_block;
    size_t truncated_blocks;
} super_block;

typedef struct {
    size_t inode_index;
    uint8_t name_len;
    char name[BYTES_FOR_NAME];
} dir_entry;


typedef struct {
    uint32_t attributes;
    uint32_t file_size;
    size_t mappings[INODE_MAPPING_SIZE];
} inode;

typedef struct {
    size_t mapping_size;
    size_t* mappings;
} mappings_list;


struct dir_entry_list_node {
    dir_entry* entry;
    struct dir_entry_list_node* next;
};

struct dir_entry_list {
    struct dir_entry_list_node* tail;
    struct dir_entry_list_node* head;
};

#endif //LINUX_2021SPRING_FS_H

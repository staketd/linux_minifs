#pragma once
#include <stddef.h>
#include <inttypes.h>
#include "constants.h"

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
    dir_entry entry;
    struct dir_entry_list_node* next;
};

struct dir_entry_list {
    struct dir_entry_list_node* tail;
    struct dir_entry_list_node* head;
};

super_block* get_super_block(int fd);
void* map_block(int fd, size_t block_offset);
mappings_list* get_mapping_list(int fd, inode* inode);
dir_entry* get_dir_entry(void* block, size_t entry_index);
size_t get_free_entry_in_block(int fd, size_t block_offset);
size_t get_free_bit_in_block(int fd, size_t block_index);
void init_dir_in_block(int fd, size_t block_offset, size_t inode_index, size_t parent_inode_index);
void set_bit_in_block(int fd, size_t block_index, size_t bit_index, uint8_t value);
size_t allocate_block(int fd);
void deallocate_block(int fd, size_t block_index);
void deallocate_inode(int fd, size_t inode_index);
inode* get_inode(int fd, size_t inode_index);
void init_root_directory(int fd);
void init_superblock(int fd);
void init_mappings(int fd);
void init_inodes(int fd);
void init(int fd);
uint32_t check_directory(inode* inode);
struct dir_entry_list* get_block_dir_entry_list(int fd, size_t block_offset);
struct dir_entry_list* get_dir_entry_list(int fd, mappings_list* list);
void free_mappings_list(mappings_list* list);
void free_entry_dir_list_node(struct dir_entry_list_node* list);
void free_entry_dir_list(struct dir_entry_list* list);
int dir_exists(struct dir_entry_list* list, const char* dir);
size_t get_inode_index(struct dir_entry_list* list, const char* name);
inode* get_inode_of_file(int fd, char* path[], size_t depth, size_t current_inode_index, size_t* result_index);
int list_directory(int fd, size_t dirs, char* path[], size_t current_inode_index, struct dir_entry_list_node* head);
size_t split_path(const char* path_old, char*** ans);
size_t concat_paths(size_t len1, char** path1, size_t len2, char** path2, char*** ans);
size_t find_free_inode_index(int fd);
void add_block_to_inode_mapping(int fd, size_t block_index, size_t inode_index);
void add_entry(int fd, inode* folder_inode, dir_entry* entry, size_t folder_inode_index);
size_t allocate_inode(int fd, uint8_t attrs, uint32_t file_size);
void set_mapping_inode(int fd, size_t inode_index, size_t mapping_id, size_t mapping_value);
int check_exists(struct dir_entry_list_node* node, const char* name);
int make_dir(int fd, size_t depth, char* path[], size_t current_inode_index);
void free_path(char** path, size_t len);
int upload_file(int fd, int file_fd, char* path[], size_t len, size_t current_inode_index, size_t file_size);
int concatenate_and_write_to_fd(int fd, char** path, size_t len, size_t current_inode_index, int write_to_fd);
size_t canonize_path(char*** path, size_t len);
void remove_entry(int fd, inode* folder_inode, size_t file_inode_index);
int remove_file(int fd, inode* folder_inode, inode* file_inode, size_t file_inode_index);
int remove_dir(int fd, inode* dir_inode);
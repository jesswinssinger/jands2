/*
 JANDS2: Jess and Santi 2.0
  * FAT file system
 FUSE: Filesystem in Userspace
 Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>
 gcc -Wall `pkg-config fuse --cflags --libs` jands2.c -o jands2
 TODO:
  * Support directories larger than block size.
  * edit mkdir to adjust for availability
  * add permissions for admin
  * update getattr for links
*/

#define FUSE_USE_VERSION 26

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <sys/time.h>
#include <math.h>

#define FAT_DISK 10000000
#define BLOCK_SIZE 4096
#define FAT_ENTRY_COUNT 2440
#define FAT_OFFSET 1
#define ROOT_OFFSET 3
#define DATA_OFFSET 4
#define EOC 0
#define MAX_FILENAME_LEN 32
#define MAX_PATH_LEN 1000

/* STRUCTS and UNIONS */
typedef struct {
	size_t fs_size;             //< size of filesystem (10MB)
	size_t block_size;          //< size of blocks (4096B)
	size_t fat_loc;             //< offset of fat
	size_t num_fat_entries;     //< # of entries in fat (2440 entries)
	size_t root_loc;            //< offset of root dir table
	size_t data_loc;            //< offset of data
	size_t free_list;           //< first block in free list
	size_t data_blocks_used;    //< # of blocks currently in use
	size_t unpriv_availability; //< # of blocks usable by unprivileged users
}
	jands_superblock;

typedef union {
	jands_superblock s;
	char pad[BLOCK_SIZE];
}
	padded_superblock;

typedef union {
	size_t f[FAT_ENTRY_COUNT];
	char pad[BLOCK_SIZE*2];
}
	padded_fat;

typedef struct {
	char name[MAX_FILENAME_LEN]; //< Name of file/dir (limited to 32 chars)
	char attr;     //< Attributes
	size_t mode;      //< Permissions
	size_t block_num; //< Block num (to find in FAT)
	size_t size;      //< Size of file; if subdir, set to 0
	time_t atime;	  //< last accessed
	time_t mtime;	  //< last modified
}
	dir_entry;

typedef struct {
	size_t num_entries;
	dir_entry entries[(BLOCK_SIZE - 1)/sizeof(dir_entry)];
}
	dir_table;

typedef union {
	dir_table d;
	char pad[BLOCK_SIZE];
}
	padded_dir_table;

//TODO: make this nonpadded to accomodate multiple files per block?
typedef struct {
	char data[BLOCK_SIZE];
}
	data_block;


/* FUNCTION DECLARATIONS */
static void print_dir_table(padded_dir_table *table);
static void print_dir_entry(dir_entry *entry);
static int parse_path(const char *path, char *dir_path, char *filename);
static int get_padded_table(const char *path, padded_dir_table *table);
static int get_entry(dir_entry *entry, padded_dir_table *table, char* filename);
static int get_entry_and_table(dir_entry *entry, padded_dir_table *table, const char* path);
static int create_dir_entry(dir_entry *entry, const char* filename,
				    int attr, mode_t mode, unsigned int block_num, size_t size);
static int get_free_block(int* free_blk);
static int update_superblock();
static int update_fat();
static int update_table(padded_dir_table* table);

/* GLOBAL VARIABLES */
int BACKING_STORE;
jands_superblock superblock;
unsigned int fat[FAT_ENTRY_COUNT];
size_t max_dir_entries;


static void print_dir_entry(dir_entry *entry)
{
	printf("PRINTING DIR ENTRY\n");
	printf("NAME: %s\n", entry->name);
	printf("ATTR: %d\n", entry->attr);
	printf("MODE: %zu\n", entry->mode);
	printf("BLOCK_NUM: %zu\n", entry->block_num);
	printf("SIZE: %zu\n", entry->size);
}

static void print_dir_table(padded_dir_table *table)
{
	printf("PRINTING DIR TABLE\n");
	printf("NUM ENTRIES: %zu\n", table->d.num_entries);
	int i;
	for (i = 0; i < table->d.num_entries; i++) {
		print_dir_entry(&(table->d.entries[i]));
	}
}

static int parse_path(const char *path, char *dir_path, char *filename)
{
	printf("IN PARSE_PATH\n");
	printf("path = %s", path);

	if (strcmp(path, "") == 0)
		return -1;

	if (strcmp(path, "/") == 0) {
		strcpy(dir_path, "/");
		strcpy(filename, ".");
		return 0;
	}

	char path_cpy[strlen(path) + 1];
	strcpy(path_cpy, path);

	char* token = strtok(path_cpy, "/");

	strcpy(dir_path, "/");
	while (token[0] != '\0') {
		strcpy(filename, token);
		token = strtok(NULL, "/");

		if (!token)
			break;
		strcat(dir_path, filename);
		strcat(dir_path, "/");
	}

	if (strlen(dir_path) > 1)
		dir_path[strlen(dir_path) - 1] = '\0';

	if (strcmp(filename, "") == 0)
		return -1;
	printf("TOKEN AT END: %s\n", token);
	printf("DIR_PATH PARSED: %s\n", dir_path);
	printf("FILENAME PARSED: %s\n\n", filename);
	return 0;
}

/** get_padded_table()
 *  Buffers padded_dir_table into table based on path
 *  Returns -1 if directory does not exist
 */
static int get_padded_table(const char *path, padded_dir_table *table)
{
	printf("IN get_padded_table\n\n");
	printf("PATH = %s\n", path);

	int res = 0;

	if (strcmp(path, "") == 0)
		return -1;

	res = lseek(BACKING_STORE, superblock.root_loc, SEEK_SET);
	if (res < 0)
		return res;

	res = read(BACKING_STORE, table, BLOCK_SIZE);
	if (res < 0)
		return res;

	printf("READ IN ROOT TABLE\n");
	print_dir_table(table);

	char dir_path[MAX_PATH_LEN];
	char filename[MAX_FILENAME_LEN];
	res = parse_path(path, dir_path, filename);
	if (res < 0)
		return res;

	printf("path parsed: dir_path = %s and filename = %s\n", dir_path, filename);

	if (strcmp(dir_path, "/") == 0)
		return 0;

	dir_entry next_entry;
	char* token = strtok(dir_path, "/");

	while (token != NULL) {
		printf("TOKEN IS NOT EMPTY: %s\n", token);
		res = get_entry(&next_entry, table, token);
		printf("DIR_PATH SO FAR: %s", dir_path);
		print_dir_entry(&next_entry);

		if (res < 0)
			return res;

		res = lseek(BACKING_STORE, next_entry.block_num*BLOCK_SIZE, SEEK_SET);
		if (res < 0)
			return res;
		res = read(BACKING_STORE, table, BLOCK_SIZE);
		if (res < 0)
			return res;

		print_dir_table(table);
		token = strtok(NULL, "/");
	}
	return 0;
}


/* get_entry(dir_entry *dir_entry, padded_dir_table table, char* filename)
 *
 * Buffers directory table entry requested (based on filename) into dir_entry
 * Returns index of entry in table on success, errors if entry doesn't exist.
 */
static int get_entry(dir_entry *entry, padded_dir_table *table, char* filename)
{
	printf("IN GET TABLE ENTRY\n");
	printf("GETTING ENTRY FOR %s\n", filename);

	int i = 0;
	if (strcmp(filename, "/") == 0)
		filename = ".";

	for (i = 0; i < table->d.num_entries; i++) {
		if (strcmp(table->d.entries[i].name, filename) == 0) {
			*entry = table->d.entries[i];
			printf("FOUND ENTRY FOR %s\n", filename);
			print_dir_entry(entry);
			return i;
		}
	}
	return -ENOENT;
}

/** get_entry_and_table(dir_entry *entry, padded_dir_table *table,
 * 						const char* path)
 *
 * Buffers entry and parent table into entry and table for given
 * path.
 * \returns index of entry in table on success,
 *			-ENOENT if entry could not be found.
 */
static int get_entry_and_table(dir_entry *entry, padded_dir_table *table,
	const char* path)
{
	printf("IN GET_ENTRY_AND_TABLE\n");
	int res;

	res = get_padded_table(path, table);

	if (res < 0)
		return res;

	char dir_path[MAX_PATH_LEN];
	char filename[MAX_FILENAME_LEN];
	res = parse_path(path, dir_path, filename);
	if (res < 0)
		return res;

	return get_entry(entry, table, filename);
}

/* create_dir_entry(...)
 * Updates data members of dir_entry based on values passed in arguments
 */
static int create_dir_entry(dir_entry *entry, const char* filename,
					int attr, mode_t mode, unsigned int block_num, size_t size)
{
	printf("IN create_dir_entry\n\n");
	strcpy(entry->name, filename);
	entry->attr = attr;
	entry->mode = mode;
	entry->block_num = block_num;
	entry->size = size;
	entry->atime = time(NULL);
	entry->mtime = time(NULL);

	return 0;
}

/** get_free_block(int* free_blk)
 *
 * Saves next free block to passed arg.
 * Marks next available free block as full in FAT.
 * \returns 0 on success.
 */
static int get_free_block(int* free_blk)
{
	printf("CHECKING FOR FREE BLOCK.... get_free_block()\n");
	if (fat[superblock.free_list] == EOC ||
	(superblock.data_blocks_used > superblock.unpriv_availability)) {
		return -ENOSPC;
	}

	int old_free_list = superblock.free_list;

	superblock.free_list = fat[superblock.free_list];
	superblock.data_blocks_used += 1;
	int update_sb_check = update_superblock();
	if (update_sb_check < 0) {
		return update_sb_check;
	}

	fat[old_free_list] = EOC;
	int update_fat_check = update_fat();
	if (update_fat_check < 0) {
		return update_fat_check;
	}

	*free_blk = old_free_list;
	return 0;
}

/** update_superblock()
 *
 * Writes superblock to BACKING_STORE.
 */
static int update_superblock()
{
	printf("IN UPDATE_superblock\n");
	int write_check;

	printf("updating....\n");
	printf("freelist = %zu", superblock.free_list);
	printf("used blocks = %zu", superblock.data_blocks_used);
	padded_superblock ps;
	ps.s = superblock;

	lseek(BACKING_STORE, 0, SEEK_SET);
	write_check = write(BACKING_STORE, &ps, BLOCK_SIZE);

	if (write_check < 0)
		return write_check;
	printf("SUPERBLOCK UPDATED\n");
	return 0;
}

/** update_fat()
 *
 * Writes fat to BACKING_STORE.
 */
static int update_fat()
{
	printf("UPDATING FAT\n");
	padded_fat pf;
	memcpy(pf.f, fat, sizeof(fat));
	lseek(BACKING_STORE, FAT_OFFSET * BLOCK_SIZE, SEEK_SET);

	int write_check = write(BACKING_STORE, &pf, BLOCK_SIZE*2);
	if (write_check < 0)
		return write_check;
	printf("FAT UPDATED\n");
	return 0;
}

/** update_table(padded_dir_table* table)
 *
 * Writes table to BACKING_STORE.
 */
static int update_table(padded_dir_table* table)
{
	printf("UPDATING TABLE\n");
	lseek(BACKING_STORE, table->d.entries[0].block_num * BLOCK_SIZE, SEEK_SET);

	int write_check = write(BACKING_STORE, table, BLOCK_SIZE);
	if (write_check < 0)
		return write_check;
	printf("TABLE UPDATED\n");
	return 0;
}

static int jands_access(const char *path, int mask)
{
	printf("IN ACCESS\n\n");

	dir_entry entry;
	padded_dir_table table;
	int res = get_entry_and_table(&entry, &table, path);

	if (res < 0) // errors
		return res;
	else // returned index of entry successfully
		return 0;
}

static int jands_getattr(const char *path, struct stat *stbuf)
{
	printf("IN GETATTR\n\n");
	int res;

	dir_entry entry;
	padded_dir_table table;
	res = get_entry_and_table(&entry, &table, path);
	if (res < 0)
		return res;

	stbuf->st_uid = getuid();
	stbuf->st_gid = getgid();
	stbuf->st_mtime = entry.mtime;
	stbuf->st_mode = entry.mode;
	stbuf->st_size = entry.size;
	stbuf->st_blksize = BLOCK_SIZE;

	time_t new_atime = time(NULL);
	if (entry.mode & S_IFDIR) {
		/* Update access time in parent dir */
		table.d.entries[res].atime = new_atime;
		update_table(&table);

		/* Update access time in subdir */
		padded_dir_table subdir;
		res = lseek(BACKING_STORE, table.d.entries[res].block_num * BLOCK_SIZE, SEEK_SET);
		if (res < 0)
			return res;
		res = read(BACKING_STORE, &subdir, BLOCK_SIZE);
		if (res < 0)
			return res;
		subdir.d.entries[0].atime = new_atime;
		update_table(&subdir);

		stbuf->st_nlink = 2; //TODO: LINKS
		stbuf->st_atime = new_atime;
	}
	else {
		stbuf->st_nlink = 1;
		stbuf->st_atime = new_atime;
	}

	return 0;
}

static int jands_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
		   off_t offset, struct fuse_file_info *fi)
{
	printf("IN READDIR\n");
	(void) fi;

	int res;

	dir_entry entry;
	padded_dir_table table;

	res = get_entry_and_table(&entry, &table, path);
	if (res < 0)
		return res;

	/* Update access time of dir about to be read. */
	table.d.entries[res].atime = time(NULL);

	update_table(&table);

	/* Get dir table of directory being read. */
	res = lseek(BACKING_STORE, entry.block_num*BLOCK_SIZE, SEEK_SET);
	if (res < 0)
		return res;
	res = read(BACKING_STORE, &table, BLOCK_SIZE);
	if (res < 0)
		return res;

	/* Update access time of . */
	table.d.entries[0].atime = time(NULL);
	update_table(&table);

	/* Buffer the entries into buf using filler. */
	int counter = offset;
	while ( counter < table.d.num_entries ) {
		entry = table.d.entries[counter];
		filler(buf, entry.name, NULL, counter+1);
		counter++;
	}

	return 0;
}

static int jands_mkdir(const char *path, mode_t mode)
{
	printf("IN MKDIR\n\n");

	int res = 0;

	/* Save parent directory table. */
	padded_dir_table parent_table;
	get_padded_table(path, &parent_table);
	parent_table.d.entries[0].atime = time(NULL);
	update_table(&parent_table);

	/* If directory table is full, return error. */
	if (parent_table.d.num_entries >= max_dir_entries)
		return -errno;

	/* Check if there is a free block; if so, mark as occupied. */
	int free_blk;
	res = get_free_block(&free_blk);
	if (res < 0)
		return res;

	/* Get new directory name. */
	char dir_path[MAX_PATH_LEN];
	char filename[MAX_FILENAME_LEN];
	parse_path(path, dir_path, filename);

	/* Add entry to parent's directory table. */
	dir_entry entry;
	create_dir_entry(&entry, filename, 0x10,
									S_IFDIR | S_IRWXU | S_IRWXG | S_IRWXO, free_blk, 0);

	parent_table.d.entries[parent_table.d.num_entries] = entry;
	parent_table.d.num_entries += 1;

	res = update_table(&parent_table);
	if (res < 0)
		return res;

	/* Make new directory table. */
	strcpy(entry.name, ".");
	entry.attr = entry.attr & 0x02;

	dir_entry parent_entry = parent_table.d.entries[0];
	res = create_dir_entry(&parent_entry, "..", (parent_entry.attr & 0x02),
		  parent_entry.mode, parent_entry.block_num, parent_entry.size);
	if (res < 0)
		return res;

	padded_dir_table new_table;
	new_table.d.num_entries = 2;
	new_table.d.entries[0] = entry;
	new_table.d.entries[1] = parent_entry;

	printf("NEW TABLE CREATED\n");
	print_dir_table(&new_table);

	res = update_table(&new_table);
	return res;
}

//TODO: not sure what we would put here, since we don't have a data structure
// for files....
static int jands_release(const char* path, struct fuse_file_info *fi)
{
	return 0;
}

static int jands_fgetattr(const char* path, struct stat* stbuf)
{
	printf("IN FGETATTR\n");
	return jands_getattr(path, stbuf);
}

static int jands_mknod(const char* path, mode_t mode, dev_t rdev)
{
	printf("IN MKNOD\n");
	/* Return error if mode is not for regular file */
	if (!S_ISREG(mode))
		return -EACCES;

	int res = 0;

	printf("parsing path....");
	/* Parse path. */
	char filename[MAX_FILENAME_LEN];
	char dir_path[MAX_PATH_LEN];
	res = parse_path(path, dir_path, filename);
	if (res < 0)
		return res;

	printf("getting parent table...");
	/* Get parent directory. */
	padded_dir_table table;
	res = get_padded_table(path, &table);
	if (res < 0)
		return res;

	printf("checking file doesn't already exist....");
	/* Check that a file with same name does not exist. */
	dir_entry node;
	res = get_entry(&node, &table, filename);
	if (!res)
		return -EEXIST;

	printf("allocating free block...");
	/* Allocate free block for new file. */
	int free_block = 0;
	res = get_free_block(&free_block);
	if (res < 0)
		return res;

	printf("creating new entry for parent table...");
	/* Create new entry for directory table */
	dir_entry new_entry;
	res = create_dir_entry(&new_entry, filename, 0,
												S_IFREG | S_IRWXU | S_IRWXG | S_IRWXO, free_block, 0);
	if (res < 0)
		return res;

	printf("adding to parent dir table and updating....");
	/* Add to parent directory table */
	table.d.entries[table.d.num_entries] = new_entry;
	table.d.num_entries++;
	res = update_table(&table);

	printf("done! %d\n", res);
	return res;
}

static int jands_create(const char* path, mode_t mode)
{
	return jands_mknod(path, (mode | S_IFREG), (dev_t) NULL);
}

//TODO: can open call access?
static int jands_open(const char* path, struct fuse_file_info* fi)
{
	printf("IN JANDS_OPEN\n");
	int res = 0;

	dir_entry entry;
	padded_dir_table table;
	res = get_entry_and_table(&entry, &table, path);
	if (res < 0)
		return res;

	printf("calling jands_access in open");
	res = jands_access(path, fi->flags);
	printf("res = %d", res);
	return res;
}
/*Read size bytes from the given file into the buffer buf,
beginning offset bytes into the file. See read(2) for full details.
Returns the number of bytes transferred,
*/
static int jands_read(const char* path, char *buf, size_t size, off_t offset,
	struct fuse_file_info* fi)
{
	printf("IN READ\n\n\n\n\n");

	int res = 0;

	/* Get dir entry. */
	dir_entry entry;
	padded_dir_table table;
	res = get_entry_and_table(&entry, &table, path);
	if (res < 0)
		return res;

	/* Check that offset is not at or beyond EOF. */
	if (offset >= entry.size)
		return 0;

	/* Read size bytes into buf. */
	res = lseek(BACKING_STORE, (entry.block_num*BLOCK_SIZE)+offset, SEEK_SET);
	if (res < 0)
		return res;

	/* If size < BLOCK_SIZE - offset, just return the read. */
	if (size < BLOCK_SIZE - offset) {
		return read(BACKING_STORE, buf, size);
	}

	/* GENERAL CASE. */
	int size_left = size;

	// First read is rest of first block from offset.
	res = read(BACKING_STORE, buf, BLOCK_SIZE-offset);
	if (res < 0)
		return res;

	size_left -= (BLOCK_SIZE - offset);

	// Read rest in block_size chunks until less than a block left to read.
	int next_blk = fat[entry.block_num];
	while (((size_left % BLOCK_SIZE) > 0) && (next_blk != EOC)) {
		res = lseek(BACKING_STORE, next_blk*BLOCK_SIZE, SEEK_SET);
		if (res < 0)
			return res;
		res = read(BACKING_STORE, buf, BLOCK_SIZE);
		if (res < 0)
			return res;

		size_left -= BLOCK_SIZE;
		next_blk = fat[next_blk];
	}

	// If we reached EOF, return number of bytes read.
	if (next_blk == EOC) {
		return size - size_left;
	}

	// Otherwise, read last bits.
	lseek(BACKING_STORE, next_blk*BLOCK_SIZE, SEEK_SET);
	res = read(BACKING_STORE, buf, size_left);
	if (res < 0)
		return res;

	return size;
}

//static int jands_readlink(const char* path, char* buf, size_t size)

static int jands_rmdir(const char* path)
{
	int res = 0;

	dir_entry entry;
	padded_dir_table parent_table;

	res = get_entry_and_table(&entry, &parent_table, path);
	if (res < 0)
		return res;

	/* Return error if directory is not empty. */
	if (entry.size > 0)
		return ENOTEMPTY;

	/* Remove entry from parent directory. */
	int i;
	for (i = res; i < max_dir_entries; ++i) {
		parent_table.d.entries[i] = parent_table.d.entries[i+1];
	}
	parent_table.d.num_entries--;
	res = update_table(&parent_table);
	if (res < 0)
		return res;

	/* Update free list. */
	int temp = entry.block_num;
	while (fat[temp] != EOC) {
		superblock.data_blocks_used--;
		temp = fat[temp];
	}

	fat[temp] = superblock.free_list;
	superblock.free_list = entry.block_num;
	res = update_superblock();

	return res;
}

static int jands_statfs(const char* path, struct statvfs* stbuf)
{
	printf("IN STATFS\n");
	int res = update_superblock();
	if (res < 0)
		return res;

	stbuf->f_bsize = superblock.block_size;
	stbuf->f_blocks = superblock.num_fat_entries;
	stbuf->f_bfree = superblock.num_fat_entries - superblock.data_blocks_used;
	stbuf->f_bavail = superblock.unpriv_availability - superblock.data_blocks_used;
	stbuf->f_namemax = 32;

	return 0;
}

static int jands_write(const char* path, const char *buf, size_t size, off_t offset, struct fuse_file_info* fi)
{
	printf("IN WRITE\n\n\n");
	int block_pointer;
	int res = 0;
	char curr_block[BLOCK_SIZE];

	dir_entry file;
	padded_dir_table directory;
	int entry_num = get_entry_and_table(&file, &directory, path);
	if (entry_num < 0)
		return entry_num;

	printf("entry num: %d\n\n\n", entry_num);

	block_pointer = file.block_num;

	//add in max file size

	int pointer = 0;
	while(pointer < size){
		if(offset > BLOCK_SIZE){
			offset -= BLOCK_SIZE;
			block_pointer = fat[block_pointer];
		}
		else{
			memcpy(curr_block, buf, size);
			printf("entry num: %s\n\n\n", curr_block);

			res = lseek(BACKING_STORE, block_pointer * BLOCK_SIZE + offset, SEEK_SET);
			if (res < 0)
				return res;

			if(size < BLOCK_SIZE){
				res = write(BACKING_STORE, curr_block, size);
				if(res < 0)
					return res;
				pointer += size;
				directory.d.entries[entry_num].size += size;
			}

			else{
				res = write(BACKING_STORE, curr_block, BLOCK_SIZE);
				if (res < 0)
					return res;
				pointer += BLOCK_SIZE;
				block_pointer = fat[block_pointer];
				directory.d.entries[entry_num].size += BLOCK_SIZE;
			}

			update_table(&directory);
		}
	}
	return pointer;
}

//static int jands_symlink(const char* to, const char* from)

static int jands_truncate(const char* path, off_t size)
{
	printf("IN TRUNCATE\n");
	int res;

	/* Get entry and table. */
	dir_entry entry;
	padded_dir_table table;
	res = get_entry_and_table(&entry, &table, path);
	if (res < 0)
		return res;

	int entry_index = res;

	//TODO: "set-user_ID and set_group-ID bits may be cleared"???
	if (size != entry.size) {
		/* Modify fat to reflect number of blocks occupied. */
		int old_size = table.d.entries[entry_index].size;
		double new_block_cnt = ceil(size / BLOCK_SIZE);
		double old_block_cnt = ceil(old_size / BLOCK_SIZE);
		int temp = table.d.entries[entry_index].block_num;
		int block_cnt = 0;

		if (new_block_cnt < old_block_cnt) {
			while (temp != EOC) {
				if (block_cnt == new_block_cnt) {
					while (temp != EOC) {
						temp = fat[temp];
						fat[temp] = EOC;
					}
				}
				else {
					temp = fat[temp];
					block_cnt++;
				}
			}
		}
		else if (old_block_cnt > new_block_cnt) {
			int num_new_blocks = new_block_cnt - old_block_cnt;

			while (fat[temp] != EOC) {
				temp = fat[temp];
			}

			while (block_cnt < num_new_blocks) {
				get_free_block(&(fat[temp]));

				/* Add new data_blocks (BLOCK_SIZE null bytes). */
				data_block blk;
				res = lseek(BACKING_STORE, fat[temp]*BLOCK_SIZE, BLOCK_SIZE);
				if (res < 0)
					return res;
				res = write(BACKING_STORE, &blk, BLOCK_SIZE);
				if (res < 0)
					return res;

				temp = fat[temp];
				block_cnt++;
			}
		}

		res = update_fat();
		if (res < 0)
			return res;

		//TODO: fill rest of old last block with null bytes?

	/* Update modification time and size. */
		table.d.entries[entry_index].mtime = time(NULL);
		table.d.entries[entry_index].size = size;

		res = update_table(&table);
		if (res < 0)
			return res;
	}

	return res;
}
//static int jands_unlink(const char* path)
//static int jands_write(const char* path, const char *buf, size_t size,
//                      off_t offset, struct fuse_file_info* fi)


static void* jands_init(struct fuse_conn_info *conn)
{
	printf("IN INIT\n\n");
	max_dir_entries = (BLOCK_SIZE - 1)/sizeof(dir_entry);
	int no_file = access("BACKING_STORE", F_OK);
	BACKING_STORE = open("BACKING_STORE", O_RDWR | O_CREAT, 0755);

	if (no_file) {
		/* Initialize superblock. */
		superblock.fs_size          = FAT_DISK;
		superblock.block_size       = BLOCK_SIZE;
		superblock.fat_loc          = FAT_OFFSET*BLOCK_SIZE;
		superblock.num_fat_entries  = FAT_ENTRY_COUNT;
		superblock.root_loc         = ROOT_OFFSET*BLOCK_SIZE;
		superblock.data_loc         = DATA_OFFSET*BLOCK_SIZE;
		superblock.data_blocks_used = 1;
		superblock.free_list        = 4;
		superblock.unpriv_availability = (int) FAT_ENTRY_COUNT * 0.8;

		// Add padding to superblock to occupy full block
		padded_superblock padded_sb;
		padded_sb.s = superblock;
		write(BACKING_STORE, &padded_sb, BLOCK_SIZE);

		/* Initialize fat. */
		int i;
		for (i = 0; i < 3; i++) {
		  fat[i] = EOC;
		}
		for (i = 3; i < superblock.num_fat_entries; i++) {
		  fat[i] = i+1;
		}

		fat[superblock.num_fat_entries - 1] = EOC;
		update_fat();

		/* Create root directory table */

		// Entry for root: .
		dir_entry root;
		  strcpy(root.name, ".");
		  root.attr = 0x10 & 0x04 & 0x02;
		  root.mode = S_IFDIR | S_IRWXU | S_IRWXG | S_IRWXO;
		  root.block_num = ROOT_OFFSET;
		  root.size = 0;
		  root.atime = time(NULL);
		  root.mtime = time(NULL);

		// Entry for root's parent dir: ..
		dir_entry parent;
		  strcpy(parent.name, "..");
		  parent.attr = 0x10 & 0x04 & 0x02;
		  parent.mode = S_IFDIR | S_IRWXU | S_IRWXG | S_IRWXO;
		  parent.block_num = -1;
		  parent.size = 0;
		  root.atime = time(NULL);
		  root.mtime = time(NULL);

		// Table
		dir_table root_table;
		  root_table.num_entries = 2;
		  root_table.entries[0] = root;
		  root_table.entries[1] = parent;

		// Add padding
		padded_dir_table padded_root;
		  padded_root.d = root_table;

		lseek(BACKING_STORE, superblock.root_loc, SEEK_SET);
		write(BACKING_STORE, &padded_root, BLOCK_SIZE);
	}

	else { // File already exists; read in superblock.
		padded_superblock ps;
		int read_check = read(BACKING_STORE, &ps, BLOCK_SIZE);
		if (read_check < 0)
			return -errno; //TODO how to handle corrupt backing store?

		superblock = ps.s;
	}
	return fuse_get_context()->private_data;
}

static struct fuse_operations jands_oper = {
	.getattr    = jands_getattr,
	.access     = jands_access,
	.readdir    = jands_readdir,
	.mkdir      = jands_mkdir,
	.release    = jands_release,
	.fgetattr   = jands_fgetattr,
	.mknod      = jands_mknod,
	.create     = jands_create,
	.open       = jands_open,
	.read       = jands_read,
	//.readlink = jands_readlink,
	.rmdir      = jands_rmdir,
	.statfs     = jands_statfs,
	//.symlink  = jands_symlink,
	.truncate   = jands_truncate,
	//.unlink   = jands_unlink,
	.write      = jands_write,
	.init       = jands_init,
};

int main(int argc, char *argv[])
{
	umask(0);
	return fuse_main(argc, argv, &jands_oper, NULL);
}

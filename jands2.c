/*
 JANDS2: Jess and Santi 2.0
	* FAT file system
 FUSE: Filesystem in Userspace
 Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

 gcc -Wall `pkg-config fuse --cflags --libs` jands2.c -o jands2
 TODO
  * Add global dir table for current directory. (and update fns)
  * Support directories larger than block size.
  * Add "/" to beginning of directory names for ls.
  * edit mkdir to adjust for availability
  * add permissions for admin
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
   size_t fat_loc;             //< offset from 0 where fat is (in bytes)
   size_t num_fat_entries;     //< number of entries in fat (2440 entries)
   size_t root_loc;            //< offset from 0 where root directory table is (in bytes)
   size_t data_loc;            //< offset from 0 where data is (in bytes) (1 block from root)
   size_t free_list;	        //< first block in free_list
   size_t data_blocks_used;    //< number of blocks currently in use
   size_t unpriv_availability; //< number of blocks usable by unprivileged users
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
   // int date_created;
   // int date_modified;
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


/* FUNCTION DECLARATIONS */
static void print_dir_table(padded_dir_table *table);
static void print_dir_entry(dir_entry *entry);
static int parse_path(const char *path, char *dir_path, char *filename);
static int get_padded_dir_table(const char *path, padded_dir_table *table);
static int get_entry(dir_entry *entry, padded_dir_table *table, char* filename);
static int new_dir_entry(dir_entry *entry, const char* filename, 
                           int attr, mode_t mode, unsigned int block_num, size_t size);
static int get_free_block(int* free_blk);
static int update_superblock();
static int update_fat();
static int update_table(padded_dir_table* table, unsigned int block_num);

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

/** get_padded_dir_table()
*  Buffers padded_dir_table into table based on path
*  Returns -1 if directory does not exist
*/
static int get_padded_dir_table(const char *path, padded_dir_table *table)
{
	printf("IN GET_padded_dir_table\n\n");
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
* Returns 0 on success, errors if entry doesn't exist.
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
			return 0;
		}
	}
	return -ENOENT;
}

/* new_dir_entry(...)
* Updates data members of dir_entry based on values passed in arguments
*/
static int new_dir_entry(dir_entry *entry, const char* filename, 
                           int attr, mode_t mode, unsigned int block_num, size_t size)
{
	printf("IN NEW_DIR_ENTRY\n\n");
	strcpy(entry->name, filename);
	entry->attr = attr;
	entry->mode = mode;
	entry->block_num = block_num;
	entry->size = size;

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

	*free_blk = superblock.free_list;
	return 0;
}

/** update_superblock()
*
* Writes superblock to BACKING_STORE. 
*/
static int update_superblock()
{	
	printf("IN UPDATE_superblock\n\n");
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
	printf("SUPERBLOCK UPDATED");
	return 0;
}

static int update_fat()
{
	printf("UPDATING FAT");
	padded_fat pf;
	memcpy(pf.f, fat, sizeof(fat));
	lseek(BACKING_STORE, FAT_OFFSET * BLOCK_SIZE, SEEK_SET);

	int write_check = write(BACKING_STORE, &pf, BLOCK_SIZE*2);
	if (write_check < 0)
		return write_check;
	printf("FAT UPDATED");
	return 0;
}

static int update_table(padded_dir_table* table, unsigned int block_num)
{
	printf("UPDATING TABLE");
	lseek(BACKING_STORE, block_num * BLOCK_SIZE, SEEK_SET);

	int write_check = write(BACKING_STORE, table, BLOCK_SIZE);
	if (write_check < 0)
		return write_check;
	printf("TABLE UPDATED\n");
	return 0;
}

static int jands_access(const char *path, int mask)
{
	printf("IN ACCESS\n\n");

	padded_dir_table table;
	int padded_dir_table_check = get_padded_dir_table(path, &table);

	printf("BACK FROM GET DIR TABLE\n");
	if (padded_dir_table_check < 0)
		return padded_dir_table_check;

	char dir_path[MAX_PATH_LEN];
	char filename[MAX_FILENAME_LEN];
	
	int parse_path_check = parse_path(path, dir_path, filename);
	if (parse_path_check < 0)
		return parse_path_check;
	
	dir_entry entry;
	printf("ABOUT TO GET DIR ENTRY\n");
	return get_entry(&entry, &table, filename);
}

static int jands_getattr(const char *path, struct stat *stbuf)
{
	printf("IN GETATTR\n\n");

	padded_dir_table table;
	printf("getting dir table for %s\n", path);
	int get_dir_check = get_padded_dir_table(path, &table);
	if (get_dir_check < 0)
		return get_dir_check;

	char dir_path[MAX_PATH_LEN];
	char filename[MAX_FILENAME_LEN];
	int parse_path_check = parse_path(path, dir_path, filename);
	
	if (parse_path_check < 0)
		return parse_path_check;

	dir_entry entry;
	int get_entry_check = get_entry(&entry, &table, filename);

	if (get_entry_check < 0)
		return get_entry_check;
		
	stbuf->st_mode = S_IFDIR | entry.mode;
	stbuf->st_size = entry.size;
	stbuf->st_blksize = BLOCK_SIZE;
	if (strcmp(path, "/") == 0)
		stbuf->st_nlink = 2;
	else
		stbuf->st_nlink = 1;

	return 0;
}

static int jands_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
		       off_t offset, struct fuse_file_info *fi)
{
	printf("IN READDIR\n\n");
	(void) fi;

	int res = 0;

	padded_dir_table table;
	res = get_padded_dir_table(path, &table);
	if (res < 0)
		return res;

	char dir_path[MAX_PATH_LEN];
	char filename[MAX_FILENAME_LEN];	
	parse_path(path, dir_path, filename);

	dir_entry entry;
	res = get_entry(&entry, &table, filename);
	if (res < 0)
		return res;

	res = lseek(BACKING_STORE, entry.block_num*BLOCK_SIZE, SEEK_SET);
	if (res < 0)
		return res;
	res = read(BACKING_STORE, &table, BLOCK_SIZE);
	if (res < 0)
		return res;

	int counter = offset;
	while ( counter < table.d.num_entries ) {
		filler(buf, table.d.entries[counter].name, NULL, counter+1);
		counter += 1;
	}

	return 0;
}

static int jands_mkdir(const char *path, mode_t mode)
{
	printf("IN MKDIR\n\n");

	int res = 0;

	/* Save parent directory table. */
	padded_dir_table parent_table;
	get_padded_dir_table(path, &parent_table);

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
	new_dir_entry(&entry, filename, 0x10, mode, free_blk, 0);
	printf("NEW ENTRY IN ROOT TABLE:::::\n");
	print_dir_entry(&entry);
	parent_table.d.entries[parent_table.d.num_entries] = entry;
	parent_table.d.num_entries += 1;
	res = update_table(&parent_table, parent_table.d.entries[0].block_num);
	print_dir_table(&parent_table);
	if (res < 0)
		return res;

	/* Make new directory table. */
	strcpy(entry.name, ".");
	entry.attr = entry.attr & 0x02;

	dir_entry parent_entry = parent_table.d.entries[0];
	res = new_dir_entry(&parent_entry, "..", (parent_entry.attr & 0x02), 
					parent_entry.mode, parent_entry.block_num, parent_entry.size);
	if (res < 0)
		return res;

	padded_dir_table new_table;
		new_table.d.num_entries = 2;
		new_table.d.entries[0] = entry;
		new_table.d.entries[1] = parent_entry;

	printf("NEW TABLE CREATED\n");
	print_dir_table(&new_table);

	res = update_table(&new_table, entry.block_num);
	return res;
}

//static int jands_release(const char* path, struct fuse_file_info *fi)
//static int jands_create(const char* path, mode_t mode)
//static int jands_fgetattr(const char* path, struct stat* stbuf)
static int jands_mknod(const char* path, mode_t mode, dev_t rdev)
{
	if (!S_ISREG(mode))
		return -EACCES;

	int res = 0;

	char filename[MAX_FILENAME_LEN];
	char dir_path[MAX_PATH_LEN];

	res = parse_path(path, dir_path, filename);
	if (res < 0)
		return res;

	padded_dir_table table;
	res = get_padded_dir_table(path, &table);

	dir_entry node;
	int check_no_exist = get_entry(&node, &table, filename);

	if (check_no_exist > -1)
		return -EEXIST;


	int free_block = 0;
	res = get_free_block(&free_block);
	if (res < 0)
		return res;

	dir_entry new_entry;
	res = new_dir_entry(&new_entry, filename, 0, mode, free_block, 0);

	return res;
}

// static int jands_open(const char* path, struct fuse_file_info* fi)




//static int jands_read(const char* path, char *buf, size_t size, off_t offset, struct fuse_file_info* fi)
//static int jands_readlink(const char* path, char* buf, size_t size)
//static int jands_rmdir(const char* path)

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

//symlink(const char* to, const char* from)
//truncate(const char* path, off_t size)
//unlink(const char* path)
//write(const char* path, const char *buf, size_t size, off_t offset, struct fuse_file_info* fi)


static void* jands_init(struct fuse_conn_info *conn)
{
   printf("IN INIT\n\n");
	int no_file = access("BACKING_STORE", F_OK);
	BACKING_STORE = open("BACKING_STORE", O_RDWR | O_CREAT, 0777);
	max_dir_entries = (BLOCK_SIZE-1)/sizeof(dir_entry);
	
	if (no_file) {
		int i;

		/* Create superblock */
		superblock.fs_size          = FAT_DISK;
		superblock.block_size       = BLOCK_SIZE;
		superblock.fat_loc          = FAT_OFFSET*BLOCK_SIZE;
		superblock.num_fat_entries  = FAT_ENTRY_COUNT;
		superblock.root_loc         = ROOT_OFFSET*BLOCK_SIZE;
		superblock.data_loc         = DATA_OFFSET*BLOCK_SIZE;
		superblock.data_blocks_used = 1;
		superblock.free_list        = 4;
		superblock.unpriv_availability = (int) FAT_ENTRY_COUNT * 0.8;

		/* Add padding to superblock to ensure it occupies a full block */
		padded_superblock padded_sb;
		padded_sb.s = superblock;

		write(BACKING_STORE, &padded_sb, BLOCK_SIZE);

		/* Initialize fat. */
		for (i = 0; i < 3; i++)
			fat[i] = EOC;

		for (i = 3; i < superblock.num_fat_entries; i++)
			fat[i] = i+1;

		fat[superblock.num_fat_entries - 1] = EOC;

		update_fat();

		/* Create root directory table */
		dir_entry root;
			strcpy(root.name, ".");
			//0x10 = a directory
			//0x04 = belongs to the system (i.e. root cannot be moved)
			//0x02 = hidden
			root.attr = 0x10 & 0x04 & 0x02;
			root.mode = 0777;
			root.block_num = ROOT_OFFSET;
			root.size = 0;
		
		dir_entry parent;
			strcpy(parent.name, "..");
			//0x10 = a directory
			//0x04 = belongs to the system (i.e. parent of root cannot be moved)
			//0x02 = hidden
			parent.attr = 0x10 & 0x04 & 0x02;
			parent.mode = 0777;
			parent.block_num = -1;
			parent.size = 0;

		dir_table root_table;
			root_table.num_entries = 2;
			root_table.entries[0] = root;
			root_table.entries[1] = parent;

		padded_dir_table padded_root;
			padded_root.d = root_table;

		print_dir_table(&padded_root);

		lseek(BACKING_STORE, superblock.root_loc, SEEK_SET);
		write(BACKING_STORE, &padded_root, BLOCK_SIZE);
	}
	else {
		padded_superblock ps;
		int read_success = read(BACKING_STORE, &ps, BLOCK_SIZE);
		if (read_success == -1)
			return -errno;

		superblock = ps.s;
	}
   return fuse_get_context()->private_data;
}

static struct fuse_operations jands_oper = {
	.getattr	= jands_getattr,
	.access		= jands_access,
	.readdir	= jands_readdir,
	.mkdir		= jands_mkdir,
	// .open		= jands_open,
	.mknod      = jands_mknod,
	.statfs     = jands_statfs,
	.init       = jands_init,
};

int main(int argc, char *argv[])
{ 
   umask(0);
	return fuse_main(argc, argv, &jands_oper, NULL);
}

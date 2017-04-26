/*
 * Copyright (c) 2005 Rob Braun
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of Rob Braun nor the names of his contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
/*
 * 03-Apr-2005
 * DRI: Rob Braun <bbraun@opendarwin.org>
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fts.h>
#include <unistd.h>
#include <fcntl.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <libxml/xmlreader.h>
#include <libxml/xmlwriter.h>
#include <libxml/xmlstring.h>
#include <limits.h>
#include <getopt.h>
#include <regex.h>
#include <errno.h>
#include "xar.h"
#include "config.h"

#define SYMBOLIC 1
#define NUMERIC  2
static int Perms = 0;
static int Local = 0;
static char *Subdoc = NULL;
static char *SubdocName = NULL;
static char *Toccksum = NULL;
static char *Compression = NULL;
static char *Rsize = NULL;

static int Err = 0;
static int Verbose = 0;
static int Coalesce = 0;
static int LinkSame = 0;

struct lnode {
	char *str;
	regex_t reg;
	struct lnode *next;
};

struct lnode *Exclude = NULL;
struct lnode *Exclude_Tail = NULL;
struct lnode *NoCompress = NULL;
struct lnode *NoCompress_Tail = NULL;

static int32_t err_callback(int32_t sev, int32_t err, xar_errctx_t ctx, void *usrctx);

static void print_file(xar_file_t f) {
	if( Verbose ) {
		char *path = xar_get_path(f);
		printf("%s\n", path);
		free(path);
	}
}

static void add_subdoc(xar_t x) {
	xar_subdoc_t s;
	int fd;
	unsigned char *buf;
	unsigned int len;
	struct stat sb;

	if( SubdocName == NULL ) SubdocName = "subdoc";

	fd = open(Subdoc, O_RDONLY);
	if( fd < 0 ) {
		fprintf(stderr, "ERROR: subdoc file %s doesn't exist.  Ignoring.\n", Subdoc);
		return;
	}
	s = xar_subdoc_new(x, (const char *)SubdocName);
	fstat(fd, &sb);
	len = sb.st_size;
	buf = malloc(len+1);
	if( buf == NULL ) {
		close(fd);
		return;
	}
	memset(buf, 0, len+1);
	read(fd, buf, len);
	close(fd);

	xar_subdoc_copyin(s, buf, len);


	return;
}

static void extract_subdoc(xar_t x, const char *name) {
	xar_subdoc_t i;

	for( i = xar_subdoc_first(x); i; i = xar_subdoc_next(i) ) {
		const char *sname = xar_subdoc_name(i);
		unsigned char *sdoc;
		int fd, size;
		if( name && strcmp(name, sname) != 0 )
			continue;
		xar_subdoc_copyout(i, &sdoc, (unsigned int *)&size);
		fd = open(Subdoc, O_WRONLY|O_CREAT|O_TRUNC, 0644);
		if( fd < 0 ) return;
		write(fd, sdoc, size);
		close(fd);
		free(sdoc);
	}

	return;
}

static int archive(const char *filename, int arglen, char *args[]) {
	xar_t x;
	FTS *fts;
	FTSENT *ent;
	int flags;
	struct lnode *i;
	const char *default_compression;

	x = xar_open(filename, WRITE);
	if( !x ) {
		fprintf(stderr, "Error creating archive %s\n", filename);
		exit(1);
	}

	if( Toccksum )
		xar_opt_set(x, XAR_OPT_TOCCKSUM, Toccksum);

	if( Compression )
		xar_opt_set(x, XAR_OPT_COMPRESSION, Compression);

	if( Coalesce )
		xar_opt_set(x, XAR_OPT_COALESCE, "true");

	if( LinkSame )
		xar_opt_set(x, XAR_OPT_LINKSAME, "true");

	if ( Rsize != NULL )
		xar_opt_set(x, XAR_OPT_RSIZE, Rsize);

	xar_register_errhandler(x, err_callback, NULL);

	if( Subdoc )
		add_subdoc(x);

	if( Perms == SYMBOLIC ) {
		xar_opt_set(x, XAR_OPT_OWNERSHIP, XAR_OPT_VAL_SYMBOLIC);
	}
	if( Perms == NUMERIC ) {
		xar_opt_set(x, XAR_OPT_OWNERSHIP, XAR_OPT_VAL_NUMERIC);
	}

	default_compression = strdup(xar_opt_get(x, XAR_OPT_COMPRESSION));
	if( !default_compression )
		default_compression = strdup(XAR_OPT_VAL_GZIP);

	flags = FTS_PHYSICAL|FTS_NOSTAT|FTS_NOCHDIR;
	if( Local )
		flags |= FTS_XDEV;
	fts = fts_open(args, flags, NULL);
	if( !fts ) {
		fprintf(stderr, "Error traversing file tree\n");
		exit(1);
	}

	while( (ent = fts_read(fts)) ) {
		xar_file_t f;
		int exclude_match = 1;
		int nocompress_match = 1;
		if( ent->fts_info == FTS_DP )
			continue;

		if( strcmp(ent->fts_path, "/") == 0 )
			continue;
		if( strcmp(ent->fts_path, ".") == 0 )
			continue;
		
		for( i = Exclude; i; i=i->next ) {
			exclude_match = regexec(&i->reg, ent->fts_path, 0, NULL, 0);
			if( !exclude_match )
				break;
		}
		if( !exclude_match ) {
			if( Verbose )
				printf("Excluding %s\n", ent->fts_path);
			continue;
		}

		for( i = NoCompress; i; i=i->next ) {
			nocompress_match = regexec(&i->reg, ent->fts_path, 0, NULL, 0);
			if( !nocompress_match ) {
				xar_opt_set(x, XAR_OPT_COMPRESSION, XAR_OPT_VAL_NONE);
				break;
			}
		}
		f = xar_add(x, ent->fts_path);
		if( !f ) {
			fprintf(stderr, "Error adding file %s\n", ent->fts_path);
		} else {
			print_file(f);
		}
		if( !nocompress_match )
			xar_opt_set(x, XAR_OPT_COMPRESSION, default_compression);
	}
	fts_close(fts);
	if( xar_close(x) != 0 ) {
		fprintf(stderr, "Error creating the archive\n");
		if( !Err )
			Err = 42;
	}

	free((char *)default_compression);
	for( i = Exclude; i; ) {
		struct lnode *tmp;
		regfree(&i->reg);
		tmp = i;
		i = i->next;
		free(tmp);
	}
	for( i = NoCompress; i; ) {
		struct lnode *tmp;
		regfree(&i->reg);
		tmp = i;
		i = i->next;
		free(tmp);
	}

	return Err;
}

static int extract(const char *filename, int arglen, char *args[]) {
	xar_t x;
	xar_iter_t i;
	xar_file_t f;
	int files_extracted = 0;
	int argi;
	struct lnode *extract_files = NULL;
	struct lnode *extract_tail = NULL;
	struct lnode *lnodei = NULL;

	for(argi = 0; args[argi]; argi++) {
		struct lnode *tmp;
		int err;
		tmp = malloc(sizeof(struct lnode));
		tmp->str = strdup(args[argi]);
		tmp->next = NULL;
		err = regcomp(&tmp->reg, tmp->str, REG_NOSUB);
		if( err ) {
			char errstr[1024];
			regerror(err, &tmp->reg, errstr, sizeof(errstr));
			printf("Error with regular expression %s: %s\n", tmp->str, errstr);
			exit(1);
		}
		if( extract_files == NULL ) {
			extract_files = tmp;
			extract_tail = tmp;
		} else {
			extract_tail->next = tmp;
			extract_tail = tmp;
		}
		
		/* Add a clause for recursive extraction */
		tmp = malloc(sizeof(struct lnode));
		asprintf(&tmp->str, "%s/.*", args[argi]);
		tmp->next = NULL;
		err = regcomp(&tmp->reg, tmp->str, REG_NOSUB);
		if( err ) {
			char errstr[1024];
			regerror(err, &tmp->reg, errstr, sizeof(errstr));
			printf("Error with regular expression %s: %s\n", tmp->str, errstr);
			exit(1);
		}
		if( extract_files == NULL ) {
			extract_files = tmp;
			extract_tail = tmp;
		} else {
			extract_tail->next = tmp;
			extract_tail = tmp;
		}
	}

	x = xar_open(filename, READ);
	if( !x ) {
		fprintf(stderr, "Error opening xar archive: %s\n", filename);
		exit(1);
	}

	xar_register_errhandler(x, err_callback, NULL);

	if( Perms == SYMBOLIC ) {
		xar_opt_set(x, XAR_OPT_OWNERSHIP, XAR_OPT_VAL_SYMBOLIC);
	}
	if( Perms == NUMERIC ) {
		xar_opt_set(x, XAR_OPT_OWNERSHIP, XAR_OPT_VAL_NUMERIC);
	}
	if ( Rsize != NULL ) {
		xar_opt_set(x, XAR_OPT_RSIZE, Rsize);
	}
	
	i = xar_iter_new();
	if( !i ) {
		fprintf(stderr, "Error creating xar iterator\n");
		exit(1);
	}

	for(f = xar_file_first(x, i); f; f = xar_file_next(i)) {
		int matched = 0;
		int exclude_match = 1;
		struct lnode *i;

		char *path = xar_get_path(f);

		if( args[0] ) {
			for(i = extract_files; i != NULL; i = i->next) {
				int extract_match = 1;

				extract_match = regexec(&i->reg, path, 0, NULL, 0);
				if( !extract_match ) {
					matched = 1;
					break;
				}
			}
		} else {
			matched = 1;
		}

		for( i = Exclude; i; i=i->next ) {
			exclude_match = regexec(&i->reg, path, 0, NULL, 0);
			if( !exclude_match )
				break;
		}
		if( !exclude_match ) {
			if( Verbose )
				printf("Excluding %s\n", path);
			free(path);
			continue;
		}
		
		if( matched ) {
			files_extracted++;
			print_file(f);
			xar_extract(x, f);
		}
		free(path);
	}
	if( args[0] && (files_extracted == 0) ) {
		fprintf(stderr, "No files matched extraction criteria.\n");
		Err = 3;
	}

	if( Subdoc )
		extract_subdoc(x, NULL);

	xar_iter_free(i);
	if( xar_close(x) != 0 ) {
		fprintf(stderr, "Error extracting the archive\n");
		if( !Err )
			Err = 42;
	}

	for(lnodei = extract_files; lnodei != NULL; ) {
		struct lnode *tmp;
		free(lnodei->str);
		regfree(&lnodei->reg);
		tmp = lnodei;
		lnodei = lnodei->next;
		free(tmp);
	}
	return Err;
}

static int list_subdocs(const char *filename) {
	xar_t x;
	xar_subdoc_t s;

	x = xar_open(filename, READ);
	if( !x ) {
		fprintf(stderr, "Error opening xar archive: %s\n", filename);
		exit(1);
	}

	for(s = xar_subdoc_first(x); s; s = xar_subdoc_next(s)) {
		printf("%s\n", xar_subdoc_name(s));
	}
	xar_close(x);

	return Err;
}

static int list(const char *filename, int arglen, char *args[]) {
	xar_t x;
	xar_iter_t i;
	xar_file_t f;

	x = xar_open(filename, READ);
	if( !x ) {
		fprintf(stderr, "Error opening xar archive: %s\n", filename);
		exit(1);
	}

	i = xar_iter_new();
	if( !i ) {
		fprintf(stderr, "Error creating xar iterator\n");
		exit(1);
	}

	for(f = xar_file_first(x, i); f; f = xar_file_next(i)) {
		print_file(f);
	}

	xar_iter_free(i);
	xar_close(x);

	return Err;
}

static int dumptoc(const char *filename, const char* tocfile) {
	xar_t x;
	x = xar_open(filename, READ);
	if( !x ) {
		fprintf(stderr, "Error opening xar archive: %s\n", filename);
		exit(1);
	}

	xar_serialize(x, tocfile);
	xar_close(x);
	return Err;
}

static int dump_header(const char *filename) {
	int fd;
	xar_header_t xh;

	if(filename == NULL)
		fd = 0;
	else {
		fd = open(filename, O_RDONLY);
		if( fd < 0 ) {
			perror("open");
			exit(1);
		}
	}

	if( read(fd, &xh, sizeof(xh)) < sizeof(xh) ) {
		fprintf(stderr, "error reading header\n");
		exit(1);
	}

	printf("magic:                  0x%x ", ntohl(xh.magic));
	if( ntohl(xh.magic) != XAR_HEADER_MAGIC )
		printf("(BAD)\n");
	else
		printf("(OK)\n");
	printf("size:                   %d\n", ntohs(xh.size));
	printf("version:                %d\n", ntohs(xh.version));
	printf("Compressed TOC length:  %" PRId64 "\n", xar_ntoh64(xh.toc_length_compressed));
	printf("Uncompressed TOC length: %" PRId64 "\n", xar_ntoh64(xh.toc_length_uncompressed));
	printf("Checksum algorithm:     %d ", ntohl(xh.cksum_alg));
	switch( ntohl(xh.cksum_alg) ) {
	case XAR_CKSUM_NONE: printf("(none)\n");
	                     break;
	case XAR_CKSUM_SHA1: printf("(SHA1)\n");
	                     break;
	case XAR_CKSUM_MD5: printf("(MD5)\n");
	                    break;
	default: printf("(unknown)\n");
	         break;
	};

	return 0;
}

static int32_t err_callback(int32_t sev, int32_t err, xar_errctx_t ctx, void *usrctx) {
	xar_file_t f;
	const char *str;
	int e;

	f = xar_err_get_file(ctx);
	str = xar_err_get_string(ctx);
	e = xar_err_get_errno(ctx);

	switch(sev) {
	case XAR_SEVERITY_DEBUG:
	case XAR_SEVERITY_INFO:
		break;
	case XAR_SEVERITY_WARNING:
		printf("%s\n", str);
		break;
	case XAR_SEVERITY_NORMAL:
		if( (err = XAR_ERR_ARCHIVE_CREATION) && f )
    			print_file(f);
		break;
	case XAR_SEVERITY_NONFATAL:
	case XAR_SEVERITY_FATAL:
		Err = 2;
		printf("Error while ");
		if( err == XAR_ERR_ARCHIVE_CREATION ) printf("creating");
		if( err == XAR_ERR_ARCHIVE_EXTRACTION ) printf("extracting");
		printf(" archive");
		if( f ) {
			const char *file = xar_get_path(f);
			if( file ) printf(":(%s)", file);
			free((char *)file);
		}
		if( str ) printf(": %s", str);
		if( err ) printf(" (%s)", strerror(e));
		if( sev == XAR_SEVERITY_NONFATAL ) {
			printf(" - ignored");
			printf("\n");
		} else {
			printf("\n");
			exit(1);
		}
		break;
	}
	return 0;
}

static void usage(const char *prog) {
	fprintf(stderr, "Usage: %s -[ctx][v] -f <archive> ...\n", prog);
	fprintf(stderr, "\t-c               Creates an archive\n");
	fprintf(stderr, "\t-x               Extracts an archive\n");
	fprintf(stderr, "\t-t               Lists an archive\n");
	fprintf(stderr, "\t-f <filename>    Specifies an archive to operate on [REQUIRED!]\n");
	fprintf(stderr, "\t-v               Print filenames as they are archived\n");
	fprintf(stderr, "\t-n name          Provides a name for a subdocument\n");
	fprintf(stderr, "\t-s <filename>    On extract, specifies the file to extract\n");
	fprintf(stderr, "\t                      subdocuments to.\n");
	fprintf(stderr, "\t                 On archival, specifies an xml file to add\n");
	fprintf(stderr, "\t                      as a subdocument.\n");
	fprintf(stderr, "\t-l               On archival, stay on the local device.\n");
	fprintf(stderr, "\t-p               On extract, set ownership based on symbolic\n");
	fprintf(stderr, "\t                      names, if possible.\n");
	fprintf(stderr, "\t-P               On extract, set ownership based on uid/gid.\n");
	fprintf(stderr, "\t--toc-cksum      Specifies the hashing algorithm to use for\n");
	fprintf(stderr, "\t                      xml header verification.\n");
	fprintf(stderr, "\t                      Valid values: none, sha1, and md5\n");
	fprintf(stderr, "\t                      Default: sha1\n");
	fprintf(stderr, "\t--dump-toc=<filename> Has xar dump the xml header into the\n");
	fprintf(stderr, "\t                      specified file.\n");
	fprintf(stderr, "\t--dump-header    Prints out the xar binary header information\n");
	fprintf(stderr, "\t--compression    Specifies the compression type to use.\n");
	fprintf(stderr, "\t                      Valid values: none, gzip, bzip2\n");
	fprintf(stderr, "\t                      Default: gzip\n");
	fprintf(stderr, "\t--list-subdocs   List the subdocuments in the xml header\n");
	fprintf(stderr, "\t--extract-subdoc=name Extracts the specified subdocument\n");
	fprintf(stderr, "\t                      to a document in cwd named <name>.xml\n");
	fprintf(stderr, "\t--exclude        POSIX regular expression of files to \n");
	fprintf(stderr, "\t                      ignore while archiving.\n");
	fprintf(stderr, "\t--rsize          Specifies the size of the buffer used\n");
	fprintf(stderr, "\t                      for read IO operations in bytes.\n");
	fprintf(stderr, "\t--coalesce-heap  When archived files are identical, only store one copy\n");
	fprintf(stderr, "\t                      This option creates an archive which\n");
	fprintf(stderr, "\t                      is not streamable\n");
	fprintf(stderr, "\t--link-same      Hardlink identical files\n");
	fprintf(stderr, "\t--no-compress    POSIX regular expression of files\n");
	fprintf(stderr, "\t                      not to archive, but not compress.\n");
	fprintf(stderr, "\t--version        Print xar's version number\n");

	return;
}

static void print_version() {
	printf("xar %s\n", XAR_VERSION);
}

int main(int argc, char *argv[]) {
	char *filename = NULL;
	char command = 0, c;
	char **args;
	const char *tocfile = NULL;
	int arglen, i, err;
	xar_t x;
	int loptind = 0;
	int required_dash_f = 0;  /* This release requires us to use -f */
	struct lnode *tmp;
	long int longtmp;
	struct option o[] = { 
		{"toc-cksum", 1, 0, 1},
		{"dump-toc", 1, 0, 'd'},
		{"compression", 1, 0, 2},
		{"list-subdocs", 0, 0, 3},
		{"help", 0, 0, 'h'},
		{"version", 0, 0, 4},
		{"dump-header", 0, 0, 5},
		{"extract-subdoc", 1, 0, 6},
		{"exclude", 1, 0, 7},
		{"rsize", 1, 0, 8},
		{"coalesce-heap", 0, 0, 9},
		{"link-same", 0, 0, 10},
		{"no-compress", 1, 0, 11},
		{ 0, 0, 0, 0}
	};

	if( argc < 2 ) {
		usage(argv[0]);
		exit(1);
	}

	while( (c = getopt_long(argc, argv, "xcvtf:hpPln:s:d:v", o, &loptind)) != -1 ) {
		switch(c) {
		case  1 : if( !optarg ) {
		          	usage(argv[0]);
		          	exit(1);
		          }
		          if( (strcmp(optarg, XAR_OPT_VAL_NONE) != 0) &&
		              (strcmp(optarg, XAR_OPT_VAL_SHA1) != 0) &&
		              (strcmp(optarg, XAR_OPT_VAL_MD5)  != 0) ) {
		          	usage(argv[0]);
		          	exit(1);
		          }
		          Toccksum = optarg;
		
		          break;
		case  2 : if( !optarg ) {
		          	usage(argv[0]);
		          	exit(1);
		          }
		          if( (strcmp(optarg, XAR_OPT_VAL_NONE) != 0) &&
		              (strcmp(optarg, XAR_OPT_VAL_GZIP) != 0) &&
		              (strcmp(optarg, XAR_OPT_VAL_BZIP) != 0) ) {
		          	usage(argv[0]);
		          	exit(1);
		          }
		          Compression = optarg;
		          break;
		case  3 : if( command && (command != 3) ) {
		          	fprintf(stderr, "Conflicting commands specified\n");
				exit(1);
		          }
			  command = 3;
			  break;
		case  4 : print_version();
		          exit(0);
		case 'd':
			if( !optarg ) {
				usage(argv[0]);
				exit(1);
			}
			tocfile = optarg;
			command = 'd';
			break;
		case  5 : command = 5;
		          break;
		case  6 :
			SubdocName = optarg;
			asprintf(&Subdoc, "%s.xml", SubdocName);
			if( !command )
				command = 6;
			break;
		case  7 :
			tmp = malloc(sizeof(struct lnode));
			tmp->str = optarg;
			tmp->next = NULL;
			err = regcomp(&tmp->reg, tmp->str, REG_NOSUB);
			if( err ) {
				char errstr[1024];
				regerror(err, &tmp->reg, errstr, sizeof(errstr));
				printf("Error with regular expression %s: %s\n", tmp->str, errstr);
				exit(1);
			}
			if( Exclude == NULL ) {
				Exclude = tmp;
				Exclude_Tail = tmp;
			} else {
				Exclude_Tail->next = tmp;
				Exclude_Tail = tmp;
			}
			break;
		case  8 :
			if ( !optarg ) {
				usage(argv[0]);
				exit(1);
			}
			longtmp = strtol(optarg, NULL, 10);
			if( (((longtmp == LONG_MIN) || (longtmp == LONG_MAX)) && (errno == ERANGE)) || (longtmp < 1) ) {
				fprintf(stderr, "Invalid rsize value: %s\n", optarg);
				exit(5);
			}
			Rsize = optarg;
			break;
		case  9 : Coalesce = 1; break;
		case 10 : LinkSame = 1; break;
		case 11 :
			tmp = malloc(sizeof(struct lnode));
			tmp->str = optarg;
			tmp->next = NULL;
			err = regcomp(&tmp->reg, tmp->str, REG_NOSUB);
			if( err ) {
				char errstr[1024];
				regerror(err, &tmp->reg, errstr, sizeof(errstr));
				printf("Error with regular expression %s: %s\n", tmp->str, errstr);
				exit(1);
			}
			if( NoCompress == NULL ) {
				NoCompress = tmp;
				NoCompress_Tail = tmp;
			} else {
				NoCompress_Tail->next = tmp;
				NoCompress_Tail = tmp;
			}
			break;
		case 'c':
		case 'x':
		case 't':
			if( command && (command != 's') ) {
				usage(argv[0]);
				fprintf(stderr, "Conflicting command flags: %c and %c specified\n", c, command);
				exit(1);
			}
			if( c == 't' )
				Verbose++;
			command = c;
			break;
		case 'f':
		        required_dash_f = 1;
			filename = optarg;
			break;
		case 'p':
			Perms = SYMBOLIC;
			break;
		case 'P':
			Perms = NUMERIC;
			break;
		case 'l':
			Local = 1;
			break;
		case 'n':
			SubdocName = optarg;
			break;
		case 's':
			Subdoc = optarg;
			if( !command )
				command = 's';
			break;
		case 'v':
			Verbose++;
			break;
		case 'h':
		default:
			usage(argv[0]);
			exit(1);
		}
	}

	if (! required_dash_f)	{
		usage(argv[0]);
		fprintf(stderr, "\n -f option is REQUIRED\n");
		exit(1);
	}

	switch(command) {
		case  5 : 
		        return dump_header(filename);
		case  3 : 
			return list_subdocs(filename);
		case 'c':
			if( optind == argc ) {
				usage(argv[0]);
				fprintf(stderr, "No files to operate on.\n");
				exit(1);
			}
			arglen = argc - optind;
			args = malloc(sizeof(char*) * (arglen+1));
			memset(args, 0, sizeof(char*) * (arglen+1));
			for( i = 0; i < arglen; i++ )
				args[i] = strdup(argv[optind + i]);

			return archive(filename, arglen, args);
		case 'd':
			if( !tocfile ) {
				usage(argv[0]);
				exit(1);
			}
			return dumptoc(filename, tocfile);
		case 'x':
			arglen = argc - optind;
			args = malloc(sizeof(char*) * (arglen+1));
			for( i = 0; i < arglen; i++ )
				args[i] = strdup(argv[optind + i]);
			args[i] = NULL;
			return extract(filename, arglen, args);
		case 't':
			arglen = argc - optind;
			args = malloc(sizeof(char*) * (arglen+1));
			for( i = 0; i < arglen; i++ )
				args[i] = strdup(argv[optind + i]);
			return list(filename, arglen, args);
		case  6 :
		case 's':
			x = xar_open(filename, READ);
			if( !x ) {
				fprintf(stderr, "Error opening xar archive: %s\n", filename);
				exit(1);
			}
			xar_register_errhandler(x, err_callback, NULL);
			extract_subdoc(x, SubdocName);
			xar_close(x);
			exit(Err);
			break;
		default:
			usage(argv[0]);
			fprintf(stderr, "Unrecognized command.\n");
			exit(1);
	}

	/* unreached */
	exit(0);
}

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
/*
 * Portions Copyright 2006, Apple Computer, Inc.
 * Christopher Ryan <ryanc@apple.com>
*/

#include <stdio.h>
#include <stdint.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include "config.h"
#ifndef HAVE_ASPRINTF
#include "asprintf.h"
#endif
#include "xar.h"
#include "archive.h"
#include "filetree.h"

uint64_t xar_ntoh64(uint64_t num) {
	int t = 1234;
	union conv {
		uint64_t i64;
		uint32_t i32[2];
	} *in, out;

	if( ntohl(t) == t ) {
		out.i64 = num;
		return out.i64;
	}
	in = (union conv *)&num;
	out.i32[1] = ntohl(in->i32[0]);
	out.i32[0] = ntohl(in->i32[1]);
	return(out.i64);
}

uint32_t xar_swap32(uint32_t num) {
	uint8_t *one, *two;
	uint32_t ret;

	two = (uint8_t *)&ret;
	one = (uint8_t *)&num;
	two[3] = one[0];
	two[2] = one[1];
	two[1] = one[2];
	two[0] = one[3];

	return ret;
}

/* xar_get_path
 * Summary: returns the archive path of the file f.
 * Caller needs to free the return value.
 */
char *xar_get_path(xar_file_t f) {
	char *ret, *tmp;
	const char *name;
	xar_file_t i;

	xar_prop_get(f, "name", &name);
	ret = strdup(name);
	for(i = XAR_FILE(f)->parent; i; i = XAR_FILE(i)->parent) {
		const char *name;
	       	xar_prop_get(i, "name", &name);
		tmp = ret;
		asprintf(&ret, "%s/%s", name, tmp);
		free(tmp);
	}

	return ret;
}

off_t	xar_get_heap_offset(xar_t x) {
	return XAR(x)->toc_count + sizeof(xar_header_t);
}

/* xar_read_fd
 * Summary: Reads from a file descriptor a certain number of bytes to a specific
 * buffer.  This simple wrapper just handles certain retryable error situations.
 * Returns -1 when it fails fatally; the number of bytes read otherwise.
 */
ssize_t xar_read_fd( int fd, void * buffer, size_t nbytes ) {
	ssize_t rb;
	ssize_t off = 0;

	while ( off < nbytes ) {
		rb = read(fd, buffer+off, nbytes-off);
		if( (rb < 1 ) && (errno != EINTR) && (errno != EAGAIN) )
			return -1;
		off += rb;
	}

	return off;
}

/* xar_write_fd
 * Summary: Writes from a buffer to a file descriptor.  Like xar_read_fd it
 * also just handles certain retryable error situations.
 * Returs -1 when it fails fatally; the number of bytes written otherwise.
 */
ssize_t xar_write_fd( int fd, void * buffer, size_t nbytes ) {
	ssize_t rb;
	ssize_t off = 0;

	while ( off < nbytes ) {
		rb = write(fd, buffer+off, nbytes-off);
		if( (rb < 1 ) && (errno != EINTR) && (errno != EAGAIN) )
			return -1;
		off += rb;
	}

	return off;
}

dev_t xar_makedev(uint32_t major, uint32_t minor)
{
#ifdef makedev
	return makedev(major, minor);
#else
	return (major << 8) | minor;
#endif
}

void xar_devmake(dev_t dev, uint32_t *out_major, uint32_t *out_minor)
{
#ifdef major
	*out_major = major(dev);
#else
	*out_major = (dev >> 8) & 0xFF;
#endif
#ifdef minor
	*out_minor = minor(dev);
#else
	*out_minor = dev & 0xFF;
#endif
	return;
}

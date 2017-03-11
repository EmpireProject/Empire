/*
 * Rob Braun <bbraun@synack.net>
 * 1-Oct-2004
 * Copyright (c) 2004 Rob Braun.  All rights reserved.
 */

#ifndef _XAR_BASE64_H_
#define _XAR_BASE64_H_

unsigned char* xar_to_base64(const unsigned char* input, int len);
unsigned char* xar_from_base64(const unsigned char* input, int len);

#endif /* _XAR_BASE64_H_ */

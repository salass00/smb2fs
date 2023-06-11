/*
 * smb2-handler - SMB2 file system client
 *
 * Copyright (C) 2022-2023 Fredrik Wikstrom <fredrik@a500.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program (in the main directory of the smb2-handler
 * distribution in the file COPYING); if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#ifndef SMB2FS_CTYPE_H
#define SMB2FS_CTYPE_H

#ifndef __AROS__
#include_next <ctype.h>
#else

/* These replacement functions only support ASCII */

static inline int isupper(int c)
{
	return (c >= 'A' && c <= 'Z');
}

static inline int islower(int c)
{
	return (c >= 'a' && c <= 'z');
}

static inline int isalpha(int c)
{
	return (c >= 'A' && c <= 'Z') ||
	       (c >= 'a' && c <= 'z');
}

static inline int isdigit(int c)
{
	return (c >= '0' && c <= '9');
}

static inline int isxdigit(int c)
{
	return (c >= '0' && c <= '9') ||
	       (c >= 'A' && c <= 'F') ||
	       (c >= 'a' && c <= 'f');
}

static inline int isspace(int c)
{
	return (c >= '\t' && c <= '\r') ||
	       c == ' ';
}

static inline int isprint(int c)
{
	return (c >= ' ' && c <= '~');
}

static inline int isgraph(int c)
{
	return (c >= '!' && c <= '~');
}

static inline int isblank(int c)
{
	return c == '\t' || c == ' ';
}

static inline int iscntrl(int c)
{
	return (c >= '\0' && c <= '\x1F') ||
	       c == '\x7F';
}

static inline int ispunct(int c)
{
	return (c >= '!' && c <= '/') ||
	       (c >= ':' && c <= '@') ||
	       (c >= '[' && c <= '`') ||
	       (c >= '{' && c <= '~');
}

static inline int isalnum(int c)
{
	return (c >= '0' && c <= '9') ||
	       (c >= 'A' && c <= 'Z') ||
	       (c >= 'a' && c <= 'z');
}

static inline int toupper(int c)
{
	if (c >= 'a' && c <= 'z')
		return c - ('a' - 'A');
	else
		return c;
}

static inline int tolower(int c)
{
	if (c >= 'A' && c <= 'Z')
		return c + ('a' - 'A');
	else
		return c;
}

static inline int isascii(int c)
{
	return (c & ~0x7F) == 0;
}

static inline int toascii(int c)
{
	return c & 0x7F;
}

#endif /* __AROS__ */

#endif /* SMB2FS_CTYPE_H */


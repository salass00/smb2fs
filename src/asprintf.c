/*
 * smb2-handler - SMB2 file system client
 *
 * Copyright (C) 2022-2025 Fredrik Wikstrom <fredrik@a500.org>
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int vasprintf(char **strp, const char *fmt, va_list ap)
{
	va_list ap_copy;
	char buffer[256];
	char *str;
	int len;

	va_copy(ap_copy, ap);
	len = vsnprintf(buffer, sizeof(buffer), fmt, ap_copy);
	va_end(ap_copy);

	if (len < 0)
	{
		*strp = NULL;
		return -1;
	}

	if (len < sizeof(buffer))
	{
		str = strdup(buffer);
	}
	else
	{
		str = malloc(len + 1);
		if (str != NULL)
		{
			int r = vsnprintf(str, len + 1, fmt, ap);
			if (r < 0)
			{
				free(str);
				*strp = NULL;
				return -1;
			}
		}
	}

	*strp = str;
	return (str != NULL) ? len : -1;
}

int asprintf(char **strp, const char *fmt, ...)
{
	int len;
	va_list args;

	va_start(args, fmt);
	len = vasprintf(strp, fmt, args);
	va_end(args);

	return len;
}


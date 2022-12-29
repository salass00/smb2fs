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

#include <proto/filesysbox.h>
#include <time.h>
#ifndef __amigaos4__
#define _KERNEL
#include <sys/time.h>
#endif

extern struct fuse_context *_fuse_context_;

#define UNIXTIMEOFFSET 252460800

int gettimeofday(struct timeval *tvp, struct timezone *tzp)
{
	struct FbxFS *fs = fuse_get_context()->fuse;
#ifdef __amigaos4__
	int32 gmtoffset = 0;
#else
	LONG gmtoffset = 0;
#endif

	/* Get difference to GMT time in minutes */
#ifdef __amigaos4__
	IFileSysBox->FbxQueryFSTags(fs,
#else
	FbxQueryFSTags(fs,
#endif
		FBXT_GMT_OFFSET, &gmtoffset,
		TAG_END);

	if (tvp != NULL)
	{
#ifdef __amigaos4__
		IFileSysBox->FbxGetSysTime(fs, (struct TimeVal *)tvp);
#else
		FbxGetSysTime(fs, tvp);
#endif
		tvp->tv_sec += UNIXTIMEOFFSET + (gmtoffset * 60);
	}

	if (tzp != NULL)
	{
		tzp->tz_minuteswest = gmtoffset;
		tzp->tz_dsttime     = -1;
	}

	return 0;
}

time_t time(time_t *tp)
{
	struct timeval tv;

	if (gettimeofday(&tv, NULL) < 0)
		return -1;

	if (tp != NULL)
		*tp = tv.tv_sec;

	return tv.tv_sec;
}


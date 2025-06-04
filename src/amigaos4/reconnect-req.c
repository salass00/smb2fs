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

#define __USE_INLINE__

#include "smb2fs.h"
#include "smb2-handler_rev.h"

LONG request_reconnect(const char *server)
{
	LONG    result;

	result = TimedDosRequesterTags(
		TDR_NonBlocking,  TRUE,
		TDR_Timeout,      30,
		TDR_TitleString,  "SMB Connection",
		TDR_FormatString, "Connection to server %s lost.",
		TDR_Arg1,         server,
		TDR_GadgetString, "Reconnect|Abort",
		TAG_END);

	return result;
}




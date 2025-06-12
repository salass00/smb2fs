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

#ifndef __amigaos4__
#include <proto/intuition.h>
#include <clib/debug_protos.h>
#endif

LONG request_reconnect(const char *server)
{
#ifndef __amigaos4__
	struct IntuitionBase *IntuitionBase;
#endif
	LONG    result = -1;

#ifdef __amigaos4__
	DebugPrintF("[smb2fs] Connection to server %s lost", server);
	result = TimedDosRequesterTags(
		TDR_NonBlocking,  TRUE,
		TDR_Timeout,      30,
		TDR_TitleString,  VERS,
		TDR_FormatString, "Connection to server %s lost",
		TDR_Arg1,         server,
		TDR_GadgetString, "Reconnect|Abort",
		TAG_END);
#else
	KPrintF((STRPTR)"[smb2fs] Connection to server %s lost", server);
	IntuitionBase = (struct IntuitionBase *)OpenLibrary((STRPTR)"intuition.library", 39);
	if (IntuitionBase != NULL)
	{
		struct EasyStruct es;

		es.es_StructSize   = sizeof(es);
		es.es_Flags        = 0;
		es.es_Title        = (STRPTR)VERS;
		es.es_TextFormat   = (STRPTR)"Connection to server %s lost";
		es.es_GadgetFormat = (STRPTR)"Reconnect|Abort";

		result = EasyRequestArgs(NULL, &es, NULL, (APTR)&server);

		CloseLibrary((struct Library *)IntuitionBase);
	}
#endif

	return result;
}




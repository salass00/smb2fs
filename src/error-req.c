/*
 * smb2-handler - SMB2 file system client
 *
 * Copyright (C) 2022-2023 Fredrik Wikstrom <fredrik@a500.org>
 * Copyright (C) 2023 Szilard Biro
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

#include <proto/exec.h>
#include <proto/intuition.h>

#ifndef __amigaos4__
#include <clib/debug_protos.h>
#endif

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

void request_error(const char *error_string, ...)
{
#ifdef __amigaos4__
	struct IntuitionIFace *IIntuition;
#else
	struct IntuitionBase *IntuitionBase;
#endif
	va_list args;
	char errstr[256];

	va_start(args, error_string);
	vsnprintf(errstr, sizeof(errstr), error_string, args);
	va_end(args);

#ifdef __amigaos4__
	DebugPrintF("[smb2fs] %s\n", errstr);
	IIntuition = (struct IntuitionIFace *)open_interface("intuition.library", 53);
	if (IIntuition != NULL)
#else
	KPrintF((STRPTR)"[smb2fs] %s\n", errstr);
	IntuitionBase = (struct IntuitionBase *)OpenLibrary((STRPTR)"intuition.library", 39);
	if (IntuitionBase != NULL)
#endif
	{
		struct EasyStruct es;
		es.es_StructSize = sizeof(es);
		es.es_Flags = 0;
		es.es_Title = (STRPTR)VERS;
		es.es_TextFormat = (STRPTR)errstr;
		es.es_GadgetFormat = (STRPTR)"OK";
		EasyRequestArgs(NULL, &es, NULL, NULL);

#ifdef __amigaos4__
		close_interface((struct Interface *)IIntuition);
#else
		CloseLibrary((struct Library *)IntuitionBase);
#endif
	}
}


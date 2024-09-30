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

#include <proto/intuition.h>
#include <classes/requester.h>

#ifndef __amigaos4__
#include <proto/requester.h>
#include <clib/alib_protos.h>
#ifndef REQ_Image
#define REQ_Image (REQ_Dummy+7)
#endif
#ifndef REQIMAGE_QUESTION
#define REQIMAGE_QUESTION (4)
#endif
#ifndef REQS_ReturnEnds
#define REQS_ReturnEnds (REQS_Dummy+8)
#endif
#endif /* !__amigaos4__ */

#include <stdio.h>
#include <string.h>

char *request_password(const char *user, const char *server)
{
#ifdef __amigaos4__
	struct IntuitionIFace *IIntuition;
#else
	struct IntuitionBase *IntuitionBase;
#endif
	char                  *password = NULL;

#ifdef __amigaos4__
	IIntuition = (struct IntuitionIFace *)open_interface("intuition.library", 53);
	if (IIntuition != NULL)
#else
	IntuitionBase = (struct IntuitionBase *)OpenLibrary((STRPTR)"intuition.library", 39);
	if (IntuitionBase != NULL)
#endif
	{
		struct Library *RequesterBase;
		Class          *RequesterClass;

#ifdef __amigaos4__
		RequesterBase = (struct Library *)OpenClass("requester.class", 53, &RequesterClass);
#else
		RequesterBase = OpenLibrary("requester.class", 42);
#endif
		if (RequesterBase != NULL)
		{
			struct Screen *screen;
#ifndef __amigaos4__
			RequesterClass = REQUESTER_GetClass();
#endif

			screen = LockPubScreen(NULL);
			if (screen != NULL)
			{
				TEXT    bodytext[256];
				TEXT    buffer[256];
				Object *reqobj;

				buffer[0] = '\0';

				snprintf(bodytext, sizeof(bodytext), "Enter password for %s@%s", user, server);

				reqobj = NewObject(RequesterClass, NULL,
					REQ_Type,        REQTYPE_STRING,
					REQ_Image,       REQIMAGE_QUESTION,
					REQ_TitleText,   VERS,
					REQ_BodyText,    bodytext,
					REQ_GadgetText,  "_Ok|_Cancel",
					REQS_AllowEmpty, FALSE,
					REQS_Invisible,  TRUE,
					REQS_Buffer,     buffer,
					REQS_MaxChars,   sizeof(buffer),
					REQS_ReturnEnds, TRUE,
					TAG_END);

				if (reqobj != NULL)
				{
					struct orRequest reqmsg;
					LONG             result;

					reqmsg.MethodID  = RM_OPENREQ;
					reqmsg.or_Attrs  = NULL;
					reqmsg.or_Window = NULL;
					reqmsg.or_Screen = screen;

					result = DoMethodA(reqobj, (Msg)&reqmsg);

					if (result && buffer[0] != '\0')
					{
						password = strdup(buffer);
					}

					DisposeObject(reqobj);
				}

				UnlockPubScreen(NULL, screen);
			}

#ifdef __amigaos4__
			CloseClass((struct ClassLibrary *)RequesterBase);
#else
			CloseLibrary(RequesterBase);
#endif
		}

#ifdef __amigaos4__
		close_interface((struct Interface *)IIntuition);
#else
		CloseLibrary((struct Library *)IntuitionBase);
#endif
	}

	return password;
}


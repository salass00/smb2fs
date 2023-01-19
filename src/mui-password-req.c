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

#include "smb2fs.h"
#include "smb2-handler_rev.h"

#include <proto/exec.h>
#include <proto/intuition.h>

#include <libraries/mui.h>
#include <proto/muimaster.h>
#include <clib/alib_protos.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

struct Library *MUIMasterBase;

char *request_password(const char *user, const char *server)
{
	struct IntuitionBase *IntuitionBase;
	char                 *password = NULL;

	IntuitionBase = (struct IntuitionBase *)OpenLibrary((STRPTR)"intuition.library", 39);
	if (IntuitionBase != NULL)
	{
		MUIMasterBase = OpenLibrary((STRPTR)MUIMASTER_NAME, 19);
		if (MUIMasterBase != NULL)
		{
			ULONG sigs = 0;
			ULONG id;
			Object *app, *win, *okButton, *cancelButton, *stringObj;
			char bodytext[256];

			snprintf(bodytext, sizeof(bodytext), "Enter password for %s@%s", user, server);

			app = (Object *)ApplicationObject,
				SubWindow, win = WindowObject,
					MUIA_Window_Title, VERS,
					WindowContents, VGroup,
						Child, Label(bodytext),
						Child, stringObj = StringObject,
							MUIA_Frame, MUIV_Frame_String,
							MUIA_String_Secret, TRUE,
						End, /* StringObject */
						Child, HGroup,
							Child, (okButton = SimpleButton("_Ok")),
							Child, (cancelButton = SimpleButton("_Cancel")),
						End, /* HGroup */
					End, /* VGroup */
				End, /* WindowObject */
			End; /* ApplicationObject */

			if (app)
			{
				DoMethod(okButton, MUIM_Notify, MUIA_Pressed, FALSE,
					app, 2, MUIM_Application_ReturnID, 31337);

				DoMethod(cancelButton, MUIM_Notify, MUIA_Pressed, FALSE,
					app, 2, MUIM_Application_ReturnID, MUIV_Application_ReturnID_Quit);

				DoMethod(win, MUIM_Notify, MUIA_Window_CloseRequest, TRUE,
					app, 2, MUIM_Application_ReturnID, MUIV_Application_ReturnID_Quit);

				set(win, MUIA_Window_Open, TRUE);

				while ((id = DoMethod(app, MUIM_Application_NewInput, &sigs)) != MUIV_Application_ReturnID_Quit)
				{
					switch (id)
					{
						case 31337:
							get(stringObj, MUIA_String_Contents, &password);
							if (password) password = strdup(password);
							DoMethod(app, MUIM_Application_ReturnID, MUIV_Application_ReturnID_Quit);
							break;
					}
					if (sigs) sigs = Wait(sigs);
				}

				MUI_DisposeObject(app);
			}

			CloseLibrary(MUIMasterBase);
			MUIMasterBase = NULL;
		}
		CloseLibrary((struct Library *)IntuitionBase);
	}
	return password;
}

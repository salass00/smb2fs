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

#include "smb2fs.h"
#include "smb2-handler_rev.h"

#include <intuition/sghooks.h>

#include <proto/exec.h>
#include <proto/intuition.h>
#include <proto/graphics.h>
#include <proto/gadtools.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <SDI/SDI_compiler.h>

#ifndef MAX
#define MAX(a,b) ((a)>(b)?(a):(b))
#endif

static inline void strmove(char *dst, const char *src)
{
	if (dst != src)
	{
		char *d = dst;
		const char *s = src;

		if (d < s)
		{
			while ((*d++ = *s++) != '\0');
		}
		else
		{
			WORD len;
			while (*s++ != '\0');
			len = s - src; /* includes NUL-terminator */
			d += len;
			while (len--) *--d = *--s;
		}
	}
}

ULONG edithook_entry(REG(a0, struct Hook *hook), REG(a2, struct SGWork *sgw), REG(a1, ULONG *msg))
{
	char *buffer = hook->h_Data;
	ULONG res = TRUE;

	if (*msg == SGH_KEY)
	{
		switch (sgw->EditOp)
		{
			case EO_NOOP:
			case EO_MOVECURSOR:
			case EO_ENTER:
				/* No-op */
				break;

			case EO_DELBACKWARD:
			case EO_DELFORWARD:
				if (sgw->NumChars < sgw->StringInfo->NumChars)
				{
					WORD cnt = sgw->StringInfo->NumChars - sgw->NumChars;
					strmove(&buffer[sgw->BufferPos], &buffer[sgw->BufferPos + cnt]);
				}
				break;

			case EO_REPLACECHAR:
				sgw->WorkBuffer[sgw->BufferPos - 1] = '*';
				buffer[sgw->BufferPos - 1] = sgw->Code;
				break;

			case EO_INSERTCHAR:
				sgw->WorkBuffer[sgw->BufferPos - 1] = '*';
				strmove(&buffer[sgw->BufferPos], &buffer[sgw->BufferPos - 1]);
				buffer[sgw->BufferPos - 1] = sgw->Code;
				break;

			default:
				sgw->Actions &= ~SGA_USE;
				sgw->Actions |= SGA_BEEP;
				break;
		}
	}
	else
	{
		res = FALSE;
	}

	return res;
}

enum
{
	GID_DUMMY,
	GID_STRING,
	GID_OKAY,
	GID_CANCEL
};

char *request_password(const char *user, const char *server)
{
	struct IntuitionBase *IntuitionBase;
	struct GfxBase *GfxBase = NULL;
	struct Library *GadToolsBase = NULL;
	struct Screen *screen = NULL;
	struct DrawInfo *dri = NULL;
	APTR vi = NULL;
	struct TextFont *font = NULL;
	char bodytext[256];
	const char okaytext[] = "Ok";
	const char canceltext[] = "Cancel";
	UWORD wborleft;
	UWORD wbortop;
	UWORD bodytextwidth;
	UWORD okaytextwidth;
	UWORD canceltextwidth;
	UWORD okaybtnwidth;
	UWORD cancelbtnwidth;
	struct RastPort temp_rp;
	struct Gadget *glist = NULL;
	struct Gadget *gad;
	struct Gadget *string;
	struct NewGadget ng;
	struct Hook edithook;
	char buffer[256];
	char *password = NULL;

	IntuitionBase = (struct IntuitionBase *)OpenLibrary((STRPTR)"intuition.library", 39);
	if (IntuitionBase == NULL)
		goto cleanup;

	GfxBase = (struct GfxBase *)OpenLibrary((STRPTR)"graphics.library", 39);
	if (GfxBase == NULL)
		goto cleanup;

	GadToolsBase = OpenLibrary((STRPTR)"gadtools.library", 39);
	if (GadToolsBase == NULL)
		goto cleanup;

	screen = LockPubScreen(NULL);
	if (screen == NULL)
		goto cleanup;

	dri = GetScreenDrawInfo(screen);
	if (dri == NULL)
		goto cleanup;

	vi = GetVisualInfoA(screen, NULL);
	if (vi == NULL)
		goto cleanup;

	wborleft = screen->WBorLeft;
	wbortop = screen->WBorTop + screen->Font->ta_YSize + 1;

	bzero(buffer, sizeof(buffer));
	bzero(&edithook, sizeof(edithook));
	edithook.h_Entry = (APTR)edithook_entry;
	edithook.h_Data  = buffer;

	font = OpenFont(screen->Font);

	snprintf(bodytext, sizeof(bodytext), "Enter password for %s@%s", user, server);

	InitRastPort(&temp_rp);
	SetFont(&temp_rp, font);

	bodytextwidth = TextLength(&temp_rp, (CONST_STRPTR)bodytext, strlen(bodytext));
	okaytextwidth = TextLength(&temp_rp, (CONST_STRPTR)okaytext, strlen(okaytext));
	canceltextwidth = TextLength(&temp_rp, (CONST_STRPTR)canceltext, strlen(canceltext));

	okaybtnwidth = okaytextwidth + 6 + (font->tf_XSize * 2);
	cancelbtnwidth = canceltextwidth + 6 + (font->tf_XSize * 2);

	gad = CreateContext(&glist);

	bzero(&ng, sizeof(ng));
	ng.ng_LeftEdge   = wborleft + 2;
	ng.ng_TopEdge    = wbortop + font->tf_YSize + 18;
	ng.ng_Width      = bodytextwidth + 12;
	ng.ng_Height     = font->tf_YSize + 6;
	ng.ng_TextAttr   = screen->Font;
	ng.ng_GadgetID   = GID_STRING;
	ng.ng_VisualInfo = vi;
	string = gad = CreateGadget(STRING_KIND, gad, &ng,
		GA_RelVerify,  TRUE,
		GTST_String,   (Tag)"",
		GTST_MaxChars, sizeof(buffer) - 1,
		GTST_EditHook, (Tag)&edithook,
		TAG_END);

	bzero(&ng, sizeof(ng));
	ng.ng_LeftEdge   = wborleft + 2;
	ng.ng_TopEdge    = wbortop + (font->tf_YSize * 2) + 26;
	ng.ng_Width      = okaybtnwidth;
	ng.ng_Height     = font->tf_YSize + 6;
	ng.ng_GadgetText = (STRPTR)okaytext;
	ng.ng_TextAttr   = screen->Font;
	ng.ng_GadgetID   = GID_OKAY;
	ng.ng_Flags      = PLACETEXT_IN;
	ng.ng_VisualInfo = vi;
	gad = CreateGadget(BUTTON_KIND, gad, &ng,
		GA_RelVerify,  TRUE,
		TAG_END);

	bzero(&ng, sizeof(ng));
	ng.ng_LeftEdge   = wborleft + bodytextwidth + 14 - cancelbtnwidth;
	ng.ng_TopEdge    = wbortop + (font->tf_YSize * 2) + 26;
	ng.ng_Width      = cancelbtnwidth;
	ng.ng_Height     = font->tf_YSize + 6;
	ng.ng_GadgetText = (STRPTR)canceltext;
	ng.ng_TextAttr   = screen->Font;
	ng.ng_GadgetID   = GID_CANCEL;
	ng.ng_Flags      = PLACETEXT_IN;
	ng.ng_VisualInfo = vi;
	gad = CreateGadget(BUTTON_KIND, gad, &ng,
		GA_RelVerify,  TRUE,
		TAG_END);

	if (gad != NULL)
	{
		UWORD width, height;
		UWORD left, top;
		struct Window *window;

		width = wborleft + screen->WBorRight + bodytextwidth + 16;
		height = wbortop + screen->WBorBottom + (font->tf_YSize * 3) + 34;

		if (width > screen->Width)
			width = screen->Width;
		if (height > screen->Height)
			height = screen->Height;

		left = (screen->Width - width) / 2;
		top = (screen->Height - height) / 2;

		window = OpenWindowTags(NULL,
			WA_PubScreen, (Tag)screen,
			WA_Title,     (Tag)VERS,
			WA_Flags,     WFLG_ACTIVATE | WFLG_CLOSEGADGET | WFLG_DRAGBAR | WFLG_DEPTHGADGET | WFLG_SIMPLE_REFRESH,
			WA_IDCMP,     IDCMP_ACTIVEWINDOW | IDCMP_CLOSEWINDOW | IDCMP_GADGETUP | IDCMP_REFRESHWINDOW,
			WA_Left,      left,
			WA_Top,       top,
			WA_Width,     width,
			WA_Height,    height,
			WA_Gadgets,   (Tag)glist,
			TAG_END);
		if (window != NULL)
		{
			struct IntuiMessage *imsg;
			BOOL done = FALSE;

			GT_RefreshWindow(window, NULL);

			DrawBevelBox(window->RPort, wborleft + 2, wbortop + 2,
			             bodytextwidth + 12, font->tf_YSize + 12,
			             GTBB_Recessed, TRUE,
			             GT_VisualInfo, (Tag)vi,
			             TAG_END);

			SetFont(window->RPort, font);
			SetABPenDrMd(window->RPort, dri->dri_Pens[TEXTPEN], 0, JAM1);
			Move(window->RPort, wborleft + 8, wbortop + 8 + font->tf_Baseline);
			Text(window->RPort, (CONST_STRPTR)bodytext, strlen(bodytext));

			while (!done)
			{
				Wait(1UL << window->UserPort->mp_SigBit);

				while ((imsg = GT_GetIMsg(window->UserPort)) != NULL)
				{
					switch (imsg->Class)
					{
						case IDCMP_ACTIVEWINDOW:
							ActivateGadget(string, window, NULL);
							break;

						case IDCMP_CLOSEWINDOW:
							done = TRUE;
							break;

						case IDCMP_GADGETUP:
							gad = imsg->IAddress;
							switch (gad->GadgetID)
							{
								case GID_STRING:
									if (imsg->Code != 0)
										break;

									/* Fall through */
								case GID_OKAY:
									if (buffer[0] == '\0')
									{
										DisplayBeep(screen);
										break;
									}

									password = strdup(buffer);

									/* Fall through */
								case GID_CANCEL:
									done = TRUE;
									break;
							}
							break;

						case IDCMP_REFRESHWINDOW:
							GT_BeginRefresh(window);

							DrawBevelBox(window->RPort, wborleft + 2, wbortop + 2,
										 bodytextwidth + 12, font->tf_YSize + 12,
										 GTBB_Recessed, TRUE,
										 GT_VisualInfo, (Tag)vi,
										 TAG_END);

							SetFont(window->RPort, font);
							SetABPenDrMd(window->RPort, dri->dri_Pens[TEXTPEN], 0, JAM1);
							Move(window->RPort, wborleft + 8, wbortop + 8 + font->tf_Baseline);
							Text(window->RPort, (CONST_STRPTR)bodytext, strlen(bodytext));

							GT_EndRefresh(window, TRUE);
							break;
					}
					GT_ReplyIMsg(imsg);
				}
			}

			CloseWindow(window);
		}
	}

cleanup:
	if (screen != NULL)
	{
		if (font != NULL) CloseFont(font);
		if (glist != NULL) FreeGadgets(glist);
		if (vi != NULL) FreeVisualInfo(vi);
		if (dri != NULL) FreeScreenDrawInfo(screen, dri);
		UnlockPubScreen(NULL, screen);
	}

	if (GadToolsBase != NULL) CloseLibrary(GadToolsBase);
	if (GfxBase != NULL) CloseLibrary((struct Library *)GfxBase);
	if (IntuitionBase != NULL) CloseLibrary((struct Library *)IntuitionBase);

	return password;
}

/* Compile with:
   m68k-amigaos-gcc -O2 -g -Wall -I../.. -I.. -DSTANDALONE_TEST -o password-req password-req.c
 */
#ifdef STANDALONE_TEST
int main(void)
{
	char *password;

	password = request_password("user", "server");
	if (password != NULL)
	{
		printf("password: %s\n", password);
		free(password);
	}
	else
	{
		printf("cancelled\n");
	}

	return 0;
}
#endif


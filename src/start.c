/*
 * smb2-handler - SMB2 file system client
 *
 * Copyright (C) 2022 Fredrik Wikstrom <fredrik@a500.org>
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

static const TEXT USED verstag[] = VERSTAG;

struct FileSysBoxIFace *IFileSysBox;
//struct SocketIFace     *ISocket;

struct Interface *open_interface(CONST_STRPTR name, int version)
{
	struct Library   *base;
	struct Interface *interface;

	base = IExec->OpenLibrary(name, version);
	if (base == NULL)
	{
		return NULL;
	}

	interface = IExec->GetInterface(base, "main", 1, NULL);
	if (interface == NULL)
	{
		IExec->CloseLibrary(base);
		return NULL;
	}

	return interface;
}

void close_interface(struct Interface *interface)
{
	if (interface != NULL)
	{
		struct Library *base = interface->Data.LibBase;

		IExec->DropInterface(interface);
		IExec->CloseLibrary(base);
	}
}

extern struct Interface *INewlib;

int main(int argc, char **argv)
{
	struct Process   *me;
	struct Library   *NewlibBase;
	struct DosPacket *pkt;
	int               rc = RETURN_ERROR;

	if (argc > 0)
	{
		IDOS->Printf("\n%s [Vectorport Filesystem]\n", VERS);
		return RETURN_OK;
	}

	if (argc == 0)
	{
		IExec->DebugPrintF("[ssh2fs] WB startup is not supported!\n");
		return RETURN_FAIL;
	}

	me = (struct Process *)IExec->FindTask(NULL);

	NewlibBase = INewlib->Data.LibBase;
	if (NewlibBase->lib_Version == 53 && NewlibBase->lib_Revision == 30)
	{
		void *reent;

		__asm__("lwz %0,0(1)\n\t"
			"lwz %0,44(%0)"
			: "=r" (reent));

		/* Version 53.30 of newlib used in 4.1 Final Edition doesn't
		 * set the pr_CLibData field to point to the reent structure.
		 */
		me->pr_CLibData = reent;
	}

	if (me->pr_CLibData == NULL) {
		IExec->DebugPrintF("[ssh2fs] pr_CLibData was not set (newlib.library V%ld.%ld).\n",
			NewlibBase->lib_Version, NewlibBase->lib_Revision);
		IExec->DebugPrintF("[ssh2fs] Handler won't be able to exit cleanly on dismount.\n");
	}

	pkt = (struct DosPacket *)argv;

	IFileSysBox = (struct FileSysBoxIFace *)open_interface("filesysbox.library", 54);
	if (IFileSysBox == NULL || !LIB_IS_AT_LEAST(IFileSysBox->Data.LibBase, 54, 7))
	{
		goto cleanup;
	}

	/* ISocket = (struct SocketIFace *)open_interface("bsdsocket.library", 4);
	if (ISocket == NULL)
	{
		goto cleanup;
	}

	if (ISocket->SocketBaseTags(
		SBTM_SETVAL(SBTC_ERRNOLONGPTR),            __errno(),
		SBTM_SETVAL(SBTC_HERRNOLONGPTR),           __h_errno(),
		SBTM_SETVAL(SBTC_CAN_SHARE_LIBRARY_BASES), TRUE,
		TAG_END))
	{
		goto cleanup;
	} */

	rc = smb2fs_main(pkt);

	/* Set to NULL so we don't reply the packet twice */
	pkt = NULL;

cleanup:

	/* if (ISocket != NULL)
	{
		close_interface((struct Interface *)ISocket);
		ISocket = NULL;
	} */

	if (IFileSysBox != NULL)
	{
		close_interface((struct Interface *)IFileSysBox);
		IFileSysBox = NULL;
	}

	if (pkt != NULL)
	{
		IDOS->ReplyPkt(pkt, DOSFALSE, ERROR_INVALID_RESIDENT_LIBRARY);
		pkt = NULL;
	}

	return rc;
}


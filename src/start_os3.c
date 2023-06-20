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

#include <bsdsocket/socketbasetags.h>
#include <proto/bsdsocket.h>
#include <SDI/SDI_compiler.h>
#include <errno.h>

struct ExecBase *SysBase;
struct DosLibrary *DOSBase;
struct UtilityBase *UtilityBase;
#ifdef __AROS__
#ifndef NO_AROSC_LIB
struct Library *aroscbase;
#else
struct Library *StdlibBase;
struct Library *CrtBase;
#endif
#endif
struct Library *FileSysBoxBase;
struct Library *SocketBase;

static const TEXT vstring[];
static const TEXT dosName[];
static const TEXT utilityName[];
#ifdef __AROS__
#ifndef NO_AROSC_LIB
static const TEXT aroscName[];
#else
static const TEXT stdlibName[];
static const TEXT crtName[];
#endif
#endif
static const TEXT filesysboxName[];
static const TEXT bsdsocketName[];

extern int setup_malloc(void);
extern int cleanup_malloc(void);

#ifdef __AROS__
AROS_UFH3(int, startup,
	AROS_UFHA(STRPTR, argstr, A0),
	AROS_UFHA(ULONG, arglen, D0),
	AROS_UFHA(struct ExecBase *, sysbase, A6)
)
{
	AROS_USERFUNC_INIT
#else
int startup(void)
{
#endif
	struct Process   *me;
	struct DosPacket *pkt = NULL;
	int               rc = RETURN_ERROR;
	struct MsgPort   *port = NULL;

#ifdef __AROS__
	SysBase = sysbase;
#else
	SysBase = *(struct ExecBase **)4;
#endif

	if (!setup_malloc())
	{
		goto cleanup;
	}

	DOSBase = (struct DosLibrary *)OpenLibrary(dosName, 39);
	if (DOSBase == NULL)
	{
		goto cleanup;
	}

	UtilityBase = (struct UtilityBase *)OpenLibrary(utilityName, 39);
	if (UtilityBase == NULL)
	{
		goto cleanup;
	}

#ifdef __AROS__
#ifndef NO_AROSC_LIB
	aroscbase = OpenLibrary(aroscName, 41);
	if (aroscbase == NULL)
	{
		goto cleanup;
	}
#else
	StdlibBase = OpenLibrary(stdlibName, 1);
	if (StdlibBase == NULL)
	{
		goto cleanup;
	}
	CrtBase = OpenLibrary(crtName, 2);
	if (CrtBase == NULL)
	{
		goto cleanup;
	}
#endif
#endif

	me = (struct Process *)FindTask(NULL);
	if (me->pr_CLI != 0)
	{
		PutStr(vstring);
		rc = RETURN_OK;
		goto cleanup;
	}

	port = &me->pr_MsgPort;
	WaitPort(port);
	struct Message *msg = GetMsg(port);
	if (msg == NULL) goto cleanup;

	if (msg->mn_Node.ln_Name == NULL)
	{
		rc = RETURN_FAIL;
		Forbid();
		ReplyMsg(msg);
		goto cleanup;
	}

	pkt = (struct DosPacket *)msg->mn_Node.ln_Name;

	FileSysBoxBase = OpenLibrary(filesysboxName, 54);
	if (FileSysBoxBase == NULL)
	{
		goto cleanup;
	}

	SocketBase = OpenLibrary(bsdsocketName, 3);
	if (SocketBase == NULL)
	{
		goto cleanup;
	}

	if (SocketBaseTags(
		SBTM_SETVAL(SBTC_BREAKMASK),     0, /* Disable CTRL-C checking in WaitSelect() */
		SBTM_SETVAL(SBTC_ERRNOLONGPTR),  &errno,
		//SBTM_SETVAL(SBTC_HERRNOLONGPTR), &h_errno // TODO
		TAG_END))
	{
		goto cleanup;
	}

	rc = smb2fs_main(pkt);

	/* Set to NULL so we don't reply the packet twice */
	pkt = NULL;

cleanup:

	if (SocketBase != NULL)
	{
		CloseLibrary(SocketBase);
		SocketBase = NULL;
	}

	if (FileSysBoxBase != NULL)
	{
		CloseLibrary(FileSysBoxBase);
		FileSysBoxBase = NULL;
	}

	if (pkt != NULL)
	{
		ReplyPkt(pkt, DOSFALSE, ERROR_INVALID_RESIDENT_LIBRARY);
		pkt = NULL;
	}

#ifdef __AROS__
#ifndef NO_AROSC_LIB
	if (aroscbase != NULL)
	{
		CloseLibrary(aroscbase);
		aroscbase = NULL;
	}
#else
	if (CrtBase != NULL)
	{
		CloseLibrary(CrtBase);
		CrtBase = NULL;
	}
	if (StdlibBase != NULL)
	{
		CloseLibrary(StdlibBase);
		StdlibBase = NULL;
	}
#endif
#endif

	if (UtilityBase != NULL)
	{
		CloseLibrary((struct Library *)UtilityBase);
		DOSBase = NULL;
	}

	if (DOSBase != NULL)
	{
		CloseLibrary((struct Library *)DOSBase);
		DOSBase = NULL;
	}

	cleanup_malloc();

	return rc;

#ifdef __AROS__
	AROS_USERFUNC_EXIT
#endif
}

/* Disable CTRL-C signal checking in libc. */
void __chkabort(void) {}

static const TEXT USED verstag[] = VERSTAG;
static const TEXT vstring[] = VSTRING;
static const TEXT dosName[] = "dos.library";
static const TEXT utilityName[] = "utility.library";
#ifdef __AROS__
#ifndef NO_AROSC_LIB
static const TEXT aroscName[] = "arosc.library";
#else
static const TEXT stdlibName[] = "stdlib.library";
static const TEXT crtName[] = "crt.library";
#endif
#endif
static const TEXT filesysboxName[] = "filesysbox.library";
static const TEXT bsdsocketName[] = "bsdsocket.library";

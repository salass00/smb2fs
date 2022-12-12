/*
 * smb2-handler - SMB2 file system client
 *
 * Copyright (C) 2022 Fredrik Wikstrom <fredrik@a500.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS `AS IS'
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "smb2fs.h"

#include <proto/intuition.h>
#include <classes/requester.h>

#include <smb2/smb2.h>
#include <smb2/libsmb2.h>

#include <ctype.h>
#include <stdio.h>

#include "smb2-handler_rev.h"

struct fuse_context *_fuse_context_;

static const char cmd_template[] = 
	"URL/A,"
	"VOLUME,"
	"NOPASSWORD/S";

enum {
	ARG_URL,
	ARG_VOLUME,
	ARG_NOPASSWORD,
	NUM_ARGS
};

struct smb2fs_mount_data {
	char          *device;
	struct RDArgs *rda;
	LONG           args[NUM_ARGS];
};

struct smb2fs {
	struct smb2_context *smb2;
	BOOL                 connected:1;
};

struct smb2fs *fsd;

static char *request_password(struct smb2_url *url)
{
	struct IntuitionIFace *IIntuition;
	char                  *password = NULL;

	IIntuition = (struct IntuitionIFace *)open_interface("intuition.library", 53);
	if (IIntuition != NULL)
	{
		struct ClassLibrary *RequesterBase;
		Class               *RequesterClass;

		RequesterBase = IIntuition->OpenClass("requester.class", 53, &RequesterClass);
		if (RequesterBase != NULL)
		{
			struct Screen *screen;

			screen = IIntuition->LockPubScreen(NULL);
			if (screen != NULL)
			{
				TEXT    bodytext[256];
				TEXT    buffer[256];
				Object *reqobj;

				buffer[0] = '\0';

				snprintf(bodytext, sizeof(bodytext), "Enter password for %s@%s", url->user, url->server);

				reqobj = IIntuition->NewObject(RequesterClass, NULL,
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

					result = IIntuition->IDoMethodA(reqobj, (Msg)&reqmsg);

					if (result && buffer[0] != '\0')
					{
						password = strdup(buffer);
					}

					IIntuition->DisposeObject(reqobj);
				}

				IIntuition->UnlockPubScreen(NULL, screen);
			}

			IIntuition->CloseClass(RequesterBase);
		}

		close_interface((struct Interface *)IIntuition);
	}

	return password;
}

static void smb2fs_destroy(void *initret);

static void *smb2fs_init(struct fuse_conn_info *fci)
{
	struct smb2fs_mount_data *md;
	struct smb2_url          *url;

	md = fuse_get_context()->private_data;

	fsd = calloc(1, sizeof(*fsd));
	if (fsd == NULL)
		return NULL;

	fsd->smb2 = smb2_init_context();
	if (fsd->smb2 == NULL)
	{
		IExec->DebugPrintF("[smb2fs] Failed to init context\n");
		smb2fs_destroy(fsd);
		return NULL;
	}

	url = smb2_parse_url(fsd->smb2, (char *)md->args[ARG_URL]);
	if (url == NULL)
	{
		IExec->DebugPrintF("[smb2fs] Failed to parse url: %s\n", md->args[ARG_URL]);
		smb2fs_destroy(fsd);
		return NULL;
	}

	if (url->password == NULL && !md->args[ARG_NOPASSWORD])
	{
		url->password = request_password(url);
		if (url->password == NULL)
		{
			smb2fs_destroy(fsd);
			return NULL;
		}
	}

	smb2_set_security_mode(fsd->smb2, SMB2_NEGOTIATE_SIGNING_ENABLED);

	if (smb2_connect_share(fsd->smb2, url->server, url->share, url->user, url->password) < 0)
	{
		IExec->DebugPrintF("[smb2fs] smb2_connect_share failed. %s\n", smb2_get_error(fsd->smb2));
		smb2_destroy_url(url);
		smb2fs_destroy(fsd);
		return NULL;
	}

	fsd->connected = TRUE;

	if (md->args[ARG_VOLUME])
	{
		strlcpy(fci->volume_name, (const char *)md->args[ARG_VOLUME], CONN_VOLUME_NAME_BYTES);
	}
	else
	{
		snprintf(fci->volume_name, CONN_VOLUME_NAME_BYTES, "%s-%s", url->server, url->share);
	}

	smb2_destroy_url(url);
	url = NULL;

	return fsd;

}

static void smb2fs_destroy(void *initret)
{
	if (fsd == NULL)
		return;

	if (fsd->smb2 != NULL)
	{
		if (fsd->connected)
		{
			smb2_disconnect_share(fsd->smb2);
			fsd->connected = FALSE;
		}
		smb2_destroy_context(fsd->smb2);
		fsd->smb2 = NULL;
	}

	free(fsd);
	fsd = NULL;
}

static struct fuse_operations smb2fs_ops =
{
	.init    = smb2fs_init,
	.destroy = smb2fs_destroy
	/* FIXME: Implement and add fs ops here */
};

static void remove_double_quotes(char *argstr)
{
	char *start = argstr;
	char *end   = strchr(start, '\0');
	int   len;

	/* Strip leading white space characters */
	while (isspace(start[0]))
	{
		start++;
	}

	/* Strip trailing white space characters */
	while (end > start && isspace(end[-1]))
	{
		end--;
	}

	/* Remove opening quote ... */
	if (start[0] == '"')
	{
		start++;

		/* ... and closing quote */
		if (end > start && end[-1] == '"')
		{
			end--;
		}
	}

	/* Move to start of buffer and NUL-terminate */
	len = end - start;
	memmove(argstr, start, len);
	argstr[len] = '\0';
}

static struct RDArgs *read_startup_args(CONST_STRPTR template, LONG *args, const char *startup)
{
	char          *argstr;
	struct RDArgs *rda, in_rda;

	argstr = malloc(strlen(startup) + 2);
	if (argstr == NULL)
	{
		IDOS->SetIoErr(ERROR_NO_FREE_STORE);
		return NULL;
	}

	//IExec->DebugPrintF("startup: '%s'\n", startup);
	strcpy(argstr, startup);
	remove_double_quotes(argstr);
	//IExec->DebugPrintF("argstr: '%s'\n", argstr);
	strcat(argstr, "\n");

	memset(&in_rda, 0, sizeof(in_rda));

	in_rda.RDA_Source.CS_Buffer = argstr;
	in_rda.RDA_Source.CS_Length = strlen(argstr);
	in_rda.RDA_Flags            = RDAF_NOPROMPT;

	rda = IDOS->ReadArgs(template, args, &in_rda);

	free(argstr);

	return rda;
}

int smb2fs_main(struct DosPacket *pkt)
{
	struct smb2fs_mount_data  md;
	struct DeviceNode        *devnode;
	const char               *device;
	const char               *startup;
	uint32                    fsflags;
	struct FbxFS             *fs = NULL;
	int                       error;
	int                       rc = RETURN_ERROR;

	memset(&md, 0, sizeof(md));

	devnode = (struct DeviceNode *)BADDR(pkt->dp_Arg3);

	device  = (const char *)BADDR(devnode->dn_Name) + 1;
	startup = (const char *)BADDR(devnode->dn_Startup) + 1;

	devnode->dn_Startup = ZERO;

	md.device = strdup(device);
	if (md.device == NULL)
	{
		error = ERROR_NO_FREE_STORE;
		goto cleanup;
	}

	md.rda = read_startup_args(cmd_template, md.args, startup);
	if (md.rda == NULL)
	{
		error = IDOS->IoErr();
		goto cleanup;
	}

	fsflags = FBXF_ENABLE_UTF8_NAMES|FBXF_ENABLE_32BIT_UIDS|FBXF_USE_FILL_DIR_STAT;

	fs = IFileSysBox->FbxSetupFSTags(pkt->dp_Link, &smb2fs_ops, sizeof(smb2fs_ops), &md,
		FBXT_FSFLAGS,     fsflags,
		FBXT_DOSTYPE,     ID_SMB2_DISK,
		FBXT_GET_CONTEXT, &_fuse_context_,
		TAG_END);

	/* Set to NULL so we don't reply the message twice */
	pkt = NULL;

	if (fs != NULL)
	{
		IFileSysBox->FbxEventLoop(fs);

		rc = RETURN_OK;
	}

cleanup:

	if (fs != NULL)
	{
		IFileSysBox->FbxCleanupFS(fs);
		fs = NULL;
	}

	if (pkt != NULL)
	{
		IDOS->ReplyPkt(pkt, DOSFALSE, error);
		pkt = NULL;
	}

	if (md.rda != NULL)
	{
		IDOS->FreeArgs(md.rda);
		md.rda = NULL;
	}

	if (md.device != NULL)
	{
		free(md.device);
		md.device = NULL;
	}

	return rc;
}


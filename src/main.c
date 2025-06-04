/*
 * smb2-handler - SMB2 file system client
 *
 * Copyright (C) 2022-2025 Fredrik Wikstrom <fredrik@a500.org>
 * Copyright (C) 2024 Walter Licht https://github.com/sirwalt
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
#include "marshalling.h"

#include <dos/filehandler.h>
#ifndef __amigaos4__
#include <clib/debug_protos.h>
#endif
#include <stdint.h>

#include <smb2/smb2.h>
#include <smb2/libsmb2.h>

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#ifdef __amigaos4__
#include <unistd.h>
#else
#include <sys/param.h>
#endif

#ifndef ZERO
#define ZERO MKBADDR(NULL)
#endif

struct fuse_context *_fuse_context_;

static const char cmd_template[] = 
	"URL/A,"
	"USER,"
	"PASSWORD,"
	"VOLUME,"
	"READONLY/S,"
	"NOPASSWORDREQ/S,"
	"NOHANDLESRCV/S,"
	"RECONNECTREQ/S";

enum {
	ARG_URL,
	ARG_USER,
	ARG_PASSWORD,
	ARG_VOLUME,
	ARG_READONLY,
	ARG_NOPASSWORDREQ,
	ARG_NO_HANDLES_RCV,
	ARG_RECONNECT_REQ,
	NUM_ARGS
};

struct smb2fs_mount_data {
	char          *device;
	struct RDArgs *rda;
#ifdef __AROS__
	SIPTR          args[NUM_ARGS];
#else
	LONG           args[NUM_ARGS];
#endif
};

struct smb2fs {
	struct smb2_context *smb2;
	struct PointerHandleRegistry *phr;
	BOOL                 rdonly:1;
	BOOL                 connected:1;
	char                *rootdir;
};

struct smb2fs *fsd;
uint32_t phr_incarnation = 1;
BOOL cfg_reconnect_req = FALSE;
BOOL cfg_handles_rcv = TRUE; // recover handles (experimental)
char last_server[128];

static void smb2fs_destroy(void *initret);

static void *smb2fs_init(struct fuse_conn_info *fci)
{
	struct smb2fs_mount_data *md;
	// KPrintF((STRPTR)"[smb2fs] smb2fs_init started.\n");
	struct smb2_url          *url;
	const char               *username;
	const char               *password;

	md = fuse_get_context()->private_data;

	if (md->args[ARG_RECONNECT_REQ])
		cfg_reconnect_req = TRUE;

	if (md->args[ARG_NO_HANDLES_RCV])
		cfg_handles_rcv = FALSE;

	fsd = calloc(1, sizeof(*fsd));
	if (fsd == NULL)
	{
		request_error("Failed to allocate memory for the file system data");
		return NULL;
	}

	fsd->phr = AllocateNewRegistry(phr_incarnation++);
	if (fsd->phr == NULL)
	{
		request_error("Failed to allocate memory for the pointer handle registry");
		free(fsd);
		fsd = NULL;
		return NULL;
	}

	if (md->args[ARG_READONLY])
		fsd->rdonly = TRUE;

	fsd->smb2 = smb2_init_context();
	if (fsd->smb2 == NULL)
	{
		request_error("Failed to init context");
		smb2fs_destroy(fsd);
		return NULL;
	}

	url = smb2_parse_url(fsd->smb2, (char *)md->args[ARG_URL]);
	if (url == NULL)
	{
		request_error("Failed to parse url:\n%s", md->args[ARG_URL]);
		smb2fs_destroy(fsd);
		return NULL;
	}

	strlcpy(last_server, url->server, sizeof(last_server));

	username = url->user;
	password = url->password;

	if (md->args[ARG_USER])
	{
		username = (const char *)md->args[ARG_USER];
	}
	if (md->args[ARG_PASSWORD])
	{
		password = (const char *)md->args[ARG_PASSWORD];
	}

	if (password == NULL && !md->args[ARG_NOPASSWORDREQ])
	{
		url->password = password = request_password(url->user, url->server);
		if (password == NULL)
		{
			request_error("No password was specified for the share");
			smb2fs_destroy(fsd);
			return NULL;
		}
	}

	if (password == NULL)
	{
		password = "";
	}

	smb2_set_security_mode(fsd->smb2, SMB2_NEGOTIATE_SIGNING_ENABLED);
	if (url->domain != NULL)
	{
		smb2_set_domain(fsd->smb2, url->domain);
	}

	if (smb2_connect_share(fsd->smb2, url->server, url->share, username, password) < 0)
	{
		request_error("smb2_connect_share failed.\n%s", smb2_get_error(fsd->smb2));
		smb2_destroy_url(url);
		smb2fs_destroy(fsd);
		return NULL;
	}

	fsd->connected = TRUE;

	if (url->path != NULL && url->path[0] != '\0')
	{
		const char *patharg = url->path;
		int         pos     = 0;
		char        pathbuf[MAXPATHLEN];
		char        namebuf[256];

		pathbuf[0] = '\0';

		do
		{
			pos = SplitName((CONST_STRPTR)patharg, '/', (STRPTR)namebuf, pos, sizeof(namebuf));

			if (namebuf[0] == '\0')
				continue;

			if (strcmp(namebuf, ".") == 0)
				continue;

			if (strcmp(namebuf, "..") == 0)
			{
				char *p;

				/* If not already at root, go up one level */
				p = strrchr(pathbuf, '/');
				if (p != NULL)
				{
					*p = '\0';
					continue;
				}
			}

			strlcat(pathbuf, "/", sizeof(pathbuf));
			strlcat(pathbuf, namebuf, sizeof(pathbuf));
		}
		while (pos != -1);

		if (pathbuf[0] != '\0' && strcmp(pathbuf, "/") != 0)
		{
			fsd->rootdir = strdup(pathbuf);
			if (fsd->rootdir == NULL)
			{
				request_error("Failed to allocate memory for the root directory");
				smb2_destroy_url(url);
				smb2fs_destroy(fsd);
				return NULL;
			}
		}
	}

	// Only on first initialization
	if(fci)
	{
		if (md->args[ARG_VOLUME])
		{
			strlcpy(fci->volume_name, (const char *)md->args[ARG_VOLUME], CONN_VOLUME_NAME_BYTES);
		}
		else
		{
			snprintf(fci->volume_name, CONN_VOLUME_NAME_BYTES, "%s-%s", url->server, url->share);
		}
	}

	smb2_destroy_url(url);
	url = NULL;

	return fsd;
}

static void smb2fs_destroy(void *initret)
{
	// KPrintF((STRPTR)"[smb2fs] smb2fs_destroy started.\n");
	if (fsd == NULL) {
		// KPrintF((STRPTR)"[smb2fs] smb2fs_destroy NULL return.\n");
		return;
	}
	
	if (fsd->smb2 != NULL)
	{
		if (fsd->connected)
		{
			// KPrintF((STRPTR)"[smb2fs] smb2fs_destroy connected => disconnect.\n");
			smb2_disconnect_share(fsd->smb2);
			// KPrintF((STRPTR)"[smb2fs] smb2fs_destroy disconnected.\n");
			fsd->connected = FALSE;
		}
		// KPrintF((STRPTR)"[smb2fs] smb2fs_destroy => destroy smb2 context.\n");
		smb2_destroy_context(fsd->smb2);
		// KPrintF((STRPTR)"[smb2fs] smb2fs_destroy smb2 context destroyed.\n");
		fsd->smb2 = NULL;
	}

	if (fsd->rootdir != NULL)
	{
		// KPrintF((STRPTR)"[smb2fs] smb2fs_destroy => free root dir.\n");
		free(fsd->rootdir);
		// KPrintF((STRPTR)"[smb2fs] smb2fs_destroy root dir freed.\n");
		fsd->rootdir = NULL;
	}

	if (fsd->phr != NULL)
	{
		FreeRegistry(fsd->phr);
		fsd->phr = NULL;
	}


	// KPrintF((STRPTR)"[smb2fs] smb2fs_destroy => free fsd.\n");
	free(fsd);
	fsd = NULL;
	// KPrintF((STRPTR)"[smb2fs] smb2fs_destroy FINISHED.\n");
}

#include "libsmb2-private.h"

// Debug function to print 'smb2_context'
/* static void debug_print_smb2_context(const struct smb2_context *ctx) {
    KPrintF("SMB2 Context:\n");
    KPrintF("Socket FD: %ld\n", ctx->fd);
	KPrintF("Connecting FDs: %lu\n", ctx->connecting_fds);
    KPrintF("Connecting FDs Count: %lu\n", ctx->connecting_fds_count);
    KPrintF("Timeout: %ld\n", ctx->timeout);
    KPrintF("Security Mode: %u\n", ctx->security_mode);
    KPrintF("Use Cached Credentials: %s\n", ctx->use_cached_creds ? "Yes" : "No");
    KPrintF("Server: %s\n", ctx->server ? ctx->server : "NULL");
    KPrintF("Share: %s\n", ctx->share ? ctx->share : "NULL");
    KPrintF("User: %s\n", ctx->user ? ctx->user : "NULL");
    
    switch (ctx->sec) {
        case 0: KPrintF("Security: None\n"); break;
        case 2: KPrintF("Security: Kerberos\n"); break;
        case 1: KPrintF("Security: NTLMSSP\n"); break;
        default: KPrintF("Security: Unknown\n"); break;
    }
    
    switch (ctx->version) {
        case SMB2_VERSION_ANY:  KPrintF("Version: SMB2_ANY\n"); break;
        case SMB2_VERSION_ANY2: KPrintF("Version: SMB2_ANY2\n"); break;
        case SMB2_VERSION_ANY3: KPrintF("Version: SMB2_ANY3\n"); break;
        case SMB2_VERSION_0202: KPrintF("Version: SMB2_0202\n"); break;
        case SMB2_VERSION_0210: KPrintF("Version: SMB2_0210\n"); break;
        case SMB2_VERSION_0300: KPrintF("Version: SMB2_0300\n"); break;
        case SMB2_VERSION_0302: KPrintF("Version: SMB2_0302\n"); break;
        case SMB2_VERSION_0311: KPrintF("Version: SMB2_0311\n"); break;
        default: KPrintF("Version: Unknown (%x)\n", ctx->version); break;
    }
} */

static int handle_connection_fault()
{
	const char *psz_error = smb2_get_error(fsd->smb2);

	request_error(psz_error);
	
	smb2_destroy_context(fsd->smb2);
	fsd->smb2 = NULL;

	if (fsd->rootdir != NULL)
	{
		free(fsd->rootdir);
		fsd->rootdir = NULL;
	}
	free(fsd);
	fsd = NULL;

	if(!cfg_reconnect_req)
		return FALSE;
	
	while(request_reconnect(last_server))
	{
		if(smb2fs_init(NULL))
			return TRUE;
	}
	
	return FALSE;
}


static int smb2fs_statfs(const char *path, struct statvfs *sfs)
{
	// KPrintF((STRPTR)"[smb2fs] smb2fs_statfs started.\n");
	struct smb2_statvfs smb2_sfs;
	int                 rc;
	char                pathbuf[MAXPATHLEN];
	uint32_t            frsize;
	uint64_t            blocks, bfree, bavail;

	if (fsd == NULL)
		/*
		* trying to reconnect in smb2fs_statfs could be cumbersome usability,
		* do to the frequent polls triggered somewhere in either AmigaDOS or filesysbox.library.
		* Reconnects are implement for all other functions.
		*/
		return -ENODEV;

	if (path == NULL || path[0] == '\0')
		path = "/";

	if (fsd->rootdir != NULL)
	{
		strlcpy(pathbuf, fsd->rootdir, sizeof(pathbuf));
		strlcat(pathbuf, path, sizeof(pathbuf));
		path = pathbuf;
	}

	if (path[0] == '/') path++; /* Remove initial slash */

	// debug_print_smb2_context(fsd->smb2);

	do {
		rc = smb2_statvfs(fsd->smb2, path, &smb2_sfs);
		if(rc < -1)
		{
			// KPrintF("[smb2fs_statfs] r2: %ld\n", rc);
			// KPrintF("[smb2fs_statfs] r2_text: %s\n", nterror_to_str(rc));
			return rc;
		}
		else if (rc < 0)
		{
			if(!handle_connection_fault())
				return -ENODEV;
		}
	} while(rc < 0);

	frsize = smb2_sfs.f_frsize;
	blocks = smb2_sfs.f_blocks;
	bfree  = smb2_sfs.f_bfree;
	bavail = smb2_sfs.f_bavail;
	while (blocks > INT32_MAX)
	{
		frsize <<= 1;
		blocks >>= 1;
		bfree  >>= 1;
		bavail >>= 1;
	}

	sfs->f_bsize   = smb2_sfs.f_bsize;
	sfs->f_frsize  = frsize;
	sfs->f_blocks  = blocks;
	sfs->f_bfree   = bfree;
	sfs->f_bavail  = bavail;
	sfs->f_files   = smb2_sfs.f_files;
	sfs->f_ffree   = smb2_sfs.f_ffree;
	sfs->f_favail  = smb2_sfs.f_favail;
	sfs->f_fsid    = smb2_sfs.f_fsid;
	sfs->f_namemax = smb2_sfs.f_namemax;
	sfs->f_flag    = 0; /* SMB protocol is case insensitive even if host fs is not */

	if (fsd->rdonly)
		sfs->f_flag |= ST_RDONLY;

	if (sfs->f_namemax > 255)
	{
		sfs->f_namemax = 255;
	}

	return 0;
}

static void smb2fs_fillstat(struct fbx_stat *stbuf, const struct smb2_stat_64 *smb2_st)
{
	// KPrintF((STRPTR)"[smb2fs] smb2fs_fillstat started.\n");
	memset(stbuf, 0, sizeof(*stbuf));

	switch (smb2_st->smb2_type)
	{
		case SMB2_TYPE_FILE:
			stbuf->st_mode = S_IFREG;
			break;
		case SMB2_TYPE_DIRECTORY:
			stbuf->st_mode = S_IFDIR;
			break;
		case SMB2_TYPE_LINK:
			stbuf->st_mode = S_IFLNK;
			break;
	}
	stbuf->st_mode |= S_IRWXU; /* Can we do something better? */

	stbuf->st_ino       = smb2_st->smb2_ino;
	stbuf->st_nlink     = smb2_st->smb2_nlink;
	stbuf->st_size      = smb2_st->smb2_size;
	stbuf->st_atime     = smb2_st->smb2_atime;
	stbuf->st_atimensec = smb2_st->smb2_atime_nsec;
	stbuf->st_mtime     = smb2_st->smb2_mtime;
	stbuf->st_mtimensec = smb2_st->smb2_mtime_nsec;
	stbuf->st_ctime     = smb2_st->smb2_ctime;
	stbuf->st_ctimensec = smb2_st->smb2_ctime_nsec;
}

static int smb2fs_getattr(const char *path, struct fbx_stat *stbuf)
{
	// KPrintF((STRPTR)"[smb2fs] smb2fs_getattr started.\n");
	struct smb2_stat_64 smb2_st;
	int                 rc;
	char                pathbuf[MAXPATHLEN];

	if (fsd == NULL)
	{
		if(cfg_reconnect_req)
		{
			if(!(request_reconnect(last_server) && smb2fs_init(NULL)))
				return -ENODEV;
		}
		else if(!smb2fs_init(NULL))
			return -ENODEV;
	}

	if (fsd->rootdir != NULL)
	{
		strlcpy(pathbuf, fsd->rootdir, sizeof(pathbuf));
		strlcat(pathbuf, path, sizeof(pathbuf));
		path = pathbuf;
	}

	if (path[0] == '/') path++; /* Remove initial slash */

	do {
		rc = smb2_stat(fsd->smb2, path, &smb2_st);
		if(rc < -1)
		{
			// KPrintF("[smb2fs_getattr] r2: %ld\n", rc);
			// KPrintF("[smb2fs_getattr] r2_text: %s\n", nterror_to_str(rc));
			return rc;
		}
		else if (rc < 0)
		{
			if(!handle_connection_fault())
				return -ENODEV;
		}
	} while(rc < 0);

	smb2fs_fillstat(stbuf, &smb2_st);

	return 0;
}

static int smb2fs_fgetattr(const char *path, struct fbx_stat *stbuf,
                           struct fuse_file_info *fi)
{
	// KPrintF((STRPTR)"[smb2fs] smb2fs_fgetattr started.\n");
	struct smb2fh      *smb2fh;
	struct smb2_stat_64 smb2_st;
	int                 rc;

	if (fsd == NULL)
	{
		if(cfg_reconnect_req)
		{
			if(!(request_reconnect(last_server) && smb2fs_init(NULL)))
				return -ENODEV;
		}
		else if(!smb2fs_init(NULL))
			return -ENODEV;
	}

	do {
		smb2fh = (struct smb2fh *) HandleToPointer(fsd->phr, (uint32_t) fi->fh);
		if (smb2fh == NULL)
			return -EINVAL;

		rc = smb2_fstat(fsd->smb2, smb2fh, &smb2_st);
		if(rc < -1)
		{
			// KPrintF("[smb2fs_fgetattr] r2: %ld\n", rc);
			// KPrintF("[smb2fs_fgetattr] r2_text: %s\n", nterror_to_str(rc));
			return rc;
		}
		else if (rc < 0)
		{
			if(!handle_connection_fault())
				return -ENODEV;
		}
	} while(rc < 0);

	smb2fs_fillstat(stbuf, &smb2_st);

	return 0;
}

static int smb2fs_mkdir(const char *path, mode_t mode)
{
	// KPrintF((STRPTR)"[smb2fs] smb2fs_mkdir started.\n");
	int  rc;
	char pathbuf[MAXPATHLEN];

	if (fsd == NULL)
	{
		if(cfg_reconnect_req)
		{
			if(!(request_reconnect(last_server) && smb2fs_init(NULL)))
				return -ENODEV;
		}
		else if(!smb2fs_init(NULL))
			return -ENODEV;
	}

	if (fsd->rdonly)
		return -EROFS;

	if (fsd->rootdir != NULL)
	{
		strlcpy(pathbuf, fsd->rootdir, sizeof(pathbuf));
		strlcat(pathbuf, path, sizeof(pathbuf));
		path = pathbuf;
	}

	if (path[0] == '/') path++; /* Remove initial slash */

	do {
		rc = smb2_mkdir(fsd->smb2, path);
		if(rc < -1)
		{
			return rc;
		}
		else if (rc < 0)
		{
			if(!handle_connection_fault())
				return -ENODEV;
		}
	} while(rc < 0);

	return 0;
}

static int smb2fs_opendir(const char *path, struct fuse_file_info *fi)
{
	// KPrintF((STRPTR)"[smb2fs] smb2fs_opendir started.\n");
	struct smb2dir *smb2dir;
	char            pathbuf[MAXPATHLEN];
	int 			r2;

	if (fsd == NULL)
	{
		if(cfg_reconnect_req)
		{
			if(!(request_reconnect(last_server) && smb2fs_init(NULL)))
				return -ENODEV;
		}
		else if(!smb2fs_init(NULL))
			return -ENODEV;
	}

	if (fsd->rootdir != NULL)
	{
		strlcpy(pathbuf, fsd->rootdir, sizeof(pathbuf));
		strlcat(pathbuf, path, sizeof(pathbuf));
		path = pathbuf;
	}

	if (path[0] == '/') path++; /* Remove initial slash */

	do {
		smb2dir = smb2_opendir(fsd->smb2, path, &r2);
		if (smb2dir == NULL)
		{
			if(r2 == -1 || r2 == SMB2_STATUS_CANCELLED)
			{
				if(!handle_connection_fault())
					return -ENODEV;
			}
			else
				return -ENOENT;
		}
	} while(smb2dir == NULL);
	// smb2dir = smb2_opendir(fsd->smb2, path);
	// if (smb2dir == NULL)
	// {
	// 	return -ENOENT;
	// }

	//fi->fh = (uint64_t)(size_t)smb2dir;
	fi->fh = AllocateHandleForPointer(fsd->phr, smb2dir);
	if (fi->fh == 0)
	{
		return -ENOMEM;
	}

	return 0;
}

static int smb2fs_releasedir(const char *path, struct fuse_file_info *fi)
{
	// KPrintF((STRPTR)"[smb2fs] smb2fs_releasedir started.\n");
	struct smb2dir *smb2dir;

	if (fsd == NULL)
	{
		if(cfg_reconnect_req)
		{
			if(!(request_reconnect(last_server) && smb2fs_init(NULL)))
				return -ENODEV;
		}
		else if(!smb2fs_init(NULL))
			return -ENODEV;
	}

	// smb2dir = (struct smb2dir *)(size_t)fi->fh;
	// if (smb2dir == NULL)
	// 	return -EINVAL;
	smb2dir = (struct smb2dir *) HandleToPointer(fsd->phr, (uint32_t) fi->fh);
	if (smb2dir == NULL)
		return -EINVAL;

	smb2_closedir(fsd->smb2, smb2dir);
	RemoveHandle(fsd->phr, (uint32_t) fi->fh);
	fi->fh = (uint64_t)(size_t)NULL;

	return 0;
}

static int smb2fs_readdir(const char *path, void *buffer, fuse_fill_dir_t filler,
	fbx_off_t offset, struct fuse_file_info *fi)
{
	// KPrintF((STRPTR)"[smb2fs] smb2fs_readdir started.\n");
	struct smb2dir    *smb2dir;
	struct smb2dirent *ent;
	struct fbx_stat    stbuf;

	if (fsd == NULL)
	{
		if(cfg_reconnect_req)
		{
			if(!(request_reconnect(last_server) && smb2fs_init(NULL)))
				return -ENODEV;
		}
		else if(!smb2fs_init(NULL))
			return -ENODEV;
	}

	if (fi == NULL)
		return -EINVAL;

	// smb2dir = (struct smb2dir *)(size_t)fi->fh;
	// if (smb2dir == NULL)
	// 	return -EINVAL;
	smb2dir = (struct smb2dir *) HandleToPointer(fsd->phr, (uint32_t) fi->fh);
	if (smb2dir == NULL)
		return -EINVAL;

	while ((ent = smb2_readdir(fsd->smb2, smb2dir)) != NULL)
	{
		smb2fs_fillstat(&stbuf, &ent->st);
		filler(buffer, ent->name, &stbuf, 0);
	}

	return 0;
}

static int smb2fs_open(const char *path, struct fuse_file_info *fi)
{
	// KPrintF((STRPTR)"[smb2fs] smb2fs_open started.\n");
	struct smb2fh *smb2fh;
	int            flags;
	char           pathbuf[MAXPATHLEN];
	int				r2;

	if (fsd == NULL)
	{
		if(cfg_reconnect_req)
		{
			if(!(request_reconnect(last_server) && smb2fs_init(NULL)))
				return -ENODEV;
		}
		else if(!smb2fs_init(NULL))
			return -ENODEV;
	}

	if (fsd->rootdir != NULL)
	{
		strlcpy(pathbuf, fsd->rootdir, sizeof(pathbuf));
		strlcat(pathbuf, path, sizeof(pathbuf));
		path = pathbuf;
	}

	if (path[0] == '/') path++; /* Remove initial slash */

	flags = fsd->rdonly ? O_RDONLY : O_RDWR;

	for (;;)
	{
		do 
		{
			smb2fh = smb2_open(fsd->smb2, path, flags, &r2);
			if(r2 == -1 || r2 == SMB2_STATUS_CANCELLED)
			{
				if(!handle_connection_fault())
					return -ENODEV;
			}
		} while (r2 == -1 || r2 == SMB2_STATUS_CANCELLED);

		// KPrintF("[smb2_open] r2: %ld\n", r2);
		// KPrintF("[smb2_open] r2_text: %s\n", nterror_to_str(r2));
		if (smb2fh != NULL)
		{
			// fi->fh = (uint64_t)(size_t)smb2fh;
			fi->fh = AllocateHandleForPointer(fsd->phr, smb2fh);
			if (fi->fh == 0)
			{
				return -ENOMEM;
			}
			return 0;
		}
		else
		{
			/* If O_RDWR failed, try O_RDONLY */
			if ((flags & O_ACCMODE) == O_RDWR)
			{
				flags = (flags & ~O_ACCMODE) | O_RDONLY;
				continue;
			}
			return -ENOENT;
		}
	}
}

static int smb2fs_create(const char *path, mode_t mode, struct fuse_file_info *fi)
{
	// KPrintF((STRPTR)"[smb2fs] smb2fs_create started.\n");
	struct smb2fh *smb2fh;
	int            flags;
	char           pathbuf[MAXPATHLEN];
	int 			r2;

	if (fsd == NULL)
	{
		if(cfg_reconnect_req)
		{
			if(!(request_reconnect(last_server) && smb2fs_init(NULL)))
				return -ENODEV;
		}
		else if(!smb2fs_init(NULL))
			return -ENODEV;
	}

	if (fsd->rdonly)
		return -EROFS;

	if (fsd->rootdir != NULL)
	{
		strlcpy(pathbuf, fsd->rootdir, sizeof(pathbuf));
		strlcat(pathbuf, path, sizeof(pathbuf));
		path = pathbuf;
	}

	if (path[0] == '/') path++; /* Remove initial slash */

	flags = O_CREAT | O_EXCL | O_RDWR;

	do 
	{
		smb2fh = smb2_open(fsd->smb2, path, flags, &r2);
		if(r2 == -1 || r2 == SMB2_STATUS_CANCELLED)
		{
			if(!handle_connection_fault())
				return -ENODEV;
		}
	} while (r2 == -1 || r2 == SMB2_STATUS_CANCELLED);

	if (smb2fh != NULL)
	{
		// fi->fh = (uint64_t)(size_t)smb2fh;
		fi->fh = AllocateHandleForPointer(fsd->phr, smb2fh);
		if (fi->fh == 0)
		{
			return -ENOMEM;
		}
		return 0;
	}

	return -1; // r2
}

static int smb2fs_release(const char *path, struct fuse_file_info *fi)
{
	// KPrintF((STRPTR)"[smb2fs] smb2fs_release started.\n");
	struct smb2fh *smb2fh;

	if (fsd == NULL)
	{
		if(cfg_reconnect_req)
		{
			if(!(request_reconnect(last_server) && smb2fs_init(NULL)))
				return -ENODEV;
		}
		else if(!smb2fs_init(NULL))
			return -ENODEV;
	}

	// smb2fh = (struct smb2fh *)(size_t)fi->fh;
	// if (smb2fh == NULL)
	// 	return -EINVAL;
	smb2fh = (struct smb2fh *) HandleToPointer(fsd->phr, (uint32_t) fi->fh);
	if (smb2fh == NULL)
		return -EINVAL;

	smb2_close(fsd->smb2, smb2fh);
	RemoveHandle(fsd->phr, (uint32_t) fi->fh);
	fi->fh = (uint64_t)(size_t)NULL;

	return 0;
}


static int smb2fs_read(const char *path, char *buffer, size_t size,
                       fbx_off_t offset, struct fuse_file_info *fi)
{
	// KPrintF((STRPTR)"[smb2fs] smb2fs_read started with path:\"%s\".\n", path);
	struct smb2fh *smb2fh;
	int64_t        new_offset;
	size_t         max_read_size, count;
	int            rc = 0;
	int				rc_open = 0;
	int            result;
	char 			*buffer_ref;

	if (fsd == NULL)
	{
		if(cfg_reconnect_req)
		{
			if(!(request_reconnect(last_server) && smb2fs_init(NULL)))
				return -ENODEV;
		}
		else if(!smb2fs_init(NULL))
			return -ENODEV;

		if(cfg_handles_rcv)
		{
			rc_open = smb2fs_open(path, fi);
			if(rc_open < 0)
				return -EIO;
		}
	}

	do {
		buffer_ref = buffer;

		smb2fh = (struct smb2fh *) HandleToPointer(fsd->phr, (uint32_t) fi->fh);
		if (smb2fh == NULL)
			return -EINVAL;

		new_offset = smb2_lseek(fsd->smb2, smb2fh, offset, SEEK_SET, NULL);
		if (new_offset < 0)
		{
			return (int)new_offset;
		}

		max_read_size = smb2_get_max_read_size(fsd->smb2);
		//IExec->DebugPrintF("max_read_size: %lu\n", max_read_size);
		result = 0;

		while (size > 0)
		{
			count = size;
			if (count > max_read_size)
				count = max_read_size;

			rc = smb2_read(fsd->smb2, smb2fh, (uint8_t *)buffer_ref, count);
			if (rc == 0)
			{
				break;
			}
			else if(rc < -1)
			{
				return rc;
			}
			else if (rc < 0)
			{
				if(!handle_connection_fault())
					return -ENODEV;

				if(cfg_handles_rcv)
				{
					rc_open = smb2fs_open(path, fi);
					if(rc_open < 0)
						return -EIO;
				}
				else
				{
					/* even if connection has reestablished, we do not have a handle recovery for now and need to fail the op */
					return -EIO;
				}
			}

			result += rc;
			buffer_ref += rc;
			size   -= rc;
		}
	} while(rc < 0);

	return result;
}

static int smb2fs_write(const char *path, const char *buffer, size_t size,
                        fbx_off_t offset, struct fuse_file_info *fi)
{
	// KPrintF((STRPTR)"[smb2fs] smb2fs_write started.\n");
	struct smb2fh *smb2fh;
	int64_t        new_offset;
	size_t         max_write_size, count;
	int            rc = 0;
	int				rc_open = 0;
	int            result;
	const char		*buffer_ref;

	if (fsd == NULL)
	{
		if(cfg_reconnect_req)
		{
			if(!(request_reconnect(last_server) && smb2fs_init(NULL)))
				return -ENODEV;
		}
		else if(!smb2fs_init(NULL))
			return -ENODEV;

		if(cfg_handles_rcv)
		{
			rc_open = smb2fs_open(path, fi);
			if(rc_open < 0)
				return -EIO;
		}
	}

	if (fsd->rdonly)
		return -EROFS;

	do {
		buffer_ref = buffer;
		smb2fh = (struct smb2fh *) HandleToPointer(fsd->phr, (uint32_t) fi->fh);
		if (smb2fh == NULL)
			return -EINVAL;

		new_offset = smb2_lseek(fsd->smb2, smb2fh, offset, SEEK_SET, NULL);
		if (new_offset < 0)
		{
			return (int)new_offset;
		}

		max_write_size = smb2_get_max_write_size(fsd->smb2);
		//IExec->DebugPrintF("max_write_size: %lu\n", max_write_size);
		result = 0;

		while (size > 0)
		{
			count = size;
			if (count > max_write_size)
				count = max_write_size;

			rc = smb2_write(fsd->smb2, smb2fh, (const uint8_t *)buffer_ref, count);
			if (rc == 0)
			{
				break;
			}
			else if(rc < -1)
			{
				return rc;
			}
			else if (rc < 0)
			{
				if(!handle_connection_fault())
					return -ENODEV;

				if(cfg_handles_rcv)
				{
					rc_open = smb2fs_open(path, fi);
					if(rc_open < 0)
						return -EIO;
				}
				else
				{
					/* even if connection has reestablished, we do not have a handle recovery for now and need to fail the op */
					return -EIO;
				}
			}

			result += rc;
			buffer_ref += rc;
			size   -= rc;
		}
	} while(rc < 0);

	return result;
}

static int smb2fs_truncate(const char *path, fbx_off_t size)
{
	// KPrintF((STRPTR)"[smb2fs] smb2fs_truncate started.\n");
	int  rc;
	char pathbuf[MAXPATHLEN];

	if (fsd == NULL)
	{
		if(cfg_reconnect_req)
		{
			if(!(request_reconnect(last_server) && smb2fs_init(NULL)))
				return -ENODEV;
		}
		else if(!smb2fs_init(NULL))
			return -ENODEV;
	}

	if (fsd->rdonly)
		return -EROFS;

	if (fsd->rootdir != NULL)
	{
		strlcpy(pathbuf, fsd->rootdir, sizeof(pathbuf));
		strlcat(pathbuf, path, sizeof(pathbuf));
		path = pathbuf;
	}

	if (path[0] == '/') path++; /* Remove initial slash */

	do {
		rc = smb2_truncate(fsd->smb2, path, size);
		if(rc < -1)
		{
			return rc;
		}
		else if (rc < 0)
		{
			if(!handle_connection_fault())
				return -ENODEV;
		}
	} while(rc < 0);

	return 0;
}

static int smb2fs_ftruncate(const char *path, fbx_off_t size, struct fuse_file_info *fi)
{
	// KPrintF((STRPTR)"[smb2fs] smb2fs_ftruncate started.\n");
	struct smb2fh *smb2fh;
	int            rc;
	int				rc_open = 0;

	if (fsd == NULL)
	{
		if(cfg_reconnect_req)
		{
			if(!(request_reconnect(last_server) && smb2fs_init(NULL)))
				return -ENODEV;
		}
		else if(!smb2fs_init(NULL))
			return -ENODEV;

		if(cfg_handles_rcv)
		{
			rc_open = smb2fs_open(path, fi);
			if(rc_open < 0)
				return -EIO;
		}
	}

	if (fsd->rdonly)
		return -EROFS;

	
	do {
		smb2fh = (struct smb2fh *) HandleToPointer(fsd->phr, (uint32_t) fi->fh);
		if (smb2fh == NULL)
			return -EINVAL;

		rc = smb2_ftruncate(fsd->smb2, smb2fh, size);
		if(rc < -1)
		{
			return rc;
		}
		else if (rc < 0)
		{
			if(!handle_connection_fault())
				return -ENODEV;

			if(cfg_handles_rcv)
			{
				rc_open = smb2fs_open(path, fi);
				if(rc_open < 0)
					return -EIO;
			}
			else
			{
				/* even if connection has reestablished, we do not have a handle recovery for now and need to fail the op */
				return -EIO;
			}
		}
	} while(rc < 0);

	return 0;
}

static int smb2fs_unlink(const char *path)
{
	// KPrintF((STRPTR)"[smb2fs] smb2fs_unlink started.\n");
	int  rc;
	char pathbuf[MAXPATHLEN];

	if (fsd == NULL)
	{
		if(cfg_reconnect_req)
		{
			if(!(request_reconnect(last_server) && smb2fs_init(NULL)))
				return -ENODEV;
		}
		else if(!smb2fs_init(NULL))
			return -ENODEV;
	}

	if (fsd->rdonly)
		return -EROFS;

	if (fsd->rootdir != NULL)
	{
		strlcpy(pathbuf, fsd->rootdir, sizeof(pathbuf));
		strlcat(pathbuf, path, sizeof(pathbuf));
		path = pathbuf;
	}

	if (path[0] == '/') path++; /* Remove initial slash */

	do {
		rc = smb2_unlink(fsd->smb2, path);
		if(rc < -1)
		{
			return rc;
		}
		else if (rc < 0)
		{
			if(!handle_connection_fault())
				return -ENODEV;
		}
	} while(rc < 0);

	return 0;
}

static int smb2fs_rmdir(const char *path)
{
	// KPrintF((STRPTR)"[smb2fs] smb2fs_rmdir started.\n");
	struct smb2dir *smb2dir;
	int  rc;
	char pathbuf[MAXPATHLEN];
	int r2;
	struct smb2dirent *ent;
	BOOL notempty = FALSE;


	if (fsd == NULL)
	{
		if(cfg_reconnect_req)
		{
			if(!(request_reconnect(last_server) && smb2fs_init(NULL)))
				return -ENODEV;
		}
		else if(!smb2fs_init(NULL))
			return -ENODEV;
	}

	if (fsd->rdonly)
		return -EROFS;

	if (fsd->rootdir != NULL)
	{
		strlcpy(pathbuf, fsd->rootdir, sizeof(pathbuf));
		strlcat(pathbuf, path, sizeof(pathbuf));
		path = pathbuf;
	}

	if (path[0] == '/') path++; /* Remove initial slash */

	/* Make sure to return correct error for non-empty directory */
	do {
		smb2dir = smb2_opendir(fsd->smb2, path, &r2);
		if (smb2dir == NULL)
		{
			if(r2 == -1 || r2 == SMB2_STATUS_CANCELLED)
			{
				if(!handle_connection_fault())
					return -ENODEV;
			}
			else
				return -ENOENT;
		}
	} while(smb2dir == NULL);

	
	while ((ent = smb2_readdir(fsd->smb2, smb2dir)) != NULL)
	{
		if (strcmp(ent->name, ".") != 0 && strcmp(ent->name, "..") != 0)
		{
			notempty = TRUE;
			break;
		}
	}
	smb2_closedir(fsd->smb2, smb2dir);

	if (notempty)
	{
		return -ENOTEMPTY;
	}

	do {
		rc = smb2_rmdir(fsd->smb2, path);
		if(rc < -1)
		{
			return rc;
		}
		else if (rc < 0)
		{
			if(!handle_connection_fault())
				return -ENODEV;
		}
	} while(rc < 0);

	return 0;
}

static int smb2fs_readlink(const char *path, char *buffer, size_t size)
{
	// KPrintF((STRPTR)"[smb2fs] smb2fs_readlink started.\n");
	int  rc;
	char pathbuf[MAXPATHLEN];

	if (fsd == NULL)
	{
		if(cfg_reconnect_req)
		{
			if(!(request_reconnect(last_server) && smb2fs_init(NULL)))
				return -ENODEV;
		}
		else if(!smb2fs_init(NULL))
			return -ENODEV;
	}

	if (fsd->rootdir != NULL)
	{
		strlcpy(pathbuf, fsd->rootdir, sizeof(pathbuf));
		strlcat(pathbuf, path, sizeof(pathbuf));
		path = pathbuf;
	}

	if (path[0] == '/') path++; /* Remove initial slash */

	do {
		rc = smb2_readlink(fsd->smb2, path, buffer, size);
		if(rc < -1)
		{
			return rc;
		}
		else if (rc < 0)
		{
			if(!handle_connection_fault())
				return -ENODEV;
		}
	} while(rc < 0);

	return 0;
}

static int smb2fs_rename(const char *srcpath, const char *dstpath)
{
	// KPrintF((STRPTR)"[smb2fs] smb2fs_rename started.\n");
	int  rc;
	char srcpathbuf[MAXPATHLEN];
	char dstpathbuf[MAXPATHLEN];

	if (fsd == NULL)
	{
		if(cfg_reconnect_req)
		{
			if(!(request_reconnect(last_server) && smb2fs_init(NULL)))
				return -ENODEV;
		}
		else if(!smb2fs_init(NULL))
			return -ENODEV;
	}

	if (fsd->rdonly)
		return -EROFS;

	if (fsd->rootdir != NULL)
	{
		strlcpy(srcpathbuf, fsd->rootdir, sizeof(srcpathbuf));
		strlcat(srcpathbuf, srcpath, sizeof(srcpathbuf));
		srcpath = srcpathbuf;
		strlcpy(dstpathbuf, fsd->rootdir, sizeof(dstpathbuf));
		strlcat(dstpathbuf, dstpath, sizeof(dstpathbuf));
		dstpath = dstpathbuf;
	}

	if (srcpath[0] == '/') srcpath++; /* Remove initial slash */
	if (dstpath[0] == '/') dstpath++;

	do {
		rc = smb2_rename(fsd->smb2, srcpath, dstpath);
		if(rc < -1)
		{
			return rc;
		}
		else if (rc < 0)
		{
			if(!handle_connection_fault())
				return -ENODEV;
		}
	} while(rc < 0);

	return 0;
}

static int smb2fs_relabel(const char *label)
{
	// KPrintF((STRPTR)"[smb2fs] smb2fs_relabel started.\n");
	/* Nothing to do here */
	return 0;
}

static struct fuse_operations smb2fs_ops =
{
	.init       = smb2fs_init,
	.destroy    = smb2fs_destroy,
	.statfs     = smb2fs_statfs,
	.getattr    = smb2fs_getattr,
	.fgetattr   = smb2fs_fgetattr,
	.mkdir      = smb2fs_mkdir,
	.opendir    = smb2fs_opendir,
	.releasedir = smb2fs_releasedir,
	.readdir    = smb2fs_readdir,
	.open       = smb2fs_open,
	.create     = smb2fs_create,
	.release    = smb2fs_release,
	.read       = smb2fs_read,
	.write      = smb2fs_write,
	.truncate   = smb2fs_truncate,
	.ftruncate  = smb2fs_ftruncate,
	.unlink     = smb2fs_unlink,
	.rmdir      = smb2fs_rmdir,
	.readlink   = smb2fs_readlink,
	.rename     = smb2fs_rename,
	.relabel    = smb2fs_relabel
};

static void remove_double_quotes(char *argstr)
{
	char *start, *end;
	int   len;

	start = argstr;
	end   = start + strlen(start);

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

#ifdef __AROS__
static struct RDArgs *read_startup_args(CONST_STRPTR template, SIPTR *args, const char *startup)
#else
static struct RDArgs *read_startup_args(CONST_STRPTR template, LONG *args, const char *startup)
#endif
{
	char          *argstr;
	struct RDArgs *rda, *result = NULL;

	argstr = malloc(strlen(startup) + 2);
	if (argstr == NULL)
	{
		SetIoErr(ERROR_NO_FREE_STORE);
		return NULL;
	}

	//IExec->DebugPrintF("[smb2fs] startup: '%s'\n", startup);
	strcpy(argstr, startup);
	remove_double_quotes(argstr);
	//IExec->DebugPrintF("[smb2fs] argstr: '%s'\n", argstr);
	strcat(argstr, "\n");

	rda = AllocDosObject(DOS_RDARGS, NULL);
	if (rda != NULL)
	{
		rda->RDA_Source.CS_Buffer = (STRPTR)argstr;
		rda->RDA_Source.CS_Length = strlen(argstr);
		rda->RDA_Flags            = RDAF_NOPROMPT;

		result = ReadArgs(template, (APTR)args, rda);
		if (result == NULL)
		{
			FreeDosObject(DOS_RDARGS, rda);
		}
	}

	free(argstr);
	return result;
}

static void free_startup_args(struct RDArgs *rda)
{
	if (rda != NULL)
	{
		FreeArgs(rda);
		FreeDosObject(DOS_RDARGS, rda);
	}
}

int smb2fs_main(struct DosPacket *pkt)
{
	struct smb2fs_mount_data  md;
	struct DeviceNode        *devnode;
	const char               *device;
	const char               *startup;
#ifdef __amigaos4__
	uint32                    fsflags;
#endif
	struct FbxFS             *fs = NULL;
	int                       error;
	int                       rc = RETURN_ERROR;

	memset(&md, 0, sizeof(md));

	devnode = (struct DeviceNode *)BADDR(pkt->dp_Arg3);

#ifdef __AROS__
	device  = (const char *)AROS_BSTR_ADDR(devnode->dn_Name);
	startup = (const char *)AROS_BSTR_ADDR(devnode->dn_Startup);
#else
	device  = (const char *)BADDR(devnode->dn_Name) + 1;
	startup = (const char *)BADDR(devnode->dn_Startup) + 1;
#endif

	devnode->dn_Startup = ZERO;

	md.device = strdup(device);
	if (md.device == NULL)
	{
		error = ERROR_NO_FREE_STORE;
		goto cleanup;
	}

	md.rda = read_startup_args((CONST_STRPTR)cmd_template, md.args, startup);
	if (md.rda == NULL)
	{
		error = IoErr();
		goto cleanup;
	}

#ifdef __amigaos4__
	fsflags = FBXF_ENABLE_UTF8_NAMES|FBXF_ENABLE_32BIT_UIDS|FBXF_USE_FILL_DIR_STAT;

	fs = FbxSetupFSTags(pkt->dp_Link, &smb2fs_ops, sizeof(smb2fs_ops), &md,
		FBXT_FSFLAGS,     fsflags,
		FBXT_DOSTYPE,     ID_SMB2_DISK,
		FBXT_GET_CONTEXT, &_fuse_context_,
		TAG_END);
#else
	struct TagItem fs_tags[] = {
		{ FBXT_FSFLAGS,     FBXF_ENABLE_UTF8_NAMES|FBXF_USE_FILL_DIR_STAT },
		{ FBXT_DOSTYPE,     ID_SMB2_DISK                                            },
		{ FBXT_GET_CONTEXT, (IPTR)&_fuse_context_                                   },
		{ TAG_END,          0                                                       }
	};

	fs = FbxSetupFS(pkt->dp_Link, fs_tags, &smb2fs_ops, sizeof(smb2fs_ops), &md);
#endif

	/* Set to NULL so we don't reply the message twice */
	pkt = NULL;

	if (fs != NULL)
	{
		FbxEventLoop(fs);

		rc = RETURN_OK;
	}

cleanup:

	if (fs != NULL)
	{
		FbxCleanupFS(fs);
		fs = NULL;
	}

	if (pkt != NULL)
	{
		ReplyPkt(pkt, DOSFALSE, error);
		pkt = NULL;
	}

	if (md.rda != NULL)
	{
		free_startup_args(md.rda);
		md.rda = NULL;
	}

	if (md.device != NULL)
	{
		free(md.device);
		md.device = NULL;
	}

	return rc;
}


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

#ifdef USE_BSDSOCKET_LIB

#include <proto/bsdsocket.h>
#include <sys/filio.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netdb.h>
#include <fcntl.h>
#include <stdarg.h>

int socket(int domain, int type, int protocol)
{
	return ISocket->socket(domain, type, protocol);
}

int connect(int sock, const struct sockaddr *addr, socklen_t addrlen)
{
	return ISocket->connect(sock, (struct sockaddr *)addr, addrlen);
}

ssize_t readv(int sock, const struct iovec *iov, int iovcnt)
{
	int      i;
	char    *ptr;
	ssize_t  total, len, rc;

	total = 0;

	for (i = 0; i < iovcnt; i++)
	{
		ptr = iov[i].iov_base;
		len = (ssize_t)iov[i].iov_len;
		while (len > 0)
		{
			rc = ISocket->recv(sock, ptr, len, 0);
			if (rc < 0)
				return -1;
			else if (rc == 0)
				return total;
			ptr   += rc;
			total += rc;
			len   -= rc;
		}
	}

	return total;
}

ssize_t writev(int sock, const struct iovec *iov, int iovcnt)
{
	int      i;
	char    *ptr;
	ssize_t  total, len, rc;

	total = 0;

	for (i = 0; i < iovcnt; i++)
	{
		ptr = iov[i].iov_base;
		len = (ssize_t)iov[i].iov_len;
		while (len > 0)
		{
			rc = ISocket->send(sock, (APTR)ptr, len, 0);
			if (rc < 0)
				return -1;
			else if (rc == 0)
				return total;
			ptr   += rc;
			total += rc;
			len   -= rc;
		}
	}

	return total;
}

int setsockopt(int sock, int level, int optname, const void *optval, socklen_t optlen)
{
	return ISocket->setsockopt(sock, level, optname, (void *)optval, optlen);
}

int getsockopt(int sock, int level, int optname, void *optval, socklen_t *optlen)
{
	return ISocket->getsockopt(sock, level, optname, optval, optlen);
}

int select(int nfds, fd_set *readfds, fd_set *writefds, fd_set *exceptfds, struct timeval *timeout)
{
	return ISocket->WaitSelect(nfds, readfds, writefds, exceptfds, timeout, NULL);
}

struct hostent *gethostbyname(const char *name)
{
	return ISocket->gethostbyname((STRPTR)name);
}

int fcntl(int sock, int cmd, ...)
{
	va_list ap;
	int arg;
	long nonblock;
	int result;

	va_start(ap, cmd);

	switch (cmd)
	{
		case F_GETFL:
			result = 0;
			break;

		case F_SETFL:
			arg = va_arg(ap, int);
			nonblock = (arg & O_NONBLOCK) ? 1 : 0;
			result = ISocket->IoctlSocket(sock, FIONBIO, &nonblock);
			break;

		default:
			errno = ENOSYS;
			result = -1;
			break;
	}

	va_end(ap);

	return result;
}

int close(int sock)
{
	return ISocket->CloseSocket(sock);
}

struct protoent *getprotobyname(const char *name)
{
	return ISocket->getprotobyname((STRPTR)name);
}

#endif /* USE_BSDSOCKET_LIB */


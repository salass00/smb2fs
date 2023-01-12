#include <string.h>
#include <stdlib.h>

char *strdup(const char *str1) {
	size_t size = strlen(str1) + 1;
	char *str2 = malloc(size);
	if (str2 != NULL) memcpy(str2, str1, size);
	return str2;
}


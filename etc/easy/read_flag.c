#include <stdio.h>

int main() {
	int i;
	FILE *fp;

	for (i = 0; i < 10; i++) {
		fp = fdopen(i, "r");
		printf("%d: ", i);
		if (fp) {
			char str[100];
			fgets(str, 100, fp);
			puts(str);
			fclose(fp);
		} else {
			puts("FAIL");
		}
	}

	return 0;
}

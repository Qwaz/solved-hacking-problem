#include <cstdio>
#include <cstring>
#include <algorithm>

using namespace std;

bool cmp_string(char *a, char *b) {
	return strcmp(a, b) < 0;
}

bool cmp_char(char a, char b) {
	return a < b;
}

char pl[67];

int main() {
	char arr1[10];
	char arr2[2500];
	char arr3[10];
	char arr4[64];
	char arr5[64];

	memset(arr1, 0, sizeof(arr1));
	//memset(arr2, 0, sizeof(arr2));
	memset(arr3, 0, sizeof(arr3));
	memset(arr4, 0, sizeof(arr4));
	memset(arr5, 0, sizeof(arr5));

	char *s[] = {
		"103066",
		"78yn",
		"91",
		"jk@O",
		"w0%3",
		"okJni",
		"32tP",
		"pYn",
		"oty3e",
		"ss",
		"whw3",
		"Gh$",
		"ju3t",
		"g986",
		"rTp0",
		"J)g",
		"a",
		"pLoKm7",
		"0o7",
		"******",
		"plokm7",
		"SSCFlg2016"
	};

	char dest[][9] = {
		"eoy3t",
		"61306",
		"169",
		"TF",
		"3utj5",
		"8g69",
		"SSC",
		"2j%O",
		"8gfl",
		"ooo",
		"ww3h",
		"4h",
		"gJ)",
		"upY89",
		"o07"
	};

	char src[] = "aP$";

	char *a1 = "\x4a\xef\xbf\xbd\xef\xbf\xbd\xef\xbf\xbd\x2e\x43\x47\x3a";

	int arr1_index = 0;
	for (int i = 0; a1[i]; i++) {
		if ((unsigned int)a1[i] - 33 <= 0x5D)
			arr1[arr1_index++] = a1[i];
	}

	int end = 19;
	sort(s, s+end, cmp_string);

	for (int i = 0; i < end; i++) {
		strcpy(&arr2[50 * i], s[i]);
		int arr2_len = strlen(&arr2[50 * i]);
		sort(&arr2[50 * i], &arr2[50 * i] + arr2_len, cmp_char);
	}
	
	int k = 0;
	do {
		while (1) {
			strcpy(arr3, dest[k]);
			int arr3_len = strlen(arr3);
			sort(arr3, arr3 + arr3_len, cmp_char);

			bool break_flag = 0;
			for (int t = 0; t < end; t++) {
				if (strcmp(&arr2[50 * t], arr3) == 0) {
					strcat(arr4, s[t]);
					break_flag = 1;
				}
			}

			if (break_flag) break;

			if (k == 3) {
				k = 4;
				strcat(arr4, src);
			} else if (k == 6) {
				sprintf(arr5, "%c", 'i');
				k = 7;
				strcat(arr4, arr5);
			} else if (k == 11) {
				k = 12;
				strcat(arr4, dest[7]);
			} else {
				break;
			}
		}
		k++;
	} while (k != 15);

	strcat(arr4, arr1);
	sprintf(arr5, "%c", '}');
	strcat(arr4, arr5);
	sprintf(arr5, "%c", '{');
	strcat(arr5, arr4);

	strcat(pl, dest[6]);
	strcat(pl, dest[3]);
	strcat(pl, arr5);

	printf("%s\n", pl);

	return 0;
}
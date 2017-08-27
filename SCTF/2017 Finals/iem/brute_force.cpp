#include <cstdio>
#include <vector>

using namespace std;

const int MAP_SIZE = 4096, DICT_SIZE = 1 << 24;

int rnd_map[MAP_SIZE], forward_map[DICT_SIZE], reverse_map[DICT_SIZE];

int permutation(int m) {
	int l = m & 0xfff;
	int r = m >> 12;
	for (int i = 0; i < 8; i++) {
		int next_r = rnd_map[r] ^ l;
		l = r;
		r = next_r;
	}
	return r | (l << 12);
}

int main() {
	FILE *f = fopen("rnd_map", "r");
	for (int i = 0; i < MAP_SIZE; i++) {
		int x, val;
		fscanf(f, "%d: %d", &x, &val);
		rnd_map[x] = val;
	}
	fclose(f);

	int recursive_cnt = 0;
	for (int m = 0; m < DICT_SIZE; m++) {
		int val = permutation(m);
		if (m == val) {
			recursive_cnt++;
		}
		forward_map[m] = val;
		reverse_map[val] = m;
	}

	puts("Done!");
	printf("There were %d recursive\n", recursive_cnt);

	int k1 = 8285592;
	for (int k2 = 0; k2 < (1 << 24); k2++) {
		int msg = 0;
		for (int r = 0; r < 100; r++) {
			msg = permutation(msg ^ k1);
			msg = permutation(msg ^ k2);
		}
		if (msg == 7434252) {
			printf("key1 = %x\nkey2 = %x\n", k1, k2);
			printf("try %06x%06x\n", k2, k1);
			break;
		}
	}

	puts("Congratulation!");
	scanf("%*s");

	return 0;
}

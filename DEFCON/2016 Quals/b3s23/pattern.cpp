#include <cstdio>
#include <cstring>
#include <random>
#include <vector>

using namespace std;

const int LIFESPAN = 15, MIN_HEIGHT = 3, MAX_HEIGHT = 10, MAX_Y = 12;

void findPattern(char *target) {
	random_device rd;
	mt19937 mt(rd());
	uniform_int_distribution<int> heightDice(MIN_HEIGHT, MAX_HEIGHT);
	uniform_real_distribution<double> probDice(0.2, 0.6), realDice(0.0, 1.0);

	int width = strlen(target);

	//init map
	int mapSize = (MAX_Y+2) * (width+2);
	char *start = new char[mapSize], *map = new char[mapSize], *tmp = new char[mapSize];
	memset(map, 0, mapSize);

	auto index = [width](int x, int y) {
		return y * (width+2) + x;
	};

	while (1) {
		RETRY:
		int x, y;

		//random init
		double threshold = probDice(mt);
		int currentHeight = heightDice(mt);

		for (y = 1; y <= currentHeight; y++) {
			for (x = 1; x <= width; x++) {
				map[index(x, y)] = realDice(mt) < threshold ? '1' : '0';
			}
		}

		for (; y <= MAX_Y; y++) {
			for (x = 1; x <= width; x++) {
				map[index(x, y)] = '0';
			}
		}

		memcpy(start, map, mapSize);

		for (int level = 0; level < LIFESPAN; level++) {
			memcpy(tmp, map, mapSize);

			//check boundary
			for (y = 2; y < MAX_Y; y++) {
				if (map[index(1, y-1)] == '1' && map[index(1, y)] == '1' && map[index(1, y+1)] == '1')
					goto RETRY;
				if (map[index(width, y-1)] == '1' && map[index(width, y)] == '1' && map[index(width, y+1)] == '1')
					goto RETRY;
			}

			for (x = 2; x < width; x++) {
				if (map[index(x-1, MAX_Y)] == '1' && map[index(x, MAX_Y)] == '1' && map[index(x+1, MAX_Y)] == '1')
					goto RETRY;
			}

			//simulate
			for (y = 1; y <= MAX_Y; y++) {
				for (x = 1; x <= width; x++) {
					int count = 0;
					for (int dy = -1; dy <= 1; dy++) {
						for (int dx = -1; dx <= 1; dx++) {
							if (dx == 0 && dy == 0) continue;
							if (tmp[index(x+dx, y+dy)] == '1') count++;
						}
					}
					map[index(x, y)] = tmp[index(x, y)];
					if (count == 3) map[index(x, y)] = '1';
					if (count <= 1 || 4 <= count) map[index(x, y)] = '0';
				}
			}
		}

		//check line match
		for (x = 1; x <= width; x++) {
			if (map[index(x, 1)] != target[x-1])
				break;
		}

		if (x == width+1) {
			break;
		}
	}

	puts("START_PATTERN");
	for (int y = 1; y <= MAX_Y; y++) {
		for (int x = 1; x <= width; x++) {
			putchar(start[index(x, y)]);
		}
		putchar('\n');
	}
	putchar('\n');

	puts("FINAL_PATTERN");
	for (int y = 1; y <= MAX_Y; y++) {
		for (int x = 1; x <= width; x++) {
			putchar(map[index(x, y)]);
		}
		putchar('\n');
	}
	putchar('\n');

	memset(map, 0, mapSize);

	delete[] start;
	delete[] map;
	delete[] tmp;
}

int main() {
	findPattern("00111100010");

	return 0;
}
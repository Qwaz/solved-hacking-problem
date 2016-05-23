#include <cstdio>
#include <vector>
#include <queue>

using namespace std;

const int INF = 999;

int numEdge;
vector < int > to_out[256], from_input[64];

bool visit[256], now_input[256], const_val[64];

//freeCount, id
pair < int, int > c[64];
vector < pair < int, int > * > state;

void input() {
	scanf("%d", &numEdge);

	for (int i = 0; i < numEdge; i++) {
		int f, s;
		scanf("%d%d", &f, &s);
		//highest bit is always 0
		if (f % 8 != 7) {
			to_out[f].push_back(s);
			from_input[s].push_back(f);
		}
	}

	for (int i = 0; i < 64; i++) {
		c[i].second = i;

		int t;
		scanf("%d", &t);
		const_val[i] ^= t;
		state.push_back(&c[i]);
	}
}

int match = 0;

bool valid_char(char c) {
	return c == ' ' || ('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z');
}

void rec() {
	sort(state.begin(), state.end(), [](auto p1, auto p2) {
		return p1->first < p2->first;
	});

	for (int i = 0; i < 32; i++) {
		char c = 0;

		int j;
		for (j = 7; j >= 0; j--) {
			if (!visit[i*8 + j]) break;
			c = c * 2 + now_input[i*8 + j];
		}

		if (j == -1 && !valid_char(c))
			return;
	}

	if (state[0]->first == INF) {
		//ANSWER!
		int i;
		char result[33];
		for (i = 0; i < 32; i++) {
			char c = 0;
			for (int j = 7; j >= 0; j--) {
				c = c * 2 + now_input[i*8 + j];
			}
			result[i] = c;
		}
		result[32] = 0;
		puts(result);

		if (i < 32)
			return;

		exit(0);
	} else {
		int id = state[0]->second;

		//prepare
		vector < int > free_input;
		for (int before : from_input[id]) {
			if (!visit[before]) {
				visit[before] = 1;
				now_input[before] = 0;
				free_input.push_back(before);
				for (int after : to_out[before]) {
					c[after].first--;
				};
			}
		}

		//try all possibility
		c[id].first = INF;
		match++;
		bool fixed_now = const_val[id];
		for (int before : from_input[id]) {
			fixed_now ^= now_input[before];
		}
		for (unsigned int flag = 0; flag < (1 << free_input.size()); flag++) {
			bool now = fixed_now;
			for (int i = 0; i < free_input.size(); i++) {
				now_input[free_input[i]] = (flag >> i) & 1;
				now ^= now_input[free_input[i]];
			}

			if (now == 0) {
				rec();
			}
		}
		match--;
		c[id].first = 0;

		//backtrack
		for (int before : free_input) {
			visit[before] = 0;
			for (int after : to_out[before]) {
				c[after].first++;
			}
		}
	}
}

void solve() {
	for (int i = 0; i < 32; i++) {
		int idx;
		//highest bit of each byte
		idx = i*8 + 7;
		now_input[idx] = 0;
		visit[idx] = 1;
	}

	for (unsigned int flag = 0; flag < (1 << 31); flag++) {
		if (flag % 0x1 == 0)
			printf("Now searching %08x\n", flag);

		for (int i = 0; i < 32; i++) {
			for (int j = 0; j <= 6; j++) {
				int idx = i * 8 + j;
				if ((flag >> i) & 1) {
					//space: 0000 0100
					now_input[idx] = j == 5;
					visit[idx] = 1;
				} else {
					//alphabet ???? ??10
					now_input[idx] = j == 6;
					visit[idx] = (j == 6) || (to_out[idx].size() == 0);
				}
			}
		}

		for (int i = 0; i < 64; i++) {
			c[i].first = 0;
		}

		for (int i = 0; i < 256; i++) {
			if (!visit[i]) {
				for (auto after : to_out[i])
					c[after].first++;
			}
		}

		rec();
	}
}

int main() {
	input();

	//" jPCPBPApIDjPDDDPRPbaDPPyFDDDDDD"
	solve();
	puts("NO ANSWER");

	return 0;
}
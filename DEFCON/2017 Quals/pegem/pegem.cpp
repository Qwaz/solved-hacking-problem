#include <cstdio>
#include <iostream>
#include <string>
#include <vector>
#include <queue>

using namespace std;
typedef long long ll;

const int MAX = 10;

int lines;
char boardId[MAX][MAX];  // capital letters

bool isValid(int f, int s) {
	if (1 <= f && f <= lines) {
		if (1 <= s && s <= f) {
			return true;
		}
	}
	return false;
}

ll maxHash() {
	ll ret = 0;
	for (int i = 1; i <= lines; i++) {
		for (int j = 1; j <= i; j++) {
			ret = (ret << 1) + 1;
		}
	}
	return ret;
}

struct state {
	bool board[MAX][MAX];

	state() {
		for (int i = 1; i <= lines; i++) {
			for (int j = 1; j <= i; j++) {
				board[i][j] = 0;
			}
		}
	}

	state(const state &that) {
		for (int i = 1; i <= lines; i++) {
			for (int j = 1; j <= i; j++) {
				board[i][j] = that.board[i][j];
			}
		}
	}

	state(ll hash) {
		for (int i = lines; i >= 1; i--) {
			for (int j = i; j >= 1; j--) {
				board[i][j] = hash & 1;
				hash >>= 1;
			}
		}
	}

	ll hash() {
		ll ret = 0;
		for (int i = 1; i <= lines; i++) {
			for (int j = 1; j <= i; j++) {
				ret = (ret << 1) + board[i][j];
			}
		}
		return ret;
	}

	bool cleared() {
		int cnt = 0;
		for (int i = 1; i <= lines; i++) {
			for (int j = 1; j <= i; j++) {
				cnt += board[i][j];
			}
		}
		return cnt == 1;
	}

	void print() {
		for (int i = 1; i <= lines; i++) {
			for (int j = 1; j <= i; j++) {
				printf("%d ", board[i][j]);
			}
			puts("");
		}
	}

	vector < pair < ll, string > > nextStates() {
		int dir[6][2] = {
			1, 0, // left down
			1, 1, // right down
			0, -1, // left
			0, 1, // right
			-1, -1, // left up
			-1, 0, // right up
		};

		vector < pair < ll, string > > ret;

		for (int nowF = 1; nowF <= lines; nowF++) {
			for (int nowS = 1; nowS <= nowF; nowS++) {
				if (board[nowF][nowS]) {
					for (int t = 0; t < 6; t++) {
						int midF = nowF+dir[t][0];
						int midS = nowS+dir[t][1];

						int nextF = midF+dir[t][0];
						int nextS = midS+dir[t][1];

						if (isValid(midF, midS) && isValid(nextF, nextS)) {
							if (board[midF][midS] && !board[nextF][nextS]) {
								state next = *this;
								next.board[nowF][nowS] = 0;
								next.board[midF][midS] = 0;
								next.board[nextF][nextS] = 1;

								string t;
								t += boardId[nowF][nowS];
								t += boardId[nextF][nextS]-'A'+'a';
								ret.push_back(make_pair(next.hash(), t));
							}
						}
					}
				}
			}
		}

		return ret;
	}
};

state initial;
int from[1 << 20];
string track[1 << 20];

void input() {
	scanf("%d", &lines);

	initial = state();
	for (int i = 1; i <= lines; i++) {
		for (int j = 1; j <= i; j++) {
			char c[2];
			scanf("%1s", &c);
			if ('a' <= c[0] && c[0] <= 'z') {
				initial.board[i][j] = 0;
				boardId[i][j] = c[0]-'a'+'A';
			} else {
				initial.board[i][j] = 1;
				boardId[i][j] = c[0];
			}
		}
	}
}

void solve() {
	queue < ll > q;

	ll now = initial.hash();
	from[now] = -1;
	q.push(now);

	while (!q.empty()) {
		now = q.front();
		q.pop();

		state sn = state(now);
		if (sn.cleared()) {
			string ans;
			while (from[now] >= 0) {
				ans = track[now] + '\n' + ans;
				now = from[now];
			}
			cout << ans;
			break;
		}

		for (pair < ll, string > next : sn.nextStates()) {
			if (from[next.first] == 0) {
				from[next.first] = now;
				track[next.first] = next.second;
				q.push(next.first);
			}
		}
	}
}

int main() {
	input();

	solve();

	return 0;
}

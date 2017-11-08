// g++ -o knapsack -O3 knapsack.cpp
#include <iostream>
#include <algorithm>
#include <vector>
#include <unordered_map>

using namespace std;
typedef __int128_t Num;

int n;
Num ans;

vector < Num > f, s, f_sum, s_sum;
unordered_map < Num, int > memo;

istream& operator>>(istream &is, Num &x) {
    string s;
    is >> s;
    auto p = s.data();
    bool neg = false;
    if (*p && *p == '-') {
        neg = true;
        p++;
    }
    x = 0;
    while (*p) x = x * 10 + *p++ - '0';
    if (neg) x = -x;
    return is;
}

ostream& operator<<(ostream &os, Num x) {
    if (x == 0) return os << "0";
    if (x < 0) {
        os << '-';
        x = -x;
    }
    string s;
    while (x != 0) {
        s.push_back(x % 10 + '0');
        x /= 10;
    }
    reverse(begin(s), end(s));
    return os << s;
}

// Solve knapsack by MITM
int main() {
    f_sum.push_back(0);
    s_sum.push_back(0);

    cin >> n >> ans;
    for (int i = 0; i < n; i++) {
        Num t;
        cin >> t;
        if (i < (n>>1)) {
            f.push_back(t);
            f_sum.push_back(t);
        } else {
            s.push_back(t);
            s_sum.push_back(t);
        }
    }

    int f_size = f.size(), s_size = s.size();
    for (int i = 1; i < f_size; i++) {
        f_sum[i] += f_sum[i-1];
    }
    for (int i = 1; i < s_size; i++) {
        s_sum[i] += s_sum[i-1];
    }

    Num val;

    // first part
    val = 0;
    for (int x = 0; x < (1 << f_size); x++) {
        memo[val] = x;
        for (int t = 0; t < f_size; t++) {
            if (((x >> t) & 1) == 0) {
                val = val + f[t] - f_sum[t];
                break;
            }
        }
    }

    // second part
    val = 0;
    for (int x = 0; x < (1 << s_size); x++) {
        if (memo.find(ans - val) != memo.end()) {
            int first_half = memo[ans - val];
            int second_half = x;

            for (int t = 0; t < f_size; t++) {
                printf("%c ", ((first_half >> t) & 1) ? '1' : '0');
            }
            for (int t = 0; t < s_size; t++) {
                printf("%c ", ((second_half >> t) & 1) ? '1' : '0');
            }
            puts("");

            return 0;
        }
        for (int t = 0; t < s_size; t++) {
            if (((x >> t) & 1) == 0) {
                val = val + s[t] - s_sum[t];
                break;
            }
        }
    }

    puts("NOT_FOUND");

    return 0;
}

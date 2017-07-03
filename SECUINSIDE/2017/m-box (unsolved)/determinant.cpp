#include <cstdio>
#include <cstring>
#include <vector>
#include <random>

using namespace std;
typedef long long ll;

const int SIZE = 9;

ll arr[9][9] = {
    0x35, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x75, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x6E, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x4B, 0x20, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x6E, 0x20, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x30, 0x20, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x77, 0x20, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x6E, 0x20,
    0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20,
}, prevArr[9][9];

ll check[8] = {
    0x35, 0x75, 0x6E, 0x4B, 0x6E, 0x30, 0x77, 0x6E
};

bool valid() {
    for (int i = 0; i < SIZE-1; i++) {
        if (arr[i][i] != check[i]) {
            return 0;
        }
    }

    for (int y = 0; y < SIZE; y++) {
        for (int x = 0; x < SIZE; x++) {
            if (arr[y][x] <= 0x1f || arr[y][x] > 0x7E) {
                return 0;
            }
        }
    }

    return 1;
}

ll determinant(int lvl, vector < int > cols) {
    if (lvl == SIZE-1) {
        return arr[lvl][cols[0]];
    }
    ll result = 0;
    int len = cols.size();
    for (int i = 0; i < len; i++) {
        vector < int > nextcols;
        for (int j = 0; j < len; j++) {
            if (j != i) {
                nextcols.push_back(cols[j]);
            }
        }

        if (i%2 == 0) {
            result += arr[lvl][cols[i]] * determinant(lvl+1, nextcols);
        } else {
            result -= arr[lvl][cols[i]] * determinant(lvl+1, nextcols);
        }
    }
    return result;
}

int main() {
    random_device rn;
    mt19937_64 rnd(rn());

    uniform_int_distribution<int> xy_gen(0, 8), val_gen(0x20, 0x7E), cnt_gen(1, 8);

    for (int y = 0; y < SIZE; y++) {
        for (int x = 0; x < SIZE; x++) {
            if (x != y) {
                arr[y][x] = val_gen(rnd);
            }
        }
    }

    vector < int > cols = {0,1,2,3,4,5,6,7,8};
    ll det, prevDet = determinant(0, cols);
    do {
        memcpy(prevArr, arr, sizeof(arr));

        int cnt = cnt_gen(rnd);
        for (int i = 0; i < cnt; i++) {
            int x, y;
            do {
                x = xy_gen(rnd);
                y = xy_gen(rnd);
            } while(x == y);

            arr[y][x] = val_gen(rnd);
        }

        det = determinant(0, cols);
        if (abs(prevDet) > abs(det)) {
            prevDet = det;
            printf("changed: %d\n", cnt);
            printf("determinant: %lld\n", det);

            for (int y = 0; y < 9; y++) {
                for (int x = 0; x < 9; x++) {
                    printf("%d ", arr[y][x]);
                }
                puts("");
            }
        } else {
            memcpy(arr, prevArr, sizeof(arr));
        }
    } while(det != 1 && det != 1);

    return 0;
}

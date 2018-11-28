#include <cstdio>
#include <algorithm>
#include <vector>
#include <cstring>

using namespace std;

const int MAX = 300, EDGE_MAX = MAX * MAX;

enum status {
    FREE,
    USE,
    BAN,
};

struct edge {
    int to;
    int id;

    edge(int to, int id) : to(to), id(id) {}
};

int num_node, num_edge;
int label[MAX], free_count[MAX], use_count[MAX], e1[EDGE_MAX], e2[EDGE_MAX];
int matrix[MAX][MAX];

bool listed[MAX];

status edge_status[EDGE_MAX];
vector < edge > edges[MAX];

bool select_node(int node) {
    if (free_count[node] > 0) {
        for (auto &e : edges[node]) {
            if (edge_status[e.id] == FREE) {
                free_count[node] -= 1;
                free_count[e.to] -= 1;

                if (use_count[node] < 2 && use_count[e.to] < 2) {
                    // select
                    edge_status[e.id] = USE;
                    use_count[node] += 1;
                    use_count[e.to] += 1;
                } else {
                    // ban
                    edge_status[e.id] = BAN;
                }
            }
        }
    }
    return use_count[node] == 2;
}

void make_list(int node, int prev, int start, vector < int > &result) {
    listed[node] = 1;

    if (node == start && prev >= 0) {
        return;
    }

    for (auto &e : edges[node]) {
        if (edge_status[e.id] == USE) {
            if (e.to != prev) {
                result.push_back(node);
                return make_list(e.to, node, start, result);
            }
        }
    }
}

vector < vector < int > > make_vec_list() {
    vector < vector < int > > vec_list;
    memset(listed, 0, sizeof(listed));
    for (int node = 0; node < num_node; node++) {
        if (!listed[node]) {
            vector < int > vec;
            make_list(node, -1, node, vec);
            vec_list.push_back(vec);
        }
    }
    return vec_list;
}

pair < int, int > get_pair(vector < int > &vec, int index) {
    if (index == vec.size() - 1) {
        return make_pair(vec[vec.size() - 1], vec[0]);
    }
    return make_pair(vec[index], vec[index + 1]);
}

int main() {
    scanf("%d%d", &num_node, &num_edge);

    for (int i = 0; i < num_node; i++) {
        scanf("%d", &label[i]);
    }

    for (int i = 1; i <= num_edge; i++) {
        int x, y;
        scanf("%d%d", &x, &y);
        e1[i] = x;
        e2[i] = y;
        free_count[x] += 1;
        free_count[y] += 1;
        edges[x].emplace_back(y, i);
        edges[y].emplace_back(x, i);
        matrix[x][y] = matrix[y][x] = i;
        edge_status[i] = FREE;
    }

    bool change = true;
    while (change) {
        change = false;
        for (int node = 0; node < num_node; node++) {
            if ((use_count[node] == 2 && free_count[node] > 0)
                || (use_count[node] < 2 && free_count[node] + use_count[node] <= 2)) {
                change = true;
                if (!select_node(node)) {
                    puts("no 2-factorization found (1)");
                    return 0;
                }
            }
        }

        if (change) {
            continue;
        }

        for (int node = 0; node < num_node; node++) {
            if (use_count[node] == 1) {
                change = true;
                if (!select_node(node)) {
                    puts("no 2-factorization found (2)");
                    return 0;
                }
                break;
            }
        }

        if (change) {
            continue;
        }

        for (int node = 0; node < num_node; node++) {
            if (use_count[node] < 2) {
                change = true;
                if (!select_node(node)) {
                    puts("no 2-factorization found (2)");
                    return 0;
                }
                break;
            }
        }
    }

    vector < vector < int > > vec_list = make_vec_list();
    while (vec_list.size() > 1) {
        for (int i = 0; i < vec_list[0].size(); i++) {
            auto p1 = get_pair(vec_list[0], i);
            for (int v = 1; v < vec_list.size(); v++) {
                for (int j = 0; j < vec_list[v].size(); j++) {
                    auto p2 = get_pair(vec_list[v], j);
                    if (matrix[p1.first][p2.first] && matrix[p1.second][p2.second]) {
                        edge_status[matrix[p1.first][p1.second]] = BAN;
                        edge_status[matrix[p2.first][p2.second]] = BAN;
                        edge_status[matrix[p1.first][p2.first]] = USE;
                        edge_status[matrix[p1.second][p2.second]] = USE;
                        goto END;
                    } else if (matrix[p1.first][p2.second] && matrix[p1.second][p2.first]) {
                        edge_status[matrix[p1.first][p1.second]] = BAN;
                        edge_status[matrix[p2.first][p2.second]] = BAN;
                        edge_status[matrix[p1.first][p2.second]] = USE;
                        edge_status[matrix[p1.second][p2.first]] = USE;
                        goto END;
                    }
                }
            }
        }
        puts("greedy merge failed");
        return 0;

        END:
        vec_list = make_vec_list();
    }

    puts("OK");
    for (int node : vec_list[0]) {
        printf("%d, ", label[node]);
    }
    printf("%d\n", label[vec_list[0][0]]);

    return 0;
}
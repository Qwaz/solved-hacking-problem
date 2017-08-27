// C++ program for building suffix array of a given text
#include <iostream>
#include <cstring>
#include <algorithm>
#include <vector>
using namespace std;

// Structure to store information of a suffix
struct suffix
{
    int index; // To store original index
    int rank[2]; // To store ranks and next rank pair
};

// A comparison function used by sort() to compare two suffixes
// Compares two pairs, returns 1 if first pair is smaller
int cmp(struct suffix a, struct suffix b)
{
    if (a.rank[0] == b.rank[0]) {
        if (a.rank[1] == b.rank[1]) {
            return a.index < b.index;
        }
        return a.rank[1] < b.rank[1];
    }
    return a.rank[0] < b.rank[0];
}

// This is the main function that takes a string 'txt' of size n as an
// argument, builds and return the suffix array for the given string
vector < int > buildSuffixArray(char *txt, int n)
{
    // A structure to store suffixes and their indexes
    struct suffix suffixes[n];

    // Store suffixes and their indexes in an array of structures.
    // The structure is needed to sort the suffixes alphabatically
    // and maintain their old indexes while sorting
    for (int i = 0; i < n; i++)
    {
        suffixes[i].index = i;
        suffixes[i].rank[0] = txt[i] - 'a';
        suffixes[i].rank[1] = ((i+1) < n)? (txt[i + 1] - 'a'): -1;
    }

    // Sort the suffixes using the comparison function
    // defined above.
    sort(suffixes, suffixes+n, cmp);

    // At his point, all suffixes are sorted according to first
    // 2 characters.  Let us sort suffixes according to first 4
    // characters, then first 8 and so on
    int ind[n];  // This array is needed to get the index in suffixes[]
                 // from original index.  This mapping is needed to get
                 // next suffix.
    for (int k = 4; k < 2*n; k = k*2)
    {
        // Assigning rank and index values to first suffix
        int rank = 0;
        int prev_rank = suffixes[0].rank[0];
        suffixes[0].rank[0] = rank;
        ind[suffixes[0].index] = 0;

        // Assigning rank to suffixes
        for (int i = 1; i < n; i++)
        {
            // If first rank and next ranks are same as that of previous
            // suffix in array, assign the same new rank to this suffix
            if (suffixes[i].rank[0] == prev_rank &&
                    suffixes[i].rank[1] == suffixes[i-1].rank[1])
            {
                prev_rank = suffixes[i].rank[0];
                suffixes[i].rank[0] = rank;
            }
            else // Otherwise increment rank and assign
            {
                prev_rank = suffixes[i].rank[0];
                suffixes[i].rank[0] = ++rank;
            }
            ind[suffixes[i].index] = i;
        }

        // Assign next rank to every suffix
        for (int i = 0; i < n; i++)
        {
            int nextindex = suffixes[i].index + k/2;
            suffixes[i].rank[1] = (nextindex < n)?
                                  suffixes[ind[nextindex]].rank[0]: -1;
        }

        // Sort the suffixes according to first k characters
        sort(suffixes, suffixes+n, cmp);
    }

    // Store indexes of all sorted suffixes in the suffix array
    vector < int > suffixArr;
    for (int i = 0; i < n; i++)
        suffixArr.push_back(suffixes[i].index);

    // Return the suffix array
    return suffixArr;
}

vector<int> kasai(char *s, int n, vector<int> sa) {
    int k=0;
    vector<int> lcp(n,0);
    vector<int> rank(n,0);

    for(int i=0; i<n; i++) rank[sa[i]]=i;

    for(int i=0; i<n; i++, k?k--:0)
    {
        if(rank[i]==n-1) {k=0; continue;}
        int j=sa[rank[i]+1];
        while(i+k<n && j+k<n && s[i+k]==s[j+k]) k++;
        lcp[rank[i]]=k;
    }
    return lcp;
}

const int MAX = 131020;

char str[MAX];

int main() {
    fgets(str, MAX, stdin);

    int len = strlen(str);
    vector < int > suffixArr = buildSuffixArray(str, len);
    vector < int > lcp = kasai(str, len, suffixArr);

    int max_lcp = 0, start = len;
    for (int i = 0; i < len; i++) {
        // printf("%d: %2d %2d %s", i, suffixArr[i], lcp[i], &str[suffixArr[i]]);
        if (max_lcp < lcp[i]) {
            max_lcp = lcp[i];
            start = suffixArr[i];
        }
    }

    str[start+max_lcp] = 0;
    printf("%s", &str[start]);

    return 0;
}

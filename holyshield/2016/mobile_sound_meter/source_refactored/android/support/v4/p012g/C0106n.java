package android.support.v4.p012g;

import java.util.Map;

/* renamed from: android.support.v4.g.n */
public class C0106n {
    static Object[] f366b;
    static int f367c;
    static Object[] f368d;
    static int f369e;
    int[] f370f;
    Object[] f371g;
    int f372h;

    public C0106n() {
        this.f370f = C0110c.f378a;
        this.f371g = C0110c.f380c;
        this.f372h = 0;
    }

    public C0106n(int i) {
        if (i == 0) {
            this.f370f = C0110c.f378a;
            this.f371g = C0110c.f380c;
        } else {
            m591e(i);
        }
        this.f372h = 0;
    }

    private static void m590a(int[] iArr, Object[] objArr, int i) {
        int i2;
        if (iArr.length == 8) {
            synchronized (C0107a.class) {
                if (f369e < 10) {
                    objArr[0] = f368d;
                    objArr[1] = iArr;
                    for (i2 = (i << 1) - 1; i2 >= 2; i2--) {
                        objArr[i2] = null;
                    }
                    f368d = objArr;
                    f369e++;
                }
            }
        } else if (iArr.length == 4) {
            synchronized (C0107a.class) {
                if (f367c < 10) {
                    objArr[0] = f366b;
                    objArr[1] = iArr;
                    for (i2 = (i << 1) - 1; i2 >= 2; i2--) {
                        objArr[i2] = null;
                    }
                    f366b = objArr;
                    f367c++;
                }
            }
        }
    }

    private void m591e(int i) {
        Object[] objArr;
        if (i == 8) {
            synchronized (C0107a.class) {
                if (f368d != null) {
                    objArr = f368d;
                    this.f371g = objArr;
                    f368d = (Object[]) objArr[0];
                    this.f370f = (int[]) objArr[1];
                    objArr[1] = null;
                    objArr[0] = null;
                    f369e--;
                    return;
                }
            }
        } else if (i == 4) {
            synchronized (C0107a.class) {
                if (f366b != null) {
                    objArr = f366b;
                    this.f371g = objArr;
                    f366b = (Object[]) objArr[0];
                    this.f370f = (int[]) objArr[1];
                    objArr[1] = null;
                    objArr[0] = null;
                    f367c--;
                    return;
                }
            }
        }
        this.f370f = new int[i];
        this.f371g = new Object[(i << 1)];
    }

    int m592a() {
        int i = this.f372h;
        if (i == 0) {
            return -1;
        }
        int a = C0110c.m631a(this.f370f, i, 0);
        if (a < 0 || this.f371g[a << 1] == null) {
            return a;
        }
        int i2 = a + 1;
        while (i2 < i && this.f370f[i2] == 0) {
            if (this.f371g[i2 << 1] == null) {
                return i2;
            }
            i2++;
        }
        a--;
        while (a >= 0 && this.f370f[a] == 0) {
            if (this.f371g[a << 1] == null) {
                return a;
            }
            a--;
        }
        return i2 ^ -1;
    }

    public int m593a(Object obj) {
        return obj == null ? m592a() : m594a(obj, obj.hashCode());
    }

    int m594a(Object obj, int i) {
        int i2 = this.f372h;
        if (i2 == 0) {
            return -1;
        }
        int a = C0110c.m631a(this.f370f, i2, i);
        if (a < 0 || obj.equals(this.f371g[a << 1])) {
            return a;
        }
        int i3 = a + 1;
        while (i3 < i2 && this.f370f[i3] == i) {
            if (obj.equals(this.f371g[i3 << 1])) {
                return i3;
            }
            i3++;
        }
        a--;
        while (a >= 0 && this.f370f[a] == i) {
            if (obj.equals(this.f371g[a << 1])) {
                return a;
            }
            a--;
        }
        return i3 ^ -1;
    }

    public Object m595a(int i, Object obj) {
        int i2 = (i << 1) + 1;
        Object obj2 = this.f371g[i2];
        this.f371g[i2] = obj;
        return obj2;
    }

    public void m596a(int i) {
        if (this.f370f.length < i) {
            Object obj = this.f370f;
            Object obj2 = this.f371g;
            m591e(i);
            if (this.f372h > 0) {
                System.arraycopy(obj, 0, this.f370f, 0, this.f372h);
                System.arraycopy(obj2, 0, this.f371g, 0, this.f372h << 1);
            }
            C0106n.m590a(obj, obj2, this.f372h);
        }
    }

    int m597b(Object obj) {
        int i = 1;
        int i2 = this.f372h * 2;
        Object[] objArr = this.f371g;
        if (obj == null) {
            while (i < i2) {
                if (objArr[i] == null) {
                    return i >> 1;
                }
                i += 2;
            }
        } else {
            while (i < i2) {
                if (obj.equals(objArr[i])) {
                    return i >> 1;
                }
                i += 2;
            }
        }
        return -1;
    }

    public Object m598b(int i) {
        return this.f371g[i << 1];
    }

    public Object m599c(int i) {
        return this.f371g[(i << 1) + 1];
    }

    public void clear() {
        if (this.f372h != 0) {
            C0106n.m590a(this.f370f, this.f371g, this.f372h);
            this.f370f = C0110c.f378a;
            this.f371g = C0110c.f380c;
            this.f372h = 0;
        }
    }

    public boolean containsKey(Object obj) {
        return m593a(obj) >= 0;
    }

    public boolean containsValue(Object obj) {
        return m597b(obj) >= 0;
    }

    public Object m600d(int i) {
        int i2 = 8;
        Object obj = this.f371g[(i << 1) + 1];
        if (this.f372h <= 1) {
            C0106n.m590a(this.f370f, this.f371g, this.f372h);
            this.f370f = C0110c.f378a;
            this.f371g = C0110c.f380c;
            this.f372h = 0;
        } else if (this.f370f.length <= 8 || this.f372h >= this.f370f.length / 3) {
            this.f372h--;
            if (i < this.f372h) {
                System.arraycopy(this.f370f, i + 1, this.f370f, i, this.f372h - i);
                System.arraycopy(this.f371g, (i + 1) << 1, this.f371g, i << 1, (this.f372h - i) << 1);
            }
            this.f371g[this.f372h << 1] = null;
            this.f371g[(this.f372h << 1) + 1] = null;
        } else {
            if (this.f372h > 8) {
                i2 = this.f372h + (this.f372h >> 1);
            }
            Object obj2 = this.f370f;
            Object obj3 = this.f371g;
            m591e(i2);
            this.f372h--;
            if (i > 0) {
                System.arraycopy(obj2, 0, this.f370f, 0, i);
                System.arraycopy(obj3, 0, this.f371g, 0, i << 1);
            }
            if (i < this.f372h) {
                System.arraycopy(obj2, i + 1, this.f370f, i, this.f372h - i);
                System.arraycopy(obj3, (i + 1) << 1, this.f371g, i << 1, (this.f372h - i) << 1);
            }
        }
        return obj;
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (!(obj instanceof Map)) {
            return false;
        }
        Map map = (Map) obj;
        if (size() != map.size()) {
            return false;
        }
        int i = 0;
        while (i < this.f372h) {
            try {
                Object b = m598b(i);
                Object c = m599c(i);
                Object obj2 = map.get(b);
                if (c == null) {
                    if (obj2 != null || !map.containsKey(b)) {
                        return false;
                    }
                } else if (!c.equals(obj2)) {
                    return false;
                }
                i++;
            } catch (NullPointerException e) {
                return false;
            } catch (ClassCastException e2) {
                return false;
            }
        }
        return true;
    }

    public Object get(Object obj) {
        int a = m593a(obj);
        return a >= 0 ? this.f371g[(a << 1) + 1] : null;
    }

    public int hashCode() {
        int[] iArr = this.f370f;
        Object[] objArr = this.f371g;
        int i = this.f372h;
        int i2 = 1;
        int i3 = 0;
        int i4 = 0;
        while (i3 < i) {
            Object obj = objArr[i2];
            i4 += (obj == null ? 0 : obj.hashCode()) ^ iArr[i3];
            i3++;
            i2 += 2;
        }
        return i4;
    }

    public boolean isEmpty() {
        return this.f372h <= 0;
    }

    public Object put(Object obj, Object obj2) {
        int a;
        int i;
        int i2 = 8;
        if (obj == null) {
            a = m592a();
            i = 0;
        } else {
            i = obj.hashCode();
            a = m594a(obj, i);
        }
        if (a >= 0) {
            int i3 = (a << 1) + 1;
            Object obj3 = this.f371g[i3];
            this.f371g[i3] = obj2;
            return obj3;
        }
        a ^= -1;
        if (this.f372h >= this.f370f.length) {
            if (this.f372h >= 8) {
                i2 = this.f372h + (this.f372h >> 1);
            } else if (this.f372h < 4) {
                i2 = 4;
            }
            Object obj4 = this.f370f;
            Object obj5 = this.f371g;
            m591e(i2);
            if (this.f370f.length > 0) {
                System.arraycopy(obj4, 0, this.f370f, 0, obj4.length);
                System.arraycopy(obj5, 0, this.f371g, 0, obj5.length);
            }
            C0106n.m590a(obj4, obj5, this.f372h);
        }
        if (a < this.f372h) {
            System.arraycopy(this.f370f, a, this.f370f, a + 1, this.f372h - a);
            System.arraycopy(this.f371g, a << 1, this.f371g, (a + 1) << 1, (this.f372h - a) << 1);
        }
        this.f370f[a] = i;
        this.f371g[a << 1] = obj;
        this.f371g[(a << 1) + 1] = obj2;
        this.f372h++;
        return null;
    }

    public Object remove(Object obj) {
        int a = m593a(obj);
        return a >= 0 ? m600d(a) : null;
    }

    public int size() {
        return this.f372h;
    }

    public String toString() {
        if (isEmpty()) {
            return "{}";
        }
        StringBuilder stringBuilder = new StringBuilder(this.f372h * 28);
        stringBuilder.append('{');
        for (int i = 0; i < this.f372h; i++) {
            if (i > 0) {
                stringBuilder.append(", ");
            }
            C0106n b = m598b(i);
            if (b != this) {
                stringBuilder.append(b);
            } else {
                stringBuilder.append("(this Map)");
            }
            stringBuilder.append('=');
            b = m599c(i);
            if (b != this) {
                stringBuilder.append(b);
            } else {
                stringBuilder.append("(this Map)");
            }
        }
        stringBuilder.append('}');
        return stringBuilder.toString();
    }
}

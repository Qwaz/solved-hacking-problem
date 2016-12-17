package android.support.v4.p012g;

/* renamed from: android.support.v4.g.f */
public class C0113f implements Cloneable {
    private static final Object f383a;
    private boolean f384b;
    private long[] f385c;
    private Object[] f386d;
    private int f387e;

    static {
        f383a = new Object();
    }

    public C0113f() {
        this(10);
    }

    public C0113f(int i) {
        this.f384b = false;
        if (i == 0) {
            this.f385c = C0110c.f379b;
            this.f386d = C0110c.f380c;
        } else {
            int b = C0110c.m634b(i);
            this.f385c = new long[b];
            this.f386d = new Object[b];
        }
        this.f387e = 0;
    }

    private void m638c() {
        int i = this.f387e;
        long[] jArr = this.f385c;
        Object[] objArr = this.f386d;
        int i2 = 0;
        for (int i3 = 0; i3 < i; i3++) {
            Object obj = objArr[i3];
            if (obj != f383a) {
                if (i3 != i2) {
                    jArr[i2] = jArr[i3];
                    objArr[i2] = obj;
                    objArr[i3] = null;
                }
                i2++;
            }
        }
        this.f384b = false;
        this.f387e = i2;
    }

    public long m639a(int i) {
        if (this.f384b) {
            m638c();
        }
        return this.f385c[i];
    }

    public C0113f m640a() {
        try {
            C0113f c0113f = (C0113f) super.clone();
            try {
                c0113f.f385c = (long[]) this.f385c.clone();
                c0113f.f386d = (Object[]) this.f386d.clone();
                return c0113f;
            } catch (CloneNotSupportedException e) {
                return c0113f;
            }
        } catch (CloneNotSupportedException e2) {
            return null;
        }
    }

    public Object m641a(long j) {
        return m642a(j, null);
    }

    public Object m642a(long j, Object obj) {
        int a = C0110c.m632a(this.f385c, this.f387e, j);
        return (a < 0 || this.f386d[a] == f383a) ? obj : this.f386d[a];
    }

    public int m643b() {
        if (this.f384b) {
            m638c();
        }
        return this.f387e;
    }

    public Object m644b(int i) {
        if (this.f384b) {
            m638c();
        }
        return this.f386d[i];
    }

    public void m645b(long j) {
        int a = C0110c.m632a(this.f385c, this.f387e, j);
        if (a >= 0 && this.f386d[a] != f383a) {
            this.f386d[a] = f383a;
            this.f384b = true;
        }
    }

    public void m646b(long j, Object obj) {
        int a = C0110c.m632a(this.f385c, this.f387e, j);
        if (a >= 0) {
            this.f386d[a] = obj;
            return;
        }
        a ^= -1;
        if (a >= this.f387e || this.f386d[a] != f383a) {
            if (this.f384b && this.f387e >= this.f385c.length) {
                m638c();
                a = C0110c.m632a(this.f385c, this.f387e, j) ^ -1;
            }
            if (this.f387e >= this.f385c.length) {
                int b = C0110c.m634b(this.f387e + 1);
                Object obj2 = new long[b];
                Object obj3 = new Object[b];
                System.arraycopy(this.f385c, 0, obj2, 0, this.f385c.length);
                System.arraycopy(this.f386d, 0, obj3, 0, this.f386d.length);
                this.f385c = obj2;
                this.f386d = obj3;
            }
            if (this.f387e - a != 0) {
                System.arraycopy(this.f385c, a, this.f385c, a + 1, this.f387e - a);
                System.arraycopy(this.f386d, a, this.f386d, a + 1, this.f387e - a);
            }
            this.f385c[a] = j;
            this.f386d[a] = obj;
            this.f387e++;
            return;
        }
        this.f385c[a] = j;
        this.f386d[a] = obj;
    }

    public /* synthetic */ Object clone() {
        return m640a();
    }

    public String toString() {
        if (m643b() <= 0) {
            return "{}";
        }
        StringBuilder stringBuilder = new StringBuilder(this.f387e * 28);
        stringBuilder.append('{');
        for (int i = 0; i < this.f387e; i++) {
            if (i > 0) {
                stringBuilder.append(", ");
            }
            stringBuilder.append(m639a(i));
            stringBuilder.append('=');
            C0113f b = m644b(i);
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

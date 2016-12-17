package android.support.v4.p012g;

/* renamed from: android.support.v4.g.o */
public class C0120o implements Cloneable {
    private static final Object f408a;
    private boolean f409b;
    private int[] f410c;
    private Object[] f411d;
    private int f412e;

    static {
        f408a = new Object();
    }

    public C0120o() {
        this(10);
    }

    public C0120o(int i) {
        this.f409b = false;
        if (i == 0) {
            this.f410c = C0110c.f378a;
            this.f411d = C0110c.f380c;
        } else {
            int a = C0110c.m630a(i);
            this.f410c = new int[a];
            this.f411d = new Object[a];
        }
        this.f412e = 0;
    }

    private void m656d() {
        int i = this.f412e;
        int[] iArr = this.f410c;
        Object[] objArr = this.f411d;
        int i2 = 0;
        for (int i3 = 0; i3 < i; i3++) {
            Object obj = objArr[i3];
            if (obj != f408a) {
                if (i3 != i2) {
                    iArr[i2] = iArr[i3];
                    objArr[i2] = obj;
                    objArr[i3] = null;
                }
                i2++;
            }
        }
        this.f409b = false;
        this.f412e = i2;
    }

    public C0120o m657a() {
        try {
            C0120o c0120o = (C0120o) super.clone();
            try {
                c0120o.f410c = (int[]) this.f410c.clone();
                c0120o.f411d = (Object[]) this.f411d.clone();
                return c0120o;
            } catch (CloneNotSupportedException e) {
                return c0120o;
            }
        } catch (CloneNotSupportedException e2) {
            return null;
        }
    }

    public Object m658a(int i) {
        return m659a(i, null);
    }

    public Object m659a(int i, Object obj) {
        int a = C0110c.m631a(this.f410c, this.f412e, i);
        return (a < 0 || this.f411d[a] == f408a) ? obj : this.f411d[a];
    }

    public int m660b() {
        if (this.f409b) {
            m656d();
        }
        return this.f412e;
    }

    public void m661b(int i) {
        int a = C0110c.m631a(this.f410c, this.f412e, i);
        if (a >= 0 && this.f411d[a] != f408a) {
            this.f411d[a] = f408a;
            this.f409b = true;
        }
    }

    public void m662b(int i, Object obj) {
        int a = C0110c.m631a(this.f410c, this.f412e, i);
        if (a >= 0) {
            this.f411d[a] = obj;
            return;
        }
        a ^= -1;
        if (a >= this.f412e || this.f411d[a] != f408a) {
            if (this.f409b && this.f412e >= this.f410c.length) {
                m656d();
                a = C0110c.m631a(this.f410c, this.f412e, i) ^ -1;
            }
            if (this.f412e >= this.f410c.length) {
                int a2 = C0110c.m630a(this.f412e + 1);
                Object obj2 = new int[a2];
                Object obj3 = new Object[a2];
                System.arraycopy(this.f410c, 0, obj2, 0, this.f410c.length);
                System.arraycopy(this.f411d, 0, obj3, 0, this.f411d.length);
                this.f410c = obj2;
                this.f411d = obj3;
            }
            if (this.f412e - a != 0) {
                System.arraycopy(this.f410c, a, this.f410c, a + 1, this.f412e - a);
                System.arraycopy(this.f411d, a, this.f411d, a + 1, this.f412e - a);
            }
            this.f410c[a] = i;
            this.f411d[a] = obj;
            this.f412e++;
            return;
        }
        this.f410c[a] = i;
        this.f411d[a] = obj;
    }

    public void m663c() {
        int i = this.f412e;
        Object[] objArr = this.f411d;
        for (int i2 = 0; i2 < i; i2++) {
            objArr[i2] = null;
        }
        this.f412e = 0;
        this.f409b = false;
    }

    public void m664c(int i) {
        m661b(i);
    }

    public /* synthetic */ Object clone() {
        return m657a();
    }

    public int m665d(int i) {
        if (this.f409b) {
            m656d();
        }
        return this.f410c[i];
    }

    public Object m666e(int i) {
        if (this.f409b) {
            m656d();
        }
        return this.f411d[i];
    }

    public String toString() {
        if (m660b() <= 0) {
            return "{}";
        }
        StringBuilder stringBuilder = new StringBuilder(this.f412e * 28);
        stringBuilder.append('{');
        for (int i = 0; i < this.f412e; i++) {
            if (i > 0) {
                stringBuilder.append(", ");
            }
            stringBuilder.append(m665d(i));
            stringBuilder.append('=');
            C0120o e = m666e(i);
            if (e != this) {
                stringBuilder.append(e);
            } else {
                stringBuilder.append("(this Map)");
            }
        }
        stringBuilder.append('}');
        return stringBuilder.toString();
    }
}

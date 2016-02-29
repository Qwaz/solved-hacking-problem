package android.support.v4.p002c;

/* renamed from: android.support.v4.c.c */
public class C0035c {
    private static final Object f191a;
    private boolean f192b;
    private int[] f193c;
    private Object[] f194d;
    private int f195e;

    static {
        f191a = new Object();
    }

    public C0035c() {
        this(10);
    }

    public C0035c(int i) {
        this.f192b = false;
        int d = C0035c.m206d(i);
        this.f193c = new int[d];
        this.f194d = new Object[d];
        this.f195e = 0;
    }

    static int m204c(int i) {
        for (int i2 = 4; i2 < 32; i2++) {
            if (i <= (1 << i2) - 12) {
                return (1 << i2) - 12;
            }
        }
        return i;
    }

    private void m205c() {
        int i = this.f195e;
        int[] iArr = this.f193c;
        Object[] objArr = this.f194d;
        int i2 = 0;
        for (int i3 = 0; i3 < i; i3++) {
            Object obj = objArr[i3];
            if (obj != f191a) {
                if (i3 != i2) {
                    iArr[i2] = iArr[i3];
                    objArr[i2] = obj;
                }
                i2++;
            }
        }
        this.f192b = false;
        this.f195e = i2;
    }

    static int m206d(int i) {
        return C0035c.m204c(i * 4) / 4;
    }

    public int m207a() {
        if (this.f192b) {
            m205c();
        }
        return this.f195e;
    }

    public int m208a(int i) {
        if (this.f192b) {
            m205c();
        }
        return this.f193c[i];
    }

    public Object m209b(int i) {
        if (this.f192b) {
            m205c();
        }
        return this.f194d[i];
    }

    public void m210b() {
        int i = this.f195e;
        Object[] objArr = this.f194d;
        for (int i2 = 0; i2 < i; i2++) {
            objArr[i2] = null;
        }
        this.f195e = 0;
        this.f192b = false;
    }
}

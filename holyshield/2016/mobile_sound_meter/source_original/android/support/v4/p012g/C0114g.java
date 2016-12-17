package android.support.v4.p012g;

import java.util.LinkedHashMap;

/* renamed from: android.support.v4.g.g */
public class C0114g {
    private final LinkedHashMap f388a;
    private int f389b;
    private int f390c;
    private int f391d;
    private int f392e;
    private int f393f;
    private int f394g;
    private int f395h;

    public C0114g(int i) {
        if (i <= 0) {
            throw new IllegalArgumentException("maxSize <= 0");
        }
        this.f390c = i;
        this.f388a = new LinkedHashMap(0, 0.75f, true);
    }

    private int m647c(Object obj, Object obj2) {
        int b = m652b(obj, obj2);
        if (b >= 0) {
            return b;
        }
        throw new IllegalStateException("Negative size: " + obj + "=" + obj2);
    }

    public final Object m648a(Object obj) {
        if (obj == null) {
            throw new NullPointerException("key == null");
        }
        synchronized (this) {
            Object obj2 = this.f388a.get(obj);
            if (obj2 != null) {
                this.f394g++;
                return obj2;
            }
            this.f395h++;
            Object b = m653b(obj);
            if (b == null) {
                return null;
            }
            synchronized (this) {
                this.f392e++;
                obj2 = this.f388a.put(obj, b);
                if (obj2 != null) {
                    this.f388a.put(obj, obj2);
                } else {
                    this.f389b += m647c(obj, b);
                }
            }
            if (obj2 != null) {
                m651a(false, obj, b, obj2);
                return obj2;
            }
            m650a(this.f390c);
            return b;
        }
    }

    public final Object m649a(Object obj, Object obj2) {
        if (obj == null || obj2 == null) {
            throw new NullPointerException("key == null || value == null");
        }
        Object put;
        synchronized (this) {
            this.f391d++;
            this.f389b += m647c(obj, obj2);
            put = this.f388a.put(obj, obj2);
            if (put != null) {
                this.f389b -= m647c(obj, put);
            }
        }
        if (put != null) {
            m651a(false, obj, put, obj2);
        }
        m650a(this.f390c);
        return put;
    }

    /* JADX WARNING: inconsistent code. */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    public void m650a(int r5) {
        /*
        r4 = this;
    L_0x0000:
        monitor-enter(r4);
        r0 = r4.f389b;	 Catch:{ all -> 0x0032 }
        if (r0 < 0) goto L_0x0011;
    L_0x0005:
        r0 = r4.f388a;	 Catch:{ all -> 0x0032 }
        r0 = r0.isEmpty();	 Catch:{ all -> 0x0032 }
        if (r0 == 0) goto L_0x0035;
    L_0x000d:
        r0 = r4.f389b;	 Catch:{ all -> 0x0032 }
        if (r0 == 0) goto L_0x0035;
    L_0x0011:
        r0 = new java.lang.IllegalStateException;	 Catch:{ all -> 0x0032 }
        r1 = new java.lang.StringBuilder;	 Catch:{ all -> 0x0032 }
        r1.<init>();	 Catch:{ all -> 0x0032 }
        r2 = r4.getClass();	 Catch:{ all -> 0x0032 }
        r2 = r2.getName();	 Catch:{ all -> 0x0032 }
        r1 = r1.append(r2);	 Catch:{ all -> 0x0032 }
        r2 = ".sizeOf() is reporting inconsistent results!";
        r1 = r1.append(r2);	 Catch:{ all -> 0x0032 }
        r1 = r1.toString();	 Catch:{ all -> 0x0032 }
        r0.<init>(r1);	 Catch:{ all -> 0x0032 }
        throw r0;	 Catch:{ all -> 0x0032 }
    L_0x0032:
        r0 = move-exception;
        monitor-exit(r4);	 Catch:{ all -> 0x0032 }
        throw r0;
    L_0x0035:
        r0 = r4.f389b;	 Catch:{ all -> 0x0032 }
        if (r0 <= r5) goto L_0x0041;
    L_0x0039:
        r0 = r4.f388a;	 Catch:{ all -> 0x0032 }
        r0 = r0.isEmpty();	 Catch:{ all -> 0x0032 }
        if (r0 == 0) goto L_0x0043;
    L_0x0041:
        monitor-exit(r4);	 Catch:{ all -> 0x0032 }
        return;
    L_0x0043:
        r0 = r4.f388a;	 Catch:{ all -> 0x0032 }
        r0 = r0.entrySet();	 Catch:{ all -> 0x0032 }
        r0 = r0.iterator();	 Catch:{ all -> 0x0032 }
        r0 = r0.next();	 Catch:{ all -> 0x0032 }
        r0 = (java.util.Map.Entry) r0;	 Catch:{ all -> 0x0032 }
        r1 = r0.getKey();	 Catch:{ all -> 0x0032 }
        r0 = r0.getValue();	 Catch:{ all -> 0x0032 }
        r2 = r4.f388a;	 Catch:{ all -> 0x0032 }
        r2.remove(r1);	 Catch:{ all -> 0x0032 }
        r2 = r4.f389b;	 Catch:{ all -> 0x0032 }
        r3 = r4.m647c(r1, r0);	 Catch:{ all -> 0x0032 }
        r2 = r2 - r3;
        r4.f389b = r2;	 Catch:{ all -> 0x0032 }
        r2 = r4.f393f;	 Catch:{ all -> 0x0032 }
        r2 = r2 + 1;
        r4.f393f = r2;	 Catch:{ all -> 0x0032 }
        monitor-exit(r4);	 Catch:{ all -> 0x0032 }
        r2 = 1;
        r3 = 0;
        r4.m651a(r2, r1, r0, r3);
        goto L_0x0000;
        */
        throw new UnsupportedOperationException("Method not decompiled: android.support.v4.g.g.a(int):void");
    }

    protected void m651a(boolean z, Object obj, Object obj2, Object obj3) {
    }

    protected int m652b(Object obj, Object obj2) {
        return 1;
    }

    protected Object m653b(Object obj) {
        return null;
    }

    public final synchronized String toString() {
        String format;
        int i = 0;
        synchronized (this) {
            int i2 = this.f394g + this.f395h;
            if (i2 != 0) {
                i = (this.f394g * 100) / i2;
            }
            format = String.format("LruCache[maxSize=%d,hits=%d,misses=%d,hitRate=%d%%]", new Object[]{Integer.valueOf(this.f390c), Integer.valueOf(this.f394g), Integer.valueOf(this.f395h), Integer.valueOf(i)});
        }
        return format;
    }
}

package android.support.v4.p004h.p013a;

import android.os.Build.VERSION;

/* renamed from: android.support.v4.h.a.ae */
public class ae {
    private static final ah f415a;
    private final Object f416b;

    static {
        if (VERSION.SDK_INT >= 16) {
            f415a = new ai();
        } else if (VERSION.SDK_INT >= 15) {
            f415a = new ag();
        } else if (VERSION.SDK_INT >= 14) {
            f415a = new af();
        } else {
            f415a = new aj();
        }
    }

    public ae(Object obj) {
        this.f416b = obj;
    }

    public void m676a(int i) {
        f415a.m681a(this.f416b, i);
    }

    public void m677a(boolean z) {
        f415a.m682a(this.f416b, z);
    }

    public void m678b(int i) {
        f415a.m683b(this.f416b, i);
    }

    public void m679c(int i) {
        f415a.m684c(this.f416b, i);
    }

    public void m680d(int i) {
        f415a.m685d(this.f416b, i);
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        ae aeVar = (ae) obj;
        return this.f416b == null ? aeVar.f416b == null : this.f416b.equals(aeVar.f416b);
    }

    public int hashCode() {
        return this.f416b == null ? 0 : this.f416b.hashCode();
    }
}

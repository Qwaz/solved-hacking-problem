package android.support.v4.p004h;

import android.os.Build.VERSION;
import android.view.View;
import android.view.animation.Interpolator;
import java.lang.ref.WeakReference;

/* renamed from: android.support.v4.h.dh */
public final class dh {
    static final dr f453a;
    private WeakReference f454b;
    private Runnable f455c;
    private Runnable f456d;
    private int f457e;

    static {
        int i = VERSION.SDK_INT;
        if (i >= 21) {
            f453a = new dq();
        } else if (i >= 19) {
            f453a = new dp();
        } else if (i >= 18) {
            f453a = new dn();
        } else if (i >= 16) {
            f453a = new C0153do();
        } else if (i >= 14) {
            f453a = new dl();
        } else {
            f453a = new dj();
        }
    }

    dh(View view) {
        this.f455c = null;
        this.f456d = null;
        this.f457e = -1;
        this.f454b = new WeakReference(view);
    }

    public long m1224a() {
        View view = (View) this.f454b.get();
        return view != null ? f453a.m1234a(this, view) : 0;
    }

    public dh m1225a(float f) {
        View view = (View) this.f454b.get();
        if (view != null) {
            f453a.m1235a(this, view, f);
        }
        return this;
    }

    public dh m1226a(long j) {
        View view = (View) this.f454b.get();
        if (view != null) {
            f453a.m1236a(this, view, j);
        }
        return this;
    }

    public dh m1227a(dy dyVar) {
        View view = (View) this.f454b.get();
        if (view != null) {
            f453a.m1237a(this, view, dyVar);
        }
        return this;
    }

    public dh m1228a(ea eaVar) {
        View view = (View) this.f454b.get();
        if (view != null) {
            f453a.m1238a(this, view, eaVar);
        }
        return this;
    }

    public dh m1229a(Interpolator interpolator) {
        View view = (View) this.f454b.get();
        if (view != null) {
            f453a.m1239a(this, view, interpolator);
        }
        return this;
    }

    public dh m1230b(float f) {
        View view = (View) this.f454b.get();
        if (view != null) {
            f453a.m1241b(this, view, f);
        }
        return this;
    }

    public dh m1231b(long j) {
        View view = (View) this.f454b.get();
        if (view != null) {
            f453a.m1242b(this, view, j);
        }
        return this;
    }

    public void m1232b() {
        View view = (View) this.f454b.get();
        if (view != null) {
            f453a.m1240b(this, view);
        }
    }

    public void m1233c() {
        View view = (View) this.f454b.get();
        if (view != null) {
            f453a.m1243c(this, view);
        }
    }
}

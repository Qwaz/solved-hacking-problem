package android.support.v4.p003a;

import android.app.Activity;
import android.content.Context;
import android.os.Handler;
import android.support.v4.p012g.C0106n;
import android.view.LayoutInflater;
import android.view.View;
import java.io.FileDescriptor;
import java.io.PrintWriter;

/* renamed from: android.support.v4.a.ac */
public abstract class ac extends aa {
    private final Activity f90a;
    final Context f91b;
    final int f92c;
    final af f93d;
    private final Handler f94e;
    private C0106n f95f;
    private boolean f96g;
    private ba f97h;
    private boolean f98i;
    private boolean f99j;

    ac(Activity activity, Context context, Handler handler, int i) {
        this.f93d = new af();
        this.f90a = activity;
        this.f91b = context;
        this.f94e = handler;
        this.f92c = i;
    }

    ac(C0045w c0045w) {
        this(c0045w, c0045w, c0045w.f318a, 0);
    }

    ba m112a(String str, boolean z, boolean z2) {
        if (this.f95f == null) {
            this.f95f = new C0106n();
        }
        ba baVar = (ba) this.f95f.get(str);
        if (baVar != null) {
            baVar.m238a(this);
            return baVar;
        } else if (!z2) {
            return baVar;
        } else {
            baVar = new ba(str, this, z);
            this.f95f.put(str, baVar);
            return baVar;
        }
    }

    public View m113a(int i) {
        return null;
    }

    void m114a(C0106n c0106n) {
        this.f95f = c0106n;
    }

    void m115a(String str) {
        if (this.f95f != null) {
            ba baVar = (ba) this.f95f.get(str);
            if (baVar != null && !baVar.f180f) {
                baVar.m247h();
                this.f95f.remove(str);
            }
        }
    }

    public void m116a(String str, FileDescriptor fileDescriptor, PrintWriter printWriter, String[] strArr) {
    }

    void m117a(boolean z) {
        this.f96g = z;
        if (this.f97h != null && this.f99j) {
            this.f99j = false;
            if (z) {
                this.f97h.m243d();
            } else {
                this.f97h.m242c();
            }
        }
    }

    public boolean m118a() {
        return true;
    }

    public boolean m119a(C0042t c0042t) {
        return true;
    }

    public LayoutInflater m120b() {
        return (LayoutInflater) this.f91b.getSystemService("layout_inflater");
    }

    void m121b(C0042t c0042t) {
    }

    void m122b(String str, FileDescriptor fileDescriptor, PrintWriter printWriter, String[] strArr) {
        printWriter.print(str);
        printWriter.print("mLoadersStarted=");
        printWriter.println(this.f99j);
        if (this.f97h != null) {
            printWriter.print(str);
            printWriter.print("Loader Manager ");
            printWriter.print(Integer.toHexString(System.identityHashCode(this.f97h)));
            printWriter.println(":");
            this.f97h.m239a(str + "  ", fileDescriptor, printWriter, strArr);
        }
    }

    public void m123c() {
    }

    public boolean m124d() {
        return true;
    }

    public int m125e() {
        return this.f92c;
    }

    Activity m126f() {
        return this.f90a;
    }

    Context m127g() {
        return this.f91b;
    }

    Handler m128h() {
        return this.f94e;
    }

    af m129i() {
        return this.f93d;
    }

    boolean m130j() {
        return this.f96g;
    }

    void m131k() {
        if (!this.f99j) {
            this.f99j = true;
            if (this.f97h != null) {
                this.f97h.m241b();
            } else if (!this.f98i) {
                this.f97h = m112a("(root)", this.f99j, false);
                if (!(this.f97h == null || this.f97h.f179e)) {
                    this.f97h.m241b();
                }
            }
            this.f98i = true;
        }
    }

    void m132l() {
        if (this.f97h != null) {
            this.f97h.m247h();
        }
    }

    void m133m() {
        if (this.f95f != null) {
            int size = this.f95f.size();
            ba[] baVarArr = new ba[size];
            for (int i = size - 1; i >= 0; i--) {
                baVarArr[i] = (ba) this.f95f.m599c(i);
            }
            for (int i2 = 0; i2 < size; i2++) {
                ba baVar = baVarArr[i2];
                baVar.m244e();
                baVar.m246g();
            }
        }
    }

    C0106n m134n() {
        int i;
        int i2 = 0;
        if (this.f95f != null) {
            int size = this.f95f.size();
            ba[] baVarArr = new ba[size];
            for (int i3 = size - 1; i3 >= 0; i3--) {
                baVarArr[i3] = (ba) this.f95f.m599c(i3);
            }
            i = 0;
            while (i2 < size) {
                ba baVar = baVarArr[i2];
                if (baVar.f180f) {
                    i = 1;
                } else {
                    baVar.m247h();
                    this.f95f.remove(baVar.f178d);
                }
                i2++;
            }
        } else {
            i = 0;
        }
        return i != 0 ? this.f95f : null;
    }
}

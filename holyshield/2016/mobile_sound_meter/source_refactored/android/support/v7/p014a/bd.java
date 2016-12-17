package android.support.v7.p014a;

import android.app.Activity;
import android.app.Dialog;
import android.content.Context;
import android.content.res.Configuration;
import android.content.res.TypedArray;
import android.os.Build.VERSION;
import android.support.v4.p004h.bu;
import android.support.v4.p004h.dh;
import android.support.v4.p004h.dy;
import android.support.v4.p004h.ea;
import android.support.v7.p015b.C0233b;
import android.support.v7.p015b.C0238g;
import android.support.v7.p015b.C0243l;
import android.support.v7.view.C0208c;
import android.support.v7.view.C0212b;
import android.support.v7.view.C0247a;
import android.support.v7.view.C0256l;
import android.support.v7.widget.ActionBarContainer;
import android.support.v7.widget.ActionBarContextView;
import android.support.v7.widget.ActionBarOverlayLayout;
import android.support.v7.widget.C0211i;
import android.support.v7.widget.Toolbar;
import android.support.v7.widget.bs;
import android.support.v7.widget.cp;
import android.util.TypedValue;
import android.view.ContextThemeWrapper;
import android.view.View;
import android.view.ViewGroup;
import android.view.animation.AccelerateInterpolator;
import android.view.animation.DecelerateInterpolator;
import android.view.animation.Interpolator;
import java.util.ArrayList;

/* renamed from: android.support.v7.a.bd */
public class bd extends C0200a implements C0211i {
    static final /* synthetic */ boolean f689h;
    private static final Interpolator f690i;
    private static final Interpolator f691j;
    private static final boolean f692k;
    private boolean f693A;
    private int f694B;
    private boolean f695C;
    private boolean f696D;
    private boolean f697E;
    private boolean f698F;
    private boolean f699G;
    private C0256l f700H;
    private boolean f701I;
    bh f702a;
    C0212b f703b;
    C0208c f704c;
    boolean f705d;
    final dy f706e;
    final dy f707f;
    final ea f708g;
    private Context f709l;
    private Context f710m;
    private Activity f711n;
    private Dialog f712o;
    private ActionBarOverlayLayout f713p;
    private ActionBarContainer f714q;
    private bs f715r;
    private ActionBarContextView f716s;
    private View f717t;
    private cp f718u;
    private ArrayList f719v;
    private int f720w;
    private boolean f721x;
    private boolean f722y;
    private ArrayList f723z;

    static {
        boolean z = true;
        f689h = !bd.class.desiredAssertionStatus();
        f690i = new AccelerateInterpolator();
        f691j = new DecelerateInterpolator();
        if (VERSION.SDK_INT < 14) {
            z = false;
        }
        f692k = z;
    }

    public bd(Activity activity, boolean z) {
        this.f719v = new ArrayList();
        this.f720w = -1;
        this.f723z = new ArrayList();
        this.f694B = 0;
        this.f695C = true;
        this.f699G = true;
        this.f706e = new be(this);
        this.f707f = new bf(this);
        this.f708g = new bg(this);
        this.f711n = activity;
        View decorView = activity.getWindow().getDecorView();
        m1828a(decorView);
        if (!z) {
            this.f717t = decorView.findViewById(16908290);
        }
    }

    public bd(Dialog dialog) {
        this.f719v = new ArrayList();
        this.f720w = -1;
        this.f723z = new ArrayList();
        this.f694B = 0;
        this.f695C = true;
        this.f699G = true;
        this.f706e = new be(this);
        this.f707f = new bf(this);
        this.f708g = new bg(this);
        this.f712o = dialog;
        m1828a(dialog.getWindow().getDecorView());
    }

    private void m1828a(View view) {
        this.f713p = (ActionBarOverlayLayout) view.findViewById(C0238g.decor_content_parent);
        if (this.f713p != null) {
            this.f713p.setActionBarVisibilityCallback(this);
        }
        this.f715r = m1831b(view.findViewById(C0238g.action_bar));
        this.f716s = (ActionBarContextView) view.findViewById(C0238g.action_context_bar);
        this.f714q = (ActionBarContainer) view.findViewById(C0238g.action_bar_container);
        if (this.f715r == null || this.f716s == null || this.f714q == null) {
            throw new IllegalStateException(getClass().getSimpleName() + " can only be used " + "with a compatible window decor layout");
        }
        this.f709l = this.f715r.m2612b();
        boolean z = (this.f715r.m2628o() & 4) != 0;
        if (z) {
            this.f721x = true;
        }
        C0247a a = C0247a.m1987a(this.f709l);
        z = a.m1993f() || z;
        m1852a(z);
        m1841k(a.m1991d());
        TypedArray obtainStyledAttributes = this.f709l.obtainStyledAttributes(null, C0243l.ActionBar, C0233b.actionBarStyle, 0);
        if (obtainStyledAttributes.getBoolean(C0243l.ActionBar_hideOnContentScroll, false)) {
            m1853b(true);
        }
        int dimensionPixelSize = obtainStyledAttributes.getDimensionPixelSize(C0243l.ActionBar_elevation, 0);
        if (dimensionPixelSize != 0) {
            m1847a((float) dimensionPixelSize);
        }
        obtainStyledAttributes.recycle();
    }

    private bs m1831b(View view) {
        if (view instanceof bs) {
            return (bs) view;
        }
        if (view instanceof Toolbar) {
            return ((Toolbar) view).getWrapper();
        }
        throw new IllegalStateException(new StringBuilder().append("Can't make a decor toolbar out of ").append(view).toString() != null ? view.getClass().getSimpleName() : "null");
    }

    private static boolean m1833b(boolean z, boolean z2, boolean z3) {
        return z3 ? true : (z || z2) ? false : true;
    }

    private void m1841k(boolean z) {
        boolean z2 = true;
        this.f693A = z;
        if (this.f693A) {
            this.f714q.setTabContainer(null);
            this.f715r.m2607a(this.f718u);
        } else {
            this.f715r.m2607a(null);
            this.f714q.setTabContainer(this.f718u);
        }
        boolean z3 = m1867j() == 2;
        if (this.f718u != null) {
            if (z3) {
                this.f718u.setVisibility(0);
                if (this.f713p != null) {
                    bu.m1002k(this.f713p);
                }
            } else {
                this.f718u.setVisibility(8);
            }
        }
        bs bsVar = this.f715r;
        boolean z4 = !this.f693A && z3;
        bsVar.m2611a(z4);
        ActionBarOverlayLayout actionBarOverlayLayout = this.f713p;
        if (this.f693A || !z3) {
            z2 = false;
        }
        actionBarOverlayLayout.setHasNonEmbeddedTabs(z2);
    }

    private void m1842l(boolean z) {
        if (bd.m1833b(this.f696D, this.f697E, this.f698F)) {
            if (!this.f699G) {
                this.f699G = true;
                m1864h(z);
            }
        } else if (this.f699G) {
            this.f699G = false;
            m1866i(z);
        }
    }

    private void m1843p() {
        if (!this.f698F) {
            this.f698F = true;
            if (this.f713p != null) {
                this.f713p.setShowingForActionMode(true);
            }
            m1842l(false);
        }
    }

    private void m1844q() {
        if (this.f698F) {
            this.f698F = false;
            if (this.f713p != null) {
                this.f713p.setShowingForActionMode(false);
            }
            m1842l(false);
        }
    }

    public int m1845a() {
        return this.f715r.m2628o();
    }

    public C0212b m1846a(C0208c c0208c) {
        if (this.f702a != null) {
            this.f702a.m1904c();
        }
        this.f713p.setHideOnContentScrollEnabled(false);
        this.f716s.m2293c();
        C0212b bhVar = new bh(this, this.f716s.getContext(), c0208c);
        if (!bhVar.m1906e()) {
            return null;
        }
        bhVar.m1905d();
        this.f716s.m2290a(bhVar);
        m1868j(true);
        this.f716s.sendAccessibilityEvent(32);
        this.f702a = bhVar;
        return bhVar;
    }

    public void m1847a(float f) {
        bu.m994c(this.f714q, f);
    }

    public void m1848a(int i) {
        this.f694B = i;
    }

    public void m1849a(int i, int i2) {
        int o = this.f715r.m2628o();
        if ((i2 & 4) != 0) {
            this.f721x = true;
        }
        this.f715r.m2615c((o & (i2 ^ -1)) | (i & i2));
    }

    public void m1850a(Configuration configuration) {
        m1841k(C0247a.m1987a(this.f709l).m1991d());
    }

    public void m1851a(CharSequence charSequence) {
        this.f715r.m2610a(charSequence);
    }

    public void m1852a(boolean z) {
        this.f715r.m2614b(z);
    }

    public void m1853b(boolean z) {
        if (!z || this.f713p.m2321a()) {
            this.f705d = z;
            this.f713p.setHideOnContentScrollEnabled(z);
            return;
        }
        throw new IllegalStateException("Action bar must be in overlay mode (Window.FEATURE_OVERLAY_ACTION_BAR) to enable hide on content scroll");
    }

    public boolean m1854b() {
        int k = m1869k();
        return this.f699G && (k == 0 || m1857d() < k);
    }

    public Context m1855c() {
        if (this.f710m == null) {
            TypedValue typedValue = new TypedValue();
            this.f709l.getTheme().resolveAttribute(C0233b.actionBarWidgetTheme, typedValue, true);
            int i = typedValue.resourceId;
            if (i != 0) {
                this.f710m = new ContextThemeWrapper(this.f709l, i);
            } else {
                this.f710m = this.f709l;
            }
        }
        return this.f710m;
    }

    public void m1856c(boolean z) {
        if (!this.f721x) {
            m1860f(z);
        }
    }

    public int m1857d() {
        return this.f713p.getActionBarHideOffset();
    }

    public void m1858d(boolean z) {
        this.f701I = z;
        if (!z && this.f700H != null) {
            this.f700H.m2051b();
        }
    }

    public void m1859e(boolean z) {
        if (z != this.f722y) {
            this.f722y = z;
            int size = this.f723z.size();
            for (int i = 0; i < size; i++) {
                ((C0213c) this.f723z.get(i)).m1911a(z);
            }
        }
    }

    public void m1860f(boolean z) {
        m1849a(z ? 4 : 0, 4);
    }

    public boolean m1861f() {
        if (this.f715r == null || !this.f715r.m2616c()) {
            return false;
        }
        this.f715r.m2617d();
        return true;
    }

    public void m1862g(boolean z) {
        this.f695C = z;
    }

    public boolean m1863g() {
        ViewGroup a = this.f715r.m2603a();
        if (a == null || a.hasFocus()) {
            return false;
        }
        a.requestFocus();
        return true;
    }

    public void m1864h(boolean z) {
        if (this.f700H != null) {
            this.f700H.m2051b();
        }
        this.f714q.setVisibility(0);
        if (this.f694B == 0 && f692k && (this.f701I || z)) {
            bu.m979a(this.f714q, 0.0f);
            float f = (float) (-this.f714q.getHeight());
            if (z) {
                int[] iArr = new int[]{0, 0};
                this.f714q.getLocationInWindow(iArr);
                f -= (float) iArr[1];
            }
            bu.m979a(this.f714q, f);
            C0256l c0256l = new C0256l();
            dh b = bu.m1000i(this.f714q).m1230b(0.0f);
            b.m1228a(this.f708g);
            c0256l.m2046a(b);
            if (this.f695C && this.f717t != null) {
                bu.m979a(this.f717t, f);
                c0256l.m2046a(bu.m1000i(this.f717t).m1230b(0.0f));
            }
            c0256l.m2049a(f691j);
            c0256l.m2045a(250);
            c0256l.m2048a(this.f707f);
            this.f700H = c0256l;
            c0256l.m2050a();
        } else {
            bu.m991b(this.f714q, 1.0f);
            bu.m979a(this.f714q, 0.0f);
            if (this.f695C && this.f717t != null) {
                bu.m979a(this.f717t, 0.0f);
            }
            this.f707f.m1268b(null);
        }
        if (this.f713p != null) {
            bu.m1002k(this.f713p);
        }
    }

    void m1865i() {
        if (this.f704c != null) {
            this.f704c.m1758a(this.f703b);
            this.f703b = null;
            this.f704c = null;
        }
    }

    public void m1866i(boolean z) {
        if (this.f700H != null) {
            this.f700H.m2051b();
        }
        if (this.f694B == 0 && f692k && (this.f701I || z)) {
            bu.m991b(this.f714q, 1.0f);
            this.f714q.setTransitioning(true);
            C0256l c0256l = new C0256l();
            float f = (float) (-this.f714q.getHeight());
            if (z) {
                int[] iArr = new int[]{0, 0};
                this.f714q.getLocationInWindow(iArr);
                f -= (float) iArr[1];
            }
            dh b = bu.m1000i(this.f714q).m1230b(f);
            b.m1228a(this.f708g);
            c0256l.m2046a(b);
            if (this.f695C && this.f717t != null) {
                c0256l.m2046a(bu.m1000i(this.f717t).m1230b(f));
            }
            c0256l.m2049a(f690i);
            c0256l.m2045a(250);
            c0256l.m2048a(this.f706e);
            this.f700H = c0256l;
            c0256l.m2050a();
            return;
        }
        this.f706e.m1268b(null);
    }

    public int m1867j() {
        return this.f715r.m2629p();
    }

    public void m1868j(boolean z) {
        dh a;
        dh a2;
        if (z) {
            m1843p();
        } else {
            m1844q();
        }
        if (z) {
            a = this.f715r.m2602a(4, 100);
            a2 = this.f716s.m2289a(0, 200);
        } else {
            a2 = this.f715r.m2602a(0, 200);
            a = this.f716s.m2289a(8, 100);
        }
        C0256l c0256l = new C0256l();
        c0256l.m2047a(a, a2);
        c0256l.m2050a();
    }

    public int m1869k() {
        return this.f714q.getHeight();
    }

    public void m1870l() {
        if (this.f697E) {
            this.f697E = false;
            m1842l(true);
        }
    }

    public void m1871m() {
        if (!this.f697E) {
            this.f697E = true;
            m1842l(true);
        }
    }

    public void m1872n() {
        if (this.f700H != null) {
            this.f700H.m2051b();
            this.f700H = null;
        }
    }

    public void m1873o() {
    }
}

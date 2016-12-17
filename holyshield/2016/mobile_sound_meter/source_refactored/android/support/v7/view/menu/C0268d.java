package android.support.v7.view.menu;

import android.content.Context;
import android.support.v4.p004h.bu;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import java.util.ArrayList;

/* renamed from: android.support.v7.view.menu.d */
public abstract class C0268d implements C0267x {
    protected Context f995a;
    protected Context f996b;
    protected C0264i f997c;
    protected LayoutInflater f998d;
    protected LayoutInflater f999e;
    protected C0260z f1000f;
    private C0207y f1001g;
    private int f1002h;
    private int f1003i;
    private int f1004j;

    public C0268d(Context context, int i, int i2) {
        this.f995a = context;
        this.f998d = LayoutInflater.from(context);
        this.f1002h = i;
        this.f1003i = i2;
    }

    public C0207y m2177a() {
        return this.f1001g;
    }

    public C0260z m2178a(ViewGroup viewGroup) {
        if (this.f1000f == null) {
            this.f1000f = (C0260z) this.f998d.inflate(this.f1002h, viewGroup, false);
            this.f1000f.m2069a(this.f997c);
            m2191b(true);
        }
        return this.f1000f;
    }

    public View m2179a(C0272m c0272m, View view, ViewGroup viewGroup) {
        aa b = view instanceof aa ? (aa) view : m2190b(viewGroup);
        m2183a(c0272m, b);
        return (View) b;
    }

    public void m2180a(int i) {
        this.f1004j = i;
    }

    public void m2181a(Context context, C0264i c0264i) {
        this.f996b = context;
        this.f999e = LayoutInflater.from(this.f996b);
        this.f997c = c0264i;
    }

    public void m2182a(C0264i c0264i, boolean z) {
        if (this.f1001g != null) {
            this.f1001g.m1754a(c0264i, z);
        }
    }

    public abstract void m2183a(C0272m c0272m, aa aaVar);

    public void m2184a(C0207y c0207y) {
        this.f1001g = c0207y;
    }

    protected void m2185a(View view, int i) {
        ViewGroup viewGroup = (ViewGroup) view.getParent();
        if (viewGroup != null) {
            viewGroup.removeView(view);
        }
        ((ViewGroup) this.f1000f).addView(view, i);
    }

    public boolean m2186a(int i, C0272m c0272m) {
        return true;
    }

    public boolean m2187a(ad adVar) {
        return this.f1001g != null ? this.f1001g.m1755a(adVar) : false;
    }

    public boolean m2188a(C0264i c0264i, C0272m c0272m) {
        return false;
    }

    protected boolean m2189a(ViewGroup viewGroup, int i) {
        viewGroup.removeViewAt(i);
        return true;
    }

    public aa m2190b(ViewGroup viewGroup) {
        return (aa) this.f998d.inflate(this.f1003i, viewGroup, false);
    }

    public void m2191b(boolean z) {
        ViewGroup viewGroup = (ViewGroup) this.f1000f;
        if (viewGroup != null) {
            int i;
            if (this.f997c != null) {
                this.f997c.m2136j();
                ArrayList i2 = this.f997c.m2135i();
                int size = i2.size();
                int i3 = 0;
                i = 0;
                while (i3 < size) {
                    int i4;
                    C0272m c0272m = (C0272m) i2.get(i3);
                    if (m2186a(i, c0272m)) {
                        View childAt = viewGroup.getChildAt(i);
                        C0272m itemData = childAt instanceof aa ? ((aa) childAt).getItemData() : null;
                        View a = m2179a(c0272m, childAt, viewGroup);
                        if (c0272m != itemData) {
                            a.setPressed(false);
                            bu.m1003l(a);
                        }
                        if (a != childAt) {
                            m2185a(a, i);
                        }
                        i4 = i + 1;
                    } else {
                        i4 = i;
                    }
                    i3++;
                    i = i4;
                }
            } else {
                i = 0;
            }
            while (i < viewGroup.getChildCount()) {
                if (!m2189a(viewGroup, i)) {
                    i++;
                }
            }
        }
    }

    public boolean m2192b() {
        return false;
    }

    public boolean m2193b(C0264i c0264i, C0272m c0272m) {
        return false;
    }
}

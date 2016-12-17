package android.support.v7.view.menu;

import android.content.Context;
import android.content.res.Resources;
import android.support.v7.p015b.C0233b;
import android.support.v7.p015b.C0236e;
import android.support.v7.p015b.C0240i;
import android.support.v7.widget.by;
import android.view.KeyEvent;
import android.view.LayoutInflater;
import android.view.MenuItem;
import android.view.View;
import android.view.View.MeasureSpec;
import android.view.View.OnKeyListener;
import android.view.ViewGroup;
import android.view.ViewTreeObserver;
import android.view.ViewTreeObserver.OnGlobalLayoutListener;
import android.widget.AdapterView;
import android.widget.AdapterView.OnItemClickListener;
import android.widget.FrameLayout;
import android.widget.ListAdapter;
import android.widget.PopupWindow.OnDismissListener;

/* renamed from: android.support.v7.view.menu.v */
public class C0281v implements C0267x, OnKeyListener, OnGlobalLayoutListener, OnItemClickListener, OnDismissListener {
    static final int f1055a;
    boolean f1056b;
    private final Context f1057c;
    private final LayoutInflater f1058d;
    private final C0264i f1059e;
    private final C0282w f1060f;
    private final boolean f1061g;
    private final int f1062h;
    private final int f1063i;
    private final int f1064j;
    private View f1065k;
    private by f1066l;
    private ViewTreeObserver f1067m;
    private C0207y f1068n;
    private ViewGroup f1069o;
    private boolean f1070p;
    private int f1071q;
    private int f1072r;

    static {
        f1055a = C0240i.abc_popup_menu_item_layout;
    }

    public C0281v(Context context, C0264i c0264i, View view) {
        this(context, c0264i, view, false, C0233b.popupMenuStyle);
    }

    public C0281v(Context context, C0264i c0264i, View view, boolean z, int i) {
        this(context, c0264i, view, z, i, 0);
    }

    public C0281v(Context context, C0264i c0264i, View view, boolean z, int i, int i2) {
        this.f1072r = 0;
        this.f1057c = context;
        this.f1058d = LayoutInflater.from(context);
        this.f1059e = c0264i;
        this.f1060f = new C0282w(this, this.f1059e);
        this.f1061g = z;
        this.f1063i = i;
        this.f1064j = i2;
        Resources resources = context.getResources();
        this.f1062h = Math.max(resources.getDisplayMetrics().widthPixels / 2, resources.getDimensionPixelSize(C0236e.abc_config_prefDialogWidth));
        this.f1065k = view;
        c0264i.m2112a((C0267x) this, context);
    }

    private int m2259g() {
        ListAdapter listAdapter = this.f1060f;
        int makeMeasureSpec = MeasureSpec.makeMeasureSpec(0, 0);
        int makeMeasureSpec2 = MeasureSpec.makeMeasureSpec(0, 0);
        int count = listAdapter.getCount();
        int i = 0;
        int i2 = 0;
        View view = null;
        int i3 = 0;
        while (i < count) {
            View view2;
            int itemViewType = listAdapter.getItemViewType(i);
            if (itemViewType != i2) {
                i2 = itemViewType;
                view2 = null;
            } else {
                view2 = view;
            }
            if (this.f1069o == null) {
                this.f1069o = new FrameLayout(this.f1057c);
            }
            view = listAdapter.getView(i, view2, this.f1069o);
            view.measure(makeMeasureSpec, makeMeasureSpec2);
            itemViewType = view.getMeasuredWidth();
            if (itemViewType >= this.f1062h) {
                return this.f1062h;
            }
            if (itemViewType <= i3) {
                itemViewType = i3;
            }
            i++;
            i3 = itemViewType;
        }
        return i3;
    }

    public void m2260a() {
        if (!m2273d()) {
            throw new IllegalStateException("MenuPopupHelper cannot be used without an anchor");
        }
    }

    public void m2261a(int i) {
        this.f1072r = i;
    }

    public void m2262a(Context context, C0264i c0264i) {
    }

    public void m2263a(C0264i c0264i, boolean z) {
        if (c0264i == this.f1059e) {
            m2274e();
            if (this.f1068n != null) {
                this.f1068n.m1754a(c0264i, z);
            }
        }
    }

    public void m2264a(C0207y c0207y) {
        this.f1068n = c0207y;
    }

    public void m2265a(View view) {
        this.f1065k = view;
    }

    public void m2266a(boolean z) {
        this.f1056b = z;
    }

    public boolean m2267a(ad adVar) {
        if (adVar.hasVisibleItems()) {
            boolean z;
            C0281v c0281v = new C0281v(this.f1057c, adVar, this.f1065k);
            c0281v.m2264a(this.f1068n);
            int size = adVar.size();
            for (int i = 0; i < size; i++) {
                MenuItem item = adVar.getItem(i);
                if (item.isVisible() && item.getIcon() != null) {
                    z = true;
                    break;
                }
            }
            z = false;
            c0281v.m2266a(z);
            if (c0281v.m2273d()) {
                if (this.f1068n == null) {
                    return true;
                }
                this.f1068n.m1755a(adVar);
                return true;
            }
        }
        return false;
    }

    public boolean m2268a(C0264i c0264i, C0272m c0272m) {
        return false;
    }

    public void m2269b(boolean z) {
        this.f1070p = false;
        if (this.f1060f != null) {
            this.f1060f.notifyDataSetChanged();
        }
    }

    public boolean m2270b() {
        return false;
    }

    public boolean m2271b(C0264i c0264i, C0272m c0272m) {
        return false;
    }

    public by m2272c() {
        return this.f1066l;
    }

    public boolean m2273d() {
        boolean z = false;
        this.f1066l = new by(this.f1057c, null, this.f1063i, this.f1064j);
        this.f1066l.m2564a((OnDismissListener) this);
        this.f1066l.m2562a((OnItemClickListener) this);
        this.f1066l.m2563a(this.f1060f);
        this.f1066l.m2565a(true);
        View view = this.f1065k;
        if (view == null) {
            return false;
        }
        if (this.f1067m == null) {
            z = true;
        }
        this.f1067m = view.getViewTreeObserver();
        if (z) {
            this.f1067m.addOnGlobalLayoutListener(this);
        }
        this.f1066l.m2561a(view);
        this.f1066l.m2570d(this.f1072r);
        if (!this.f1070p) {
            this.f1071q = m2259g();
            this.f1070p = true;
        }
        this.f1066l.m2574f(this.f1071q);
        this.f1066l.m2576g(2);
        this.f1066l.m2567c();
        this.f1066l.m2583m().setOnKeyListener(this);
        return true;
    }

    public void m2274e() {
        if (m2275f()) {
            this.f1066l.m2579i();
        }
    }

    public boolean m2275f() {
        return this.f1066l != null && this.f1066l.m2581k();
    }

    public void onDismiss() {
        this.f1066l = null;
        this.f1059e.close();
        if (this.f1067m != null) {
            if (!this.f1067m.isAlive()) {
                this.f1067m = this.f1065k.getViewTreeObserver();
            }
            this.f1067m.removeGlobalOnLayoutListener(this);
            this.f1067m = null;
        }
    }

    public void onGlobalLayout() {
        if (m2275f()) {
            View view = this.f1065k;
            if (view == null || !view.isShown()) {
                m2274e();
            } else if (m2275f()) {
                this.f1066l.m2567c();
            }
        }
    }

    public void onItemClick(AdapterView adapterView, View view, int i, long j) {
        C0282w c0282w = this.f1060f;
        c0282w.f1074b.m2117a(c0282w.m2277a(i), 0);
    }

    public boolean onKey(View view, int i, KeyEvent keyEvent) {
        if (keyEvent.getAction() != 1 || i != 82) {
            return false;
        }
        m2274e();
        return true;
    }
}

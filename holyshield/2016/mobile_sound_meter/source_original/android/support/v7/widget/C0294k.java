package android.support.v7.widget;

import android.content.Context;
import android.content.res.Configuration;
import android.content.res.Resources;
import android.graphics.drawable.Drawable;
import android.support.v4.p004h.C0161n;
import android.support.v4.p004h.C0162o;
import android.support.v7.p015b.C0239h;
import android.support.v7.p015b.C0240i;
import android.support.v7.p019e.C0246a;
import android.support.v7.view.C0247a;
import android.support.v7.view.menu.ActionMenuItemView;
import android.support.v7.view.menu.C0260z;
import android.support.v7.view.menu.C0264i;
import android.support.v7.view.menu.C0268d;
import android.support.v7.view.menu.C0272m;
import android.support.v7.view.menu.C0281v;
import android.support.v7.view.menu.aa;
import android.support.v7.view.menu.ad;
import android.util.SparseBooleanArray;
import android.view.MenuItem;
import android.view.View;
import android.view.View.MeasureSpec;
import android.view.ViewGroup;
import android.view.ViewGroup.LayoutParams;
import java.util.ArrayList;

/* renamed from: android.support.v7.widget.k */
class C0294k extends C0268d implements C0162o {
    private C0297n f1561A;
    final C0302s f1562g;
    int f1563h;
    private C0299p f1564i;
    private Drawable f1565j;
    private boolean f1566k;
    private boolean f1567l;
    private boolean f1568m;
    private int f1569n;
    private int f1570o;
    private int f1571p;
    private boolean f1572q;
    private boolean f1573r;
    private boolean f1574s;
    private boolean f1575t;
    private int f1576u;
    private final SparseBooleanArray f1577v;
    private View f1578w;
    private C0301r f1579x;
    private C0296m f1580y;
    private C0298o f1581z;

    public C0294k(Context context) {
        super(context, C0240i.abc_action_menu_layout, C0240i.abc_action_menu_item_layout);
        this.f1577v = new SparseBooleanArray();
        this.f1562g = new C0302s();
    }

    private View m2802a(MenuItem menuItem) {
        ViewGroup viewGroup = (ViewGroup) this.f;
        if (viewGroup == null) {
            return null;
        }
        int childCount = viewGroup.getChildCount();
        for (int i = 0; i < childCount; i++) {
            View childAt = viewGroup.getChildAt(i);
            if ((childAt instanceof aa) && ((aa) childAt).getItemData() == menuItem) {
                return childAt;
            }
        }
        return null;
    }

    public C0260z m2811a(ViewGroup viewGroup) {
        C0260z a = super.m2178a(viewGroup);
        ((ActionMenuView) a).setPresenter(this);
        return a;
    }

    public View m2812a(C0272m c0272m, View view, ViewGroup viewGroup) {
        View actionView = c0272m.getActionView();
        if (actionView == null || c0272m.m2238n()) {
            actionView = super.m2179a(c0272m, view, viewGroup);
        }
        actionView.setVisibility(c0272m.isActionViewExpanded() ? 8 : 0);
        ActionMenuView actionMenuView = (ActionMenuView) viewGroup;
        LayoutParams layoutParams = actionView.getLayoutParams();
        if (!actionMenuView.checkLayoutParams(layoutParams)) {
            actionView.setLayoutParams(actionMenuView.m2357a(layoutParams));
        }
        return actionView;
    }

    public void m2813a(Context context, C0264i c0264i) {
        super.m2181a(context, c0264i);
        Resources resources = context.getResources();
        C0247a a = C0247a.m1987a(context);
        if (!this.f1568m) {
            this.f1567l = a.m1989b();
        }
        if (!this.f1574s) {
            this.f1569n = a.m1990c();
        }
        if (!this.f1572q) {
            this.f1571p = a.m1988a();
        }
        int i = this.f1569n;
        if (this.f1567l) {
            if (this.f1564i == null) {
                this.f1564i = new C0299p(this, this.a);
                if (this.f1566k) {
                    this.f1564i.setImageDrawable(this.f1565j);
                    this.f1565j = null;
                    this.f1566k = false;
                }
                int makeMeasureSpec = MeasureSpec.makeMeasureSpec(0, 0);
                this.f1564i.measure(makeMeasureSpec, makeMeasureSpec);
            }
            i -= this.f1564i.getMeasuredWidth();
        } else {
            this.f1564i = null;
        }
        this.f1570o = i;
        this.f1576u = (int) (56.0f * resources.getDisplayMetrics().density);
        this.f1578w = null;
    }

    public void m2814a(Configuration configuration) {
        if (!this.f1572q) {
            this.f1571p = this.b.getResources().getInteger(C0239h.abc_max_action_buttons);
        }
        if (this.c != null) {
            this.c.m2123b(true);
        }
    }

    public void m2815a(Drawable drawable) {
        if (this.f1564i != null) {
            this.f1564i.setImageDrawable(drawable);
            return;
        }
        this.f1566k = true;
        this.f1565j = drawable;
    }

    public void m2816a(C0264i c0264i, boolean z) {
        m2830f();
        super.m2182a(c0264i, z);
    }

    public void m2817a(C0272m c0272m, aa aaVar) {
        aaVar.m2055a(c0272m, 0);
        ActionMenuItemView actionMenuItemView = (ActionMenuItemView) aaVar;
        actionMenuItemView.setItemInvoker((ActionMenuView) this.f);
        if (this.f1561A == null) {
            this.f1561A = new C0297n();
        }
        actionMenuItemView.setPopupCallback(this.f1561A);
    }

    public void m2818a(ActionMenuView actionMenuView) {
        this.f = actionMenuView;
        actionMenuView.m2358a(this.c);
    }

    public void m2819a(boolean z) {
        if (z) {
            super.m2187a(null);
        } else {
            this.c.m2115a(false);
        }
    }

    public boolean m2820a(int i, C0272m c0272m) {
        return c0272m.m2234j();
    }

    public boolean m2821a(ad adVar) {
        if (!adVar.hasVisibleItems()) {
            return false;
        }
        ad adVar2 = adVar;
        while (adVar2.m2153s() != this.c) {
            adVar2 = (ad) adVar2.m2153s();
        }
        View a = m2802a(adVar2.getItem());
        if (a == null) {
            if (this.f1564i == null) {
                return false;
            }
            a = this.f1564i;
        }
        this.f1563h = adVar.getItem().getItemId();
        this.f1580y = new C0296m(this, this.b, adVar);
        this.f1580y.m2265a(a);
        this.f1580y.m2260a();
        super.m2187a(adVar);
        return true;
    }

    public boolean m2822a(ViewGroup viewGroup, int i) {
        return viewGroup.getChildAt(i) == this.f1564i ? false : super.m2189a(viewGroup, i);
    }

    public void m2823b(boolean z) {
        int i;
        int i2 = 1;
        int i3 = 0;
        ViewGroup viewGroup = (ViewGroup) ((View) this.f).getParent();
        if (viewGroup != null) {
            C0246a.m1986a(viewGroup);
        }
        super.m2191b(z);
        ((View) this.f).requestLayout();
        if (this.c != null) {
            ArrayList k = this.c.m2137k();
            int size = k.size();
            for (i = 0; i < size; i++) {
                C0161n a = ((C0272m) k.get(i)).m2216a();
                if (a != null) {
                    a.m1336a((C0162o) this);
                }
            }
        }
        ArrayList l = this.c != null ? this.c.m2138l() : null;
        if (this.f1567l && l != null) {
            i = l.size();
            if (i == 1) {
                i3 = !((C0272m) l.get(0)).isActionViewExpanded() ? 1 : 0;
            } else {
                if (i <= 0) {
                    i2 = 0;
                }
                i3 = i2;
            }
        }
        if (i3 != 0) {
            if (this.f1564i == null) {
                this.f1564i = new C0299p(this, this.a);
            }
            viewGroup = (ViewGroup) this.f1564i.getParent();
            if (viewGroup != this.f) {
                if (viewGroup != null) {
                    viewGroup.removeView(this.f1564i);
                }
                ActionMenuView actionMenuView = (ActionMenuView) this.f;
                actionMenuView.addView(this.f1564i, actionMenuView.m2366c());
            }
        } else if (this.f1564i != null && this.f1564i.getParent() == this.f) {
            ((ViewGroup) this.f).removeView(this.f1564i);
        }
        ((ActionMenuView) this.f).setOverflowReserved(this.f1567l);
    }

    public boolean m2824b() {
        int i;
        ArrayList i2 = this.c.m2135i();
        int size = i2.size();
        int i3 = this.f1571p;
        int i4 = this.f1570o;
        int makeMeasureSpec = MeasureSpec.makeMeasureSpec(0, 0);
        ViewGroup viewGroup = (ViewGroup) this.f;
        int i5 = 0;
        int i6 = 0;
        Object obj = null;
        int i7 = 0;
        while (i7 < size) {
            C0272m c0272m = (C0272m) i2.get(i7);
            if (c0272m.m2236l()) {
                i5++;
            } else if (c0272m.m2235k()) {
                i6++;
            } else {
                obj = 1;
            }
            i = (this.f1575t && c0272m.isActionViewExpanded()) ? 0 : i3;
            i7++;
            i3 = i;
        }
        if (this.f1567l && (r4 != null || i5 + i6 > i3)) {
            i3--;
        }
        i7 = i3 - i5;
        SparseBooleanArray sparseBooleanArray = this.f1577v;
        sparseBooleanArray.clear();
        i = 0;
        if (this.f1573r) {
            i = i4 / this.f1576u;
            i6 = ((i4 % this.f1576u) / i) + this.f1576u;
        } else {
            i6 = 0;
        }
        int i8 = 0;
        i3 = 0;
        int i9 = i;
        while (i8 < size) {
            c0272m = (C0272m) i2.get(i8);
            int i10;
            if (c0272m.m2236l()) {
                View a = m2812a(c0272m, this.f1578w, viewGroup);
                if (this.f1578w == null) {
                    this.f1578w = a;
                }
                if (this.f1573r) {
                    i9 -= ActionMenuView.m2352a(a, i6, i9, makeMeasureSpec, 0);
                } else {
                    a.measure(makeMeasureSpec, makeMeasureSpec);
                }
                i5 = a.getMeasuredWidth();
                i10 = i4 - i5;
                if (i3 != 0) {
                    i5 = i3;
                }
                i3 = c0272m.getGroupId();
                if (i3 != 0) {
                    sparseBooleanArray.put(i3, true);
                }
                c0272m.m2227d(true);
                i = i10;
                i3 = i7;
            } else if (c0272m.m2235k()) {
                boolean z;
                int groupId = c0272m.getGroupId();
                boolean z2 = sparseBooleanArray.get(groupId);
                boolean z3 = (i7 > 0 || z2) && i4 > 0 && (!this.f1573r || i9 > 0);
                if (z3) {
                    View a2 = m2812a(c0272m, this.f1578w, viewGroup);
                    if (this.f1578w == null) {
                        this.f1578w = a2;
                    }
                    boolean z4;
                    if (this.f1573r) {
                        int a3 = ActionMenuView.m2352a(a2, i6, i9, makeMeasureSpec, 0);
                        i10 = i9 - a3;
                        if (a3 == 0) {
                            i9 = 0;
                        } else {
                            z4 = z3;
                        }
                        i5 = i10;
                    } else {
                        a2.measure(makeMeasureSpec, makeMeasureSpec);
                        boolean z5 = z3;
                        i5 = i9;
                        z4 = z5;
                    }
                    i10 = a2.getMeasuredWidth();
                    i4 -= i10;
                    if (i3 == 0) {
                        i3 = i10;
                    }
                    if (this.f1573r) {
                        z = i9 & (i4 >= 0 ? 1 : 0);
                        i10 = i3;
                        i3 = i5;
                    } else {
                        z = i9 & (i4 + i3 > 0 ? 1 : 0);
                        i10 = i3;
                        i3 = i5;
                    }
                } else {
                    z = z3;
                    i10 = i3;
                    i3 = i9;
                }
                if (z && groupId != 0) {
                    sparseBooleanArray.put(groupId, true);
                    i9 = i7;
                } else if (z2) {
                    sparseBooleanArray.put(groupId, false);
                    i5 = i7;
                    for (i7 = 0; i7 < i8; i7++) {
                        C0272m c0272m2 = (C0272m) i2.get(i7);
                        if (c0272m2.getGroupId() == groupId) {
                            if (c0272m2.m2234j()) {
                                i5++;
                            }
                            c0272m2.m2227d(false);
                        }
                    }
                    i9 = i5;
                } else {
                    i9 = i7;
                }
                if (z) {
                    i9--;
                }
                c0272m.m2227d(z);
                i5 = i10;
                i = i4;
                int i11 = i3;
                i3 = i9;
                i9 = i11;
            } else {
                c0272m.m2227d(false);
                i5 = i3;
                i = i4;
                i3 = i7;
            }
            i8++;
            i4 = i;
            i7 = i3;
            i3 = i5;
        }
        return true;
    }

    public Drawable m2825c() {
        return this.f1564i != null ? this.f1564i.getDrawable() : this.f1566k ? this.f1565j : null;
    }

    public void m2826c(boolean z) {
        this.f1567l = z;
        this.f1568m = true;
    }

    public void m2827d(boolean z) {
        this.f1575t = z;
    }

    public boolean m2828d() {
        if (!this.f1567l || m2832h() || this.c == null || this.f == null || this.f1581z != null || this.c.m2138l().isEmpty()) {
            return false;
        }
        this.f1581z = new C0298o(this, new C0301r(this, this.b, this.c, this.f1564i, true));
        ((View) this.f).post(this.f1581z);
        super.m2187a(null);
        return true;
    }

    public boolean m2829e() {
        if (this.f1581z == null || this.f == null) {
            C0281v c0281v = this.f1579x;
            if (c0281v == null) {
                return false;
            }
            c0281v.m2274e();
            return true;
        }
        ((View) this.f).removeCallbacks(this.f1581z);
        this.f1581z = null;
        return true;
    }

    public boolean m2830f() {
        return m2829e() | m2831g();
    }

    public boolean m2831g() {
        if (this.f1580y == null) {
            return false;
        }
        this.f1580y.m2274e();
        return true;
    }

    public boolean m2832h() {
        return this.f1579x != null && this.f1579x.m2275f();
    }

    public boolean m2833i() {
        return this.f1581z != null || m2832h();
    }
}

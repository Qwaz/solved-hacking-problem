package android.support.v7.widget;

import android.content.Context;
import android.graphics.drawable.Drawable;
import android.os.Build.VERSION;
import android.os.Parcelable;
import android.support.v4.p004h.C0164q;
import android.support.v4.p004h.am;
import android.support.v4.p004h.ar;
import android.support.v4.p004h.az;
import android.support.v4.p004h.bu;
import android.support.v7.p014a.C0210b;
import android.support.v7.p015b.C0233b;
import android.support.v7.p015b.C0243l;
import android.support.v7.view.C0253i;
import android.support.v7.view.menu.C0203j;
import android.support.v7.view.menu.C0207y;
import android.support.v7.view.menu.C0264i;
import android.support.v7.view.menu.C0267x;
import android.support.v7.view.menu.C0272m;
import android.text.TextUtils;
import android.text.TextUtils.TruncateAt;
import android.util.AttributeSet;
import android.view.ContextThemeWrapper;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.MotionEvent;
import android.view.View;
import android.view.View.MeasureSpec;
import android.view.View.OnClickListener;
import android.view.ViewGroup;
import android.view.ViewGroup.LayoutParams;
import android.view.ViewGroup.MarginLayoutParams;
import android.widget.ImageButton;
import android.widget.ImageView;
import android.widget.TextView;
import java.util.ArrayList;
import java.util.List;

public class Toolbar extends ViewGroup {
    private boolean f1226A;
    private final ArrayList f1227B;
    private final ArrayList f1228C;
    private final int[] f1229D;
    private dn f1230E;
    private final C0287y f1231F;
    private dq f1232G;
    private C0294k f1233H;
    private dl f1234I;
    private C0207y f1235J;
    private C0203j f1236K;
    private boolean f1237L;
    private final Runnable f1238M;
    private final ao f1239N;
    View f1240a;
    private ActionMenuView f1241b;
    private TextView f1242c;
    private TextView f1243d;
    private ImageButton f1244e;
    private ImageView f1245f;
    private Drawable f1246g;
    private CharSequence f1247h;
    private ImageButton f1248i;
    private Context f1249j;
    private int f1250k;
    private int f1251l;
    private int f1252m;
    private int f1253n;
    private int f1254o;
    private int f1255p;
    private int f1256q;
    private int f1257r;
    private int f1258s;
    private final co f1259t;
    private int f1260u;
    private CharSequence f1261v;
    private CharSequence f1262w;
    private int f1263x;
    private int f1264y;
    private boolean f1265z;

    public Toolbar(Context context) {
        this(context, null);
    }

    public Toolbar(Context context, AttributeSet attributeSet) {
        this(context, attributeSet, C0233b.toolbarStyle);
    }

    public Toolbar(Context context, AttributeSet attributeSet, int i) {
        super(context, attributeSet, i);
        this.f1259t = new co();
        this.f1260u = 8388627;
        this.f1227B = new ArrayList();
        this.f1228C = new ArrayList();
        this.f1229D = new int[2];
        this.f1231F = new di(this);
        this.f1238M = new dj(this);
        dh a = dh.m2710a(getContext(), attributeSet, C0243l.Toolbar, i, 0);
        this.f1251l = a.m2726g(C0243l.Toolbar_titleTextAppearance, 0);
        this.f1252m = a.m2726g(C0243l.Toolbar_subtitleTextAppearance, 0);
        this.f1260u = a.m2718c(C0243l.Toolbar_android_gravity, this.f1260u);
        this.f1253n = 48;
        int d = a.m2720d(C0243l.Toolbar_titleMargins, 0);
        this.f1258s = d;
        this.f1257r = d;
        this.f1256q = d;
        this.f1255p = d;
        d = a.m2720d(C0243l.Toolbar_titleMarginStart, -1);
        if (d >= 0) {
            this.f1255p = d;
        }
        d = a.m2720d(C0243l.Toolbar_titleMarginEnd, -1);
        if (d >= 0) {
            this.f1256q = d;
        }
        d = a.m2720d(C0243l.Toolbar_titleMarginTop, -1);
        if (d >= 0) {
            this.f1257r = d;
        }
        d = a.m2720d(C0243l.Toolbar_titleMarginBottom, -1);
        if (d >= 0) {
            this.f1258s = d;
        }
        this.f1254o = a.m2722e(C0243l.Toolbar_maxButtonHeight, -1);
        d = a.m2720d(C0243l.Toolbar_contentInsetStart, Integer.MIN_VALUE);
        int d2 = a.m2720d(C0243l.Toolbar_contentInsetEnd, Integer.MIN_VALUE);
        this.f1259t.m2656b(a.m2722e(C0243l.Toolbar_contentInsetLeft, 0), a.m2722e(C0243l.Toolbar_contentInsetRight, 0));
        if (!(d == Integer.MIN_VALUE && d2 == Integer.MIN_VALUE)) {
            this.f1259t.m2653a(d, d2);
        }
        this.f1246g = a.m2713a(C0243l.Toolbar_collapseIcon);
        this.f1247h = a.m2719c(C0243l.Toolbar_collapseContentDescription);
        CharSequence c = a.m2719c(C0243l.Toolbar_title);
        if (!TextUtils.isEmpty(c)) {
            setTitle(c);
        }
        c = a.m2719c(C0243l.Toolbar_subtitle);
        if (!TextUtils.isEmpty(c)) {
            setSubtitle(c);
        }
        this.f1249j = getContext();
        setPopupTheme(a.m2726g(C0243l.Toolbar_popupTheme, 0));
        Drawable a2 = a.m2713a(C0243l.Toolbar_navigationIcon);
        if (a2 != null) {
            setNavigationIcon(a2);
        }
        c = a.m2719c(C0243l.Toolbar_navigationContentDescription);
        if (!TextUtils.isEmpty(c)) {
            setNavigationContentDescription(c);
        }
        a2 = a.m2713a(C0243l.Toolbar_logo);
        if (a2 != null) {
            setLogo(a2);
        }
        c = a.m2719c(C0243l.Toolbar_logoDescription);
        if (!TextUtils.isEmpty(c)) {
            setLogoDescription(c);
        }
        if (a.m2725f(C0243l.Toolbar_titleTextColor)) {
            setTitleTextColor(a.m2716b(C0243l.Toolbar_titleTextColor, -1));
        }
        if (a.m2725f(C0243l.Toolbar_subtitleTextColor)) {
            setSubtitleTextColor(a.m2716b(C0243l.Toolbar_subtitleTextColor, -1));
        }
        a.m2714a();
        this.f1239N = ao.m2497a();
    }

    private int m2414a(int i) {
        int i2 = i & 112;
        switch (i2) {
            case C0243l.Toolbar_titleMarginBottom /*16*/:
            case C0243l.AppCompatTheme_homeAsUpIndicator /*48*/:
            case C0243l.AppCompatTheme_panelMenuListTheme /*80*/:
                return i2;
            default:
                return this.f1260u & 112;
        }
    }

    private int m2415a(View view, int i) {
        dm dmVar = (dm) view.getLayoutParams();
        int measuredHeight = view.getMeasuredHeight();
        int i2 = i > 0 ? (measuredHeight - i) / 2 : 0;
        switch (m2414a(dmVar.a)) {
            case C0243l.AppCompatTheme_homeAsUpIndicator /*48*/:
                return getPaddingTop() - i2;
            case C0243l.AppCompatTheme_panelMenuListTheme /*80*/:
                return (((getHeight() - getPaddingBottom()) - measuredHeight) - dmVar.bottomMargin) - i2;
            default:
                int i3;
                int paddingTop = getPaddingTop();
                int paddingBottom = getPaddingBottom();
                int height = getHeight();
                i2 = (((height - paddingTop) - paddingBottom) - measuredHeight) / 2;
                if (i2 < dmVar.topMargin) {
                    i3 = dmVar.topMargin;
                } else {
                    measuredHeight = (((height - paddingBottom) - measuredHeight) - i2) - paddingTop;
                    i3 = measuredHeight < dmVar.bottomMargin ? Math.max(0, i2 - (dmVar.bottomMargin - measuredHeight)) : i2;
                }
                return i3 + paddingTop;
        }
    }

    private int m2416a(View view, int i, int i2, int i3, int i4, int[] iArr) {
        MarginLayoutParams marginLayoutParams = (MarginLayoutParams) view.getLayoutParams();
        int i5 = marginLayoutParams.leftMargin - iArr[0];
        int i6 = marginLayoutParams.rightMargin - iArr[1];
        int max = Math.max(0, i5) + Math.max(0, i6);
        iArr[0] = Math.max(0, -i5);
        iArr[1] = Math.max(0, -i6);
        view.measure(getChildMeasureSpec(i, ((getPaddingLeft() + getPaddingRight()) + max) + i2, marginLayoutParams.width), getChildMeasureSpec(i3, (((getPaddingTop() + getPaddingBottom()) + marginLayoutParams.topMargin) + marginLayoutParams.bottomMargin) + i4, marginLayoutParams.height));
        return view.getMeasuredWidth() + max;
    }

    private int m2417a(View view, int i, int[] iArr, int i2) {
        dm dmVar = (dm) view.getLayoutParams();
        int i3 = dmVar.leftMargin - iArr[0];
        int max = Math.max(0, i3) + i;
        iArr[0] = Math.max(0, -i3);
        i3 = m2415a(view, i2);
        int measuredWidth = view.getMeasuredWidth();
        view.layout(max, i3, max + measuredWidth, view.getMeasuredHeight() + i3);
        return (dmVar.rightMargin + measuredWidth) + max;
    }

    private int m2418a(List list, int[] iArr) {
        int i = iArr[0];
        int i2 = iArr[1];
        int size = list.size();
        int i3 = 0;
        int i4 = 0;
        int i5 = i2;
        int i6 = i;
        while (i3 < size) {
            View view = (View) list.get(i3);
            dm dmVar = (dm) view.getLayoutParams();
            i6 = dmVar.leftMargin - i6;
            i = dmVar.rightMargin - i5;
            int max = Math.max(0, i6);
            int max2 = Math.max(0, i);
            i6 = Math.max(0, -i6);
            i5 = Math.max(0, -i);
            i3++;
            i4 += (view.getMeasuredWidth() + max) + max2;
        }
        return i4;
    }

    private void m2420a(View view, int i, int i2, int i3, int i4, int i5) {
        MarginLayoutParams marginLayoutParams = (MarginLayoutParams) view.getLayoutParams();
        int childMeasureSpec = getChildMeasureSpec(i, (((getPaddingLeft() + getPaddingRight()) + marginLayoutParams.leftMargin) + marginLayoutParams.rightMargin) + i2, marginLayoutParams.width);
        int childMeasureSpec2 = getChildMeasureSpec(i3, (((getPaddingTop() + getPaddingBottom()) + marginLayoutParams.topMargin) + marginLayoutParams.bottomMargin) + i4, marginLayoutParams.height);
        int mode = MeasureSpec.getMode(childMeasureSpec2);
        if (mode != 1073741824 && i5 >= 0) {
            if (mode != 0) {
                i5 = Math.min(MeasureSpec.getSize(childMeasureSpec2), i5);
            }
            childMeasureSpec2 = MeasureSpec.makeMeasureSpec(i5, 1073741824);
        }
        view.measure(childMeasureSpec, childMeasureSpec2);
    }

    private void m2421a(View view, boolean z) {
        LayoutParams layoutParams = view.getLayoutParams();
        if (layoutParams == null) {
            layoutParams = m2454i();
        } else if (checkLayoutParams(layoutParams)) {
            dm dmVar = (dm) layoutParams;
        } else {
            layoutParams = m2440a(layoutParams);
        }
        layoutParams.f1529b = 1;
        if (!z || this.f1240a == null) {
            addView(view, layoutParams);
            return;
        }
        view.setLayoutParams(layoutParams);
        this.f1228C.add(view);
    }

    private void m2422a(List list, int i) {
        int i2 = 1;
        int i3 = 0;
        if (bu.m995d(this) != 1) {
            i2 = 0;
        }
        int childCount = getChildCount();
        int a = C0164q.m1347a(i, bu.m995d(this));
        list.clear();
        dm dmVar;
        if (i2 != 0) {
            for (i3 = childCount - 1; i3 >= 0; i3--) {
                View childAt = getChildAt(i3);
                dmVar = (dm) childAt.getLayoutParams();
                if (dmVar.f1529b == 0 && m2423a(childAt) && m2424b(dmVar.a) == a) {
                    list.add(childAt);
                }
            }
            return;
        }
        while (i3 < childCount) {
            View childAt2 = getChildAt(i3);
            dmVar = (dm) childAt2.getLayoutParams();
            if (dmVar.f1529b == 0 && m2423a(childAt2) && m2424b(dmVar.a) == a) {
                list.add(childAt2);
            }
            i3++;
        }
    }

    private boolean m2423a(View view) {
        return (view == null || view.getParent() != this || view.getVisibility() == 8) ? false : true;
    }

    private int m2424b(int i) {
        int d = bu.m995d(this);
        int a = C0164q.m1347a(i, d) & 7;
        switch (a) {
            case C0243l.View_android_focusable /*1*/:
            case C0243l.View_paddingEnd /*3*/:
            case C0243l.Toolbar_contentInsetStart /*5*/:
                return a;
            default:
                return d == 1 ? 5 : 3;
        }
    }

    private int m2425b(View view) {
        MarginLayoutParams marginLayoutParams = (MarginLayoutParams) view.getLayoutParams();
        return am.m851b(marginLayoutParams) + am.m850a(marginLayoutParams);
    }

    private int m2426b(View view, int i, int[] iArr, int i2) {
        dm dmVar = (dm) view.getLayoutParams();
        int i3 = dmVar.rightMargin - iArr[1];
        int max = i - Math.max(0, i3);
        iArr[1] = Math.max(0, -i3);
        i3 = m2415a(view, i2);
        int measuredWidth = view.getMeasuredWidth();
        view.layout(max - measuredWidth, i3, max, view.getMeasuredHeight() + i3);
        return max - (dmVar.leftMargin + measuredWidth);
    }

    private int m2428c(View view) {
        MarginLayoutParams marginLayoutParams = (MarginLayoutParams) view.getLayoutParams();
        return marginLayoutParams.bottomMargin + marginLayoutParams.topMargin;
    }

    private boolean m2431d(View view) {
        return view.getParent() == this || this.f1228C.contains(view);
    }

    private MenuInflater getMenuInflater() {
        return new C0253i(getContext());
    }

    private void m2432l() {
        if (this.f1245f == null) {
            this.f1245f = new ImageView(getContext());
        }
    }

    private void m2433m() {
        m2434n();
        if (this.f1241b.m2367d() == null) {
            C0264i c0264i = (C0264i) this.f1241b.getMenu();
            if (this.f1234I == null) {
                this.f1234I = new dl();
            }
            this.f1241b.setExpandedActionViewsExclusive(true);
            c0264i.m2112a(this.f1234I, this.f1249j);
        }
    }

    private void m2434n() {
        if (this.f1241b == null) {
            this.f1241b = new ActionMenuView(getContext());
            this.f1241b.setPopupTheme(this.f1250k);
            this.f1241b.setOnMenuItemClickListener(this.f1231F);
            this.f1241b.m2359a(this.f1235J, this.f1236K);
            LayoutParams i = m2454i();
            i.a = 8388613 | (this.f1253n & 112);
            this.f1241b.setLayoutParams(i);
            m2421a(this.f1241b, false);
        }
    }

    private void m2435o() {
        if (this.f1244e == null) {
            this.f1244e = new ImageButton(getContext(), null, C0233b.toolbarNavigationButtonStyle);
            LayoutParams i = m2454i();
            i.a = 8388611 | (this.f1253n & 112);
            this.f1244e.setLayoutParams(i);
        }
    }

    private void m2436p() {
        if (this.f1248i == null) {
            this.f1248i = new ImageButton(getContext(), null, C0233b.toolbarNavigationButtonStyle);
            this.f1248i.setImageDrawable(this.f1246g);
            this.f1248i.setContentDescription(this.f1247h);
            LayoutParams i = m2454i();
            i.a = 8388611 | (this.f1253n & 112);
            i.f1529b = 2;
            this.f1248i.setLayoutParams(i);
            this.f1248i.setOnClickListener(new dk(this));
        }
    }

    private void m2437q() {
        removeCallbacks(this.f1238M);
        post(this.f1238M);
    }

    private boolean m2438r() {
        if (!this.f1237L) {
            return false;
        }
        int childCount = getChildCount();
        for (int i = 0; i < childCount; i++) {
            View childAt = getChildAt(i);
            if (m2423a(childAt) && childAt.getMeasuredWidth() > 0 && childAt.getMeasuredHeight() > 0) {
                return false;
            }
        }
        return true;
    }

    public dm m2439a(AttributeSet attributeSet) {
        return new dm(getContext(), attributeSet);
    }

    protected dm m2440a(LayoutParams layoutParams) {
        return layoutParams instanceof dm ? new dm((dm) layoutParams) : layoutParams instanceof C0210b ? new dm((C0210b) layoutParams) : layoutParams instanceof MarginLayoutParams ? new dm((MarginLayoutParams) layoutParams) : new dm(layoutParams);
    }

    public void m2441a(int i, int i2) {
        this.f1259t.m2653a(i, i2);
    }

    public void m2442a(Context context, int i) {
        this.f1251l = i;
        if (this.f1242c != null) {
            this.f1242c.setTextAppearance(context, i);
        }
    }

    public void m2443a(C0264i c0264i, C0294k c0294k) {
        if (c0264i != null || this.f1241b != null) {
            m2434n();
            C0264i d = this.f1241b.m2367d();
            if (d != c0264i) {
                if (d != null) {
                    d.m2122b(this.f1233H);
                    d.m2122b(this.f1234I);
                }
                if (this.f1234I == null) {
                    this.f1234I = new dl();
                }
                c0294k.m2827d(true);
                if (c0264i != null) {
                    c0264i.m2112a((C0267x) c0294k, this.f1249j);
                    c0264i.m2112a(this.f1234I, this.f1249j);
                } else {
                    c0294k.m2813a(this.f1249j, null);
                    this.f1234I.m2729a(this.f1249j, null);
                    c0294k.m2823b(true);
                    this.f1234I.m2733b(true);
                }
                this.f1241b.setPopupTheme(this.f1250k);
                this.f1241b.setPresenter(c0294k);
                this.f1233H = c0294k;
            }
        }
    }

    public void m2444a(C0207y c0207y, C0203j c0203j) {
        this.f1235J = c0207y;
        this.f1236K = c0203j;
        if (this.f1241b != null) {
            this.f1241b.m2359a(c0207y, c0203j);
        }
    }

    public boolean m2445a() {
        return getVisibility() == 0 && this.f1241b != null && this.f1241b.m2360a();
    }

    public void m2446b(Context context, int i) {
        this.f1252m = i;
        if (this.f1243d != null) {
            this.f1243d.setTextAppearance(context, i);
        }
    }

    public boolean m2447b() {
        return this.f1241b != null && this.f1241b.m2370g();
    }

    public boolean m2448c() {
        return this.f1241b != null && this.f1241b.m2371h();
    }

    protected boolean checkLayoutParams(LayoutParams layoutParams) {
        return super.checkLayoutParams(layoutParams) && (layoutParams instanceof dm);
    }

    public boolean m2449d() {
        return this.f1241b != null && this.f1241b.m2368e();
    }

    public boolean m2450e() {
        return this.f1241b != null && this.f1241b.m2369f();
    }

    public void m2451f() {
        if (this.f1241b != null) {
            this.f1241b.m2372i();
        }
    }

    public boolean m2452g() {
        return (this.f1234I == null || this.f1234I.f1527b == null) ? false : true;
    }

    protected /* synthetic */ LayoutParams generateDefaultLayoutParams() {
        return m2454i();
    }

    public /* synthetic */ LayoutParams generateLayoutParams(AttributeSet attributeSet) {
        return m2439a(attributeSet);
    }

    protected /* synthetic */ LayoutParams generateLayoutParams(LayoutParams layoutParams) {
        return m2440a(layoutParams);
    }

    public int getContentInsetEnd() {
        return this.f1259t.m2658d();
    }

    public int getContentInsetLeft() {
        return this.f1259t.m2652a();
    }

    public int getContentInsetRight() {
        return this.f1259t.m2655b();
    }

    public int getContentInsetStart() {
        return this.f1259t.m2657c();
    }

    public Drawable getLogo() {
        return this.f1245f != null ? this.f1245f.getDrawable() : null;
    }

    public CharSequence getLogoDescription() {
        return this.f1245f != null ? this.f1245f.getContentDescription() : null;
    }

    public Menu getMenu() {
        m2433m();
        return this.f1241b.getMenu();
    }

    public CharSequence getNavigationContentDescription() {
        return this.f1244e != null ? this.f1244e.getContentDescription() : null;
    }

    public Drawable getNavigationIcon() {
        return this.f1244e != null ? this.f1244e.getDrawable() : null;
    }

    public Drawable getOverflowIcon() {
        m2433m();
        return this.f1241b.getOverflowIcon();
    }

    public int getPopupTheme() {
        return this.f1250k;
    }

    public CharSequence getSubtitle() {
        return this.f1262w;
    }

    public CharSequence getTitle() {
        return this.f1261v;
    }

    public bs getWrapper() {
        if (this.f1232G == null) {
            this.f1232G = new dq(this, true);
        }
        return this.f1232G;
    }

    public void m2453h() {
        C0272m c0272m = this.f1234I == null ? null : this.f1234I.f1527b;
        if (c0272m != null) {
            c0272m.collapseActionView();
        }
    }

    protected dm m2454i() {
        return new dm(-2, -2);
    }

    void m2455j() {
        for (int childCount = getChildCount() - 1; childCount >= 0; childCount--) {
            View childAt = getChildAt(childCount);
            if (!(((dm) childAt.getLayoutParams()).f1529b == 2 || childAt == this.f1241b)) {
                removeViewAt(childCount);
                this.f1228C.add(childAt);
            }
        }
    }

    void m2456k() {
        for (int size = this.f1228C.size() - 1; size >= 0; size--) {
            addView((View) this.f1228C.get(size));
        }
        this.f1228C.clear();
    }

    protected void onDetachedFromWindow() {
        super.onDetachedFromWindow();
        removeCallbacks(this.f1238M);
    }

    public boolean onHoverEvent(MotionEvent motionEvent) {
        int a = az.m895a(motionEvent);
        if (a == 9) {
            this.f1226A = false;
        }
        if (!this.f1226A) {
            boolean onHoverEvent = super.onHoverEvent(motionEvent);
            if (a == 9 && !onHoverEvent) {
                this.f1226A = true;
            }
        }
        if (a == 10 || a == 3) {
            this.f1226A = false;
        }
        return true;
    }

    protected void onLayout(boolean z, int i, int i2, int i3, int i4) {
        int i5;
        int i6;
        int i7;
        int measuredHeight;
        int measuredWidth;
        Object obj = bu.m995d(this) == 1 ? 1 : null;
        int width = getWidth();
        int height = getHeight();
        int paddingLeft = getPaddingLeft();
        int paddingRight = getPaddingRight();
        int paddingTop = getPaddingTop();
        int paddingBottom = getPaddingBottom();
        int i8 = width - paddingRight;
        int[] iArr = this.f1229D;
        iArr[1] = 0;
        iArr[0] = 0;
        int h = bu.m999h(this);
        if (!m2423a(this.f1244e)) {
            i5 = paddingLeft;
        } else if (obj != null) {
            i8 = m2426b(this.f1244e, i8, iArr, h);
            i5 = paddingLeft;
        } else {
            i5 = m2417a(this.f1244e, paddingLeft, iArr, h);
        }
        if (m2423a(this.f1248i)) {
            if (obj != null) {
                i8 = m2426b(this.f1248i, i8, iArr, h);
            } else {
                i5 = m2417a(this.f1248i, i5, iArr, h);
            }
        }
        if (m2423a(this.f1241b)) {
            if (obj != null) {
                i5 = m2417a(this.f1241b, i5, iArr, h);
            } else {
                i8 = m2426b(this.f1241b, i8, iArr, h);
            }
        }
        iArr[0] = Math.max(0, getContentInsetLeft() - i5);
        iArr[1] = Math.max(0, getContentInsetRight() - ((width - paddingRight) - i8));
        i5 = Math.max(i5, getContentInsetLeft());
        i8 = Math.min(i8, (width - paddingRight) - getContentInsetRight());
        if (m2423a(this.f1240a)) {
            if (obj != null) {
                i8 = m2426b(this.f1240a, i8, iArr, h);
            } else {
                i5 = m2417a(this.f1240a, i5, iArr, h);
            }
        }
        if (!m2423a(this.f1245f)) {
            i6 = i8;
            i7 = i5;
        } else if (obj != null) {
            i6 = m2426b(this.f1245f, i8, iArr, h);
            i7 = i5;
        } else {
            i6 = i8;
            i7 = m2417a(this.f1245f, i5, iArr, h);
        }
        boolean a = m2423a(this.f1242c);
        boolean a2 = m2423a(this.f1243d);
        i5 = 0;
        if (a) {
            dm dmVar = (dm) this.f1242c.getLayoutParams();
            i5 = 0 + (dmVar.bottomMargin + (dmVar.topMargin + this.f1242c.getMeasuredHeight()));
        }
        if (a2) {
            dmVar = (dm) this.f1243d.getLayoutParams();
            measuredHeight = (dmVar.bottomMargin + (dmVar.topMargin + this.f1243d.getMeasuredHeight())) + i5;
        } else {
            measuredHeight = i5;
        }
        if (a || a2) {
            int paddingTop2;
            dmVar = (dm) (a ? this.f1242c : this.f1243d).getLayoutParams();
            dm dmVar2 = (dm) (a2 ? this.f1243d : this.f1242c).getLayoutParams();
            Object obj2 = ((!a || this.f1242c.getMeasuredWidth() <= 0) && (!a2 || this.f1243d.getMeasuredWidth() <= 0)) ? null : 1;
            switch (this.f1260u & 112) {
                case C0243l.AppCompatTheme_homeAsUpIndicator /*48*/:
                    paddingTop2 = (dmVar.topMargin + getPaddingTop()) + this.f1257r;
                    break;
                case C0243l.AppCompatTheme_panelMenuListTheme /*80*/:
                    paddingTop2 = (((height - paddingBottom) - dmVar2.bottomMargin) - this.f1258s) - measuredHeight;
                    break;
                default:
                    paddingTop2 = (((height - paddingTop) - paddingBottom) - measuredHeight) / 2;
                    if (paddingTop2 < dmVar.topMargin + this.f1257r) {
                        i8 = dmVar.topMargin + this.f1257r;
                    } else {
                        measuredHeight = (((height - paddingBottom) - measuredHeight) - paddingTop2) - paddingTop;
                        i8 = measuredHeight < dmVar.bottomMargin + this.f1258s ? Math.max(0, paddingTop2 - ((dmVar2.bottomMargin + this.f1258s) - measuredHeight)) : paddingTop2;
                    }
                    paddingTop2 = paddingTop + i8;
                    break;
            }
            if (obj != null) {
                i8 = (obj2 != null ? this.f1255p : 0) - iArr[1];
                i5 = i6 - Math.max(0, i8);
                iArr[1] = Math.max(0, -i8);
                if (a) {
                    dmVar = (dm) this.f1242c.getLayoutParams();
                    measuredWidth = i5 - this.f1242c.getMeasuredWidth();
                    i6 = this.f1242c.getMeasuredHeight() + paddingTop2;
                    this.f1242c.layout(measuredWidth, paddingTop2, i5, i6);
                    paddingTop2 = i6 + dmVar.bottomMargin;
                    i6 = measuredWidth - this.f1256q;
                } else {
                    i6 = i5;
                }
                if (a2) {
                    dmVar = (dm) this.f1243d.getLayoutParams();
                    measuredWidth = dmVar.topMargin + paddingTop2;
                    measuredHeight = this.f1243d.getMeasuredHeight() + measuredWidth;
                    this.f1243d.layout(i5 - this.f1243d.getMeasuredWidth(), measuredWidth, i5, measuredHeight);
                    i8 = dmVar.bottomMargin + measuredHeight;
                    i8 = i5 - this.f1256q;
                } else {
                    i8 = i5;
                }
                i6 = obj2 != null ? Math.min(i6, i8) : i5;
            } else {
                i8 = (obj2 != null ? this.f1255p : 0) - iArr[0];
                i7 += Math.max(0, i8);
                iArr[0] = Math.max(0, -i8);
                if (a) {
                    dmVar = (dm) this.f1242c.getLayoutParams();
                    i5 = this.f1242c.getMeasuredWidth() + i7;
                    measuredWidth = this.f1242c.getMeasuredHeight() + paddingTop2;
                    this.f1242c.layout(i7, paddingTop2, i5, measuredWidth);
                    i8 = dmVar.bottomMargin + measuredWidth;
                    measuredWidth = i5 + this.f1256q;
                    i5 = i8;
                } else {
                    measuredWidth = i7;
                    i5 = paddingTop2;
                }
                if (a2) {
                    dmVar = (dm) this.f1243d.getLayoutParams();
                    i5 += dmVar.topMargin;
                    paddingTop2 = this.f1243d.getMeasuredWidth() + i7;
                    measuredHeight = this.f1243d.getMeasuredHeight() + i5;
                    this.f1243d.layout(i7, i5, paddingTop2, measuredHeight);
                    i8 = dmVar.bottomMargin + measuredHeight;
                    i8 = this.f1256q + paddingTop2;
                } else {
                    i8 = i7;
                }
                if (obj2 != null) {
                    i7 = Math.max(measuredWidth, i8);
                }
            }
        }
        m2422a(this.f1227B, 3);
        int size = this.f1227B.size();
        i5 = i7;
        for (measuredWidth = 0; measuredWidth < size; measuredWidth++) {
            i5 = m2417a((View) this.f1227B.get(measuredWidth), i5, iArr, h);
        }
        m2422a(this.f1227B, 5);
        i7 = this.f1227B.size();
        for (measuredWidth = 0; measuredWidth < i7; measuredWidth++) {
            i6 = m2426b((View) this.f1227B.get(measuredWidth), i6, iArr, h);
        }
        m2422a(this.f1227B, 1);
        measuredWidth = m2418a(this.f1227B, iArr);
        i8 = ((((width - paddingLeft) - paddingRight) / 2) + paddingLeft) - (measuredWidth / 2);
        measuredWidth += i8;
        if (i8 < i5) {
            i8 = i5;
        } else if (measuredWidth > i6) {
            i8 -= measuredWidth - i6;
        }
        paddingLeft = this.f1227B.size();
        measuredWidth = i8;
        for (i5 = 0; i5 < paddingLeft; i5++) {
            measuredWidth = m2417a((View) this.f1227B.get(i5), measuredWidth, iArr, h);
        }
        this.f1227B.clear();
    }

    protected void onMeasure(int i, int i2) {
        int i3;
        int i4;
        int max;
        int i5 = 0;
        int i6 = 0;
        int[] iArr = this.f1229D;
        if (du.m2794a(this)) {
            i3 = 0;
            i4 = 1;
        } else {
            i3 = 1;
            i4 = 0;
        }
        int i7 = 0;
        if (m2423a(this.f1244e)) {
            m2420a(this.f1244e, i, 0, i2, 0, this.f1254o);
            i7 = this.f1244e.getMeasuredWidth() + m2425b(this.f1244e);
            max = Math.max(0, this.f1244e.getMeasuredHeight() + m2428c(this.f1244e));
            i6 = du.m2792a(0, bu.m997f(this.f1244e));
            i5 = max;
        }
        if (m2423a(this.f1248i)) {
            m2420a(this.f1248i, i, 0, i2, 0, this.f1254o);
            i7 = this.f1248i.getMeasuredWidth() + m2425b(this.f1248i);
            i5 = Math.max(i5, this.f1248i.getMeasuredHeight() + m2428c(this.f1248i));
            i6 = du.m2792a(i6, bu.m997f(this.f1248i));
        }
        int contentInsetStart = getContentInsetStart();
        int max2 = 0 + Math.max(contentInsetStart, i7);
        iArr[i4] = Math.max(0, contentInsetStart - i7);
        i7 = 0;
        if (m2423a(this.f1241b)) {
            m2420a(this.f1241b, i, max2, i2, 0, this.f1254o);
            i7 = this.f1241b.getMeasuredWidth() + m2425b(this.f1241b);
            i5 = Math.max(i5, this.f1241b.getMeasuredHeight() + m2428c(this.f1241b));
            i6 = du.m2792a(i6, bu.m997f(this.f1241b));
        }
        contentInsetStart = getContentInsetEnd();
        max2 += Math.max(contentInsetStart, i7);
        iArr[i3] = Math.max(0, contentInsetStart - i7);
        if (m2423a(this.f1240a)) {
            max2 += m2416a(this.f1240a, i, max2, i2, 0, iArr);
            i5 = Math.max(i5, this.f1240a.getMeasuredHeight() + m2428c(this.f1240a));
            i6 = du.m2792a(i6, bu.m997f(this.f1240a));
        }
        if (m2423a(this.f1245f)) {
            max2 += m2416a(this.f1245f, i, max2, i2, 0, iArr);
            i5 = Math.max(i5, this.f1245f.getMeasuredHeight() + m2428c(this.f1245f));
            i6 = du.m2792a(i6, bu.m997f(this.f1245f));
        }
        i4 = getChildCount();
        i3 = 0;
        int i8 = i5;
        i5 = i6;
        while (i3 < i4) {
            View childAt = getChildAt(i3);
            if (((dm) childAt.getLayoutParams()).f1529b != 0) {
                i7 = i5;
                contentInsetStart = i8;
            } else if (m2423a(childAt)) {
                max2 += m2416a(childAt, i, max2, i2, 0, iArr);
                max = Math.max(i8, childAt.getMeasuredHeight() + m2428c(childAt));
                i7 = du.m2792a(i5, bu.m997f(childAt));
                contentInsetStart = max;
            } else {
                i7 = i5;
                contentInsetStart = i8;
            }
            i3++;
            i5 = i7;
            i8 = contentInsetStart;
        }
        contentInsetStart = 0;
        i7 = 0;
        i6 = this.f1257r + this.f1258s;
        max = this.f1255p + this.f1256q;
        if (m2423a(this.f1242c)) {
            m2416a(this.f1242c, i, max2 + max, i2, i6, iArr);
            contentInsetStart = m2425b(this.f1242c) + this.f1242c.getMeasuredWidth();
            i7 = this.f1242c.getMeasuredHeight() + m2428c(this.f1242c);
            i5 = du.m2792a(i5, bu.m997f(this.f1242c));
        }
        if (m2423a(this.f1243d)) {
            contentInsetStart = Math.max(contentInsetStart, m2416a(this.f1243d, i, max2 + max, i2, i6 + i7, iArr));
            i7 += this.f1243d.getMeasuredHeight() + m2428c(this.f1243d);
            i5 = du.m2792a(i5, bu.m997f(this.f1243d));
        }
        contentInsetStart += max2;
        i7 = Math.max(i8, i7) + (getPaddingTop() + getPaddingBottom());
        contentInsetStart = bu.m976a(Math.max(contentInsetStart + (getPaddingLeft() + getPaddingRight()), getSuggestedMinimumWidth()), i, -16777216 & i5);
        i7 = bu.m976a(Math.max(i7, getSuggestedMinimumHeight()), i2, i5 << 16);
        if (m2438r()) {
            i7 = 0;
        }
        setMeasuredDimension(contentInsetStart, i7);
    }

    protected void onRestoreInstanceState(Parcelable parcelable) {
        if (parcelable instanceof C0288do) {
            C0288do c0288do = (C0288do) parcelable;
            super.onRestoreInstanceState(c0288do.getSuperState());
            Menu d = this.f1241b != null ? this.f1241b.m2367d() : null;
            if (!(c0288do.f1530a == 0 || this.f1234I == null || d == null)) {
                MenuItem findItem = d.findItem(c0288do.f1530a);
                if (findItem != null) {
                    ar.m865b(findItem);
                }
            }
            if (c0288do.f1531b) {
                m2437q();
                return;
            }
            return;
        }
        super.onRestoreInstanceState(parcelable);
    }

    public void onRtlPropertiesChanged(int i) {
        boolean z = true;
        if (VERSION.SDK_INT >= 17) {
            super.onRtlPropertiesChanged(i);
        }
        co coVar = this.f1259t;
        if (i != 1) {
            z = false;
        }
        coVar.m2654a(z);
    }

    protected Parcelable onSaveInstanceState() {
        Parcelable c0288do = new C0288do(super.onSaveInstanceState());
        if (!(this.f1234I == null || this.f1234I.f1527b == null)) {
            c0288do.f1530a = this.f1234I.f1527b.getItemId();
        }
        c0288do.f1531b = m2447b();
        return c0288do;
    }

    public boolean onTouchEvent(MotionEvent motionEvent) {
        int a = az.m895a(motionEvent);
        if (a == 0) {
            this.f1265z = false;
        }
        if (!this.f1265z) {
            boolean onTouchEvent = super.onTouchEvent(motionEvent);
            if (a == 0 && !onTouchEvent) {
                this.f1265z = true;
            }
        }
        if (a == 1 || a == 3) {
            this.f1265z = false;
        }
        return true;
    }

    public void setCollapsible(boolean z) {
        this.f1237L = z;
        requestLayout();
    }

    public void setLogo(int i) {
        setLogo(this.f1239N.m2520a(getContext(), i));
    }

    public void setLogo(Drawable drawable) {
        if (drawable != null) {
            m2432l();
            if (!m2431d(this.f1245f)) {
                m2421a(this.f1245f, true);
            }
        } else if (this.f1245f != null && m2431d(this.f1245f)) {
            removeView(this.f1245f);
            this.f1228C.remove(this.f1245f);
        }
        if (this.f1245f != null) {
            this.f1245f.setImageDrawable(drawable);
        }
    }

    public void setLogoDescription(int i) {
        setLogoDescription(getContext().getText(i));
    }

    public void setLogoDescription(CharSequence charSequence) {
        if (!TextUtils.isEmpty(charSequence)) {
            m2432l();
        }
        if (this.f1245f != null) {
            this.f1245f.setContentDescription(charSequence);
        }
    }

    public void setNavigationContentDescription(int i) {
        setNavigationContentDescription(i != 0 ? getContext().getText(i) : null);
    }

    public void setNavigationContentDescription(CharSequence charSequence) {
        if (!TextUtils.isEmpty(charSequence)) {
            m2435o();
        }
        if (this.f1244e != null) {
            this.f1244e.setContentDescription(charSequence);
        }
    }

    public void setNavigationIcon(int i) {
        setNavigationIcon(this.f1239N.m2520a(getContext(), i));
    }

    public void setNavigationIcon(Drawable drawable) {
        if (drawable != null) {
            m2435o();
            if (!m2431d(this.f1244e)) {
                m2421a(this.f1244e, true);
            }
        } else if (this.f1244e != null && m2431d(this.f1244e)) {
            removeView(this.f1244e);
            this.f1228C.remove(this.f1244e);
        }
        if (this.f1244e != null) {
            this.f1244e.setImageDrawable(drawable);
        }
    }

    public void setNavigationOnClickListener(OnClickListener onClickListener) {
        m2435o();
        this.f1244e.setOnClickListener(onClickListener);
    }

    public void setOnMenuItemClickListener(dn dnVar) {
        this.f1230E = dnVar;
    }

    public void setOverflowIcon(Drawable drawable) {
        m2433m();
        this.f1241b.setOverflowIcon(drawable);
    }

    public void setPopupTheme(int i) {
        if (this.f1250k != i) {
            this.f1250k = i;
            if (i == 0) {
                this.f1249j = getContext();
            } else {
                this.f1249j = new ContextThemeWrapper(getContext(), i);
            }
        }
    }

    public void setSubtitle(int i) {
        setSubtitle(getContext().getText(i));
    }

    public void setSubtitle(CharSequence charSequence) {
        if (!TextUtils.isEmpty(charSequence)) {
            if (this.f1243d == null) {
                Context context = getContext();
                this.f1243d = new TextView(context);
                this.f1243d.setSingleLine();
                this.f1243d.setEllipsize(TruncateAt.END);
                if (this.f1252m != 0) {
                    this.f1243d.setTextAppearance(context, this.f1252m);
                }
                if (this.f1264y != 0) {
                    this.f1243d.setTextColor(this.f1264y);
                }
            }
            if (!m2431d(this.f1243d)) {
                m2421a(this.f1243d, true);
            }
        } else if (this.f1243d != null && m2431d(this.f1243d)) {
            removeView(this.f1243d);
            this.f1228C.remove(this.f1243d);
        }
        if (this.f1243d != null) {
            this.f1243d.setText(charSequence);
        }
        this.f1262w = charSequence;
    }

    public void setSubtitleTextColor(int i) {
        this.f1264y = i;
        if (this.f1243d != null) {
            this.f1243d.setTextColor(i);
        }
    }

    public void setTitle(int i) {
        setTitle(getContext().getText(i));
    }

    public void setTitle(CharSequence charSequence) {
        if (!TextUtils.isEmpty(charSequence)) {
            if (this.f1242c == null) {
                Context context = getContext();
                this.f1242c = new TextView(context);
                this.f1242c.setSingleLine();
                this.f1242c.setEllipsize(TruncateAt.END);
                if (this.f1251l != 0) {
                    this.f1242c.setTextAppearance(context, this.f1251l);
                }
                if (this.f1263x != 0) {
                    this.f1242c.setTextColor(this.f1263x);
                }
            }
            if (!m2431d(this.f1242c)) {
                m2421a(this.f1242c, true);
            }
        } else if (this.f1242c != null && m2431d(this.f1242c)) {
            removeView(this.f1242c);
            this.f1228C.remove(this.f1242c);
        }
        if (this.f1242c != null) {
            this.f1242c.setText(charSequence);
        }
        this.f1261v = charSequence;
    }

    public void setTitleTextColor(int i) {
        this.f1263x = i;
        if (this.f1242c != null) {
            this.f1242c.setTextColor(i);
        }
    }
}

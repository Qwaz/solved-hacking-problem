package android.support.v7.widget;

import android.content.Context;
import android.content.res.Configuration;
import android.content.res.TypedArray;
import android.graphics.Canvas;
import android.graphics.Rect;
import android.graphics.drawable.Drawable;
import android.os.Build.VERSION;
import android.support.v4.p004h.bk;
import android.support.v4.p004h.bl;
import android.support.v4.p004h.bu;
import android.support.v4.p004h.dh;
import android.support.v4.p004h.dy;
import android.support.v4.widget.at;
import android.support.v7.p015b.C0233b;
import android.support.v7.p015b.C0238g;
import android.support.v7.p015b.C0243l;
import android.support.v7.view.menu.C0207y;
import android.util.AttributeSet;
import android.view.Menu;
import android.view.View;
import android.view.ViewGroup;
import android.view.ViewGroup.LayoutParams;
import android.view.Window.Callback;

public class ActionBarOverlayLayout extends ViewGroup implements bk, br {
    static final int[] f1105a;
    private final Runnable f1106A;
    private final bl f1107B;
    private int f1108b;
    private int f1109c;
    private ContentFrameLayout f1110d;
    private ActionBarContainer f1111e;
    private bs f1112f;
    private Drawable f1113g;
    private boolean f1114h;
    private boolean f1115i;
    private boolean f1116j;
    private boolean f1117k;
    private boolean f1118l;
    private int f1119m;
    private int f1120n;
    private final Rect f1121o;
    private final Rect f1122p;
    private final Rect f1123q;
    private final Rect f1124r;
    private final Rect f1125s;
    private final Rect f1126t;
    private C0211i f1127u;
    private final int f1128v;
    private at f1129w;
    private dh f1130x;
    private final dy f1131y;
    private final Runnable f1132z;

    static {
        f1105a = new int[]{C0233b.actionBarSize, 16842841};
    }

    public ActionBarOverlayLayout(Context context) {
        this(context, null);
    }

    public ActionBarOverlayLayout(Context context, AttributeSet attributeSet) {
        super(context, attributeSet);
        this.f1109c = 0;
        this.f1121o = new Rect();
        this.f1122p = new Rect();
        this.f1123q = new Rect();
        this.f1124r = new Rect();
        this.f1125s = new Rect();
        this.f1126t = new Rect();
        this.f1128v = 600;
        this.f1131y = new C0290f(this);
        this.f1132z = new C0291g(this);
        this.f1106A = new C0292h(this);
        m2306a(context);
        this.f1107B = new bl(this);
    }

    private bs m2305a(View view) {
        if (view instanceof bs) {
            return (bs) view;
        }
        if (view instanceof Toolbar) {
            return ((Toolbar) view).getWrapper();
        }
        throw new IllegalStateException("Can't make a decor toolbar out of " + view.getClass().getSimpleName());
    }

    private void m2306a(Context context) {
        boolean z = true;
        TypedArray obtainStyledAttributes = getContext().getTheme().obtainStyledAttributes(f1105a);
        this.f1108b = obtainStyledAttributes.getDimensionPixelSize(0, 0);
        this.f1113g = obtainStyledAttributes.getDrawable(1);
        setWillNotDraw(this.f1113g == null);
        obtainStyledAttributes.recycle();
        if (context.getApplicationInfo().targetSdkVersion >= 19) {
            z = false;
        }
        this.f1114h = z;
        this.f1129w = at.m1467a(context);
    }

    private boolean m2308a(float f, float f2) {
        this.f1129w.m1470a(0, 0, 0, (int) f2, 0, 0, Integer.MIN_VALUE, Integer.MAX_VALUE);
        return this.f1129w.m1476d() > this.f1111e.getHeight();
    }

    private boolean m2310a(View view, Rect rect, boolean z, boolean z2, boolean z3, boolean z4) {
        boolean z5 = false;
        C0293j c0293j = (C0293j) view.getLayoutParams();
        if (z && c0293j.leftMargin != rect.left) {
            c0293j.leftMargin = rect.left;
            z5 = true;
        }
        if (z2 && c0293j.topMargin != rect.top) {
            c0293j.topMargin = rect.top;
            z5 = true;
        }
        if (z4 && c0293j.rightMargin != rect.right) {
            c0293j.rightMargin = rect.right;
            z5 = true;
        }
        if (!z3 || c0293j.bottomMargin == rect.bottom) {
            return z5;
        }
        c0293j.bottomMargin = rect.bottom;
        return true;
    }

    private void m2313k() {
        removeCallbacks(this.f1132z);
        removeCallbacks(this.f1106A);
        if (this.f1130x != null) {
            this.f1130x.m1232b();
        }
    }

    private void m2314l() {
        m2313k();
        postDelayed(this.f1132z, 600);
    }

    private void m2315m() {
        m2313k();
        postDelayed(this.f1106A, 600);
    }

    private void m2316n() {
        m2313k();
        this.f1132z.run();
    }

    private void m2317o() {
        m2313k();
        this.f1106A.run();
    }

    public C0293j m2318a(AttributeSet attributeSet) {
        return new C0293j(getContext(), attributeSet);
    }

    public void m2319a(int i) {
        m2323c();
        switch (i) {
            case C0243l.View_paddingStart /*2*/:
                this.f1112f.m2619f();
            case C0243l.Toolbar_contentInsetStart /*5*/:
                this.f1112f.m2620g();
            case C0243l.AppCompatTheme_seekBarStyle /*109*/:
                setOverlayMode(true);
            default:
        }
    }

    public void m2320a(Menu menu, C0207y c0207y) {
        m2323c();
        this.f1112f.m2608a(menu, c0207y);
    }

    public boolean m2321a() {
        return this.f1115i;
    }

    protected C0293j m2322b() {
        return new C0293j(-1, -1);
    }

    void m2323c() {
        if (this.f1110d == null) {
            this.f1110d = (ContentFrameLayout) findViewById(C0238g.action_bar_activity_content);
            this.f1111e = (ActionBarContainer) findViewById(C0238g.action_bar_container);
            this.f1112f = m2305a(findViewById(C0238g.action_bar));
        }
    }

    protected boolean checkLayoutParams(LayoutParams layoutParams) {
        return layoutParams instanceof C0293j;
    }

    public boolean m2324d() {
        m2323c();
        return this.f1112f.m2621h();
    }

    public void draw(Canvas canvas) {
        super.draw(canvas);
        if (this.f1113g != null && !this.f1114h) {
            int bottom = this.f1111e.getVisibility() == 0 ? (int) ((((float) this.f1111e.getBottom()) + bu.m998g(this.f1111e)) + 0.5f) : 0;
            this.f1113g.setBounds(0, bottom, getWidth(), this.f1113g.getIntrinsicHeight() + bottom);
            this.f1113g.draw(canvas);
        }
    }

    public boolean m2325e() {
        m2323c();
        return this.f1112f.m2622i();
    }

    public boolean m2326f() {
        m2323c();
        return this.f1112f.m2623j();
    }

    protected boolean fitSystemWindows(Rect rect) {
        boolean a;
        m2323c();
        if ((bu.m1001j(this) & 256) != 0) {
            a = m2310a(this.f1111e, rect, true, true, false, true);
            this.f1124r.set(rect);
            du.m2793a(this, this.f1124r, this.f1121o);
        } else {
            a = m2310a(this.f1111e, rect, true, true, false, true);
            this.f1124r.set(rect);
            du.m2793a(this, this.f1124r, this.f1121o);
        }
        if (!this.f1122p.equals(this.f1121o)) {
            this.f1122p.set(this.f1121o);
            a = true;
        }
        if (a) {
            requestLayout();
        }
        return true;
    }

    public boolean m2327g() {
        m2323c();
        return this.f1112f.m2624k();
    }

    protected /* synthetic */ LayoutParams generateDefaultLayoutParams() {
        return m2322b();
    }

    public /* synthetic */ LayoutParams generateLayoutParams(AttributeSet attributeSet) {
        return m2318a(attributeSet);
    }

    protected LayoutParams generateLayoutParams(LayoutParams layoutParams) {
        return new C0293j(layoutParams);
    }

    public int getActionBarHideOffset() {
        return this.f1111e != null ? -((int) bu.m998g(this.f1111e)) : 0;
    }

    public int getNestedScrollAxes() {
        return this.f1107B.m967a();
    }

    public CharSequence getTitle() {
        m2323c();
        return this.f1112f.m2618e();
    }

    public boolean m2328h() {
        m2323c();
        return this.f1112f.m2625l();
    }

    public void m2329i() {
        m2323c();
        this.f1112f.m2626m();
    }

    public void m2330j() {
        m2323c();
        this.f1112f.m2627n();
    }

    protected void onConfigurationChanged(Configuration configuration) {
        if (VERSION.SDK_INT >= 8) {
            super.onConfigurationChanged(configuration);
        }
        m2306a(getContext());
        bu.m1002k(this);
    }

    protected void onDetachedFromWindow() {
        super.onDetachedFromWindow();
        m2313k();
    }

    protected void onLayout(boolean z, int i, int i2, int i3, int i4) {
        int childCount = getChildCount();
        int paddingLeft = getPaddingLeft();
        int paddingRight = (i3 - i) - getPaddingRight();
        int paddingTop = getPaddingTop();
        paddingRight = (i4 - i2) - getPaddingBottom();
        for (int i5 = 0; i5 < childCount; i5++) {
            View childAt = getChildAt(i5);
            if (childAt.getVisibility() != 8) {
                C0293j c0293j = (C0293j) childAt.getLayoutParams();
                int i6 = c0293j.leftMargin + paddingLeft;
                paddingRight = c0293j.topMargin + paddingTop;
                childAt.layout(i6, paddingRight, childAt.getMeasuredWidth() + i6, childAt.getMeasuredHeight() + paddingRight);
            }
        }
    }

    protected void onMeasure(int i, int i2) {
        int i3;
        m2323c();
        measureChildWithMargins(this.f1111e, i, 0, i2, 0);
        C0293j c0293j = (C0293j) this.f1111e.getLayoutParams();
        int max = Math.max(0, (this.f1111e.getMeasuredWidth() + c0293j.leftMargin) + c0293j.rightMargin);
        int max2 = Math.max(0, c0293j.bottomMargin + (this.f1111e.getMeasuredHeight() + c0293j.topMargin));
        int a = du.m2792a(0, bu.m997f(this.f1111e));
        Object obj = (bu.m1001j(this) & 256) != 0 ? 1 : null;
        if (obj != null) {
            i3 = this.f1108b;
            if (this.f1116j && this.f1111e.getTabContainer() != null) {
                i3 += this.f1108b;
            }
        } else {
            i3 = this.f1111e.getVisibility() != 8 ? this.f1111e.getMeasuredHeight() : 0;
        }
        this.f1123q.set(this.f1121o);
        this.f1125s.set(this.f1124r);
        Rect rect;
        Rect rect2;
        if (this.f1115i || obj != null) {
            rect = this.f1125s;
            rect.top = i3 + rect.top;
            rect2 = this.f1125s;
            rect2.bottom += 0;
        } else {
            rect = this.f1123q;
            rect.top = i3 + rect.top;
            rect2 = this.f1123q;
            rect2.bottom += 0;
        }
        m2310a(this.f1110d, this.f1123q, true, true, true, true);
        if (!this.f1126t.equals(this.f1125s)) {
            this.f1126t.set(this.f1125s);
            this.f1110d.m1768a(this.f1125s);
        }
        measureChildWithMargins(this.f1110d, i, 0, i2, 0);
        c0293j = (C0293j) this.f1110d.getLayoutParams();
        int max3 = Math.max(max, (this.f1110d.getMeasuredWidth() + c0293j.leftMargin) + c0293j.rightMargin);
        i3 = Math.max(max2, c0293j.bottomMargin + (this.f1110d.getMeasuredHeight() + c0293j.topMargin));
        int a2 = du.m2792a(a, bu.m997f(this.f1110d));
        setMeasuredDimension(bu.m976a(Math.max(max3 + (getPaddingLeft() + getPaddingRight()), getSuggestedMinimumWidth()), i, a2), bu.m976a(Math.max(i3 + (getPaddingTop() + getPaddingBottom()), getSuggestedMinimumHeight()), i2, a2 << 16));
    }

    public boolean onNestedFling(View view, float f, float f2, boolean z) {
        if (!this.f1117k || !z) {
            return false;
        }
        if (m2308a(f, f2)) {
            m2317o();
        } else {
            m2316n();
        }
        this.f1118l = true;
        return true;
    }

    public boolean onNestedPreFling(View view, float f, float f2) {
        return false;
    }

    public void onNestedPreScroll(View view, int i, int i2, int[] iArr) {
    }

    public void onNestedScroll(View view, int i, int i2, int i3, int i4) {
        this.f1119m += i2;
        setActionBarHideOffset(this.f1119m);
    }

    public void onNestedScrollAccepted(View view, View view2, int i) {
        this.f1107B.m969a(view, view2, i);
        this.f1119m = getActionBarHideOffset();
        m2313k();
        if (this.f1127u != null) {
            this.f1127u.m1825n();
        }
    }

    public boolean onStartNestedScroll(View view, View view2, int i) {
        return ((i & 2) == 0 || this.f1111e.getVisibility() != 0) ? false : this.f1117k;
    }

    public void onStopNestedScroll(View view) {
        if (this.f1117k && !this.f1118l) {
            if (this.f1119m <= this.f1111e.getHeight()) {
                m2314l();
            } else {
                m2315m();
            }
        }
        if (this.f1127u != null) {
            this.f1127u.m1826o();
        }
    }

    public void onWindowSystemUiVisibilityChanged(int i) {
        boolean z = true;
        if (VERSION.SDK_INT >= 16) {
            super.onWindowSystemUiVisibilityChanged(i);
        }
        m2323c();
        int i2 = this.f1120n ^ i;
        this.f1120n = i;
        boolean z2 = (i & 4) == 0;
        boolean z3 = (i & 256) != 0;
        if (this.f1127u != null) {
            C0211i c0211i = this.f1127u;
            if (z3) {
                z = false;
            }
            c0211i.m1822g(z);
            if (z2 || !z3) {
                this.f1127u.m1823l();
            } else {
                this.f1127u.m1824m();
            }
        }
        if ((i2 & 256) != 0 && this.f1127u != null) {
            bu.m1002k(this);
        }
    }

    protected void onWindowVisibilityChanged(int i) {
        super.onWindowVisibilityChanged(i);
        this.f1109c = i;
        if (this.f1127u != null) {
            this.f1127u.m1821a(i);
        }
    }

    public void setActionBarHideOffset(int i) {
        m2313k();
        bu.m979a(this.f1111e, (float) (-Math.max(0, Math.min(i, this.f1111e.getHeight()))));
    }

    public void setActionBarVisibilityCallback(C0211i c0211i) {
        this.f1127u = c0211i;
        if (getWindowToken() != null) {
            this.f1127u.m1821a(this.f1109c);
            if (this.f1120n != 0) {
                onWindowSystemUiVisibilityChanged(this.f1120n);
                bu.m1002k(this);
            }
        }
    }

    public void setHasNonEmbeddedTabs(boolean z) {
        this.f1116j = z;
    }

    public void setHideOnContentScrollEnabled(boolean z) {
        if (z != this.f1117k) {
            this.f1117k = z;
            if (!z) {
                m2313k();
                setActionBarHideOffset(0);
            }
        }
    }

    public void setIcon(int i) {
        m2323c();
        this.f1112f.m2604a(i);
    }

    public void setIcon(Drawable drawable) {
        m2323c();
        this.f1112f.m2605a(drawable);
    }

    public void setLogo(int i) {
        m2323c();
        this.f1112f.m2613b(i);
    }

    public void setOverlayMode(boolean z) {
        this.f1115i = z;
        boolean z2 = z && getContext().getApplicationInfo().targetSdkVersion < 19;
        this.f1114h = z2;
    }

    public void setShowingForActionMode(boolean z) {
    }

    public void setUiOptions(int i) {
    }

    public void setWindowCallback(Callback callback) {
        m2323c();
        this.f1112f.m2609a(callback);
    }

    public void setWindowTitle(CharSequence charSequence) {
        m2323c();
        this.f1112f.m2610a(charSequence);
    }

    public boolean shouldDelayChildPressedState() {
        return false;
    }
}

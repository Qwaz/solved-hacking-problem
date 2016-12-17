package android.support.v7.widget;

import android.content.Context;
import android.content.res.Configuration;
import android.graphics.drawable.Drawable;
import android.os.Build.VERSION;
import android.support.v7.view.menu.ActionMenuItemView;
import android.support.v7.view.menu.C0203j;
import android.support.v7.view.menu.C0207y;
import android.support.v7.view.menu.C0259k;
import android.support.v7.view.menu.C0260z;
import android.support.v7.view.menu.C0264i;
import android.support.v7.view.menu.C0272m;
import android.util.AttributeSet;
import android.view.ContextThemeWrapper;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.view.View.MeasureSpec;
import android.view.ViewGroup.LayoutParams;
import android.view.accessibility.AccessibilityEvent;

public class ActionMenuView extends bw implements C0259k, C0260z {
    private C0264i f1148a;
    private Context f1149b;
    private int f1150c;
    private boolean f1151d;
    private C0294k f1152e;
    private C0207y f1153f;
    private C0203j f1154g;
    private boolean f1155h;
    private int f1156i;
    private int f1157j;
    private int f1158k;
    private C0287y f1159l;

    public ActionMenuView(Context context) {
        this(context, null);
    }

    public ActionMenuView(Context context, AttributeSet attributeSet) {
        super(context, attributeSet);
        setBaselineAligned(false);
        float f = context.getResources().getDisplayMetrics().density;
        this.f1157j = (int) (56.0f * f);
        this.f1158k = (int) (f * 4.0f);
        this.f1149b = context;
        this.f1150c = 0;
    }

    static int m2352a(View view, int i, int i2, int i3, int i4) {
        int i5;
        boolean z = false;
        C0305w c0305w = (C0305w) view.getLayoutParams();
        int makeMeasureSpec = MeasureSpec.makeMeasureSpec(MeasureSpec.getSize(i3) - i4, MeasureSpec.getMode(i3));
        ActionMenuItemView actionMenuItemView = view instanceof ActionMenuItemView ? (ActionMenuItemView) view : null;
        boolean z2 = actionMenuItemView != null && actionMenuItemView.m2065b();
        if (i2 <= 0 || (z2 && i2 < 2)) {
            i5 = 0;
        } else {
            view.measure(MeasureSpec.makeMeasureSpec(i * i2, Integer.MIN_VALUE), makeMeasureSpec);
            int measuredWidth = view.getMeasuredWidth();
            i5 = measuredWidth / i;
            if (measuredWidth % i != 0) {
                i5++;
            }
            if (z2 && r1 < 2) {
                i5 = 2;
            }
        }
        if (!c0305w.f1594a && z2) {
            z = true;
        }
        c0305w.f1597d = z;
        c0305w.f1595b = i5;
        view.measure(MeasureSpec.makeMeasureSpec(i5 * i, 1073741824), makeMeasureSpec);
        return i5;
    }

    private void m2355c(int i, int i2) {
        int mode = MeasureSpec.getMode(i2);
        int size = MeasureSpec.getSize(i);
        int size2 = MeasureSpec.getSize(i2);
        int paddingLeft = getPaddingLeft() + getPaddingRight();
        int paddingTop = getPaddingTop() + getPaddingBottom();
        int childMeasureSpec = getChildMeasureSpec(i2, paddingTop, -2);
        int i3 = size - paddingLeft;
        int i4 = i3 / this.f1157j;
        size = i3 % this.f1157j;
        if (i4 == 0) {
            setMeasuredDimension(i3, 0);
            return;
        }
        Object obj;
        int i5 = this.f1157j + (size / i4);
        int i6 = 0;
        int i7 = 0;
        int i8 = 0;
        paddingLeft = 0;
        Object obj2 = null;
        long j = 0;
        int childCount = getChildCount();
        int i9 = 0;
        while (i9 < childCount) {
            int i10;
            long j2;
            int i11;
            int i12;
            int i13;
            View childAt = getChildAt(i9);
            if (childAt.getVisibility() == 8) {
                i10 = paddingLeft;
                j2 = j;
                i11 = i6;
                i12 = i4;
                i4 = i7;
            } else {
                boolean z = childAt instanceof ActionMenuItemView;
                i13 = paddingLeft + 1;
                if (z) {
                    childAt.setPadding(this.f1158k, 0, this.f1158k, 0);
                }
                C0305w c0305w = (C0305w) childAt.getLayoutParams();
                c0305w.f1599f = false;
                c0305w.f1596c = 0;
                c0305w.f1595b = 0;
                c0305w.f1597d = false;
                c0305w.leftMargin = 0;
                c0305w.rightMargin = 0;
                boolean z2 = z && ((ActionMenuItemView) childAt).m2065b();
                c0305w.f1598e = z2;
                int a = m2352a(childAt, i5, c0305w.f1594a ? 1 : i4, childMeasureSpec, paddingTop);
                i7 = Math.max(i7, a);
                paddingLeft = c0305w.f1597d ? i8 + 1 : i8;
                obj = c0305w.f1594a ? 1 : obj2;
                int i14 = i4 - a;
                i8 = Math.max(i6, childAt.getMeasuredHeight());
                if (a == 1) {
                    long j3 = ((long) (1 << i9)) | j;
                    i11 = i8;
                    i12 = i14;
                    i8 = paddingLeft;
                    obj2 = obj;
                    j2 = j3;
                    i4 = i7;
                    i10 = i13;
                } else {
                    i10 = i13;
                    i4 = i7;
                    long j4 = j;
                    i11 = i8;
                    i12 = i14;
                    obj2 = obj;
                    i8 = paddingLeft;
                    j2 = j4;
                }
            }
            i9++;
            i7 = i4;
            i6 = i11;
            i4 = i12;
            j = j2;
            paddingLeft = i10;
        }
        Object obj3 = (obj2 == null || paddingLeft != 2) ? null : 1;
        Object obj4 = null;
        long j5 = j;
        paddingTop = i4;
        while (i8 > 0 && paddingTop > 0) {
            i13 = Integer.MAX_VALUE;
            j = 0;
            i4 = 0;
            int i15 = 0;
            while (i15 < childCount) {
                c0305w = (C0305w) getChildAt(i15).getLayoutParams();
                if (c0305w.f1597d) {
                    int i16 = c0305w.f1595b;
                    if (r0 < i13) {
                        i4 = c0305w.f1595b;
                        j = (long) (1 << i15);
                        size = 1;
                    } else if (c0305w.f1595b == i13) {
                        j |= (long) (1 << i15);
                        size = i4 + 1;
                        i4 = i13;
                    } else {
                        size = i4;
                        i4 = i13;
                    }
                } else {
                    size = i4;
                    i4 = i13;
                }
                i15++;
                i13 = i4;
                i4 = size;
            }
            j5 |= j;
            if (i4 > paddingTop) {
                j = j5;
                break;
            }
            i15 = i13 + 1;
            i13 = 0;
            i4 = paddingTop;
            long j6 = j5;
            while (i13 < childCount) {
                View childAt2 = getChildAt(i13);
                c0305w = (C0305w) childAt2.getLayoutParams();
                if ((((long) (1 << i13)) & j) != 0) {
                    if (obj3 != null && c0305w.f1598e && i4 == 1) {
                        childAt2.setPadding(this.f1158k + i5, 0, this.f1158k, 0);
                    }
                    c0305w.f1595b++;
                    c0305w.f1599f = true;
                    size = i4 - 1;
                } else if (c0305w.f1595b == i15) {
                    j6 |= (long) (1 << i13);
                    size = i4;
                } else {
                    size = i4;
                }
                i13++;
                i4 = size;
            }
            j5 = j6;
            i9 = 1;
            paddingTop = i4;
        }
        j = j5;
        obj = (obj2 == null && paddingLeft == 1) ? 1 : null;
        if (paddingTop <= 0 || j == 0 || (paddingTop >= paddingLeft - 1 && obj == null && i7 <= 1)) {
            obj3 = obj4;
        } else {
            float f;
            View childAt3;
            float bitCount = (float) Long.bitCount(j);
            if (obj == null) {
                if (!((1 & j) == 0 || ((C0305w) getChildAt(0).getLayoutParams()).f1598e)) {
                    bitCount -= 0.5f;
                }
                if (!((((long) (1 << (childCount - 1))) & j) == 0 || ((C0305w) getChildAt(childCount - 1).getLayoutParams()).f1598e)) {
                    f = bitCount - 0.5f;
                    paddingLeft = f <= 0.0f ? (int) (((float) (paddingTop * i5)) / f) : 0;
                    i4 = 0;
                    obj3 = obj4;
                    while (i4 < childCount) {
                        if ((((long) (1 << i4)) & j) != 0) {
                            obj = obj3;
                        } else {
                            childAt3 = getChildAt(i4);
                            c0305w = (C0305w) childAt3.getLayoutParams();
                            if (childAt3 instanceof ActionMenuItemView) {
                                c0305w.f1596c = paddingLeft;
                                c0305w.f1599f = true;
                                if (i4 == 0 && !c0305w.f1598e) {
                                    c0305w.leftMargin = (-paddingLeft) / 2;
                                }
                                obj = 1;
                            } else if (c0305w.f1594a) {
                                if (i4 != 0) {
                                    c0305w.leftMargin = paddingLeft / 2;
                                }
                                if (i4 != childCount - 1) {
                                    c0305w.rightMargin = paddingLeft / 2;
                                }
                                obj = obj3;
                            } else {
                                c0305w.f1596c = paddingLeft;
                                c0305w.f1599f = true;
                                c0305w.rightMargin = (-paddingLeft) / 2;
                                obj = 1;
                            }
                        }
                        i4++;
                        obj3 = obj;
                    }
                }
            }
            f = bitCount;
            if (f <= 0.0f) {
            }
            i4 = 0;
            obj3 = obj4;
            while (i4 < childCount) {
                if ((((long) (1 << i4)) & j) != 0) {
                    childAt3 = getChildAt(i4);
                    c0305w = (C0305w) childAt3.getLayoutParams();
                    if (childAt3 instanceof ActionMenuItemView) {
                        c0305w.f1596c = paddingLeft;
                        c0305w.f1599f = true;
                        c0305w.leftMargin = (-paddingLeft) / 2;
                        obj = 1;
                    } else if (c0305w.f1594a) {
                        if (i4 != 0) {
                            c0305w.leftMargin = paddingLeft / 2;
                        }
                        if (i4 != childCount - 1) {
                            c0305w.rightMargin = paddingLeft / 2;
                        }
                        obj = obj3;
                    } else {
                        c0305w.f1596c = paddingLeft;
                        c0305w.f1599f = true;
                        c0305w.rightMargin = (-paddingLeft) / 2;
                        obj = 1;
                    }
                } else {
                    obj = obj3;
                }
                i4++;
                obj3 = obj;
            }
        }
        if (obj3 != null) {
            for (paddingLeft = 0; paddingLeft < childCount; paddingLeft++) {
                childAt = getChildAt(paddingLeft);
                c0305w = (C0305w) childAt.getLayoutParams();
                if (c0305w.f1599f) {
                    childAt.measure(MeasureSpec.makeMeasureSpec(c0305w.f1596c + (c0305w.f1595b * i5), 1073741824), childMeasureSpec);
                }
            }
        }
        if (mode == 1073741824) {
            i6 = size2;
        }
        setMeasuredDimension(i3, i6);
    }

    public C0305w m2356a(AttributeSet attributeSet) {
        return new C0305w(getContext(), attributeSet);
    }

    protected C0305w m2357a(LayoutParams layoutParams) {
        if (layoutParams == null) {
            return m2365b();
        }
        C0305w c0305w = layoutParams instanceof C0305w ? new C0305w((C0305w) layoutParams) : new C0305w(layoutParams);
        if (c0305w.h > 0) {
            return c0305w;
        }
        c0305w.h = 16;
        return c0305w;
    }

    public void m2358a(C0264i c0264i) {
        this.f1148a = c0264i;
    }

    public void m2359a(C0207y c0207y, C0203j c0203j) {
        this.f1153f = c0207y;
        this.f1154g = c0203j;
    }

    public boolean m2360a() {
        return this.f1151d;
    }

    protected boolean m2361a(int i) {
        boolean z = false;
        if (i == 0) {
            return false;
        }
        View childAt = getChildAt(i - 1);
        View childAt2 = getChildAt(i);
        if (i < getChildCount() && (childAt instanceof C0258u)) {
            z = 0 | ((C0258u) childAt).m2058d();
        }
        return (i <= 0 || !(childAt2 instanceof C0258u)) ? z : ((C0258u) childAt2).m2057c() | z;
    }

    public boolean m2362a(C0272m c0272m) {
        return this.f1148a.m2117a((MenuItem) c0272m, 0);
    }

    public /* synthetic */ bx m2363b(AttributeSet attributeSet) {
        return m2356a(attributeSet);
    }

    protected /* synthetic */ bx m2364b(LayoutParams layoutParams) {
        return m2357a(layoutParams);
    }

    protected C0305w m2365b() {
        C0305w c0305w = new C0305w(-2, -2);
        c0305w.h = 16;
        return c0305w;
    }

    public C0305w m2366c() {
        C0305w b = m2365b();
        b.f1594a = true;
        return b;
    }

    protected boolean checkLayoutParams(LayoutParams layoutParams) {
        return layoutParams != null && (layoutParams instanceof C0305w);
    }

    public C0264i m2367d() {
        return this.f1148a;
    }

    public boolean dispatchPopulateAccessibilityEvent(AccessibilityEvent accessibilityEvent) {
        return false;
    }

    public boolean m2368e() {
        return this.f1152e != null && this.f1152e.m2828d();
    }

    public boolean m2369f() {
        return this.f1152e != null && this.f1152e.m2829e();
    }

    public boolean m2370g() {
        return this.f1152e != null && this.f1152e.m2832h();
    }

    protected /* synthetic */ LayoutParams generateDefaultLayoutParams() {
        return m2365b();
    }

    public /* synthetic */ LayoutParams generateLayoutParams(AttributeSet attributeSet) {
        return m2356a(attributeSet);
    }

    protected /* synthetic */ LayoutParams generateLayoutParams(LayoutParams layoutParams) {
        return m2357a(layoutParams);
    }

    public Menu getMenu() {
        if (this.f1148a == null) {
            Context context = getContext();
            this.f1148a = new C0264i(context);
            this.f1148a.m2109a(new C0306x());
            this.f1152e = new C0294k(context);
            this.f1152e.m2826c(true);
            this.f1152e.m2184a(this.f1153f != null ? this.f1153f : new C0304v());
            this.f1148a.m2112a(this.f1152e, this.f1149b);
            this.f1152e.m2818a(this);
        }
        return this.f1148a;
    }

    public Drawable getOverflowIcon() {
        getMenu();
        return this.f1152e.m2825c();
    }

    public int getPopupTheme() {
        return this.f1150c;
    }

    public int getWindowAnimations() {
        return 0;
    }

    public boolean m2371h() {
        return this.f1152e != null && this.f1152e.m2833i();
    }

    public void m2372i() {
        if (this.f1152e != null) {
            this.f1152e.m2830f();
        }
    }

    protected /* synthetic */ bx m2373j() {
        return m2365b();
    }

    public void onConfigurationChanged(Configuration configuration) {
        if (VERSION.SDK_INT >= 8) {
            super.onConfigurationChanged(configuration);
        }
        if (this.f1152e != null) {
            this.f1152e.m2823b(false);
            if (this.f1152e.m2832h()) {
                this.f1152e.m2829e();
                this.f1152e.m2828d();
            }
        }
    }

    public void onDetachedFromWindow() {
        super.onDetachedFromWindow();
        m2372i();
    }

    protected void onLayout(boolean z, int i, int i2, int i3, int i4) {
        if (this.f1155h) {
            int i5;
            int i6;
            C0305w c0305w;
            int paddingLeft;
            int childCount = getChildCount();
            int i7 = (i4 - i2) / 2;
            int dividerWidth = getDividerWidth();
            int i8 = 0;
            int i9 = 0;
            int paddingRight = ((i3 - i) - getPaddingRight()) - getPaddingLeft();
            Object obj = null;
            boolean a = du.m2794a(this);
            int i10 = 0;
            while (i10 < childCount) {
                Object obj2;
                View childAt = getChildAt(i10);
                if (childAt.getVisibility() == 8) {
                    obj2 = obj;
                    i5 = i9;
                    i6 = paddingRight;
                    paddingRight = i8;
                } else {
                    c0305w = (C0305w) childAt.getLayoutParams();
                    if (c0305w.f1594a) {
                        i6 = childAt.getMeasuredWidth();
                        if (m2361a(i10)) {
                            i6 += dividerWidth;
                        }
                        int measuredHeight = childAt.getMeasuredHeight();
                        if (a) {
                            paddingLeft = c0305w.leftMargin + getPaddingLeft();
                            i5 = paddingLeft + i6;
                        } else {
                            i5 = (getWidth() - getPaddingRight()) - c0305w.rightMargin;
                            paddingLeft = i5 - i6;
                        }
                        int i11 = i7 - (measuredHeight / 2);
                        childAt.layout(paddingLeft, i11, i5, measuredHeight + i11);
                        i6 = paddingRight - i6;
                        obj2 = 1;
                        i5 = i9;
                        paddingRight = i8;
                    } else {
                        i5 = (childAt.getMeasuredWidth() + c0305w.leftMargin) + c0305w.rightMargin;
                        paddingLeft = i8 + i5;
                        i5 = paddingRight - i5;
                        if (m2361a(i10)) {
                            paddingLeft += dividerWidth;
                        }
                        Object obj3 = obj;
                        i6 = i5;
                        i5 = i9 + 1;
                        paddingRight = paddingLeft;
                        obj2 = obj3;
                    }
                }
                i10++;
                i8 = paddingRight;
                paddingRight = i6;
                i9 = i5;
                obj = obj2;
            }
            if (childCount == 1 && obj == null) {
                View childAt2 = getChildAt(0);
                i6 = childAt2.getMeasuredWidth();
                i5 = childAt2.getMeasuredHeight();
                paddingRight = ((i3 - i) / 2) - (i6 / 2);
                i9 = i7 - (i5 / 2);
                childAt2.layout(paddingRight, i9, i6 + paddingRight, i5 + i9);
                return;
            }
            paddingLeft = i9 - (obj != null ? 0 : 1);
            paddingRight = Math.max(0, paddingLeft > 0 ? paddingRight / paddingLeft : 0);
            View childAt3;
            if (a) {
                i6 = getWidth() - getPaddingRight();
                i5 = 0;
                while (i5 < childCount) {
                    childAt3 = getChildAt(i5);
                    c0305w = (C0305w) childAt3.getLayoutParams();
                    if (childAt3.getVisibility() == 8) {
                        paddingLeft = i6;
                    } else if (c0305w.f1594a) {
                        paddingLeft = i6;
                    } else {
                        i6 -= c0305w.rightMargin;
                        i8 = childAt3.getMeasuredWidth();
                        i10 = childAt3.getMeasuredHeight();
                        dividerWidth = i7 - (i10 / 2);
                        childAt3.layout(i6 - i8, dividerWidth, i6, i10 + dividerWidth);
                        paddingLeft = i6 - ((c0305w.leftMargin + i8) + paddingRight);
                    }
                    i5++;
                    i6 = paddingLeft;
                }
                return;
            }
            i6 = getPaddingLeft();
            i5 = 0;
            while (i5 < childCount) {
                childAt3 = getChildAt(i5);
                c0305w = (C0305w) childAt3.getLayoutParams();
                if (childAt3.getVisibility() == 8) {
                    paddingLeft = i6;
                } else if (c0305w.f1594a) {
                    paddingLeft = i6;
                } else {
                    i6 += c0305w.leftMargin;
                    i8 = childAt3.getMeasuredWidth();
                    i10 = childAt3.getMeasuredHeight();
                    dividerWidth = i7 - (i10 / 2);
                    childAt3.layout(i6, dividerWidth, i6 + i8, i10 + dividerWidth);
                    paddingLeft = ((c0305w.rightMargin + i8) + paddingRight) + i6;
                }
                i5++;
                i6 = paddingLeft;
            }
            return;
        }
        super.onLayout(z, i, i2, i3, i4);
    }

    protected void onMeasure(int i, int i2) {
        boolean z = this.f1155h;
        this.f1155h = MeasureSpec.getMode(i) == 1073741824;
        if (z != this.f1155h) {
            this.f1156i = 0;
        }
        int size = MeasureSpec.getSize(i);
        if (!(!this.f1155h || this.f1148a == null || size == this.f1156i)) {
            this.f1156i = size;
            this.f1148a.m2123b(true);
        }
        int childCount = getChildCount();
        if (!this.f1155h || childCount <= 0) {
            for (int i3 = 0; i3 < childCount; i3++) {
                C0305w c0305w = (C0305w) getChildAt(i3).getLayoutParams();
                c0305w.rightMargin = 0;
                c0305w.leftMargin = 0;
            }
            super.onMeasure(i, i2);
            return;
        }
        m2355c(i, i2);
    }

    public void setExpandedActionViewsExclusive(boolean z) {
        this.f1152e.m2827d(z);
    }

    public void setOnMenuItemClickListener(C0287y c0287y) {
        this.f1159l = c0287y;
    }

    public void setOverflowIcon(Drawable drawable) {
        getMenu();
        this.f1152e.m2815a(drawable);
    }

    public void setOverflowReserved(boolean z) {
        this.f1151d = z;
    }

    public void setPopupTheme(int i) {
        if (this.f1150c != i) {
            this.f1150c = i;
            if (i == 0) {
                this.f1149b = getContext();
            } else {
                this.f1149b = new ContextThemeWrapper(getContext(), i);
            }
        }
    }

    public void setPresenter(C0294k c0294k) {
        this.f1152e = c0294k;
        this.f1152e.m2818a(this);
    }
}

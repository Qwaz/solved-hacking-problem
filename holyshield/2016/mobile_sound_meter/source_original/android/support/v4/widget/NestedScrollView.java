package android.support.v4.widget;

import android.content.Context;
import android.content.res.TypedArray;
import android.graphics.Canvas;
import android.graphics.Rect;
import android.os.Parcelable;
import android.support.v4.p004h.az;
import android.support.v4.p004h.bi;
import android.support.v4.p004h.bj;
import android.support.v4.p004h.bk;
import android.support.v4.p004h.bl;
import android.support.v4.p004h.bn;
import android.support.v4.p004h.bp;
import android.support.v4.p004h.bu;
import android.support.v7.p015b.C0243l;
import android.util.AttributeSet;
import android.util.Log;
import android.util.TypedValue;
import android.view.FocusFinder;
import android.view.KeyEvent;
import android.view.MotionEvent;
import android.view.VelocityTracker;
import android.view.View;
import android.view.View.MeasureSpec;
import android.view.ViewConfiguration;
import android.view.ViewGroup;
import android.view.ViewGroup.LayoutParams;
import android.view.ViewGroup.MarginLayoutParams;
import android.view.ViewParent;
import android.view.animation.AnimationUtils;
import android.widget.FrameLayout;
import java.util.List;

public class NestedScrollView extends FrameLayout implements bi, bk, bn {
    private static final ad f481v;
    private static final int[] f482w;
    private ae f483A;
    private long f484a;
    private final Rect f485b;
    private at f486c;
    private C0192s f487d;
    private C0192s f488e;
    private int f489f;
    private boolean f490g;
    private boolean f491h;
    private View f492i;
    private boolean f493j;
    private VelocityTracker f494k;
    private boolean f495l;
    private boolean f496m;
    private int f497n;
    private int f498o;
    private int f499p;
    private int f500q;
    private final int[] f501r;
    private final int[] f502s;
    private int f503t;
    private af f504u;
    private final bl f505x;
    private final bj f506y;
    private float f507z;

    static {
        f481v = new ad();
        f482w = new int[]{16843130};
    }

    public NestedScrollView(Context context) {
        this(context, null);
    }

    public NestedScrollView(Context context, AttributeSet attributeSet) {
        this(context, attributeSet, 0);
    }

    public NestedScrollView(Context context, AttributeSet attributeSet, int i) {
        super(context, attributeSet, i);
        this.f485b = new Rect();
        this.f490g = true;
        this.f491h = false;
        this.f492i = null;
        this.f493j = false;
        this.f496m = true;
        this.f500q = -1;
        this.f501r = new int[2];
        this.f502s = new int[2];
        m1361a();
        TypedArray obtainStyledAttributes = context.obtainStyledAttributes(attributeSet, f482w, i, 0);
        setFillViewport(obtainStyledAttributes.getBoolean(0, false));
        obtainStyledAttributes.recycle();
        this.f505x = new bl(this);
        this.f506y = new bj(this);
        setNestedScrollingEnabled(true);
        bu.m984a((View) this, f481v);
    }

    private View m1360a(boolean z, int i, int i2) {
        List focusables = getFocusables(2);
        View view = null;
        Object obj = null;
        int size = focusables.size();
        int i3 = 0;
        while (i3 < size) {
            View view2;
            Object obj2;
            View view3 = (View) focusables.get(i3);
            int top = view3.getTop();
            int bottom = view3.getBottom();
            if (i < bottom && top < i2) {
                Object obj3 = (i >= top || bottom >= i2) ? null : 1;
                if (view == null) {
                    Object obj4 = obj3;
                    view2 = view3;
                    obj2 = obj4;
                } else {
                    Object obj5 = ((!z || top >= view.getTop()) && (z || bottom <= view.getBottom())) ? null : 1;
                    if (obj != null) {
                        if (!(obj3 == null || obj5 == null)) {
                            view2 = view3;
                            obj2 = obj;
                        }
                    } else if (obj3 != null) {
                        view2 = view3;
                        int i4 = 1;
                    } else if (obj5 != null) {
                        view2 = view3;
                        obj2 = obj;
                    }
                }
                i3++;
                view = view2;
                obj = obj2;
            }
            obj2 = obj;
            view2 = view;
            i3++;
            view = view2;
            obj = obj2;
        }
        return view;
    }

    private void m1361a() {
        this.f486c = at.m1468a(getContext(), null);
        setFocusable(true);
        setDescendantFocusability(262144);
        setWillNotDraw(false);
        ViewConfiguration viewConfiguration = ViewConfiguration.get(getContext());
        this.f497n = viewConfiguration.getScaledTouchSlop();
        this.f498o = viewConfiguration.getScaledMinimumFlingVelocity();
        this.f499p = viewConfiguration.getScaledMaximumFlingVelocity();
    }

    private void m1362a(MotionEvent motionEvent) {
        int action = (motionEvent.getAction() & 65280) >> 8;
        if (az.m898b(motionEvent, action) == this.f500q) {
            action = action == 0 ? 1 : 0;
            this.f489f = (int) az.m901d(motionEvent, action);
            this.f500q = az.m898b(motionEvent, action);
            if (this.f494k != null) {
                this.f494k.clear();
            }
        }
    }

    private boolean m1363a(int i, int i2, int i3) {
        boolean z = false;
        int height = getHeight();
        int scrollY = getScrollY();
        int i4 = scrollY + height;
        boolean z2 = i == 33;
        View a = m1360a(z2, i2, i3);
        if (a == null) {
            a = this;
        }
        if (i2 < scrollY || i3 > i4) {
            m1375e(z2 ? i2 - scrollY : i3 - i4);
            z = true;
        }
        if (a != findFocus()) {
            a.requestFocus(i);
        }
        return z;
    }

    private boolean m1364a(Rect rect, boolean z) {
        int a = m1379a(rect);
        boolean z2 = a != 0;
        if (z2) {
            if (z) {
                scrollBy(0, a);
            } else {
                m1380a(0, a);
            }
        }
        return z2;
    }

    private boolean m1365a(View view) {
        return !m1366a(view, 0, getHeight());
    }

    private boolean m1366a(View view, int i, int i2) {
        view.getDrawingRect(this.f485b);
        offsetDescendantRectToMyCoords(view, this.f485b);
        return this.f485b.bottom + i >= getScrollY() && this.f485b.top - i <= getScrollY() + i2;
    }

    private static boolean m1367a(View view, View view2) {
        if (view == view2) {
            return true;
        }
        ViewParent parent = view.getParent();
        boolean z = (parent instanceof ViewGroup) && m1367a((View) parent, view2);
        return z;
    }

    private static int m1368b(int i, int i2, int i3) {
        return (i2 >= i3 || i < 0) ? 0 : i2 + i > i3 ? i3 - i2 : i;
    }

    private void m1369b(View view) {
        view.getDrawingRect(this.f485b);
        offsetDescendantRectToMyCoords(view, this.f485b);
        int a = m1379a(this.f485b);
        if (a != 0) {
            scrollBy(0, a);
        }
    }

    private boolean m1370b() {
        View childAt = getChildAt(0);
        if (childAt == null) {
            return false;
        }
        return getHeight() < (childAt.getHeight() + getPaddingTop()) + getPaddingBottom();
    }

    private void m1371c() {
        if (this.f494k == null) {
            this.f494k = VelocityTracker.obtain();
        } else {
            this.f494k.clear();
        }
    }

    private boolean m1372c(int i, int i2) {
        if (getChildCount() <= 0) {
            return false;
        }
        int scrollY = getScrollY();
        View childAt = getChildAt(0);
        return i2 >= childAt.getTop() - scrollY && i2 < childAt.getBottom() - scrollY && i >= childAt.getLeft() && i < childAt.getRight();
    }

    private void m1373d() {
        if (this.f494k == null) {
            this.f494k = VelocityTracker.obtain();
        }
    }

    private void m1374e() {
        if (this.f494k != null) {
            this.f494k.recycle();
            this.f494k = null;
        }
    }

    private void m1375e(int i) {
        if (i == 0) {
            return;
        }
        if (this.f496m) {
            m1380a(0, i);
        } else {
            scrollBy(0, i);
        }
    }

    private void m1376f() {
        this.f493j = false;
        m1374e();
        stopNestedScroll();
        if (this.f487d != null) {
            this.f487d.m1565b();
            this.f488e.m1565b();
        }
    }

    private void m1377f(int i) {
        int scrollY = getScrollY();
        boolean z = (scrollY > 0 || i > 0) && (scrollY < getScrollRange() || i < 0);
        if (!dispatchNestedPreFling(0.0f, (float) i)) {
            dispatchNestedFling(0.0f, (float) i, z);
            if (z) {
                m1387d(i);
            }
        }
    }

    private void m1378g() {
        if (bu.m977a(this) == 2) {
            this.f487d = null;
            this.f488e = null;
        } else if (this.f487d == null) {
            Context context = getContext();
            this.f487d = new C0192s(context);
            this.f488e = new C0192s(context);
        }
    }

    private int getScrollRange() {
        return getChildCount() > 0 ? Math.max(0, getChildAt(0).getHeight() - ((getHeight() - getPaddingBottom()) - getPaddingTop())) : 0;
    }

    private float getVerticalScrollFactorCompat() {
        if (this.f507z == 0.0f) {
            TypedValue typedValue = new TypedValue();
            Context context = getContext();
            if (context.getTheme().resolveAttribute(16842829, typedValue, true)) {
                this.f507z = typedValue.getDimension(context.getResources().getDisplayMetrics());
            } else {
                throw new IllegalStateException("Expected theme to define listPreferredItemHeight.");
            }
        }
        return this.f507z;
    }

    protected int m1379a(Rect rect) {
        if (getChildCount() == 0) {
            return 0;
        }
        int height = getHeight();
        int scrollY = getScrollY();
        int i = scrollY + height;
        int verticalFadingEdgeLength = getVerticalFadingEdgeLength();
        if (rect.top > 0) {
            scrollY += verticalFadingEdgeLength;
        }
        if (rect.bottom < getChildAt(0).getHeight()) {
            i -= verticalFadingEdgeLength;
        }
        if (rect.bottom > i && rect.top > scrollY) {
            scrollY = Math.min(rect.height() > height ? (rect.top - scrollY) + 0 : (rect.bottom - i) + 0, getChildAt(0).getBottom() - i);
        } else if (rect.top >= scrollY || rect.bottom >= i) {
            scrollY = 0;
        } else {
            scrollY = Math.max(rect.height() > height ? 0 - (i - rect.bottom) : 0 - (scrollY - rect.top), -getScrollY());
        }
        return scrollY;
    }

    public final void m1380a(int i, int i2) {
        if (getChildCount() != 0) {
            if (AnimationUtils.currentAnimationTimeMillis() - this.f484a > 250) {
                int max = Math.max(0, getChildAt(0).getHeight() - ((getHeight() - getPaddingBottom()) - getPaddingTop()));
                int scrollY = getScrollY();
                this.f486c.m1469a(getScrollX(), scrollY, 0, Math.max(0, Math.min(scrollY + i2, max)) - scrollY);
                bu.m990b(this);
            } else {
                if (!this.f486c.m1472a()) {
                    this.f486c.m1479g();
                }
                scrollBy(i, i2);
            }
            this.f484a = AnimationUtils.currentAnimationTimeMillis();
        }
    }

    public boolean m1381a(int i) {
        int i2 = i == 130 ? 1 : 0;
        int height = getHeight();
        if (i2 != 0) {
            this.f485b.top = getScrollY() + height;
            i2 = getChildCount();
            if (i2 > 0) {
                View childAt = getChildAt(i2 - 1);
                if (this.f485b.top + height > childAt.getBottom()) {
                    this.f485b.top = childAt.getBottom() - height;
                }
            }
        } else {
            this.f485b.top = getScrollY() - height;
            if (this.f485b.top < 0) {
                this.f485b.top = 0;
            }
        }
        this.f485b.bottom = this.f485b.top + height;
        return m1363a(i, this.f485b.top, this.f485b.bottom);
    }

    boolean m1382a(int i, int i2, int i3, int i4, int i5, int i6, int i7, int i8, boolean z) {
        boolean z2;
        boolean z3;
        int a = bu.m977a(this);
        Object obj = computeHorizontalScrollRange() > computeHorizontalScrollExtent() ? 1 : null;
        Object obj2 = computeVerticalScrollRange() > computeVerticalScrollExtent() ? 1 : null;
        Object obj3 = (a == 0 || (a == 1 && obj != null)) ? 1 : null;
        obj = (a == 0 || (a == 1 && obj2 != null)) ? 1 : null;
        int i9 = i3 + i;
        if (obj3 == null) {
            i7 = 0;
        }
        int i10 = i4 + i2;
        if (obj == null) {
            i8 = 0;
        }
        int i11 = -i7;
        int i12 = i7 + i5;
        a = -i8;
        int i13 = i8 + i6;
        if (i9 > i12) {
            z2 = true;
        } else if (i9 < i11) {
            z2 = true;
            i12 = i11;
        } else {
            z2 = false;
            i12 = i9;
        }
        if (i10 > i13) {
            z3 = true;
        } else if (i10 < a) {
            z3 = true;
            i13 = a;
        } else {
            z3 = false;
            i13 = i10;
        }
        if (z3) {
            this.f486c.m1473a(i12, i13, 0, 0, 0, getScrollRange());
        }
        onOverScrolled(i12, i13, z2, z3);
        return z2 || z3;
    }

    public boolean m1383a(KeyEvent keyEvent) {
        int i = 33;
        this.f485b.setEmpty();
        if (m1370b()) {
            if (keyEvent.getAction() != 0) {
                return false;
            }
            switch (keyEvent.getKeyCode()) {
                case C0243l.Toolbar_collapseContentDescription /*19*/:
                    return !keyEvent.isAltPressed() ? m1386c(33) : m1385b(33);
                case C0243l.Toolbar_navigationIcon /*20*/:
                    return !keyEvent.isAltPressed() ? m1386c(130) : m1385b(130);
                case C0243l.AppCompatTheme_editTextColor /*62*/:
                    if (!keyEvent.isShiftPressed()) {
                        i = 130;
                    }
                    m1381a(i);
                    return false;
                default:
                    return false;
            }
        } else if (!isFocused() || keyEvent.getKeyCode() == 4) {
            return false;
        } else {
            View findFocus = findFocus();
            if (findFocus == this) {
                findFocus = null;
            }
            findFocus = FocusFinder.getInstance().findNextFocus(this, findFocus, 130);
            boolean z = (findFocus == null || findFocus == this || !findFocus.requestFocus(130)) ? false : true;
            return z;
        }
    }

    public void addView(View view) {
        if (getChildCount() > 0) {
            throw new IllegalStateException("ScrollView can host only one direct child");
        }
        super.addView(view);
    }

    public void addView(View view, int i) {
        if (getChildCount() > 0) {
            throw new IllegalStateException("ScrollView can host only one direct child");
        }
        super.addView(view, i);
    }

    public void addView(View view, int i, LayoutParams layoutParams) {
        if (getChildCount() > 0) {
            throw new IllegalStateException("ScrollView can host only one direct child");
        }
        super.addView(view, i, layoutParams);
    }

    public void addView(View view, LayoutParams layoutParams) {
        if (getChildCount() > 0) {
            throw new IllegalStateException("ScrollView can host only one direct child");
        }
        super.addView(view, layoutParams);
    }

    public final void m1384b(int i, int i2) {
        m1380a(i - getScrollX(), i2 - getScrollY());
    }

    public boolean m1385b(int i) {
        int i2 = i == 130 ? 1 : 0;
        int height = getHeight();
        this.f485b.top = 0;
        this.f485b.bottom = height;
        if (i2 != 0) {
            i2 = getChildCount();
            if (i2 > 0) {
                this.f485b.bottom = getChildAt(i2 - 1).getBottom() + getPaddingBottom();
                this.f485b.top = this.f485b.bottom - height;
            }
        }
        return m1363a(i, this.f485b.top, this.f485b.bottom);
    }

    public boolean m1386c(int i) {
        View findFocus = findFocus();
        if (findFocus == this) {
            findFocus = null;
        }
        View findNextFocus = FocusFinder.getInstance().findNextFocus(this, findFocus, i);
        int maxScrollAmount = getMaxScrollAmount();
        if (findNextFocus == null || !m1366a(findNextFocus, maxScrollAmount, getHeight())) {
            if (i == 33 && getScrollY() < maxScrollAmount) {
                maxScrollAmount = getScrollY();
            } else if (i == 130 && getChildCount() > 0) {
                int bottom = getChildAt(0).getBottom();
                int scrollY = (getScrollY() + getHeight()) - getPaddingBottom();
                if (bottom - scrollY < maxScrollAmount) {
                    maxScrollAmount = bottom - scrollY;
                }
            }
            if (maxScrollAmount == 0) {
                return false;
            }
            if (i != 130) {
                maxScrollAmount = -maxScrollAmount;
            }
            m1375e(maxScrollAmount);
        } else {
            findNextFocus.getDrawingRect(this.f485b);
            offsetDescendantRectToMyCoords(findNextFocus, this.f485b);
            m1375e(m1379a(this.f485b));
            findNextFocus.requestFocus(i);
        }
        if (findFocus != null && findFocus.isFocused() && m1365a(findFocus)) {
            int descendantFocusability = getDescendantFocusability();
            setDescendantFocusability(131072);
            requestFocus();
            setDescendantFocusability(descendantFocusability);
        }
        return true;
    }

    public int computeHorizontalScrollExtent() {
        return super.computeHorizontalScrollExtent();
    }

    public int computeHorizontalScrollOffset() {
        return super.computeHorizontalScrollOffset();
    }

    public int computeHorizontalScrollRange() {
        return super.computeHorizontalScrollRange();
    }

    public void computeScroll() {
        if (this.f486c.m1478f()) {
            int scrollX = getScrollX();
            int scrollY = getScrollY();
            int b = this.f486c.m1474b();
            int c = this.f486c.m1475c();
            if (scrollX != b || scrollY != c) {
                int scrollRange = getScrollRange();
                int a = bu.m977a(this);
                int i = (a == 0 || (a == 1 && scrollRange > 0)) ? 1 : 0;
                m1382a(b - scrollX, c - scrollY, scrollX, scrollY, 0, scrollRange, 0, 0, false);
                if (i != 0) {
                    m1378g();
                    if (c <= 0 && scrollY > 0) {
                        this.f487d.m1563a((int) this.f486c.m1477e());
                    } else if (c >= scrollRange && scrollY < scrollRange) {
                        this.f488e.m1563a((int) this.f486c.m1477e());
                    }
                }
            }
        }
    }

    public int computeVerticalScrollExtent() {
        return super.computeVerticalScrollExtent();
    }

    public int computeVerticalScrollOffset() {
        return Math.max(0, super.computeVerticalScrollOffset());
    }

    public int computeVerticalScrollRange() {
        int height = (getHeight() - getPaddingBottom()) - getPaddingTop();
        if (getChildCount() == 0) {
            return height;
        }
        int bottom = getChildAt(0).getBottom();
        int scrollY = getScrollY();
        height = Math.max(0, bottom - height);
        return scrollY < 0 ? bottom - scrollY : scrollY > height ? bottom + (scrollY - height) : bottom;
    }

    public void m1387d(int i) {
        if (getChildCount() > 0) {
            int height = (getHeight() - getPaddingBottom()) - getPaddingTop();
            int height2 = getChildAt(0).getHeight();
            this.f486c.m1471a(getScrollX(), getScrollY(), 0, i, 0, 0, 0, Math.max(0, height2 - height), 0, height / 2);
            bu.m990b(this);
        }
    }

    public boolean dispatchKeyEvent(KeyEvent keyEvent) {
        return super.dispatchKeyEvent(keyEvent) || m1383a(keyEvent);
    }

    public boolean dispatchNestedFling(float f, float f2, boolean z) {
        return this.f506y.m961a(f, f2, z);
    }

    public boolean dispatchNestedPreFling(float f, float f2) {
        return this.f506y.m960a(f, f2);
    }

    public boolean dispatchNestedPreScroll(int i, int i2, int[] iArr, int[] iArr2) {
        return this.f506y.m964a(i, i2, iArr, iArr2);
    }

    public boolean dispatchNestedScroll(int i, int i2, int i3, int i4, int[] iArr) {
        return this.f506y.m963a(i, i2, i3, i4, iArr);
    }

    public void draw(Canvas canvas) {
        super.draw(canvas);
        if (this.f487d != null) {
            int save;
            int width;
            int scrollY = getScrollY();
            if (!this.f487d.m1561a()) {
                save = canvas.save();
                width = (getWidth() - getPaddingLeft()) - getPaddingRight();
                canvas.translate((float) getPaddingLeft(), (float) Math.min(0, scrollY));
                this.f487d.m1560a(width, getHeight());
                if (this.f487d.m1564a(canvas)) {
                    bu.m990b(this);
                }
                canvas.restoreToCount(save);
            }
            if (!this.f488e.m1561a()) {
                save = canvas.save();
                width = (getWidth() - getPaddingLeft()) - getPaddingRight();
                int height = getHeight();
                canvas.translate((float) ((-width) + getPaddingLeft()), (float) (Math.max(getScrollRange(), scrollY) + height));
                canvas.rotate(180.0f, (float) width, 0.0f);
                this.f488e.m1560a(width, height);
                if (this.f488e.m1564a(canvas)) {
                    bu.m990b(this);
                }
                canvas.restoreToCount(save);
            }
        }
    }

    protected float getBottomFadingEdgeStrength() {
        if (getChildCount() == 0) {
            return 0.0f;
        }
        int verticalFadingEdgeLength = getVerticalFadingEdgeLength();
        int bottom = (getChildAt(0).getBottom() - getScrollY()) - (getHeight() - getPaddingBottom());
        return bottom < verticalFadingEdgeLength ? ((float) bottom) / ((float) verticalFadingEdgeLength) : 1.0f;
    }

    public int getMaxScrollAmount() {
        return (int) (0.5f * ((float) getHeight()));
    }

    public int getNestedScrollAxes() {
        return this.f505x.m967a();
    }

    protected float getTopFadingEdgeStrength() {
        if (getChildCount() == 0) {
            return 0.0f;
        }
        int verticalFadingEdgeLength = getVerticalFadingEdgeLength();
        int scrollY = getScrollY();
        return scrollY < verticalFadingEdgeLength ? ((float) scrollY) / ((float) verticalFadingEdgeLength) : 1.0f;
    }

    public boolean hasNestedScrollingParent() {
        return this.f506y.m965b();
    }

    public boolean isNestedScrollingEnabled() {
        return this.f506y.m959a();
    }

    protected void measureChild(View view, int i, int i2) {
        view.measure(getChildMeasureSpec(i, getPaddingLeft() + getPaddingRight(), view.getLayoutParams().width), MeasureSpec.makeMeasureSpec(0, 0));
    }

    protected void measureChildWithMargins(View view, int i, int i2, int i3, int i4) {
        MarginLayoutParams marginLayoutParams = (MarginLayoutParams) view.getLayoutParams();
        view.measure(getChildMeasureSpec(i, (((getPaddingLeft() + getPaddingRight()) + marginLayoutParams.leftMargin) + marginLayoutParams.rightMargin) + i2, marginLayoutParams.width), MeasureSpec.makeMeasureSpec(marginLayoutParams.bottomMargin + marginLayoutParams.topMargin, 0));
    }

    public void onAttachedToWindow() {
        this.f491h = false;
    }

    public boolean onGenericMotionEvent(MotionEvent motionEvent) {
        if ((az.m900c(motionEvent) & 2) == 0) {
            return false;
        }
        switch (motionEvent.getAction()) {
            case C0243l.Toolbar_contentInsetRight /*8*/:
                if (this.f493j) {
                    return false;
                }
                float e = az.m902e(motionEvent, 9);
                if (e == 0.0f) {
                    return false;
                }
                int verticalScrollFactorCompat = (int) (e * getVerticalScrollFactorCompat());
                int scrollRange = getScrollRange();
                int scrollY = getScrollY();
                verticalScrollFactorCompat = scrollY - verticalScrollFactorCompat;
                if (verticalScrollFactorCompat < 0) {
                    scrollRange = 0;
                } else if (verticalScrollFactorCompat <= scrollRange) {
                    scrollRange = verticalScrollFactorCompat;
                }
                if (scrollRange == scrollY) {
                    return false;
                }
                super.scrollTo(getScrollX(), scrollRange);
                return true;
            default:
                return false;
        }
    }

    public boolean onInterceptTouchEvent(MotionEvent motionEvent) {
        boolean z = false;
        int action = motionEvent.getAction();
        if (action == 2 && this.f493j) {
            return true;
        }
        switch (action & 255) {
            case C0243l.View_android_theme /*0*/:
                action = (int) motionEvent.getY();
                if (!m1372c((int) motionEvent.getX(), action)) {
                    this.f493j = false;
                    m1374e();
                    break;
                }
                this.f489f = action;
                this.f500q = az.m898b(motionEvent, 0);
                m1371c();
                this.f494k.addMovement(motionEvent);
                this.f486c.m1478f();
                if (!this.f486c.m1472a()) {
                    z = true;
                }
                this.f493j = z;
                startNestedScroll(2);
                break;
            case C0243l.View_android_focusable /*1*/:
            case C0243l.View_paddingEnd /*3*/:
                this.f493j = false;
                this.f500q = -1;
                m1374e();
                if (this.f486c.m1473a(getScrollX(), getScrollY(), 0, 0, 0, getScrollRange())) {
                    bu.m990b(this);
                }
                stopNestedScroll();
                break;
            case C0243l.View_paddingStart /*2*/:
                action = this.f500q;
                if (action != -1) {
                    int a = az.m896a(motionEvent, action);
                    if (a != -1) {
                        action = (int) az.m901d(motionEvent, a);
                        if (Math.abs(action - this.f489f) > this.f497n && (getNestedScrollAxes() & 2) == 0) {
                            this.f493j = true;
                            this.f489f = action;
                            m1373d();
                            this.f494k.addMovement(motionEvent);
                            this.f503t = 0;
                            ViewParent parent = getParent();
                            if (parent != null) {
                                parent.requestDisallowInterceptTouchEvent(true);
                                break;
                            }
                        }
                    }
                    Log.e("NestedScrollView", "Invalid pointerId=" + action + " in onInterceptTouchEvent");
                    break;
                }
                break;
            case C0243l.Toolbar_contentInsetEnd /*6*/:
                m1362a(motionEvent);
                break;
        }
        return this.f493j;
    }

    protected void onLayout(boolean z, int i, int i2, int i3, int i4) {
        super.onLayout(z, i, i2, i3, i4);
        this.f490g = false;
        if (this.f492i != null && m1367a(this.f492i, (View) this)) {
            m1369b(this.f492i);
        }
        this.f492i = null;
        if (!this.f491h) {
            if (this.f504u != null) {
                scrollTo(getScrollX(), this.f504u.f526a);
                this.f504u = null;
            }
            int max = Math.max(0, (getChildCount() > 0 ? getChildAt(0).getMeasuredHeight() : 0) - (((i4 - i2) - getPaddingBottom()) - getPaddingTop()));
            if (getScrollY() > max) {
                scrollTo(getScrollX(), max);
            } else if (getScrollY() < 0) {
                scrollTo(getScrollX(), 0);
            }
        }
        scrollTo(getScrollX(), getScrollY());
        this.f491h = true;
    }

    protected void onMeasure(int i, int i2) {
        super.onMeasure(i, i2);
        if (this.f495l && MeasureSpec.getMode(i2) != 0 && getChildCount() > 0) {
            View childAt = getChildAt(0);
            int measuredHeight = getMeasuredHeight();
            if (childAt.getMeasuredHeight() < measuredHeight) {
                childAt.measure(getChildMeasureSpec(i, getPaddingLeft() + getPaddingRight(), ((FrameLayout.LayoutParams) childAt.getLayoutParams()).width), MeasureSpec.makeMeasureSpec((measuredHeight - getPaddingTop()) - getPaddingBottom(), 1073741824));
            }
        }
    }

    public boolean onNestedFling(View view, float f, float f2, boolean z) {
        if (z) {
            return false;
        }
        m1377f((int) f2);
        return true;
    }

    public boolean onNestedPreFling(View view, float f, float f2) {
        return dispatchNestedPreFling(f, f2);
    }

    public void onNestedPreScroll(View view, int i, int i2, int[] iArr) {
        dispatchNestedPreScroll(i, i2, iArr, null);
    }

    public void onNestedScroll(View view, int i, int i2, int i3, int i4) {
        int scrollY = getScrollY();
        scrollBy(0, i4);
        int scrollY2 = getScrollY() - scrollY;
        dispatchNestedScroll(0, scrollY2, 0, i4 - scrollY2, null);
    }

    public void onNestedScrollAccepted(View view, View view2, int i) {
        this.f505x.m969a(view, view2, i);
        startNestedScroll(2);
    }

    protected void onOverScrolled(int i, int i2, boolean z, boolean z2) {
        super.scrollTo(i, i2);
    }

    protected boolean onRequestFocusInDescendants(int i, Rect rect) {
        if (i == 2) {
            i = 130;
        } else if (i == 1) {
            i = 33;
        }
        View findNextFocus = rect == null ? FocusFinder.getInstance().findNextFocus(this, null, i) : FocusFinder.getInstance().findNextFocusFromRect(this, rect, i);
        return (findNextFocus == null || m1365a(findNextFocus)) ? false : findNextFocus.requestFocus(i, rect);
    }

    protected void onRestoreInstanceState(Parcelable parcelable) {
        if (parcelable instanceof af) {
            af afVar = (af) parcelable;
            super.onRestoreInstanceState(afVar.getSuperState());
            this.f504u = afVar;
            requestLayout();
            return;
        }
        super.onRestoreInstanceState(parcelable);
    }

    protected Parcelable onSaveInstanceState() {
        Parcelable afVar = new af(super.onSaveInstanceState());
        afVar.f526a = getScrollY();
        return afVar;
    }

    protected void onScrollChanged(int i, int i2, int i3, int i4) {
        super.onScrollChanged(i, i2, i3, i4);
        if (this.f483A != null) {
            this.f483A.m1429a(this, i, i2, i3, i4);
        }
    }

    protected void onSizeChanged(int i, int i2, int i3, int i4) {
        super.onSizeChanged(i, i2, i3, i4);
        View findFocus = findFocus();
        if (findFocus != null && this != findFocus && m1366a(findFocus, 0, i4)) {
            findFocus.getDrawingRect(this.f485b);
            offsetDescendantRectToMyCoords(findFocus, this.f485b);
            m1375e(m1379a(this.f485b));
        }
    }

    public boolean onStartNestedScroll(View view, View view2, int i) {
        return (i & 2) != 0;
    }

    public void onStopNestedScroll(View view) {
        this.f505x.m968a(view);
        stopNestedScroll();
    }

    public boolean onTouchEvent(MotionEvent motionEvent) {
        m1373d();
        MotionEvent obtain = MotionEvent.obtain(motionEvent);
        int a = az.m895a(motionEvent);
        if (a == 0) {
            this.f503t = 0;
        }
        obtain.offsetLocation(0.0f, (float) this.f503t);
        switch (a) {
            case C0243l.View_android_theme /*0*/:
                if (getChildCount() != 0) {
                    boolean z = !this.f486c.m1472a();
                    this.f493j = z;
                    if (z) {
                        ViewParent parent = getParent();
                        if (parent != null) {
                            parent.requestDisallowInterceptTouchEvent(true);
                        }
                    }
                    if (!this.f486c.m1472a()) {
                        this.f486c.m1479g();
                    }
                    this.f489f = (int) motionEvent.getY();
                    this.f500q = az.m898b(motionEvent, 0);
                    startNestedScroll(2);
                    break;
                }
                return false;
            case C0243l.View_android_focusable /*1*/:
                if (this.f493j) {
                    VelocityTracker velocityTracker = this.f494k;
                    velocityTracker.computeCurrentVelocity(1000, (float) this.f499p);
                    a = (int) bp.m971a(velocityTracker, this.f500q);
                    if (Math.abs(a) > this.f498o) {
                        m1377f(-a);
                    } else if (this.f486c.m1473a(getScrollX(), getScrollY(), 0, 0, 0, getScrollRange())) {
                        bu.m990b(this);
                    }
                }
                this.f500q = -1;
                m1376f();
                break;
            case C0243l.View_paddingStart /*2*/:
                int a2 = az.m896a(motionEvent, this.f500q);
                if (a2 != -1) {
                    int i;
                    int d = (int) az.m901d(motionEvent, a2);
                    a = this.f489f - d;
                    if (dispatchNestedPreScroll(0, a, this.f502s, this.f501r)) {
                        a -= this.f502s[1];
                        obtain.offsetLocation(0.0f, (float) this.f501r[1]);
                        this.f503t += this.f501r[1];
                    }
                    if (this.f493j || Math.abs(a) <= this.f497n) {
                        i = a;
                    } else {
                        ViewParent parent2 = getParent();
                        if (parent2 != null) {
                            parent2.requestDisallowInterceptTouchEvent(true);
                        }
                        this.f493j = true;
                        i = a > 0 ? a - this.f497n : a + this.f497n;
                    }
                    if (this.f493j) {
                        this.f489f = d - this.f501r[1];
                        int scrollY = getScrollY();
                        int scrollRange = getScrollRange();
                        a = bu.m977a(this);
                        Object obj = (a == 0 || (a == 1 && scrollRange > 0)) ? 1 : null;
                        if (m1382a(0, i, 0, getScrollY(), 0, scrollRange, 0, 0, true) && !hasNestedScrollingParent()) {
                            this.f494k.clear();
                        }
                        int scrollY2 = getScrollY() - scrollY;
                        if (!dispatchNestedScroll(0, scrollY2, 0, i - scrollY2, this.f501r)) {
                            if (obj != null) {
                                m1378g();
                                a = scrollY + i;
                                if (a < 0) {
                                    this.f487d.m1562a(((float) i) / ((float) getHeight()), az.m899c(motionEvent, a2) / ((float) getWidth()));
                                    if (!this.f488e.m1561a()) {
                                        this.f488e.m1565b();
                                    }
                                } else if (a > scrollRange) {
                                    this.f488e.m1562a(((float) i) / ((float) getHeight()), 1.0f - (az.m899c(motionEvent, a2) / ((float) getWidth())));
                                    if (!this.f487d.m1561a()) {
                                        this.f487d.m1565b();
                                    }
                                }
                                if (!(this.f487d == null || (this.f487d.m1561a() && this.f488e.m1561a()))) {
                                    bu.m990b(this);
                                    break;
                                }
                            }
                        }
                        this.f489f -= this.f501r[1];
                        obtain.offsetLocation(0.0f, (float) this.f501r[1]);
                        this.f503t += this.f501r[1];
                        break;
                    }
                }
                Log.e("NestedScrollView", "Invalid pointerId=" + this.f500q + " in onTouchEvent");
                break;
                break;
            case C0243l.View_paddingEnd /*3*/:
                if (this.f493j && getChildCount() > 0 && this.f486c.m1473a(getScrollX(), getScrollY(), 0, 0, 0, getScrollRange())) {
                    bu.m990b(this);
                }
                this.f500q = -1;
                m1376f();
                break;
            case C0243l.Toolbar_contentInsetStart /*5*/:
                a = az.m897b(motionEvent);
                this.f489f = (int) az.m901d(motionEvent, a);
                this.f500q = az.m898b(motionEvent, a);
                break;
            case C0243l.Toolbar_contentInsetEnd /*6*/:
                m1362a(motionEvent);
                this.f489f = (int) az.m901d(motionEvent, az.m896a(motionEvent, this.f500q));
                break;
        }
        if (this.f494k != null) {
            this.f494k.addMovement(obtain);
        }
        obtain.recycle();
        return true;
    }

    public void requestChildFocus(View view, View view2) {
        if (this.f490g) {
            this.f492i = view2;
        } else {
            m1369b(view2);
        }
        super.requestChildFocus(view, view2);
    }

    public boolean requestChildRectangleOnScreen(View view, Rect rect, boolean z) {
        rect.offset(view.getLeft() - view.getScrollX(), view.getTop() - view.getScrollY());
        return m1364a(rect, z);
    }

    public void requestDisallowInterceptTouchEvent(boolean z) {
        if (z) {
            m1374e();
        }
        super.requestDisallowInterceptTouchEvent(z);
    }

    public void requestLayout() {
        this.f490g = true;
        super.requestLayout();
    }

    public void scrollTo(int i, int i2) {
        if (getChildCount() > 0) {
            View childAt = getChildAt(0);
            int b = m1368b(i, (getWidth() - getPaddingRight()) - getPaddingLeft(), childAt.getWidth());
            int b2 = m1368b(i2, (getHeight() - getPaddingBottom()) - getPaddingTop(), childAt.getHeight());
            if (b != getScrollX() || b2 != getScrollY()) {
                super.scrollTo(b, b2);
            }
        }
    }

    public void setFillViewport(boolean z) {
        if (z != this.f495l) {
            this.f495l = z;
            requestLayout();
        }
    }

    public void setNestedScrollingEnabled(boolean z) {
        this.f506y.m958a(z);
    }

    public void setOnScrollChangeListener(ae aeVar) {
        this.f483A = aeVar;
    }

    public void setSmoothScrollingEnabled(boolean z) {
        this.f496m = z;
    }

    public boolean shouldDelayChildPressedState() {
        return true;
    }

    public boolean startNestedScroll(int i) {
        return this.f506y.m962a(i);
    }

    public void stopNestedScroll() {
        this.f506y.m966c();
    }
}

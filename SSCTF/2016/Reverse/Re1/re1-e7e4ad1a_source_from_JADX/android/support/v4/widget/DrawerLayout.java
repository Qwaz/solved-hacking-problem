package android.support.v4.widget;

import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.drawable.Drawable;
import android.os.Parcel;
import android.os.Parcelable;
import android.os.Parcelable.Creator;
import android.support.v4.view.C0036a;
import android.support.v4.view.C0043f;
import android.support.v4.view.C0061x;
import android.util.AttributeSet;
import android.view.KeyEvent;
import android.view.MotionEvent;
import android.view.View;
import android.view.View.BaseSavedState;
import android.view.ViewGroup;
import android.view.ViewGroup.LayoutParams;
import android.view.ViewGroup.MarginLayoutParams;

public class DrawerLayout extends ViewGroup {
    private static final int[] f270a;
    private int f271b;
    private int f272c;
    private float f273d;
    private Paint f274e;
    private final C0086y f275f;
    private final C0086y f276g;
    private final C0065d f277h;
    private final C0065d f278i;
    private int f279j;
    private boolean f280k;
    private boolean f281l;
    private int f282m;
    private int f283n;
    private boolean f284o;
    private boolean f285p;
    private C0062a f286q;
    private float f287r;
    private float f288s;
    private Drawable f289t;
    private Drawable f290u;

    public class SavedState extends BaseSavedState {
        public static final Creator CREATOR;
        int f267a;
        int f268b;
        int f269c;

        static {
            CREATOR = new C0064c();
        }

        public SavedState(Parcel parcel) {
            super(parcel);
            this.f267a = 0;
            this.f268b = 0;
            this.f269c = 0;
            this.f267a = parcel.readInt();
        }

        public SavedState(Parcelable parcelable) {
            super(parcelable);
            this.f267a = 0;
            this.f268b = 0;
            this.f269c = 0;
        }

        public void writeToParcel(Parcel parcel, int i) {
            super.writeToParcel(parcel, i);
            parcel.writeInt(this.f267a);
        }
    }

    static {
        f270a = new int[]{16842931};
    }

    static String m389b(int i) {
        return (i & 3) == 3 ? "LEFT" : (i & 5) == 5 ? "RIGHT" : Integer.toHexString(i);
    }

    private boolean m391d() {
        int childCount = getChildCount();
        for (int i = 0; i < childCount; i++) {
            if (((C0063b) getChildAt(i).getLayoutParams()).f314c) {
                return true;
            }
        }
        return false;
    }

    private boolean m392e() {
        return m393f() != null;
    }

    private View m393f() {
        int childCount = getChildCount();
        for (int i = 0; i < childCount; i++) {
            View childAt = getChildAt(i);
            if (m410g(childAt) && m413j(childAt)) {
                return childAt;
            }
        }
        return null;
    }

    private static boolean m394k(View view) {
        Drawable background = view.getBackground();
        return background != null && background.getOpacity() == -1;
    }

    public int m395a(View view) {
        int e = m408e(view);
        return e == 3 ? this.f282m : e == 5 ? this.f283n : 0;
    }

    View m396a() {
        int childCount = getChildCount();
        for (int i = 0; i < childCount; i++) {
            View childAt = getChildAt(i);
            if (((C0063b) childAt.getLayoutParams()).f315d) {
                return childAt;
            }
        }
        return null;
    }

    View m397a(int i) {
        int childCount = getChildCount();
        for (int i2 = 0; i2 < childCount; i2++) {
            View childAt = getChildAt(i2);
            if ((m408e(childAt) & 7) == (i & 7)) {
                return childAt;
            }
        }
        return null;
    }

    public void m398a(int i, int i2) {
        int a = C0036a.m245a(i2, C0061x.m387d(this));
        if (a == 3) {
            this.f282m = i;
        } else if (a == 5) {
            this.f283n = i;
        }
        if (i != 0) {
            (a == 3 ? this.f275f : this.f276g).m574e();
        }
        View a2;
        switch (i) {
            case 1:
                a2 = m397a(a);
                if (a2 != null) {
                    m412i(a2);
                }
            case 2:
                a2 = m397a(a);
                if (a2 != null) {
                    m411h(a2);
                }
            default:
        }
    }

    void m399a(int i, int i2, View view) {
        int i3 = 1;
        int a = this.f275f.m556a();
        int a2 = this.f276g.m556a();
        if (!(a == 1 || a2 == 1)) {
            i3 = (a == 2 || a2 == 2) ? 2 : 0;
        }
        if (view != null && i2 == 0) {
            C0063b c0063b = (C0063b) view.getLayoutParams();
            if (c0063b.f313b == 0.0f) {
                m404b(view);
            } else if (c0063b.f313b == 1.0f) {
                m406c(view);
            }
        }
        if (i3 != this.f279j) {
            this.f279j = i3;
            if (this.f286q != null) {
                this.f286q.m430a(i3);
            }
        }
    }

    void m400a(View view, float f) {
        if (this.f286q != null) {
            this.f286q.m432a(view, f);
        }
    }

    void m401a(boolean z) {
        int childCount = getChildCount();
        int i = 0;
        for (int i2 = 0; i2 < childCount; i2++) {
            View childAt = getChildAt(i2);
            C0063b c0063b = (C0063b) childAt.getLayoutParams();
            if (m410g(childAt) && (!z || c0063b.f314c)) {
                i = m402a(childAt, 3) ? i | this.f275f.m561a(childAt, -childAt.getWidth(), childAt.getTop()) : i | this.f276g.m561a(childAt, getWidth(), childAt.getTop());
                c0063b.f314c = false;
            }
        }
        this.f277h.m452a();
        this.f278i.m452a();
        if (i != 0) {
            invalidate();
        }
    }

    boolean m402a(View view, int i) {
        return (m408e(view) & i) == i;
    }

    public void m403b() {
        m401a(false);
    }

    void m404b(View view) {
        C0063b c0063b = (C0063b) view.getLayoutParams();
        if (c0063b.f315d) {
            c0063b.f315d = false;
            if (this.f286q != null) {
                this.f286q.m433b(view);
            }
            sendAccessibilityEvent(32);
        }
    }

    void m405b(View view, float f) {
        C0063b c0063b = (C0063b) view.getLayoutParams();
        if (f != c0063b.f313b) {
            c0063b.f313b = f;
            m400a(view, f);
        }
    }

    void m406c(View view) {
        C0063b c0063b = (C0063b) view.getLayoutParams();
        if (!c0063b.f315d) {
            c0063b.f315d = true;
            if (this.f286q != null) {
                this.f286q.m431a(view);
            }
            view.sendAccessibilityEvent(32);
        }
    }

    protected boolean checkLayoutParams(LayoutParams layoutParams) {
        return (layoutParams instanceof C0063b) && super.checkLayoutParams(layoutParams);
    }

    public void computeScroll() {
        int childCount = getChildCount();
        float f = 0.0f;
        for (int i = 0; i < childCount; i++) {
            f = Math.max(f, ((C0063b) getChildAt(i).getLayoutParams()).f313b);
        }
        this.f273d = f;
        if ((this.f275f.m562a(true) | this.f276g.m562a(true)) != 0) {
            C0061x.m385b(this);
        }
    }

    float m407d(View view) {
        return ((C0063b) view.getLayoutParams()).f313b;
    }

    protected boolean drawChild(Canvas canvas, View view, long j) {
        int i;
        int height = getHeight();
        boolean f = m409f(view);
        int i2 = 0;
        int width = getWidth();
        int save = canvas.save();
        if (f) {
            int childCount = getChildCount();
            int i3 = 0;
            while (i3 < childCount) {
                View childAt = getChildAt(i3);
                if (childAt != view && childAt.getVisibility() == 0 && m394k(childAt) && m410g(childAt)) {
                    if (childAt.getHeight() < height) {
                        i = width;
                    } else if (m402a(childAt, 3)) {
                        i = childAt.getRight();
                        if (i <= i2) {
                            i = i2;
                        }
                        i2 = i;
                        i = width;
                    } else {
                        i = childAt.getLeft();
                        if (i < width) {
                        }
                    }
                    i3++;
                    width = i;
                }
                i = width;
                i3++;
                width = i;
            }
            canvas.clipRect(i2, 0, width, getHeight());
        }
        i = width;
        boolean drawChild = super.drawChild(canvas, view, j);
        canvas.restoreToCount(save);
        if (this.f273d > 0.0f && f) {
            this.f274e.setColor((((int) (((float) ((this.f272c & -16777216) >>> 24)) * this.f273d)) << 24) | (this.f272c & 16777215));
            canvas.drawRect((float) i2, 0.0f, (float) i, (float) getHeight(), this.f274e);
        } else if (this.f289t != null && m402a(view, 3)) {
            i = this.f289t.getIntrinsicWidth();
            i2 = view.getRight();
            r2 = Math.max(0.0f, Math.min(((float) i2) / ((float) this.f275f.m563b()), 1.0f));
            this.f289t.setBounds(i2, view.getTop(), i + i2, view.getBottom());
            this.f289t.setAlpha((int) (255.0f * r2));
            this.f289t.draw(canvas);
        } else if (this.f290u != null && m402a(view, 5)) {
            i = this.f290u.getIntrinsicWidth();
            i2 = view.getLeft();
            r2 = Math.max(0.0f, Math.min(((float) (getWidth() - i2)) / ((float) this.f276g.m563b()), 1.0f));
            this.f290u.setBounds(i2 - i, view.getTop(), i2, view.getBottom());
            this.f290u.setAlpha((int) (255.0f * r2));
            this.f290u.draw(canvas);
        }
        return drawChild;
    }

    int m408e(View view) {
        return C0036a.m245a(((C0063b) view.getLayoutParams()).f312a, C0061x.m387d(view));
    }

    boolean m409f(View view) {
        return ((C0063b) view.getLayoutParams()).f312a == 0;
    }

    boolean m410g(View view) {
        return (C0036a.m245a(((C0063b) view.getLayoutParams()).f312a, C0061x.m387d(view)) & 7) != 0;
    }

    protected LayoutParams generateDefaultLayoutParams() {
        return new C0063b(-1, -1);
    }

    public LayoutParams generateLayoutParams(AttributeSet attributeSet) {
        return new C0063b(getContext(), attributeSet);
    }

    protected LayoutParams generateLayoutParams(LayoutParams layoutParams) {
        return layoutParams instanceof C0063b ? new C0063b((C0063b) layoutParams) : layoutParams instanceof MarginLayoutParams ? new C0063b((MarginLayoutParams) layoutParams) : new C0063b(layoutParams);
    }

    public void m411h(View view) {
        if (m410g(view)) {
            if (this.f281l) {
                C0063b c0063b = (C0063b) view.getLayoutParams();
                c0063b.f313b = 1.0f;
                c0063b.f315d = true;
            } else if (m402a(view, 3)) {
                this.f275f.m561a(view, 0, view.getTop());
            } else {
                this.f276g.m561a(view, getWidth() - view.getWidth(), view.getTop());
            }
            invalidate();
            return;
        }
        throw new IllegalArgumentException("View " + view + " is not a sliding drawer");
    }

    public void m412i(View view) {
        if (m410g(view)) {
            if (this.f281l) {
                C0063b c0063b = (C0063b) view.getLayoutParams();
                c0063b.f313b = 0.0f;
                c0063b.f315d = false;
            } else if (m402a(view, 3)) {
                this.f275f.m561a(view, -view.getWidth(), view.getTop());
            } else {
                this.f276g.m561a(view, getWidth(), view.getTop());
            }
            invalidate();
            return;
        }
        throw new IllegalArgumentException("View " + view + " is not a sliding drawer");
    }

    public boolean m413j(View view) {
        if (m410g(view)) {
            return ((C0063b) view.getLayoutParams()).f313b > 0.0f;
        } else {
            throw new IllegalArgumentException("View " + view + " is not a drawer");
        }
    }

    protected void onAttachedToWindow() {
        super.onAttachedToWindow();
        this.f281l = true;
    }

    protected void onDetachedFromWindow() {
        super.onDetachedFromWindow();
        this.f281l = true;
    }

    /* JADX WARNING: inconsistent code. */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    public boolean onInterceptTouchEvent(android.view.MotionEvent r8) {
        /*
        r7 = this;
        r1 = 1;
        r2 = 0;
        r0 = android.support.v4.view.C0050m.m324a(r8);
        r3 = r7.f275f;
        r3 = r3.m560a(r8);
        r4 = r7.f276g;
        r4 = r4.m560a(r8);
        r3 = r3 | r4;
        switch(r0) {
            case 0: goto L_0x0027;
            case 1: goto L_0x0063;
            case 2: goto L_0x004e;
            case 3: goto L_0x0063;
            default: goto L_0x0016;
        };
    L_0x0016:
        r0 = r2;
    L_0x0017:
        if (r3 != 0) goto L_0x0025;
    L_0x0019:
        if (r0 != 0) goto L_0x0025;
    L_0x001b:
        r0 = r7.m391d();
        if (r0 != 0) goto L_0x0025;
    L_0x0021:
        r0 = r7.f285p;
        if (r0 == 0) goto L_0x0026;
    L_0x0025:
        r2 = r1;
    L_0x0026:
        return r2;
    L_0x0027:
        r0 = r8.getX();
        r4 = r8.getY();
        r7.f287r = r0;
        r7.f288s = r4;
        r5 = r7.f273d;
        r6 = 0;
        r5 = (r5 > r6 ? 1 : (r5 == r6 ? 0 : -1));
        if (r5 <= 0) goto L_0x006b;
    L_0x003a:
        r5 = r7.f275f;
        r0 = (int) r0;
        r4 = (int) r4;
        r0 = r5.m573d(r0, r4);
        r0 = r7.m409f(r0);
        if (r0 == 0) goto L_0x006b;
    L_0x0048:
        r0 = r1;
    L_0x0049:
        r7.f284o = r2;
        r7.f285p = r2;
        goto L_0x0017;
    L_0x004e:
        r0 = r7.f275f;
        r4 = 3;
        r0 = r0.m570c(r4);
        if (r0 == 0) goto L_0x0016;
    L_0x0057:
        r0 = r7.f277h;
        r0.m452a();
        r0 = r7.f278i;
        r0.m452a();
        r0 = r2;
        goto L_0x0017;
    L_0x0063:
        r7.m401a(r1);
        r7.f284o = r2;
        r7.f285p = r2;
        goto L_0x0016;
    L_0x006b:
        r0 = r2;
        goto L_0x0049;
        */
        throw new UnsupportedOperationException("Method not decompiled: android.support.v4.widget.DrawerLayout.onInterceptTouchEvent(android.view.MotionEvent):boolean");
    }

    public boolean onKeyDown(int i, KeyEvent keyEvent) {
        if (i != 4 || !m392e()) {
            return super.onKeyDown(i, keyEvent);
        }
        C0043f.m307b(keyEvent);
        return true;
    }

    public boolean onKeyUp(int i, KeyEvent keyEvent) {
        if (i != 4) {
            return super.onKeyUp(i, keyEvent);
        }
        View f = m393f();
        if (f != null && m395a(f) == 0) {
            m403b();
        }
        return f != null;
    }

    protected void onLayout(boolean z, int i, int i2, int i3, int i4) {
        this.f280k = true;
        int i5 = i3 - i;
        int childCount = getChildCount();
        for (int i6 = 0; i6 < childCount; i6++) {
            View childAt = getChildAt(i6);
            if (childAt.getVisibility() != 8) {
                C0063b c0063b = (C0063b) childAt.getLayoutParams();
                if (m409f(childAt)) {
                    childAt.layout(c0063b.leftMargin, c0063b.topMargin, c0063b.leftMargin + childAt.getMeasuredWidth(), c0063b.topMargin + childAt.getMeasuredHeight());
                } else {
                    int i7;
                    float f;
                    int measuredWidth = childAt.getMeasuredWidth();
                    int measuredHeight = childAt.getMeasuredHeight();
                    if (m402a(childAt, 3)) {
                        i7 = ((int) (((float) measuredWidth) * c0063b.f313b)) + (-measuredWidth);
                        f = ((float) (measuredWidth + i7)) / ((float) measuredWidth);
                    } else {
                        i7 = i5 - ((int) (((float) measuredWidth) * c0063b.f313b));
                        f = ((float) (i5 - i7)) / ((float) measuredWidth);
                    }
                    Object obj = f != c0063b.f313b ? 1 : null;
                    int i8;
                    switch (c0063b.f312a & 112) {
                        case 16:
                            int i9 = i4 - i2;
                            i8 = (i9 - measuredHeight) / 2;
                            if (i8 < c0063b.topMargin) {
                                i8 = c0063b.topMargin;
                            } else if (i8 + measuredHeight > i9 - c0063b.bottomMargin) {
                                i8 = (i9 - c0063b.bottomMargin) - measuredHeight;
                            }
                            childAt.layout(i7, i8, measuredWidth + i7, measuredHeight + i8);
                            break;
                        case 80:
                            i8 = i4 - i2;
                            childAt.layout(i7, (i8 - c0063b.bottomMargin) - childAt.getMeasuredHeight(), measuredWidth + i7, i8 - c0063b.bottomMargin);
                            break;
                        default:
                            childAt.layout(i7, c0063b.topMargin, measuredWidth + i7, measuredHeight);
                            break;
                    }
                    if (obj != null) {
                        m405b(childAt, f);
                    }
                    int i10 = c0063b.f313b > 0.0f ? 0 : 4;
                    if (childAt.getVisibility() != i10) {
                        childAt.setVisibility(i10);
                    }
                }
            }
        }
        this.f280k = false;
        this.f281l = false;
    }

    /* JADX WARNING: inconsistent code. */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    protected void onMeasure(int r12, int r13) {
        /*
        r11 = this;
        r1 = 300; // 0x12c float:4.2E-43 double:1.48E-321;
        r4 = 0;
        r7 = -2147483648; // 0xffffffff80000000 float:-0.0 double:NaN;
        r10 = 1073741824; // 0x40000000 float:2.0 double:5.304989477E-315;
        r3 = android.view.View.MeasureSpec.getMode(r12);
        r5 = android.view.View.MeasureSpec.getMode(r13);
        r2 = android.view.View.MeasureSpec.getSize(r12);
        r0 = android.view.View.MeasureSpec.getSize(r13);
        if (r3 != r10) goto L_0x001b;
    L_0x0019:
        if (r5 == r10) goto L_0x0046;
    L_0x001b:
        r6 = r11.isInEditMode();
        if (r6 == 0) goto L_0x0048;
    L_0x0021:
        if (r3 != r7) goto L_0x0040;
    L_0x0023:
        if (r5 != r7) goto L_0x0044;
    L_0x0025:
        r1 = r0;
    L_0x0026:
        r11.setMeasuredDimension(r2, r1);
        r5 = r11.getChildCount();
        r3 = r4;
    L_0x002e:
        if (r3 >= r5) goto L_0x0109;
    L_0x0030:
        r6 = r11.getChildAt(r3);
        r0 = r6.getVisibility();
        r7 = 8;
        if (r0 != r7) goto L_0x0050;
    L_0x003c:
        r0 = r3 + 1;
        r3 = r0;
        goto L_0x002e;
    L_0x0040:
        if (r3 != 0) goto L_0x0023;
    L_0x0042:
        r2 = r1;
        goto L_0x0023;
    L_0x0044:
        if (r5 == 0) goto L_0x0026;
    L_0x0046:
        r1 = r0;
        goto L_0x0026;
    L_0x0048:
        r0 = new java.lang.IllegalArgumentException;
        r1 = "DrawerLayout must be measured with MeasureSpec.EXACTLY.";
        r0.<init>(r1);
        throw r0;
    L_0x0050:
        r0 = r6.getLayoutParams();
        r0 = (android.support.v4.widget.C0063b) r0;
        r7 = r11.m409f(r6);
        if (r7 == 0) goto L_0x0077;
    L_0x005c:
        r7 = r0.leftMargin;
        r7 = r2 - r7;
        r8 = r0.rightMargin;
        r7 = r7 - r8;
        r7 = android.view.View.MeasureSpec.makeMeasureSpec(r7, r10);
        r8 = r0.topMargin;
        r8 = r1 - r8;
        r0 = r0.bottomMargin;
        r0 = r8 - r0;
        r0 = android.view.View.MeasureSpec.makeMeasureSpec(r0, r10);
        r6.measure(r7, r0);
        goto L_0x003c;
    L_0x0077:
        r7 = r11.m410g(r6);
        if (r7 == 0) goto L_0x00da;
    L_0x007d:
        r7 = r11.m408e(r6);
        r7 = r7 & 7;
        r8 = r4 & r7;
        if (r8 == 0) goto L_0x00bc;
    L_0x0087:
        r0 = new java.lang.IllegalStateException;
        r1 = new java.lang.StringBuilder;
        r1.<init>();
        r2 = "Child drawer has absolute gravity ";
        r1 = r1.append(r2);
        r2 = m389b(r7);
        r1 = r1.append(r2);
        r2 = " but this ";
        r1 = r1.append(r2);
        r2 = "DrawerLayout";
        r1 = r1.append(r2);
        r2 = " already has a ";
        r1 = r1.append(r2);
        r2 = "drawer view along that edge";
        r1 = r1.append(r2);
        r1 = r1.toString();
        r0.<init>(r1);
        throw r0;
    L_0x00bc:
        r7 = r11.f271b;
        r8 = r0.leftMargin;
        r7 = r7 + r8;
        r8 = r0.rightMargin;
        r7 = r7 + r8;
        r8 = r0.width;
        r7 = getChildMeasureSpec(r12, r7, r8);
        r8 = r0.topMargin;
        r9 = r0.bottomMargin;
        r8 = r8 + r9;
        r0 = r0.height;
        r0 = getChildMeasureSpec(r13, r8, r0);
        r6.measure(r7, r0);
        goto L_0x003c;
    L_0x00da:
        r0 = new java.lang.IllegalStateException;
        r1 = new java.lang.StringBuilder;
        r1.<init>();
        r2 = "Child ";
        r1 = r1.append(r2);
        r1 = r1.append(r6);
        r2 = " at index ";
        r1 = r1.append(r2);
        r1 = r1.append(r3);
        r2 = " does not have a valid layout_gravity - must be Gravity.LEFT, ";
        r1 = r1.append(r2);
        r2 = "Gravity.RIGHT or Gravity.NO_GRAVITY";
        r1 = r1.append(r2);
        r1 = r1.toString();
        r0.<init>(r1);
        throw r0;
    L_0x0109:
        return;
        */
        throw new UnsupportedOperationException("Method not decompiled: android.support.v4.widget.DrawerLayout.onMeasure(int, int):void");
    }

    protected void onRestoreInstanceState(Parcelable parcelable) {
        SavedState savedState = (SavedState) parcelable;
        super.onRestoreInstanceState(savedState.getSuperState());
        if (savedState.f267a != 0) {
            View a = m397a(savedState.f267a);
            if (a != null) {
                m411h(a);
            }
        }
        m398a(savedState.f268b, 3);
        m398a(savedState.f269c, 5);
    }

    protected Parcelable onSaveInstanceState() {
        Parcelable savedState = new SavedState(super.onSaveInstanceState());
        int childCount = getChildCount();
        for (int i = 0; i < childCount; i++) {
            View childAt = getChildAt(i);
            if (m410g(childAt)) {
                C0063b c0063b = (C0063b) childAt.getLayoutParams();
                if (c0063b.f315d) {
                    savedState.f267a = c0063b.f312a;
                    break;
                }
            }
        }
        savedState.f268b = this.f282m;
        savedState.f269c = this.f283n;
        return savedState;
    }

    public boolean onTouchEvent(MotionEvent motionEvent) {
        this.f275f.m565b(motionEvent);
        this.f276g.m565b(motionEvent);
        float x;
        float y;
        switch (motionEvent.getAction() & 255) {
            case 0:
                x = motionEvent.getX();
                y = motionEvent.getY();
                this.f287r = x;
                this.f288s = y;
                this.f284o = false;
                this.f285p = false;
                break;
            case 1:
                boolean z;
                x = motionEvent.getX();
                y = motionEvent.getY();
                View d = this.f275f.m573d((int) x, (int) y);
                if (d != null && m409f(d)) {
                    x -= this.f287r;
                    y -= this.f288s;
                    int d2 = this.f275f.m572d();
                    if ((x * x) + (y * y) < ((float) (d2 * d2))) {
                        View a = m396a();
                        if (a != null) {
                            z = m395a(a) == 2;
                            m401a(z);
                            this.f284o = false;
                            break;
                        }
                    }
                }
                z = true;
                m401a(z);
                this.f284o = false;
            case 3:
                m401a(true);
                this.f284o = false;
                this.f285p = false;
                break;
        }
        return true;
    }

    public void requestDisallowInterceptTouchEvent(boolean z) {
        super.requestDisallowInterceptTouchEvent(z);
        this.f284o = z;
        if (z) {
            m401a(true);
        }
    }

    public void requestLayout() {
        if (!this.f280k) {
            super.requestLayout();
        }
    }

    public void setDrawerListener(C0062a c0062a) {
        this.f286q = c0062a;
    }

    public void setDrawerLockMode(int i) {
        m398a(i, 3);
        m398a(i, 5);
    }

    public void setScrimColor(int i) {
        this.f272c = i;
        invalidate();
    }
}

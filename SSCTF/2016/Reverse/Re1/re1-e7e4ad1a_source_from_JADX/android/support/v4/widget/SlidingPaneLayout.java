package android.support.v4.widget;

import android.graphics.Bitmap;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.PorterDuff.Mode;
import android.graphics.PorterDuffColorFilter;
import android.graphics.Rect;
import android.graphics.drawable.Drawable;
import android.os.Build.VERSION;
import android.os.Parcel;
import android.os.Parcelable;
import android.os.Parcelable.Creator;
import android.support.v4.view.C0061x;
import android.util.AttributeSet;
import android.util.Log;
import android.view.MotionEvent;
import android.view.View;
import android.view.View.BaseSavedState;
import android.view.View.MeasureSpec;
import android.view.ViewGroup;
import android.view.ViewGroup.LayoutParams;
import android.view.ViewGroup.MarginLayoutParams;
import java.util.ArrayList;

public class SlidingPaneLayout extends ViewGroup {
    static final C0082u f292a;
    private int f293b;
    private int f294c;
    private Drawable f295d;
    private final int f296e;
    private boolean f297f;
    private View f298g;
    private float f299h;
    private float f300i;
    private int f301j;
    private boolean f302k;
    private int f303l;
    private float f304m;
    private float f305n;
    private C0080s f306o;
    private final C0086y f307p;
    private boolean f308q;
    private boolean f309r;
    private final Rect f310s;
    private final ArrayList f311t;

    class SavedState extends BaseSavedState {
        public static final Creator CREATOR;
        boolean f291a;

        static {
            CREATOR = new C0081t();
        }

        private SavedState(Parcel parcel) {
            super(parcel);
            this.f291a = parcel.readInt() != 0;
        }

        SavedState(Parcelable parcelable) {
            super(parcelable);
        }

        public void writeToParcel(Parcel parcel, int i) {
            super.writeToParcel(parcel, i);
            parcel.writeInt(this.f291a ? 1 : 0);
        }
    }

    static {
        int i = VERSION.SDK_INT;
        if (i >= 17) {
            f292a = new C0085x();
        } else if (i >= 16) {
            f292a = new C0084w();
        } else {
            f292a = new C0083v();
        }
    }

    private void m415a(float f) {
        int i = 0;
        C0079r c0079r = (C0079r) this.f298g.getLayoutParams();
        int i2 = (!c0079r.f329c || c0079r.leftMargin > 0) ? 0 : 1;
        int childCount = getChildCount();
        while (i < childCount) {
            View childAt = getChildAt(i);
            if (childAt != this.f298g) {
                int i3 = (int) ((1.0f - this.f300i) * ((float) this.f303l));
                this.f300i = f;
                childAt.offsetLeftAndRight(i3 - ((int) ((1.0f - f) * ((float) this.f303l))));
                if (i2 != 0) {
                    m417a(childAt, 1.0f - this.f300i, this.f294c);
                }
            }
            i++;
        }
    }

    private void m417a(View view, float f, int i) {
        C0079r c0079r = (C0079r) view.getLayoutParams();
        if (f > 0.0f && i != 0) {
            int i2 = (((int) (((float) ((-16777216 & i) >>> 24)) * f)) << 24) | (16777215 & i);
            if (c0079r.f330d == null) {
                c0079r.f330d = new Paint();
            }
            c0079r.f330d.setColorFilter(new PorterDuffColorFilter(i2, Mode.SRC_OVER));
            if (C0061x.m386c(view) != 2) {
                C0061x.m381a(view, 2, c0079r.f330d);
            }
            m421d(view);
        } else if (C0061x.m386c(view) != 0) {
            if (c0079r.f330d != null) {
                c0079r.f330d.setColorFilter(null);
            }
            Runnable c0078q = new C0078q(this, view);
            this.f311t.add(c0078q);
            C0061x.m383a((View) this, c0078q);
        }
    }

    private boolean m418a(View view, int i) {
        if (!this.f309r && !m424a(0.0f, i)) {
            return false;
        }
        this.f308q = false;
        return true;
    }

    private boolean m419b(View view, int i) {
        if (!this.f309r && !m424a(1.0f, i)) {
            return false;
        }
        this.f308q = true;
        return true;
    }

    private static boolean m420c(View view) {
        if (C0061x.m388e(view)) {
            return true;
        }
        if (VERSION.SDK_INT >= 18) {
            return false;
        }
        Drawable background = view.getBackground();
        return background != null ? background.getOpacity() == -1 : false;
    }

    private void m421d(View view) {
        f292a.m534a(this, view);
    }

    void m422a() {
        int childCount = getChildCount();
        for (int i = 0; i < childCount; i++) {
            View childAt = getChildAt(i);
            if (childAt.getVisibility() == 4) {
                childAt.setVisibility(0);
            }
        }
    }

    void m423a(View view) {
        int i;
        int i2;
        int i3;
        int i4;
        int paddingLeft = getPaddingLeft();
        int width = getWidth() - getPaddingRight();
        int paddingTop = getPaddingTop();
        int height = getHeight() - getPaddingBottom();
        if (view == null || !m420c(view)) {
            i = 0;
            i2 = 0;
            i3 = 0;
            i4 = 0;
        } else {
            i4 = view.getLeft();
            i3 = view.getRight();
            i2 = view.getTop();
            i = view.getBottom();
        }
        int childCount = getChildCount();
        int i5 = 0;
        while (i5 < childCount) {
            View childAt = getChildAt(i5);
            if (childAt != view) {
                int i6 = (Math.max(paddingLeft, childAt.getLeft()) < i4 || Math.max(paddingTop, childAt.getTop()) < i2 || Math.min(width, childAt.getRight()) > i3 || Math.min(height, childAt.getBottom()) > i) ? 0 : 4;
                childAt.setVisibility(i6);
                i5++;
            } else {
                return;
            }
        }
    }

    boolean m424a(float f, int i) {
        if (!this.f297f) {
            return false;
        }
        C0079r c0079r = (C0079r) this.f298g.getLayoutParams();
        if (!this.f307p.m561a(this.f298g, (int) (((float) (c0079r.leftMargin + getPaddingLeft())) + (((float) this.f301j) * f)), this.f298g.getTop())) {
            return false;
        }
        m422a();
        C0061x.m385b(this);
        return true;
    }

    public boolean m425b() {
        return m419b(this.f298g, 0);
    }

    boolean m426b(View view) {
        if (view == null) {
            return false;
        }
        boolean z = this.f297f && ((C0079r) view.getLayoutParams()).f329c && this.f299h > 0.0f;
        return z;
    }

    public boolean m427c() {
        return m418a(this.f298g, 0);
    }

    protected boolean checkLayoutParams(LayoutParams layoutParams) {
        return (layoutParams instanceof C0079r) && super.checkLayoutParams(layoutParams);
    }

    public void computeScroll() {
        if (!this.f307p.m562a(true)) {
            return;
        }
        if (this.f297f) {
            C0061x.m385b(this);
        } else {
            this.f307p.m575f();
        }
    }

    public boolean m428d() {
        return !this.f297f || this.f299h == 1.0f;
    }

    public void draw(Canvas canvas) {
        super.draw(canvas);
        View childAt = getChildCount() > 1 ? getChildAt(1) : null;
        if (childAt != null && this.f295d != null) {
            int intrinsicWidth = this.f295d.getIntrinsicWidth();
            int left = childAt.getLeft();
            this.f295d.setBounds(left - intrinsicWidth, childAt.getTop(), left, childAt.getBottom());
            this.f295d.draw(canvas);
        }
    }

    protected boolean drawChild(Canvas canvas, View view, long j) {
        boolean drawChild;
        C0079r c0079r = (C0079r) view.getLayoutParams();
        int save = canvas.save(2);
        if (!(!this.f297f || c0079r.f328b || this.f298g == null)) {
            canvas.getClipBounds(this.f310s);
            this.f310s.right = Math.min(this.f310s.right, this.f298g.getLeft());
            canvas.clipRect(this.f310s);
        }
        if (VERSION.SDK_INT >= 11) {
            drawChild = super.drawChild(canvas, view, j);
        } else if (!c0079r.f329c || this.f299h <= 0.0f) {
            if (view.isDrawingCacheEnabled()) {
                view.setDrawingCacheEnabled(false);
            }
            drawChild = super.drawChild(canvas, view, j);
        } else {
            if (!view.isDrawingCacheEnabled()) {
                view.setDrawingCacheEnabled(true);
            }
            Bitmap drawingCache = view.getDrawingCache();
            if (drawingCache != null) {
                canvas.drawBitmap(drawingCache, (float) view.getLeft(), (float) view.getTop(), c0079r.f330d);
                drawChild = false;
            } else {
                Log.e("SlidingPaneLayout", "drawChild: child view " + view + " returned null drawing cache");
                drawChild = super.drawChild(canvas, view, j);
            }
        }
        canvas.restoreToCount(save);
        return drawChild;
    }

    public boolean m429e() {
        return this.f297f;
    }

    protected LayoutParams generateDefaultLayoutParams() {
        return new C0079r();
    }

    public LayoutParams generateLayoutParams(AttributeSet attributeSet) {
        return new C0079r(getContext(), attributeSet);
    }

    protected LayoutParams generateLayoutParams(LayoutParams layoutParams) {
        return layoutParams instanceof MarginLayoutParams ? new C0079r((MarginLayoutParams) layoutParams) : new C0079r(layoutParams);
    }

    public int getCoveredFadeColor() {
        return this.f294c;
    }

    public int getParallaxDistance() {
        return this.f303l;
    }

    public int getSliderFadeColor() {
        return this.f293b;
    }

    protected void onAttachedToWindow() {
        super.onAttachedToWindow();
        this.f309r = true;
    }

    protected void onDetachedFromWindow() {
        super.onDetachedFromWindow();
        this.f309r = true;
        int size = this.f311t.size();
        for (int i = 0; i < size; i++) {
            ((C0078q) this.f311t.get(i)).run();
        }
        this.f311t.clear();
    }

    /* JADX WARNING: inconsistent code. */
    /* Code decompiled incorrectly, please refer to instructions dump. */
    public boolean onInterceptTouchEvent(android.view.MotionEvent r8) {
        /*
        r7 = this;
        r2 = 0;
        r1 = 1;
        r3 = android.support.v4.view.C0050m.m324a(r8);
        r0 = r7.f297f;
        if (r0 != 0) goto L_0x002d;
    L_0x000a:
        if (r3 != 0) goto L_0x002d;
    L_0x000c:
        r0 = r7.getChildCount();
        if (r0 <= r1) goto L_0x002d;
    L_0x0012:
        r0 = r7.getChildAt(r1);
        if (r0 == 0) goto L_0x002d;
    L_0x0018:
        r4 = r7.f307p;
        r5 = r8.getX();
        r5 = (int) r5;
        r6 = r8.getY();
        r6 = (int) r6;
        r0 = r4.m568b(r0, r5, r6);
        if (r0 != 0) goto L_0x0041;
    L_0x002a:
        r0 = r1;
    L_0x002b:
        r7.f308q = r0;
    L_0x002d:
        r0 = r7.f297f;
        if (r0 == 0) goto L_0x0037;
    L_0x0031:
        r0 = r7.f302k;
        if (r0 == 0) goto L_0x0043;
    L_0x0035:
        if (r3 == 0) goto L_0x0043;
    L_0x0037:
        r0 = r7.f307p;
        r0.m574e();
        r2 = super.onInterceptTouchEvent(r8);
    L_0x0040:
        return r2;
    L_0x0041:
        r0 = r2;
        goto L_0x002b;
    L_0x0043:
        r0 = 3;
        if (r3 == r0) goto L_0x0048;
    L_0x0046:
        if (r3 != r1) goto L_0x004e;
    L_0x0048:
        r0 = r7.f307p;
        r0.m574e();
        goto L_0x0040;
    L_0x004e:
        switch(r3) {
            case 0: goto L_0x005e;
            case 1: goto L_0x0051;
            case 2: goto L_0x0082;
            default: goto L_0x0051;
        };
    L_0x0051:
        r0 = r2;
    L_0x0052:
        r3 = r7.f307p;
        r3 = r3.m560a(r8);
        if (r3 != 0) goto L_0x005c;
    L_0x005a:
        if (r0 == 0) goto L_0x0040;
    L_0x005c:
        r2 = r1;
        goto L_0x0040;
    L_0x005e:
        r7.f302k = r2;
        r0 = r8.getX();
        r3 = r8.getY();
        r7.f304m = r0;
        r7.f305n = r3;
        r4 = r7.f307p;
        r5 = r7.f298g;
        r0 = (int) r0;
        r3 = (int) r3;
        r0 = r4.m568b(r5, r0, r3);
        if (r0 == 0) goto L_0x0051;
    L_0x0078:
        r0 = r7.f298g;
        r0 = r7.m426b(r0);
        if (r0 == 0) goto L_0x0051;
    L_0x0080:
        r0 = r1;
        goto L_0x0052;
    L_0x0082:
        r0 = r8.getX();
        r3 = r8.getY();
        r4 = r7.f304m;
        r0 = r0 - r4;
        r0 = java.lang.Math.abs(r0);
        r4 = r7.f305n;
        r3 = r3 - r4;
        r3 = java.lang.Math.abs(r3);
        r4 = r7.f307p;
        r4 = r4.m572d();
        r4 = (float) r4;
        r4 = (r0 > r4 ? 1 : (r0 == r4 ? 0 : -1));
        if (r4 <= 0) goto L_0x0051;
    L_0x00a3:
        r0 = (r3 > r0 ? 1 : (r3 == r0 ? 0 : -1));
        if (r0 <= 0) goto L_0x0051;
    L_0x00a7:
        r0 = r7.f307p;
        r0.m574e();
        r7.f302k = r1;
        goto L_0x0040;
        */
        throw new UnsupportedOperationException("Method not decompiled: android.support.v4.widget.SlidingPaneLayout.onInterceptTouchEvent(android.view.MotionEvent):boolean");
    }

    protected void onLayout(boolean z, int i, int i2, int i3, int i4) {
        int i5 = i3 - i;
        int paddingLeft = getPaddingLeft();
        int paddingRight = getPaddingRight();
        int paddingTop = getPaddingTop();
        int childCount = getChildCount();
        if (this.f309r) {
            float f = (this.f297f && this.f308q) ? 1.0f : 0.0f;
            this.f299h = f;
        }
        int i6 = 0;
        int i7 = paddingLeft;
        while (i6 < childCount) {
            int i8;
            int i9;
            View childAt = getChildAt(i6);
            if (childAt.getVisibility() == 8) {
                i8 = i7;
            } else {
                C0079r c0079r = (C0079r) childAt.getLayoutParams();
                int measuredWidth = childAt.getMeasuredWidth();
                if (c0079r.f328b) {
                    int min = (Math.min(paddingLeft, (i5 - paddingRight) - this.f296e) - i7) - (c0079r.leftMargin + c0079r.rightMargin);
                    this.f301j = min;
                    c0079r.f329c = ((c0079r.leftMargin + i7) + min) + (measuredWidth / 2) > i5 - paddingRight;
                    i8 = (c0079r.leftMargin + ((int) (((float) min) * this.f299h))) + i7;
                    i9 = 0;
                } else if (!this.f297f || this.f303l == 0) {
                    i9 = 0;
                    i8 = paddingLeft;
                } else {
                    i9 = (int) ((1.0f - this.f299h) * ((float) this.f303l));
                    i8 = paddingLeft;
                }
                i9 = i8 - i9;
                childAt.layout(i9, paddingTop, i9 + measuredWidth, childAt.getMeasuredHeight() + paddingTop);
                paddingLeft += childAt.getWidth();
            }
            i6++;
            i7 = i8;
        }
        if (this.f309r) {
            if (this.f297f) {
                if (this.f303l != 0) {
                    m415a(this.f299h);
                }
                if (((C0079r) this.f298g.getLayoutParams()).f329c) {
                    m417a(this.f298g, this.f299h, this.f293b);
                }
            } else {
                for (i9 = 0; i9 < childCount; i9++) {
                    m417a(getChildAt(i9), 0.0f, this.f293b);
                }
            }
            m423a(this.f298g);
        }
        this.f309r = false;
    }

    protected void onMeasure(int i, int i2) {
        int i3;
        int i4;
        int mode = MeasureSpec.getMode(i);
        int size = MeasureSpec.getSize(i);
        int mode2 = MeasureSpec.getMode(i2);
        int size2 = MeasureSpec.getSize(i2);
        if (mode == 1073741824) {
            if (mode2 == 0) {
                if (!isInEditMode()) {
                    throw new IllegalStateException("Height must not be UNSPECIFIED");
                } else if (mode2 == 0) {
                    i3 = Integer.MIN_VALUE;
                    i4 = size;
                    size = 300;
                }
            }
            i3 = mode2;
            i4 = size;
            size = size2;
        } else if (!isInEditMode()) {
            throw new IllegalStateException("Width must have an exact value or MATCH_PARENT");
        } else if (mode == Integer.MIN_VALUE) {
            i3 = mode2;
            i4 = size;
            size = size2;
        } else {
            if (mode == 0) {
                i3 = mode2;
                i4 = 300;
                size = size2;
            }
            i3 = mode2;
            i4 = size;
            size = size2;
        }
        switch (i3) {
            case Integer.MIN_VALUE:
                size2 = 0;
                mode2 = (size - getPaddingTop()) - getPaddingBottom();
                break;
            case 1073741824:
                size2 = (size - getPaddingTop()) - getPaddingBottom();
                mode2 = size2;
                break;
            default:
                size2 = 0;
                mode2 = -1;
                break;
        }
        boolean z = false;
        int paddingLeft = (i4 - getPaddingLeft()) - getPaddingRight();
        int childCount = getChildCount();
        if (childCount > 2) {
            Log.e("SlidingPaneLayout", "onMeasure: More than two child views are not supported.");
        }
        this.f298g = null;
        int i5 = 0;
        int i6 = size2;
        float f = 0.0f;
        while (i5 < childCount) {
            float f2;
            int i7;
            boolean z2;
            View childAt = getChildAt(i5);
            C0079r c0079r = (C0079r) childAt.getLayoutParams();
            if (childAt.getVisibility() == 8) {
                c0079r.f329c = false;
                size2 = paddingLeft;
                f2 = f;
                i7 = i6;
                z2 = z;
            } else {
                if (c0079r.f327a > 0.0f) {
                    f += c0079r.f327a;
                    if (c0079r.width == 0) {
                        size2 = paddingLeft;
                        f2 = f;
                        i7 = i6;
                        z2 = z;
                    }
                }
                mode = c0079r.leftMargin + c0079r.rightMargin;
                mode = c0079r.width == -2 ? MeasureSpec.makeMeasureSpec(i4 - mode, Integer.MIN_VALUE) : c0079r.width == -1 ? MeasureSpec.makeMeasureSpec(i4 - mode, 1073741824) : MeasureSpec.makeMeasureSpec(c0079r.width, 1073741824);
                i7 = c0079r.height == -2 ? MeasureSpec.makeMeasureSpec(mode2, Integer.MIN_VALUE) : c0079r.height == -1 ? MeasureSpec.makeMeasureSpec(mode2, 1073741824) : MeasureSpec.makeMeasureSpec(c0079r.height, 1073741824);
                childAt.measure(mode, i7);
                mode = childAt.getMeasuredWidth();
                i7 = childAt.getMeasuredHeight();
                if (i3 == Integer.MIN_VALUE && i7 > i6) {
                    i6 = Math.min(i7, mode2);
                }
                i7 = paddingLeft - mode;
                boolean z3 = i7 < 0;
                c0079r.f328b = z3;
                z3 |= z;
                if (c0079r.f328b) {
                    this.f298g = childAt;
                }
                size2 = i7;
                i7 = i6;
                float f3 = f;
                z2 = z3;
                f2 = f3;
            }
            i5++;
            z = z2;
            i6 = i7;
            f = f2;
            paddingLeft = size2;
        }
        if (z || f > 0.0f) {
            int i8 = i4 - this.f296e;
            for (i3 = 0; i3 < childCount; i3++) {
                View childAt2 = getChildAt(i3);
                if (childAt2.getVisibility() != 8) {
                    c0079r = (C0079r) childAt2.getLayoutParams();
                    if (childAt2.getVisibility() != 8) {
                        Object obj = (c0079r.width != 0 || c0079r.f327a <= 0.0f) ? null : 1;
                        i7 = obj != null ? 0 : childAt2.getMeasuredWidth();
                        if (!z || childAt2 == this.f298g) {
                            if (c0079r.f327a > 0.0f) {
                                mode = c0079r.width == 0 ? c0079r.height == -2 ? MeasureSpec.makeMeasureSpec(mode2, Integer.MIN_VALUE) : c0079r.height == -1 ? MeasureSpec.makeMeasureSpec(mode2, 1073741824) : MeasureSpec.makeMeasureSpec(c0079r.height, 1073741824) : MeasureSpec.makeMeasureSpec(childAt2.getMeasuredHeight(), 1073741824);
                                if (z) {
                                    size2 = i4 - (c0079r.rightMargin + c0079r.leftMargin);
                                    i5 = MeasureSpec.makeMeasureSpec(size2, 1073741824);
                                    if (i7 != size2) {
                                        childAt2.measure(i5, mode);
                                    }
                                } else {
                                    childAt2.measure(MeasureSpec.makeMeasureSpec(((int) ((c0079r.f327a * ((float) Math.max(0, paddingLeft))) / f)) + i7, 1073741824), mode);
                                }
                            }
                        } else if (c0079r.width < 0 && (i7 > i8 || c0079r.f327a > 0.0f)) {
                            size2 = obj != null ? c0079r.height == -2 ? MeasureSpec.makeMeasureSpec(mode2, Integer.MIN_VALUE) : c0079r.height == -1 ? MeasureSpec.makeMeasureSpec(mode2, 1073741824) : MeasureSpec.makeMeasureSpec(c0079r.height, 1073741824) : MeasureSpec.makeMeasureSpec(childAt2.getMeasuredHeight(), 1073741824);
                            childAt2.measure(MeasureSpec.makeMeasureSpec(i8, 1073741824), size2);
                        }
                    }
                }
            }
        }
        setMeasuredDimension(i4, i6);
        this.f297f = z;
        if (this.f307p.m556a() != 0 && !z) {
            this.f307p.m575f();
        }
    }

    protected void onRestoreInstanceState(Parcelable parcelable) {
        SavedState savedState = (SavedState) parcelable;
        super.onRestoreInstanceState(savedState.getSuperState());
        if (savedState.f291a) {
            m425b();
        } else {
            m427c();
        }
        this.f308q = savedState.f291a;
    }

    protected Parcelable onSaveInstanceState() {
        Parcelable savedState = new SavedState(super.onSaveInstanceState());
        savedState.f291a = m429e() ? m428d() : this.f308q;
        return savedState;
    }

    protected void onSizeChanged(int i, int i2, int i3, int i4) {
        super.onSizeChanged(i, i2, i3, i4);
        if (i != i3) {
            this.f309r = true;
        }
    }

    public boolean onTouchEvent(MotionEvent motionEvent) {
        if (!this.f297f) {
            return super.onTouchEvent(motionEvent);
        }
        this.f307p.m565b(motionEvent);
        float x;
        float y;
        switch (motionEvent.getAction() & 255) {
            case 0:
                x = motionEvent.getX();
                y = motionEvent.getY();
                this.f304m = x;
                this.f305n = y;
                return true;
            case 1:
                if (!m426b(this.f298g)) {
                    return true;
                }
                x = motionEvent.getX();
                y = motionEvent.getY();
                float f = x - this.f304m;
                float f2 = y - this.f305n;
                int d = this.f307p.m572d();
                if ((f * f) + (f2 * f2) >= ((float) (d * d)) || !this.f307p.m568b(this.f298g, (int) x, (int) y)) {
                    return true;
                }
                m418a(this.f298g, 0);
                return true;
            default:
                return true;
        }
    }

    public void requestChildFocus(View view, View view2) {
        super.requestChildFocus(view, view2);
        if (!isInTouchMode() && !this.f297f) {
            this.f308q = view == this.f298g;
        }
    }

    public void setCoveredFadeColor(int i) {
        this.f294c = i;
    }

    public void setPanelSlideListener(C0080s c0080s) {
        this.f306o = c0080s;
    }

    public void setParallaxDistance(int i) {
        this.f303l = i;
        requestLayout();
    }

    public void setShadowDrawable(Drawable drawable) {
        this.f295d = drawable;
    }

    public void setShadowResource(int i) {
        setShadowDrawable(getResources().getDrawable(i));
    }

    public void setSliderFadeColor(int i) {
        this.f293b = i;
    }
}

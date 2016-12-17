package android.support.v7.widget;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.drawable.Drawable;
import android.os.Build.VERSION;
import android.support.v4.p004h.C0164q;
import android.support.v4.p004h.bu;
import android.support.v7.p015b.C0243l;
import android.util.AttributeSet;
import android.view.View;
import android.view.View.MeasureSpec;
import android.view.ViewGroup;
import android.view.ViewGroup.LayoutParams;
import android.view.accessibility.AccessibilityEvent;
import android.view.accessibility.AccessibilityNodeInfo;

public class bw extends ViewGroup {
    private boolean f1133a;
    private int f1134b;
    private int f1135c;
    private int f1136d;
    private int f1137e;
    private int f1138f;
    private float f1139g;
    private boolean f1140h;
    private int[] f1141i;
    private int[] f1142j;
    private Drawable f1143k;
    private int f1144l;
    private int f1145m;
    private int f1146n;
    private int f1147o;

    public bw(Context context) {
        this(context, null);
    }

    public bw(Context context, AttributeSet attributeSet) {
        this(context, attributeSet, 0);
    }

    public bw(Context context, AttributeSet attributeSet, int i) {
        super(context, attributeSet, i);
        this.f1133a = true;
        this.f1134b = -1;
        this.f1135c = 0;
        this.f1137e = 8388659;
        dh a = dh.m2710a(context, attributeSet, C0243l.LinearLayoutCompat, i, 0);
        int a2 = a.m2712a(C0243l.LinearLayoutCompat_android_orientation, -1);
        if (a2 >= 0) {
            setOrientation(a2);
        }
        a2 = a.m2712a(C0243l.LinearLayoutCompat_android_gravity, -1);
        if (a2 >= 0) {
            setGravity(a2);
        }
        boolean a3 = a.m2715a(C0243l.LinearLayoutCompat_android_baselineAligned, true);
        if (!a3) {
            setBaselineAligned(a3);
        }
        this.f1139g = a.m2711a(C0243l.LinearLayoutCompat_android_weightSum, -1.0f);
        this.f1134b = a.m2712a(C0243l.LinearLayoutCompat_android_baselineAlignedChildIndex, -1);
        this.f1140h = a.m2715a(C0243l.LinearLayoutCompat_measureWithLargestChild, false);
        setDividerDrawable(a.m2713a(C0243l.LinearLayoutCompat_divider));
        this.f1146n = a.m2712a(C0243l.LinearLayoutCompat_showDividers, 0);
        this.f1147o = a.m2722e(C0243l.LinearLayoutCompat_dividerPadding, 0);
        a.m2714a();
    }

    private void m2331a(View view, int i, int i2, int i3, int i4) {
        view.layout(i, i2, i + i3, i2 + i4);
    }

    private void m2332c(int i, int i2) {
        int makeMeasureSpec = MeasureSpec.makeMeasureSpec(getMeasuredWidth(), 1073741824);
        for (int i3 = 0; i3 < i; i3++) {
            View b = m2344b(i3);
            if (b.getVisibility() != 8) {
                bx bxVar = (bx) b.getLayoutParams();
                if (bxVar.width == -1) {
                    int i4 = bxVar.height;
                    bxVar.height = b.getMeasuredHeight();
                    measureChildWithMargins(b, makeMeasureSpec, 0, i2, 0);
                    bxVar.height = i4;
                }
            }
        }
    }

    private void m2333d(int i, int i2) {
        int makeMeasureSpec = MeasureSpec.makeMeasureSpec(getMeasuredHeight(), 1073741824);
        for (int i3 = 0; i3 < i; i3++) {
            View b = m2344b(i3);
            if (b.getVisibility() != 8) {
                bx bxVar = (bx) b.getLayoutParams();
                if (bxVar.height == -1) {
                    int i4 = bxVar.width;
                    bxVar.width = b.getMeasuredWidth();
                    measureChildWithMargins(b, i2, 0, makeMeasureSpec, 0);
                    bxVar.width = i4;
                }
            }
        }
    }

    int m2334a(View view) {
        return 0;
    }

    int m2335a(View view, int i) {
        return 0;
    }

    void m2336a(int i, int i2) {
        int i3;
        int i4;
        int i5;
        View b;
        this.f1138f = 0;
        int i6 = 0;
        int i7 = 0;
        int i8 = 0;
        int i9 = 0;
        Object obj = 1;
        float f = 0.0f;
        int virtualChildCount = getVirtualChildCount();
        int mode = MeasureSpec.getMode(i);
        int mode2 = MeasureSpec.getMode(i2);
        Object obj2 = null;
        Object obj3 = null;
        int i10 = this.f1134b;
        boolean z = this.f1140h;
        int i11 = Integer.MIN_VALUE;
        int i12 = 0;
        while (i12 < virtualChildCount) {
            Object obj4;
            Object obj5;
            int i13;
            View b2 = m2344b(i12);
            if (b2 == null) {
                this.f1138f += m2350d(i12);
                i3 = i11;
                obj4 = obj3;
                obj5 = obj;
                i4 = i7;
                i13 = i6;
            } else if (b2.getVisibility() == 8) {
                i12 += m2335a(b2, i12);
                i3 = i11;
                obj4 = obj3;
                obj5 = obj;
                i4 = i7;
                i13 = i6;
            } else {
                if (m2349c(i12)) {
                    this.f1138f += this.f1145m;
                }
                bx bxVar = (bx) b2.getLayoutParams();
                float f2 = f + bxVar.f1422g;
                if (mode2 == 1073741824 && bxVar.height == 0 && bxVar.f1422g > 0.0f) {
                    i3 = this.f1138f;
                    this.f1138f = Math.max(i3, (bxVar.topMargin + i3) + bxVar.bottomMargin);
                    obj3 = 1;
                } else {
                    i3 = Integer.MIN_VALUE;
                    if (bxVar.height == 0 && bxVar.f1422g > 0.0f) {
                        i3 = 0;
                        bxVar.height = -2;
                    }
                    int i14 = i3;
                    m2340a(b2, i12, i, 0, i2, f2 == 0.0f ? this.f1138f : 0);
                    if (i14 != Integer.MIN_VALUE) {
                        bxVar.height = i14;
                    }
                    i3 = b2.getMeasuredHeight();
                    int i15 = this.f1138f;
                    this.f1138f = Math.max(i15, (((i15 + i3) + bxVar.topMargin) + bxVar.bottomMargin) + m2341b(b2));
                    if (z) {
                        i11 = Math.max(i3, i11);
                    }
                }
                if (i10 >= 0 && i10 == i12 + 1) {
                    this.f1135c = this.f1138f;
                }
                if (i12 >= i10 || bxVar.f1422g <= 0.0f) {
                    Object obj6;
                    Object obj7 = null;
                    if (mode == 1073741824 || bxVar.width != -1) {
                        obj6 = obj2;
                    } else {
                        obj6 = 1;
                        obj7 = 1;
                    }
                    i4 = bxVar.rightMargin + bxVar.leftMargin;
                    i13 = b2.getMeasuredWidth() + i4;
                    i6 = Math.max(i6, i13);
                    int a = du.m2792a(i7, bu.m997f(b2));
                    obj5 = (obj == null || bxVar.width != -1) ? null : 1;
                    if (bxVar.f1422g > 0.0f) {
                        i3 = Math.max(i9, obj7 != null ? i4 : i13);
                        i4 = i8;
                    } else {
                        if (obj7 == null) {
                            i4 = i13;
                        }
                        i4 = Math.max(i8, i4);
                        i3 = i9;
                    }
                    i12 += m2335a(b2, i12);
                    obj4 = obj3;
                    i9 = i3;
                    i8 = i4;
                    i13 = i6;
                    i3 = i11;
                    i4 = a;
                    obj2 = obj6;
                    f = f2;
                } else {
                    throw new RuntimeException("A child of LinearLayout with index less than mBaselineAlignedChildIndex has weight > 0, which won't work.  Either remove the weight, or don't set mBaselineAlignedChildIndex.");
                }
            }
            i12++;
            i11 = i3;
            obj3 = obj4;
            obj = obj5;
            i7 = i4;
            i6 = i13;
        }
        if (this.f1138f > 0 && m2349c(virtualChildCount)) {
            this.f1138f += this.f1145m;
        }
        if (z && (mode2 == Integer.MIN_VALUE || mode2 == 0)) {
            this.f1138f = 0;
            i5 = 0;
            while (i5 < virtualChildCount) {
                b = m2344b(i5);
                if (b == null) {
                    this.f1138f += m2350d(i5);
                    i3 = i5;
                } else if (b.getVisibility() == 8) {
                    i3 = m2335a(b, i5) + i5;
                } else {
                    bx bxVar2 = (bx) b.getLayoutParams();
                    int i16 = this.f1138f;
                    this.f1138f = Math.max(i16, (bxVar2.bottomMargin + ((i16 + i11) + bxVar2.topMargin)) + m2341b(b));
                    i3 = i5;
                }
                i5 = i3 + 1;
            }
        }
        this.f1138f += getPaddingTop() + getPaddingBottom();
        int a2 = bu.m976a(Math.max(this.f1138f, getSuggestedMinimumHeight()), i2, 0);
        i5 = (16777215 & a2) - this.f1138f;
        int i17;
        if (obj3 != null || (i5 != 0 && f > 0.0f)) {
            if (this.f1139g > 0.0f) {
                f = this.f1139g;
            }
            this.f1138f = 0;
            i11 = 0;
            float f3 = f;
            Object obj8 = obj;
            i17 = i8;
            i16 = i7;
            i9 = i6;
            i15 = i5;
            while (i11 < virtualChildCount) {
                View b3 = m2344b(i11);
                if (b3.getVisibility() == 8) {
                    i3 = i17;
                    i5 = i16;
                    i4 = i9;
                    obj5 = obj8;
                } else {
                    float f4;
                    float f5;
                    bxVar2 = (bx) b3.getLayoutParams();
                    float f6 = bxVar2.f1422g;
                    if (f6 > 0.0f) {
                        i5 = (int) ((((float) i15) * f6) / f3);
                        f3 -= f6;
                        i15 -= i5;
                        i4 = getChildMeasureSpec(i, ((getPaddingLeft() + getPaddingRight()) + bxVar2.leftMargin) + bxVar2.rightMargin, bxVar2.width);
                        if (bxVar2.height == 0 && mode2 == 1073741824) {
                            if (i5 <= 0) {
                                i5 = 0;
                            }
                            b3.measure(i4, MeasureSpec.makeMeasureSpec(i5, 1073741824));
                        } else {
                            i5 += b3.getMeasuredHeight();
                            if (i5 < 0) {
                                i5 = 0;
                            }
                            b3.measure(i4, MeasureSpec.makeMeasureSpec(i5, 1073741824));
                        }
                        f4 = f3;
                        i12 = i15;
                        i15 = du.m2792a(i16, bu.m997f(b3) & -256);
                        f5 = f4;
                    } else {
                        f5 = f3;
                        i12 = i15;
                        i15 = i16;
                    }
                    i16 = bxVar2.leftMargin + bxVar2.rightMargin;
                    i4 = b3.getMeasuredWidth() + i16;
                    i9 = Math.max(i9, i4);
                    Object obj9 = (mode == 1073741824 || bxVar2.width != -1) ? null : 1;
                    if (obj9 == null) {
                        i16 = i4;
                    }
                    i4 = Math.max(i17, i16);
                    obj5 = (obj8 == null || bxVar2.width != -1) ? null : 1;
                    i13 = this.f1138f;
                    this.f1138f = Math.max(i13, (bxVar2.bottomMargin + ((b3.getMeasuredHeight() + i13) + bxVar2.topMargin)) + m2341b(b3));
                    i3 = i4;
                    i4 = i9;
                    f4 = f5;
                    i5 = i15;
                    i15 = i12;
                    f3 = f4;
                }
                i11++;
                i17 = i3;
                i9 = i4;
                obj8 = obj5;
                i16 = i5;
            }
            this.f1138f += getPaddingTop() + getPaddingBottom();
            obj = obj8;
            i3 = i17;
            i7 = i16;
            i5 = i9;
        } else {
            i17 = Math.max(i8, i9);
            if (z && mode2 != 1073741824) {
                for (i5 = 0; i5 < virtualChildCount; i5++) {
                    b = m2344b(i5);
                    if (!(b == null || b.getVisibility() == 8 || ((bx) b.getLayoutParams()).f1422g <= 0.0f)) {
                        b.measure(MeasureSpec.makeMeasureSpec(b.getMeasuredWidth(), 1073741824), MeasureSpec.makeMeasureSpec(i11, 1073741824));
                    }
                }
            }
            i3 = i17;
            i5 = i6;
        }
        if (obj != null || mode == 1073741824) {
            i3 = i5;
        }
        setMeasuredDimension(bu.m976a(Math.max(i3 + (getPaddingLeft() + getPaddingRight()), getSuggestedMinimumWidth()), i, i7), a2);
        if (obj2 != null) {
            m2332c(virtualChildCount, i2);
        }
    }

    void m2337a(int i, int i2, int i3, int i4) {
        int paddingLeft = getPaddingLeft();
        int i5 = i3 - i;
        int paddingRight = i5 - getPaddingRight();
        int paddingRight2 = (i5 - paddingLeft) - getPaddingRight();
        int virtualChildCount = getVirtualChildCount();
        int i6 = this.f1137e & 8388615;
        switch (this.f1137e & 112) {
            case C0243l.Toolbar_titleMarginBottom /*16*/:
                i5 = getPaddingTop() + (((i4 - i2) - this.f1138f) / 2);
                break;
            case C0243l.AppCompatTheme_panelMenuListTheme /*80*/:
                i5 = ((getPaddingTop() + i4) - i2) - this.f1138f;
                break;
            default:
                i5 = getPaddingTop();
                break;
        }
        int i7 = 0;
        int i8 = i5;
        while (i7 < virtualChildCount) {
            View b = m2344b(i7);
            if (b == null) {
                i8 += m2350d(i7);
                i5 = i7;
            } else if (b.getVisibility() != 8) {
                int i9;
                int measuredWidth = b.getMeasuredWidth();
                int measuredHeight = b.getMeasuredHeight();
                bx bxVar = (bx) b.getLayoutParams();
                i5 = bxVar.f1423h;
                if (i5 < 0) {
                    i5 = i6;
                }
                switch (C0164q.m1347a(i5, bu.m995d(this)) & 7) {
                    case C0243l.View_android_focusable /*1*/:
                        i9 = ((((paddingRight2 - measuredWidth) / 2) + paddingLeft) + bxVar.leftMargin) - bxVar.rightMargin;
                        break;
                    case C0243l.Toolbar_contentInsetStart /*5*/:
                        i9 = (paddingRight - measuredWidth) - bxVar.rightMargin;
                        break;
                    default:
                        i9 = paddingLeft + bxVar.leftMargin;
                        break;
                }
                int i10 = (m2349c(i7) ? this.f1145m + i8 : i8) + bxVar.topMargin;
                m2331a(b, i9, i10 + m2334a(b), measuredWidth, measuredHeight);
                i8 = i10 + ((bxVar.bottomMargin + measuredHeight) + m2341b(b));
                i5 = m2335a(b, i7) + i7;
            } else {
                i5 = i7;
            }
            i7 = i5 + 1;
        }
    }

    void m2338a(Canvas canvas) {
        int virtualChildCount = getVirtualChildCount();
        int i = 0;
        while (i < virtualChildCount) {
            View b = m2344b(i);
            if (!(b == null || b.getVisibility() == 8 || !m2349c(i))) {
                m2339a(canvas, (b.getTop() - ((bx) b.getLayoutParams()).topMargin) - this.f1145m);
            }
            i++;
        }
        if (m2349c(virtualChildCount)) {
            int height;
            View b2 = m2344b(virtualChildCount - 1);
            if (b2 == null) {
                height = (getHeight() - getPaddingBottom()) - this.f1145m;
            } else {
                bx bxVar = (bx) b2.getLayoutParams();
                height = bxVar.bottomMargin + b2.getBottom();
            }
            m2339a(canvas, height);
        }
    }

    void m2339a(Canvas canvas, int i) {
        this.f1143k.setBounds(getPaddingLeft() + this.f1147o, i, (getWidth() - getPaddingRight()) - this.f1147o, this.f1145m + i);
        this.f1143k.draw(canvas);
    }

    void m2340a(View view, int i, int i2, int i3, int i4, int i5) {
        measureChildWithMargins(view, i2, i3, i4, i5);
    }

    int m2341b(View view) {
        return 0;
    }

    public bx m2342b(AttributeSet attributeSet) {
        return new bx(getContext(), attributeSet);
    }

    protected bx m2343b(LayoutParams layoutParams) {
        return new bx(layoutParams);
    }

    View m2344b(int i) {
        return getChildAt(i);
    }

    void m2345b(int i, int i2) {
        int i3;
        int i4;
        int i5;
        bx bxVar;
        this.f1138f = 0;
        int i6 = 0;
        int i7 = 0;
        int i8 = 0;
        int i9 = 0;
        Object obj = 1;
        float f = 0.0f;
        int virtualChildCount = getVirtualChildCount();
        int mode = MeasureSpec.getMode(i);
        int mode2 = MeasureSpec.getMode(i2);
        Object obj2 = null;
        Object obj3 = null;
        if (this.f1141i == null || this.f1142j == null) {
            this.f1141i = new int[4];
            this.f1142j = new int[4];
        }
        int[] iArr = this.f1141i;
        int[] iArr2 = this.f1142j;
        iArr[3] = -1;
        iArr[2] = -1;
        iArr[1] = -1;
        iArr[0] = -1;
        iArr2[3] = -1;
        iArr2[2] = -1;
        iArr2[1] = -1;
        iArr2[0] = -1;
        boolean z = this.f1133a;
        boolean z2 = this.f1140h;
        Object obj4 = mode == 1073741824 ? 1 : null;
        int i10 = Integer.MIN_VALUE;
        int i11 = 0;
        while (i11 < virtualChildCount) {
            Object obj5;
            Object obj6;
            int i12;
            View b = m2344b(i11);
            if (b == null) {
                this.f1138f += m2350d(i11);
                i3 = i10;
                obj5 = obj3;
                obj6 = obj;
                i4 = i7;
                i12 = i6;
            } else if (b.getVisibility() == 8) {
                i11 += m2335a(b, i11);
                i3 = i10;
                obj5 = obj3;
                obj6 = obj;
                i4 = i7;
                i12 = i6;
            } else {
                Object obj7;
                if (m2349c(i11)) {
                    this.f1138f += this.f1144l;
                }
                bx bxVar2 = (bx) b.getLayoutParams();
                float f2 = f + bxVar2.f1422g;
                if (mode == 1073741824 && bxVar2.width == 0 && bxVar2.f1422g > 0.0f) {
                    if (obj4 != null) {
                        this.f1138f += bxVar2.leftMargin + bxVar2.rightMargin;
                    } else {
                        i3 = this.f1138f;
                        this.f1138f = Math.max(i3, (bxVar2.leftMargin + i3) + bxVar2.rightMargin);
                    }
                    if (z) {
                        i3 = MeasureSpec.makeMeasureSpec(0, 0);
                        b.measure(i3, i3);
                    } else {
                        obj3 = 1;
                    }
                } else {
                    i3 = Integer.MIN_VALUE;
                    if (bxVar2.width == 0 && bxVar2.f1422g > 0.0f) {
                        i3 = 0;
                        bxVar2.width = -2;
                    }
                    int i13 = i3;
                    m2340a(b, i11, i, f2 == 0.0f ? this.f1138f : 0, i2, 0);
                    if (i13 != Integer.MIN_VALUE) {
                        bxVar2.width = i13;
                    }
                    i3 = b.getMeasuredWidth();
                    if (obj4 != null) {
                        this.f1138f += ((bxVar2.leftMargin + i3) + bxVar2.rightMargin) + m2341b(b);
                    } else {
                        int i14 = this.f1138f;
                        this.f1138f = Math.max(i14, (((i14 + i3) + bxVar2.leftMargin) + bxVar2.rightMargin) + m2341b(b));
                    }
                    if (z2) {
                        i10 = Math.max(i3, i10);
                    }
                }
                Object obj8 = null;
                if (mode2 == 1073741824 || bxVar2.height != -1) {
                    obj7 = obj2;
                } else {
                    obj7 = 1;
                    obj8 = 1;
                }
                i4 = bxVar2.bottomMargin + bxVar2.topMargin;
                i12 = b.getMeasuredHeight() + i4;
                int a = du.m2792a(i7, bu.m997f(b));
                if (z) {
                    i7 = b.getBaseline();
                    if (i7 != -1) {
                        int i15 = ((((bxVar2.f1423h < 0 ? this.f1137e : bxVar2.f1423h) & 112) >> 4) & -2) >> 1;
                        iArr[i15] = Math.max(iArr[i15], i7);
                        iArr2[i15] = Math.max(iArr2[i15], i12 - i7);
                    }
                }
                i7 = Math.max(i6, i12);
                obj6 = (obj == null || bxVar2.height != -1) ? null : 1;
                if (bxVar2.f1422g > 0.0f) {
                    i3 = Math.max(i9, obj8 != null ? i4 : i12);
                    i4 = i8;
                } else {
                    if (obj8 == null) {
                        i4 = i12;
                    }
                    i4 = Math.max(i8, i4);
                    i3 = i9;
                }
                i11 += m2335a(b, i11);
                obj5 = obj3;
                i9 = i3;
                i8 = i4;
                i12 = i7;
                i3 = i10;
                i4 = a;
                obj2 = obj7;
                f = f2;
            }
            i11++;
            i10 = i3;
            obj3 = obj5;
            obj = obj6;
            i7 = i4;
            i6 = i12;
        }
        if (this.f1138f > 0 && m2349c(virtualChildCount)) {
            this.f1138f += this.f1144l;
        }
        i11 = (iArr[1] == -1 && iArr[0] == -1 && iArr[2] == -1 && iArr[3] == -1) ? i6 : Math.max(i6, Math.max(iArr[3], Math.max(iArr[0], Math.max(iArr[1], iArr[2]))) + Math.max(iArr2[3], Math.max(iArr2[0], Math.max(iArr2[1], iArr2[2]))));
        if (z2 && (mode == Integer.MIN_VALUE || mode == 0)) {
            this.f1138f = 0;
            i5 = 0;
            while (i5 < virtualChildCount) {
                View b2 = m2344b(i5);
                if (b2 == null) {
                    this.f1138f += m2350d(i5);
                    i3 = i5;
                } else if (b2.getVisibility() == 8) {
                    i3 = m2335a(b2, i5) + i5;
                } else {
                    bxVar = (bx) b2.getLayoutParams();
                    if (obj4 != null) {
                        this.f1138f = ((bxVar.rightMargin + (bxVar.leftMargin + i10)) + m2341b(b2)) + this.f1138f;
                        i3 = i5;
                    } else {
                        i4 = this.f1138f;
                        this.f1138f = Math.max(i4, (bxVar.rightMargin + ((i4 + i10) + bxVar.leftMargin)) + m2341b(b2));
                        i3 = i5;
                    }
                }
                i5 = i3 + 1;
            }
        }
        this.f1138f += getPaddingLeft() + getPaddingRight();
        int a2 = bu.m976a(Math.max(this.f1138f, getSuggestedMinimumWidth()), i, 0);
        i5 = (16777215 & a2) - this.f1138f;
        int i16;
        if (obj3 != null || (i5 != 0 && f > 0.0f)) {
            if (this.f1139g > 0.0f) {
                f = this.f1139g;
            }
            iArr[3] = -1;
            iArr[2] = -1;
            iArr[1] = -1;
            iArr[0] = -1;
            iArr2[3] = -1;
            iArr2[2] = -1;
            iArr2[1] = -1;
            iArr2[0] = -1;
            this.f1138f = 0;
            i10 = 0;
            float f3 = f;
            Object obj9 = obj;
            i16 = i8;
            i15 = i7;
            i14 = i5;
            i8 = -1;
            while (i10 < virtualChildCount) {
                float f4;
                Object obj10;
                View b3 = m2344b(i10);
                if (b3 == null) {
                    f4 = f3;
                    i5 = i14;
                    i4 = i8;
                    i14 = i16;
                    obj10 = obj9;
                } else if (b3.getVisibility() == 8) {
                    f4 = f3;
                    i5 = i14;
                    i4 = i8;
                    i14 = i16;
                    obj10 = obj9;
                } else {
                    float f5;
                    bxVar = (bx) b3.getLayoutParams();
                    float f6 = bxVar.f1422g;
                    if (f6 > 0.0f) {
                        i5 = (int) ((((float) i14) * f6) / f3);
                        f3 -= f6;
                        i4 = i14 - i5;
                        i14 = getChildMeasureSpec(i2, ((getPaddingTop() + getPaddingBottom()) + bxVar.topMargin) + bxVar.bottomMargin, bxVar.height);
                        if (bxVar.width == 0 && mode == 1073741824) {
                            if (i5 <= 0) {
                                i5 = 0;
                            }
                            b3.measure(MeasureSpec.makeMeasureSpec(i5, 1073741824), i14);
                        } else {
                            i5 += b3.getMeasuredWidth();
                            if (i5 < 0) {
                                i5 = 0;
                            }
                            b3.measure(MeasureSpec.makeMeasureSpec(i5, 1073741824), i14);
                        }
                        i9 = du.m2792a(i15, bu.m997f(b3) & -16777216);
                        f5 = f3;
                    } else {
                        i4 = i14;
                        i9 = i15;
                        f5 = f3;
                    }
                    if (obj4 != null) {
                        this.f1138f += ((b3.getMeasuredWidth() + bxVar.leftMargin) + bxVar.rightMargin) + m2341b(b3);
                    } else {
                        i5 = this.f1138f;
                        this.f1138f = Math.max(i5, (((b3.getMeasuredWidth() + i5) + bxVar.leftMargin) + bxVar.rightMargin) + m2341b(b3));
                    }
                    obj5 = (mode2 == 1073741824 || bxVar.height != -1) ? null : 1;
                    i11 = bxVar.topMargin + bxVar.bottomMargin;
                    i14 = b3.getMeasuredHeight() + i11;
                    i8 = Math.max(i8, i14);
                    i11 = Math.max(i16, obj5 != null ? i11 : i14);
                    obj5 = (obj9 == null || bxVar.height != -1) ? null : 1;
                    if (z) {
                        i12 = b3.getBaseline();
                        if (i12 != -1) {
                            i3 = ((((bxVar.f1423h < 0 ? this.f1137e : bxVar.f1423h) & 112) >> 4) & -2) >> 1;
                            iArr[i3] = Math.max(iArr[i3], i12);
                            iArr2[i3] = Math.max(iArr2[i3], i14 - i12);
                        }
                    }
                    f4 = f5;
                    i14 = i11;
                    obj10 = obj5;
                    i15 = i9;
                    i5 = i4;
                    i4 = i8;
                }
                i10++;
                i16 = i14;
                i8 = i4;
                obj9 = obj10;
                i14 = i5;
                f3 = f4;
            }
            this.f1138f += getPaddingLeft() + getPaddingRight();
            if (!(iArr[1] == -1 && iArr[0] == -1 && iArr[2] == -1 && iArr[3] == -1)) {
                i8 = Math.max(i8, Math.max(iArr[3], Math.max(iArr[0], Math.max(iArr[1], iArr[2]))) + Math.max(iArr2[3], Math.max(iArr2[0], Math.max(iArr2[1], iArr2[2]))));
            }
            obj = obj9;
            i3 = i16;
            i7 = i15;
            i5 = i8;
        } else {
            i16 = Math.max(i8, i9);
            if (z2 && mode != 1073741824) {
                for (i5 = 0; i5 < virtualChildCount; i5++) {
                    View b4 = m2344b(i5);
                    if (!(b4 == null || b4.getVisibility() == 8 || ((bx) b4.getLayoutParams()).f1422g <= 0.0f)) {
                        b4.measure(MeasureSpec.makeMeasureSpec(i10, 1073741824), MeasureSpec.makeMeasureSpec(b4.getMeasuredHeight(), 1073741824));
                    }
                }
            }
            i3 = i16;
            i5 = i11;
        }
        if (obj != null || mode2 == 1073741824) {
            i3 = i5;
        }
        setMeasuredDimension((-16777216 & i7) | a2, bu.m976a(Math.max(i3 + (getPaddingTop() + getPaddingBottom()), getSuggestedMinimumHeight()), i2, i7 << 16));
        if (obj2 != null) {
            m2333d(virtualChildCount, i);
        }
    }

    void m2346b(int i, int i2, int i3, int i4) {
        int paddingLeft;
        int i5;
        int i6;
        boolean a = du.m2794a(this);
        int paddingTop = getPaddingTop();
        int i7 = i4 - i2;
        int paddingBottom = i7 - getPaddingBottom();
        int paddingBottom2 = (i7 - paddingTop) - getPaddingBottom();
        int virtualChildCount = getVirtualChildCount();
        i7 = this.f1137e & 8388615;
        int i8 = this.f1137e & 112;
        boolean z = this.f1133a;
        int[] iArr = this.f1141i;
        int[] iArr2 = this.f1142j;
        switch (C0164q.m1347a(i7, bu.m995d(this))) {
            case C0243l.View_android_focusable /*1*/:
                paddingLeft = getPaddingLeft() + (((i3 - i) - this.f1138f) / 2);
                break;
            case C0243l.Toolbar_contentInsetStart /*5*/:
                paddingLeft = ((getPaddingLeft() + i3) - i) - this.f1138f;
                break;
            default:
                paddingLeft = getPaddingLeft();
                break;
        }
        if (a) {
            i5 = -1;
            i6 = virtualChildCount - 1;
        } else {
            i5 = 1;
            i6 = 0;
        }
        int i9 = 0;
        while (i9 < virtualChildCount) {
            int i10 = i6 + (i5 * i9);
            View b = m2344b(i10);
            if (b == null) {
                paddingLeft += m2350d(i10);
                i7 = i9;
            } else if (b.getVisibility() != 8) {
                int i11;
                int measuredWidth = b.getMeasuredWidth();
                int measuredHeight = b.getMeasuredHeight();
                bx bxVar = (bx) b.getLayoutParams();
                i7 = (!z || bxVar.height == -1) ? -1 : b.getBaseline();
                int i12 = bxVar.f1423h;
                if (i12 < 0) {
                    i12 = i8;
                }
                switch (i12 & 112) {
                    case C0243l.Toolbar_titleMarginBottom /*16*/:
                        i11 = ((((paddingBottom2 - measuredHeight) / 2) + paddingTop) + bxVar.topMargin) - bxVar.bottomMargin;
                        break;
                    case C0243l.AppCompatTheme_homeAsUpIndicator /*48*/:
                        i11 = paddingTop + bxVar.topMargin;
                        if (i7 != -1) {
                            i11 += iArr[1] - i7;
                            break;
                        }
                        break;
                    case C0243l.AppCompatTheme_panelMenuListTheme /*80*/:
                        i11 = (paddingBottom - measuredHeight) - bxVar.bottomMargin;
                        if (i7 != -1) {
                            i11 -= iArr2[2] - (b.getMeasuredHeight() - i7);
                            break;
                        }
                        break;
                    default:
                        i11 = paddingTop;
                        break;
                }
                paddingLeft = (m2349c(i10) ? this.f1144l + paddingLeft : paddingLeft) + bxVar.leftMargin;
                m2331a(b, paddingLeft + m2334a(b), i11, measuredWidth, measuredHeight);
                paddingLeft += (bxVar.rightMargin + measuredWidth) + m2341b(b);
                i7 = m2335a(b, i10) + i9;
            } else {
                i7 = i9;
            }
            i9 = i7 + 1;
        }
    }

    void m2347b(Canvas canvas) {
        int virtualChildCount = getVirtualChildCount();
        boolean a = du.m2794a(this);
        int i = 0;
        while (i < virtualChildCount) {
            View b = m2344b(i);
            if (!(b == null || b.getVisibility() == 8 || !m2349c(i))) {
                bx bxVar = (bx) b.getLayoutParams();
                m2348b(canvas, a ? bxVar.rightMargin + b.getRight() : (b.getLeft() - bxVar.leftMargin) - this.f1144l);
            }
            i++;
        }
        if (m2349c(virtualChildCount)) {
            int paddingLeft;
            View b2 = m2344b(virtualChildCount - 1);
            if (b2 == null) {
                paddingLeft = a ? getPaddingLeft() : (getWidth() - getPaddingRight()) - this.f1144l;
            } else {
                bxVar = (bx) b2.getLayoutParams();
                paddingLeft = a ? (b2.getLeft() - bxVar.leftMargin) - this.f1144l : bxVar.rightMargin + b2.getRight();
            }
            m2348b(canvas, paddingLeft);
        }
    }

    void m2348b(Canvas canvas, int i) {
        this.f1143k.setBounds(i, getPaddingTop() + this.f1147o, this.f1144l + i, (getHeight() - getPaddingBottom()) - this.f1147o);
        this.f1143k.draw(canvas);
    }

    protected boolean m2349c(int i) {
        if (i == 0) {
            return (this.f1146n & 1) != 0;
        } else {
            if (i == getChildCount()) {
                return (this.f1146n & 4) != 0;
            } else {
                if ((this.f1146n & 2) == 0) {
                    return false;
                }
                for (int i2 = i - 1; i2 >= 0; i2--) {
                    if (getChildAt(i2).getVisibility() != 8) {
                        return true;
                    }
                }
                return false;
            }
        }
    }

    protected boolean checkLayoutParams(LayoutParams layoutParams) {
        return layoutParams instanceof bx;
    }

    int m2350d(int i) {
        return 0;
    }

    protected /* synthetic */ LayoutParams generateDefaultLayoutParams() {
        return m2351j();
    }

    public /* synthetic */ LayoutParams generateLayoutParams(AttributeSet attributeSet) {
        return m2342b(attributeSet);
    }

    protected /* synthetic */ LayoutParams generateLayoutParams(LayoutParams layoutParams) {
        return m2343b(layoutParams);
    }

    public int getBaseline() {
        if (this.f1134b < 0) {
            return super.getBaseline();
        }
        if (getChildCount() <= this.f1134b) {
            throw new RuntimeException("mBaselineAlignedChildIndex of LinearLayout set to an index that is out of bounds.");
        }
        View childAt = getChildAt(this.f1134b);
        int baseline = childAt.getBaseline();
        if (baseline != -1) {
            int i;
            int i2 = this.f1135c;
            if (this.f1136d == 1) {
                i = this.f1137e & 112;
                if (i != 48) {
                    switch (i) {
                        case C0243l.Toolbar_titleMarginBottom /*16*/:
                            i = i2 + (((((getBottom() - getTop()) - getPaddingTop()) - getPaddingBottom()) - this.f1138f) / 2);
                            break;
                        case C0243l.AppCompatTheme_panelMenuListTheme /*80*/:
                            i = ((getBottom() - getTop()) - getPaddingBottom()) - this.f1138f;
                            break;
                    }
                }
            }
            i = i2;
            return (((bx) childAt.getLayoutParams()).topMargin + i) + baseline;
        } else if (this.f1134b == 0) {
            return -1;
        } else {
            throw new RuntimeException("mBaselineAlignedChildIndex of LinearLayout points to a View that doesn't know how to get its baseline.");
        }
    }

    public int getBaselineAlignedChildIndex() {
        return this.f1134b;
    }

    public Drawable getDividerDrawable() {
        return this.f1143k;
    }

    public int getDividerPadding() {
        return this.f1147o;
    }

    public int getDividerWidth() {
        return this.f1144l;
    }

    public int getOrientation() {
        return this.f1136d;
    }

    public int getShowDividers() {
        return this.f1146n;
    }

    int getVirtualChildCount() {
        return getChildCount();
    }

    public float getWeightSum() {
        return this.f1139g;
    }

    protected bx m2351j() {
        return this.f1136d == 0 ? new bx(-2, -2) : this.f1136d == 1 ? new bx(-1, -2) : null;
    }

    protected void onDraw(Canvas canvas) {
        if (this.f1143k != null) {
            if (this.f1136d == 1) {
                m2338a(canvas);
            } else {
                m2347b(canvas);
            }
        }
    }

    public void onInitializeAccessibilityEvent(AccessibilityEvent accessibilityEvent) {
        if (VERSION.SDK_INT >= 14) {
            super.onInitializeAccessibilityEvent(accessibilityEvent);
            accessibilityEvent.setClassName(bw.class.getName());
        }
    }

    public void onInitializeAccessibilityNodeInfo(AccessibilityNodeInfo accessibilityNodeInfo) {
        if (VERSION.SDK_INT >= 14) {
            super.onInitializeAccessibilityNodeInfo(accessibilityNodeInfo);
            accessibilityNodeInfo.setClassName(bw.class.getName());
        }
    }

    protected void onLayout(boolean z, int i, int i2, int i3, int i4) {
        if (this.f1136d == 1) {
            m2337a(i, i2, i3, i4);
        } else {
            m2346b(i, i2, i3, i4);
        }
    }

    protected void onMeasure(int i, int i2) {
        if (this.f1136d == 1) {
            m2336a(i, i2);
        } else {
            m2345b(i, i2);
        }
    }

    public void setBaselineAligned(boolean z) {
        this.f1133a = z;
    }

    public void setBaselineAlignedChildIndex(int i) {
        if (i < 0 || i >= getChildCount()) {
            throw new IllegalArgumentException("base aligned child index out of range (0, " + getChildCount() + ")");
        }
        this.f1134b = i;
    }

    public void setDividerDrawable(Drawable drawable) {
        boolean z = false;
        if (drawable != this.f1143k) {
            this.f1143k = drawable;
            if (drawable != null) {
                this.f1144l = drawable.getIntrinsicWidth();
                this.f1145m = drawable.getIntrinsicHeight();
            } else {
                this.f1144l = 0;
                this.f1145m = 0;
            }
            if (drawable == null) {
                z = true;
            }
            setWillNotDraw(z);
            requestLayout();
        }
    }

    public void setDividerPadding(int i) {
        this.f1147o = i;
    }

    public void setGravity(int i) {
        if (this.f1137e != i) {
            int i2 = (8388615 & i) == 0 ? 8388611 | i : i;
            if ((i2 & 112) == 0) {
                i2 |= 48;
            }
            this.f1137e = i2;
            requestLayout();
        }
    }

    public void setHorizontalGravity(int i) {
        int i2 = i & 8388615;
        if ((this.f1137e & 8388615) != i2) {
            this.f1137e = i2 | (this.f1137e & -8388616);
            requestLayout();
        }
    }

    public void setMeasureWithLargestChildEnabled(boolean z) {
        this.f1140h = z;
    }

    public void setOrientation(int i) {
        if (this.f1136d != i) {
            this.f1136d = i;
            requestLayout();
        }
    }

    public void setShowDividers(int i) {
        if (i != this.f1146n) {
            requestLayout();
        }
        this.f1146n = i;
    }

    public void setVerticalGravity(int i) {
        int i2 = i & 112;
        if ((this.f1137e & 112) != i2) {
            this.f1137e = i2 | (this.f1137e & -113);
            requestLayout();
        }
    }

    public void setWeightSum(float f) {
        this.f1139g = Math.max(0.0f, f);
    }

    public boolean shouldDelayChildPressedState() {
        return false;
    }
}

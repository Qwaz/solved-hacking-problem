package android.support.v7.widget;

import android.content.Context;
import android.content.res.ColorStateList;
import android.content.res.TypedArray;
import android.graphics.Color;
import android.support.v4.p006c.C0088a;
import android.util.TypedValue;

class dc {
    static final int[] f1504a;
    static final int[] f1505b;
    static final int[] f1506c;
    static final int[] f1507d;
    static final int[] f1508e;
    static final int[] f1509f;
    static final int[] f1510g;
    static final int[] f1511h;
    private static final ThreadLocal f1512i;
    private static final int[] f1513j;

    static {
        f1512i = new ThreadLocal();
        f1504a = new int[]{-16842910};
        f1505b = new int[]{16842908};
        f1506c = new int[]{16843518};
        f1507d = new int[]{16842919};
        f1508e = new int[]{16842912};
        f1509f = new int[]{16842913};
        f1510g = new int[]{-16842919, -16842908};
        f1511h = new int[0];
        f1513j = new int[1];
    }

    public static int m2700a(Context context, int i) {
        f1513j[0] = i;
        TypedArray obtainStyledAttributes = context.obtainStyledAttributes(null, f1513j);
        try {
            int color = obtainStyledAttributes.getColor(0, 0);
            return color;
        } finally {
            obtainStyledAttributes.recycle();
        }
    }

    static int m2701a(Context context, int i, float f) {
        int a = m2700a(context, i);
        return C0088a.m567b(a, Math.round(((float) Color.alpha(a)) * f));
    }

    private static TypedValue m2702a() {
        TypedValue typedValue = (TypedValue) f1512i.get();
        if (typedValue != null) {
            return typedValue;
        }
        typedValue = new TypedValue();
        f1512i.set(typedValue);
        return typedValue;
    }

    public static ColorStateList m2703b(Context context, int i) {
        f1513j[0] = i;
        TypedArray obtainStyledAttributes = context.obtainStyledAttributes(null, f1513j);
        try {
            ColorStateList colorStateList = obtainStyledAttributes.getColorStateList(0);
            return colorStateList;
        } finally {
            obtainStyledAttributes.recycle();
        }
    }

    public static int m2704c(Context context, int i) {
        ColorStateList b = m2703b(context, i);
        if (b != null && b.isStateful()) {
            return b.getColorForState(f1504a, b.getDefaultColor());
        }
        TypedValue a = m2702a();
        context.getTheme().resolveAttribute(16842803, a, true);
        return m2701a(context, i, a.getFloat());
    }
}

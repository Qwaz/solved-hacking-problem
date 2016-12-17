package android.support.v7.widget;

import android.content.Context;
import android.content.res.TypedArray;
import android.graphics.drawable.Drawable;
import android.util.AttributeSet;

public class dh {
    private final Context f1521a;
    private final TypedArray f1522b;

    private dh(Context context, TypedArray typedArray) {
        this.f1521a = context;
        this.f1522b = typedArray;
    }

    public static dh m2709a(Context context, AttributeSet attributeSet, int[] iArr) {
        return new dh(context, context.obtainStyledAttributes(attributeSet, iArr));
    }

    public static dh m2710a(Context context, AttributeSet attributeSet, int[] iArr, int i, int i2) {
        return new dh(context, context.obtainStyledAttributes(attributeSet, iArr, i, i2));
    }

    public float m2711a(int i, float f) {
        return this.f1522b.getFloat(i, f);
    }

    public int m2712a(int i, int i2) {
        return this.f1522b.getInt(i, i2);
    }

    public Drawable m2713a(int i) {
        if (this.f1522b.hasValue(i)) {
            int resourceId = this.f1522b.getResourceId(i, 0);
            if (resourceId != 0) {
                return ao.m2497a().m2520a(this.f1521a, resourceId);
            }
        }
        return this.f1522b.getDrawable(i);
    }

    public void m2714a() {
        this.f1522b.recycle();
    }

    public boolean m2715a(int i, boolean z) {
        return this.f1522b.getBoolean(i, z);
    }

    public int m2716b(int i, int i2) {
        return this.f1522b.getColor(i, i2);
    }

    public Drawable m2717b(int i) {
        if (this.f1522b.hasValue(i)) {
            int resourceId = this.f1522b.getResourceId(i, 0);
            if (resourceId != 0) {
                return ao.m2497a().m2521a(this.f1521a, resourceId, true);
            }
        }
        return null;
    }

    public int m2718c(int i, int i2) {
        return this.f1522b.getInteger(i, i2);
    }

    public CharSequence m2719c(int i) {
        return this.f1522b.getText(i);
    }

    public int m2720d(int i, int i2) {
        return this.f1522b.getDimensionPixelOffset(i, i2);
    }

    public String m2721d(int i) {
        return this.f1522b.getString(i);
    }

    public int m2722e(int i, int i2) {
        return this.f1522b.getDimensionPixelSize(i, i2);
    }

    public CharSequence[] m2723e(int i) {
        return this.f1522b.getTextArray(i);
    }

    public int m2724f(int i, int i2) {
        return this.f1522b.getLayoutDimension(i, i2);
    }

    public boolean m2725f(int i) {
        return this.f1522b.hasValue(i);
    }

    public int m2726g(int i, int i2) {
        return this.f1522b.getResourceId(i, i2);
    }
}

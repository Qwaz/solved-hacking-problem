package android.support.v7.widget;

import android.content.Context;
import android.content.res.TypedArray;
import android.graphics.drawable.Drawable;
import android.util.AttributeSet;
import android.widget.TextView;

class bo extends bn {
    private static final int[] f1417b;
    private df f1418c;
    private df f1419d;

    static {
        f1417b = new int[]{16843666, 16843667};
    }

    bo(TextView textView) {
        super(textView);
    }

    void m2600a() {
        super.m2595a();
        if (this.f1418c != null || this.f1419d != null) {
            Drawable[] compoundDrawablesRelative = this.a.getCompoundDrawablesRelative();
            m2597a(compoundDrawablesRelative[0], this.f1418c);
            m2597a(compoundDrawablesRelative[2], this.f1419d);
        }
    }

    void m2601a(AttributeSet attributeSet, int i) {
        super.m2598a(attributeSet, i);
        Context context = this.a.getContext();
        ao a = ao.m2497a();
        TypedArray obtainStyledAttributes = context.obtainStyledAttributes(attributeSet, f1417b, i, 0);
        if (obtainStyledAttributes.hasValue(0)) {
            this.f1418c = bn.m2594a(context, a, obtainStyledAttributes.getResourceId(0, 0));
        }
        if (obtainStyledAttributes.hasValue(1)) {
            this.f1419d = bn.m2594a(context, a, obtainStyledAttributes.getResourceId(1, 0));
        }
        obtainStyledAttributes.recycle();
    }
}

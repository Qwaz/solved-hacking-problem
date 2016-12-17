package android.support.v7.widget;

import android.content.Context;
import android.graphics.Bitmap;
import android.support.v4.p004h.bu;
import android.support.v7.p015b.C0233b;
import android.util.AttributeSet;
import android.widget.RatingBar;

public class bd extends RatingBar {
    private bb f1347a;
    private ao f1348b;

    public bd(Context context, AttributeSet attributeSet) {
        this(context, attributeSet, C0233b.ratingBarStyle);
    }

    public bd(Context context, AttributeSet attributeSet, int i) {
        super(context, attributeSet, i);
        this.f1348b = ao.m2497a();
        this.f1347a = new bb(this, this.f1348b);
        this.f1347a.m2541a(attributeSet, i);
    }

    protected synchronized void onMeasure(int i, int i2) {
        super.onMeasure(i, i2);
        Bitmap a = this.f1347a.m2540a();
        if (a != null) {
            setMeasuredDimension(bu.m976a(a.getWidth() * getNumStars(), i, 0), getMeasuredHeight());
        }
    }
}

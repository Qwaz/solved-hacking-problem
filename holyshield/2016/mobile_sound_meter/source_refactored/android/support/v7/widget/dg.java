package android.support.v7.widget;

import android.content.Context;
import android.content.res.Resources;
import android.graphics.drawable.Drawable;
import java.lang.ref.WeakReference;

class dg extends cn {
    private final WeakReference f1520a;

    public dg(Context context, Resources resources) {
        super(resources);
        this.f1520a = new WeakReference(context);
    }

    public Drawable getDrawable(int i) {
        Drawable drawable = super.getDrawable(i);
        Context context = (Context) this.f1520a.get();
        if (!(drawable == null || context == null)) {
            ao.m2497a();
            ao.m2503a(context, i, drawable);
        }
        return drawable;
    }
}

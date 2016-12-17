package android.support.v7.widget;

import android.graphics.drawable.Drawable;
import android.support.v4.p002b.C0020a;
import android.support.v7.p015b.C0243l;
import android.util.AttributeSet;
import android.widget.ImageView;

public class aw {
    private final ImageView f1325a;
    private final ao f1326b;

    public aw(ImageView imageView, ao aoVar) {
        this.f1325a = imageView;
        this.f1326b = aoVar;
    }

    public void m2529a(int i) {
        if (i != 0) {
            Drawable a = this.f1326b != null ? this.f1326b.m2520a(this.f1325a.getContext(), i) : C0020a.m74a(this.f1325a.getContext(), i);
            if (a != null) {
                bt.m2633a(a);
            }
            this.f1325a.setImageDrawable(a);
            return;
        }
        this.f1325a.setImageDrawable(null);
    }

    public void m2530a(AttributeSet attributeSet, int i) {
        dh a = dh.m2710a(this.f1325a.getContext(), attributeSet, C0243l.AppCompatImageView, i, 0);
        try {
            Drawable b = a.m2717b(C0243l.AppCompatImageView_android_src);
            if (b != null) {
                this.f1325a.setImageDrawable(b);
            }
            int g = a.m2726g(C0243l.AppCompatImageView_srcCompat, -1);
            if (g != -1) {
                b = this.f1326b.m2520a(this.f1325a.getContext(), g);
                if (b != null) {
                    this.f1325a.setImageDrawable(b);
                }
            }
            b = this.f1325a.getDrawable();
            if (b != null) {
                bt.m2633a(b);
            }
            a.m2714a();
        } catch (Throwable th) {
            a.m2714a();
        }
    }
}
